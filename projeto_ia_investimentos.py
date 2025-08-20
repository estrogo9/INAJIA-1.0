# ================= PARTE 1 =================
# imports, utilitários, coleta, indicadores, login e inicialização

import os
import time
import threading
import streamlit as st
import pandas as pd
import numpy as np
import yfinance as yf
from prophet import Prophet
from datetime import datetime, timedelta
import plotly.graph_objects as go
import hashlib
import json
from pathlib import Path
import smtplib
from email.message import EmailMessage
import logging

# Auto-refresh opcional
try:
    from streamlit_autorefresh import st_autorefresh
    AUTORELOAD_AVAILABLE = True
except Exception:
    AUTORELOAD_AVAILABLE = False

# Firebase opcional
try:
    import firebase_admin
    from firebase_admin import credentials, db
    FIREBASE_AVAILABLE = True
except Exception:
    FIREBASE_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("investimentos_ia")

BASE_DIR = Path(".")
USUARIOS_PATH = BASE_DIR / "usuarios.json"
WATCHLIST_PATH = BASE_DIR / "watchlist.json"
CHAT_PATH = BASE_DIR / "chat.json"
MARKET_UNIVERSE_PATH = BASE_DIR / "market_universe.json"

ADMIN_NOME = "gabriel"
ADMIN_SENHA = "111228031412"

EMAIL_REMETENTE = os.getenv("EMAIL_REMETENTE", "copro04052025@gmail.com")
EMAIL_SENHA = os.getenv("EMAIL_SENHA", "iwuf wchh ysrq wmkm")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH", "")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL", "")

# ====================== Funções ======================

def enviar_email(destinatario, assunto, corpo):
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_REMETENTE
        msg["To"] = destinatario
        msg["Subject"] = assunto
        msg.set_content(corpo)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_REMETENTE, EMAIL_SENHA)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.warning(f"Falha ao enviar e-mail para {destinatario}: {e}")
        return False

# ====================== Firebase ======================

def init_firebase_if_available():
    if not FIREBASE_AVAILABLE or not FIREBASE_CRED_PATH or not FIREBASE_DB_URL:
        return False
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(FIREBASE_CRED_PATH)
            firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
        return True
    except Exception as e:
        logger.error(f"Erro inicializar Firebase: {e}")
        return False

FIREBASE_INIT_OK = init_firebase_if_available()

def firebase_get(path):
    if not FIREBASE_INIT_OK:
        return None
    try:
        ref = db.reference(path)
        return ref.get()
    except Exception as e:
        logger.warning(f"firebase_get erro: {e}")
        return None

def firebase_set(path, value):
    if not FIREBASE_INIT_OK:
        return False
    try:
        ref = db.reference(path)
        ref.set(value)
        return True
    except Exception as e:
        logger.warning(f"firebase_set erro: {e}")
        return False

def firebase_push(path, value):
    if not FIREBASE_INIT_OK:
        return False
    try:
        ref = db.reference(path)
        ref.push(value)
        return True
    except Exception as e:
        logger.warning(f"firebase_push erro: {e}")
        return False

# ====================== Arquivo Local ======================

def carregar_json(path: Path, default):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Erro carregar_json {path}: {e}")
    return default

def salvar_json(path: Path, data):
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro salvar_json {path}: {e}")

# ====================== Usuários ======================

def hash_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode("utf-8")).hexdigest()

def carregar_usuarios() -> dict:
    return carregar_json(USUARIOS_PATH, {})

def salvar_usuarios(usuarios: dict):
    salvar_json(USUARIOS_PATH, usuarios)

def criar_conta_usuario(username: str, senha: str, email: str):
    usuarios = carregar_usuarios()
    if username in usuarios:
        return False, "Usuário já existe."
    for u in usuarios.values():
        if isinstance(u, dict) and u.get("email") == email:
            return False, "Email já cadastrado."
    usuarios[username] = {"senha": hash_senha(senha), "email": email}
    salvar_usuarios(usuarios)
    enviar_email(email, "Bem-vindo ao Sistema IA Investimentos", f"Olá {username},\nSua conta foi criada com sucesso.")
    return True, "Conta criada com sucesso."

def validar_login_usuario(email: str, senha: str):
    usuarios = carregar_usuarios()
    for username, dados in usuarios.items():
        if isinstance(dados, dict) and dados.get("email") == email:
            if dados.get("senha") == hash_senha(senha):
                return True, username
            else:
                return False, "Senha incorreta."
    return False, "Email não encontrado."

# ====================== Watchlist ======================

def carregar_watchlist():
    return carregar_json(WATCHLIST_PATH, [])

def salvar_watchlist(wl):
    salvar_json(WATCHLIST_PATH, wl)

# ====================== Chat ======================

def carregar_chat_local():
    return carregar_json(CHAT_PATH, {"global": [], "private": {}})

def salvar_chat_local(chat):
    salvar_json(CHAT_PATH, chat)

_CHAT_POLL_INTERVAL = 2.0

def _poll_chat_loop():
    while True:
        try:
            local_chat = carregar_chat_local()
            if FIREBASE_INIT_OK:
                fb_chat = firebase_get("/chat")
                if fb_chat is None:
                    firebase_set("/chat", local_chat)
                else:
                    # Merge global
                    local_chat["global"] = max(local_chat.get("global", []), fb_chat.get("global", []), key=len)
                    # Merge private
                    fb_private = fb_chat.get("private", {})
                    loc_private = local_chat.get("private", {})
                    for k, v in fb_private.items():
                        if len(v) > len(loc_private.get(k, [])):
                            loc_private[k] = v
                    local_chat["private"] = loc_private
                    salvar_chat_local(local_chat)
        except Exception as e:
            logger.warning(f"poll chat loop erro: {e}")
        time.sleep(_CHAT_POLL_INTERVAL)

_poll_thread_started = False

def start_chat_polling_thread():
    global _poll_thread_started
    if _poll_thread_started:
        return
    t = threading.Thread(target=_poll_chat_loop, daemon=True)
    t.start()
    _poll_thread_started = True

def push_global_message(user: str, msg: str):
    entry = {"user": user, "msg": msg, "timestamp": datetime.utcnow().isoformat()}
    if FIREBASE_INIT_OK:
        try:
            firebase_push("/chat/global", entry)
            return True
        except:
            pass
    chat = carregar_chat_local()
    chat.setdefault("global", []).append(entry)
    salvar_chat_local(chat)
    return True

def push_private_message(sender: str, recipient_username: str, msg: str):
    key = "|".join(sorted([sender, recipient_username]))
    entry = {"user": sender, "msg": msg, "timestamp": datetime.utcnow().isoformat()}
    chat = carregar_chat_local()
    chat.setdefault("private", {}).setdefault(key, []).append(entry)
    salvar_chat_local(chat)
    return True

def get_local_chat_snapshot():
    start_chat_polling_thread()
    return carregar_chat_local()

# ====================== Coleta de Dados ======================

def coletar_dados_ativo(ticker: str, periodo: str = "730d"):
    try:
        ticker = ticker.strip().upper()
        hoje = datetime.now()
        dias = int(periodo[:-1]) if periodo.endswith("d") else int(periodo[:-1]) * 365
        dias = min(dias, 730)
        inicio = hoje - timedelta(days=dias)
        df = yf.download(ticker, start=inicio.strftime("%Y-%m-%d"), end=(hoje+timedelta(days=1)).strftime("%Y-%m-%d"), progress=False)
        if df is None or df.empty:
            return None
        df = df.reset_index()
        df.rename(columns={"Date": "ds", "Adj Close": "y"}, inplace=True)
        df["ds"] = pd.to_datetime(df["ds"]).dt.tz_localize(None)
        df = df[["ds", "y"]].dropna()
        return df
    except Exception as e:
        logger.warning(f"Erro coletar_dados_ativo({ticker}): {e}")
        return None

def prever_futuro(dados: pd.DataFrame, dias: int = 90):
    try:
        df = dados.copy()
        m = Prophet(daily_seasonality=True)
        m.fit(df)
        fut = m.make_future_dataframe(periods=dias, freq="D")
        fut = fut[fut["ds"] > pd.Timestamp(datetime.now())]
        return m.predict(fut)
    except Exception as e:
        logger.warning(f"Prophet falhou: {e}")
        return None

def calcular_indicadores_basicos(df: pd.DataFrame):
    df = df.copy().sort_values("ds")
    df["retorno"] = df["y"].pct_change()
    for w in [5,10,20,50]:
        df[f"sma_{w}"] = df["y"].rolling(window=w).mean()
        df[f"ema_{w}"] = df["y"].ewm(span=w, adjust=False).mean()
    delta = df["y"].diff()
    up = delta.clip(lower=0).rolling(14).mean()
    down = -delta.clip(upper=0).rolling(14).mean()
    rs = up / down.replace(0, np.nan)
    df["rsi_14"] = 100 - (100 / (1 + rs))
    return df

# ====================== Inicialização ======================

def safe_rerun():
    if hasattr(st, "experimental_rerun"):
        st.experimental_rerun()
    elif hasattr(st, "rerun"):
        st.rerun()
    else:
        st.session_state["_force_update"] = not st.session_state.get("_force_update", False)

def inicializar_sessao():
    defaults = {
        "admin_logado": False,
        "usuario_logado": False,
        "usuario_nome": "",
        "usuario_email": "",
        "_force_update": False
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

def tela_inicial():
    st.title("Sistema IA Investimentos")
    escolha = st.radio("Escolha o tipo de acesso:", ["Usuário", "Admin"])
    if escolha == "Admin":
        st.subheader("Login Admin")
        nome = st.text_input("Nome do admin")
        senha = st.text_input("Senha do admin", type="password")
        if st.button("Login Admin"):
            if nome == ADMIN_NOME and senha == ADMIN_SENHA:
                st.session_state["admin_logado"] = True
                st.success("Admin logado com sucesso!")
                safe_rerun()
            else:
                st.error("Nome ou senha incorretos.")
    else:
        st.subheader("Login Usuário")
        email = st.text_input("Email")
        senha = st.text_input("Senha", type="password")
        if st.button("Login"):
            ok, resultado = validar_login_usuario(email, senha)
            if ok:
                st.session_state["usuario_logado"] = True
                st.session_state["usuario_nome"] = resultado
                st.session_state["usuario_email"] = email
                st.success(f"Bem-vindo {resultado}!")
                safe_rerun()
            else:
                st.error(resultado)
        st.markdown("---")
        st.subheader("Criar Conta")
        novo_user = st.text_input("Nome de usuário")
        novo_email = st.text_input("Email novo")
        nova_senha = st.text_input("Senha nova", type="password")
        if st.button("Criar Conta"):
            ok, msg = criar_conta_usuario(novo_user, nova_senha, novo_email)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

# ================= PARTE 2 =================
# Painéis, interface, menus e funcionalidades de usuário/admin

def tela_usuario():
    st.sidebar.title(f"Bem-vindo {st.session_state['usuario_nome']}")
    menu = st.sidebar.radio("Menu", ["Chat Global", "Chat Privado", "Watchlist", "Ativos", "Indicadores", "Sair"])

    if menu == "Chat Global":
        st.subheader("Chat Global")
        chat_snapshot = get_local_chat_snapshot()
        for msg in chat_snapshot.get("global", []):
            st.markdown(f"**{msg['user']}**: {msg['msg']}  \n_{msg['timestamp']}_")
        nova_msg = st.text_input("Digite sua mensagem")
        if st.button("Enviar Mensagem Global"):
            if nova_msg.strip():
                push_global_message(st.session_state['usuario_nome'], nova_msg)
                safe_rerun()

    elif menu == "Chat Privado":
        st.subheader("Chat Privado")
        usuarios = list(carregar_usuarios().keys())
        usuarios.remove(st.session_state['usuario_nome'])
        destinatario = st.selectbox("Escolha o usuário", usuarios)
        chat_key = "|".join(sorted([st.session_state['usuario_nome'], destinatario]))
        chat_snapshot = get_local_chat_snapshot()
        mensagens = chat_snapshot.get("private", {}).get(chat_key, [])
        for msg in mensagens:
            st.markdown(f"**{msg['user']}**: {msg['msg']}  \n_{msg['timestamp']}_")
        nova_msg = st.text_input("Digite sua mensagem privada")
        if st.button("Enviar Mensagem Privada"):
            if nova_msg.strip():
                push_private_message(st.session_state['usuario_nome'], destinatario, nova_msg)
                safe_rerun()

    elif menu == "Watchlist":
        st.subheader("Watchlist")
        wl = carregar_watchlist()
        ticker = st.text_input("Adicionar ativo (Ex: AAPL)")
        if st.button("Adicionar"):
            if ticker.strip().upper() not in wl:
                wl.append(ticker.strip().upper())
                salvar_watchlist(wl)
                safe_rerun()
        st.write("Ativos na Watchlist:", wl)

    elif menu == "Ativos":
        st.subheader("Análise de Ativos")
        ticker = st.text_input("Digite o ticker")
        if st.button("Carregar dados"):
            df = coletar_dados_ativo(ticker)
            if df is not None:
                st.write(df.tail())
                st.line_chart(df.set_index("ds")["y"])
            else:
                st.error("Falha ao carregar dados.")

    elif menu == "Indicadores":
        st.subheader("Indicadores Técnicos")
        ticker = st.text_input("Digite o ticker para indicadores")
        if st.button("Calcular Indicadores"):
            df = coletar_dados_ativo(ticker)
            if df is not None:
                df_ind = calcular_indicadores_basicos(df)
                st.write(df_ind.tail())
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df_ind["ds"], y=df_ind["y"], mode="lines", name="Preço"))
                fig.add_trace(go.Scatter(x=df_ind["ds"], y=df_ind["sma_5"], mode="lines", name="SMA5"))
                fig.add_trace(go.Scatter(x=df_ind["ds"], y=df_ind["ema_5"], mode="lines", name="EMA5"))
                st.plotly_chart(fig)
            else:
                st.error("Falha ao carregar dados do ativo.")

    elif menu == "Sair":
        st.session_state["usuario_logado"] = False
        st.session_state["usuario_nome"] = ""
        st.session_state["usuario_email"] = ""
        safe_rerun()

# ====================== Painel Admin ======================

def tela_admin():
    st.sidebar.title("Painel Admin")
    menu = st.sidebar.radio("Menu Admin", ["Chat Global", "Gerenciar Usuários", "E-mails", "Sair"])
    if menu == "Chat Global":
        st.subheader("Chat Global")
        chat_snapshot = get_local_chat_snapshot()
        for msg in chat_snapshot.get("global", []):
            st.markdown(f"**{msg['user']}**: {msg['msg']}  \n_{msg['timestamp']}_")
    elif menu == "Gerenciar Usuários":
        st.subheader("Usuários cadastrados")
        usuarios = carregar_usuarios()
        for uname, data in usuarios.items():
            st.write(f"{uname} - {data.get('email','')}")
        remover = st.text_input("Remover usuário (nome)")
        if st.button("Remover"):
            if remover in usuarios:
                usuarios.pop(remover)
                salvar_usuarios(usuarios)
                st.success(f"Usuário {remover} removido")
                safe_rerun()
            else:
                st.error("Usuário não encontrado.")
    elif menu == "E-mails":
        st.subheader("Enviar e-mail para todos usuários")
        assunto = st.text_input("Assunto")
        corpo = st.text_area("Corpo do e-mail")
        if st.button("Enviar"):
            usuarios = carregar_usuarios()
            for u, d in usuarios.items():
                enviar_email(d.get("email",""), assunto, corpo)
            st.success("E-mails enviados.")
    elif menu == "Sair":
        st.session_state["admin_logado"] = False
        safe_rerun()

# ====================== Executar ======================

def main():
    inicializar_sessao()
    if st.session_state.get("admin_logado", False):
        tela_admin()
    elif st.session_state.get("usuario_logado", False):
        tela_usuario()
    else:
        tela_inicial()

if __name__ == "__main__":
    main()

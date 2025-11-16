"""
workshield.py
Lógica principal: gerenciamento de usuários, autenticação (PBKDF2),
ingestão de mensagens, detecção automática de incidentes e geração de logs.
"""

import os
import hashlib
import secrets
import re
import logging

from avl import AVLTree
from models import User, Incident

# CONFIGURAÇÃO DE LOGS
LOG_FILE = "workshield.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("workshield")

# REGEX DE PII
CPF_RE = re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b')
CREDIT_RE = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

BAD_DOMAINS = [
    "phishing-login.com",
    "fakebank-secure.net"
]

# HASH E VERIFICAÇÃO

def hash_password(password: str, salt: bytes = None):
    """
    Gera o hash de uma senha utilizando PBKDF2-HMAC-SHA256.

    Args:
        password (str): Senha em texto puro.
        salt (bytes, optional): Salt para hashing. Se não for fornecido, gera um novo.

    Returns:
        tuple(str, str): Hash em hexadecimal e salt em hexadecimal.
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return dk.hex(), salt.hex()


def verify_password(stored_hash_hex: str, stored_salt_hex: str, password_guess: str) -> bool:
    """
    Verifica se uma senha corresponde ao hash armazenado.

    Args:
        stored_hash_hex (str): Hash salvo em hexadecimal.
        stored_salt_hex (str): Salt salvo em hexadecimal.
        password_guess (str): Senha fornecida pelo usuário.

    Returns:
        bool: True se a senha estiver correta, False caso contrário.
    """
    salt = bytes.fromhex(stored_salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password_guess.encode(), salt, 100000)
    return dk.hex() == stored_hash_hex

# SISTEMA PRINCIPAL

class WorkShieldSystem:
    """
    Classe principal do sistema WorkShield.

    Gerencia:
    - Usuários (cadastrar, autenticar)
    - Sessões via token
    - Detecção automática de PII e links maliciosos
    - Geração de incidentes
    - Armazenamento eficiente usando árvores AVL
    """

    def __init__(self):
        """
        Inicializa as estruturas de dados do sistema.
        """
        self.users = AVLTree()      
        self.incidents = AVLTree()  
        self.sessions = {}          
        self.incident_seq = 0

        logger.info("WorkShield System inicializado.")

    
    # CADASTRO
    def signup(self, username: str, password: str, role="user") -> bool:
        """
        Registra um novo usuário no sistema.

        Args:
            username (str): Nome do usuário.
            password (str): Senha em texto puro.
            role (str): Papel do usuário (ex: 'user', 'admin').

        Returns:
            bool: True se o cadastro for bem-sucedido, False se o usuário já existir.
        """
        stored_user, _ = self.users.search(username)

        if stored_user is not None:
            logger.warning(f"Tentativa de cadastro falhou: usuário '{username}' já existe.")
            return False

        pwdhash, salt = hash_password(password)
        user = User(username=username, password_hash=pwdhash, salt=salt, role=role)

        self.users.insert(username, user)
        logger.info(f"Usuário criado com sucesso: {username} (role={role})")

        return True

    # LOGIN
    def login(self, username: str, password: str):
        """
        Autentica um usuário e gera um token de sessão.

        Args:
            username (str): Nome de usuário.
            password (str): Senha em texto puro.

        Returns:
            str | None: Token de sessão se autenticado; None caso contrário.
        """
        stored_user, _ = self.users.search(username)
        if stored_user is None:
            logger.warning(f"Tentativa de login falhou: usuário '{username}' não encontrado.")
            return None

        if verify_password(stored_user.password_hash, stored_user.salt, password):
            token = secrets.token_hex(16)
            self.sessions[token] = username
            logger.info(f"Usuário '{username}' fez login. Token={token}")
            return token

        logger.warning(f"Senha incorreta para usuário '{username}'.")
        return None

    # WHOAMI
    def get_user_by_token(self, token: str):
        """
        Retorna o usuário associado a um token de sessão.

        Args:
            token (str): Token da sessão.

        Returns:
            User | None: Objeto User correspondente ou None se o token for inválido.
        """
        username = self.sessions.get(token)
        if not username:
            logger.debug(f"Token inválido: {token}")
            return None

        user, _ = self.users.search(username)
        return user

    def whoami(self, token: str):
        """
        Devolve o usuário autenticado correspondente ao token.

        Args:
            token (str): Token da sessão.

        Returns:
            User | None: Usuário autenticado ou None.
        """
        return self.get_user_by_token(token)

    # LOGOUT
    def logout(self, token: str):
        """
        Encerra a sessão associada a um token.

        Args:
            token (str): Token da sessão.

        Returns:
            bool: True se o logout foi realizado; False se o token for inválido.
        """
        removed = self.sessions.pop(token, None)
        if removed:
            logger.info(f"Token {token} desconectado.")
            return True

        logger.warning(f"Tentativa de logout falhou: token inválido {token}.")
        return False

    # INGEST MESSAGE
    def ingest_message(self, source: str, username: str, message: str):
        """
        Analisa mensagens enviadas pelos usuários, detectando:
        - Dados pessoais sensíveis (PII)
        - Possíveis números de cartão de crédito
        - Links maliciosos

        Caso algo suspeito seja encontrado, gera automaticamente um incidente.

        Args:
            source (str): Origem da mensagem (ex: "chat-app", "email").
            username (str): Usuário que enviou a mensagem.
            message (str): Texto da mensagem.

        Returns:
            tuple(Incident, str) | None:
                - Objeto Incident gerado
                - Mensagem de alerta para o usuário
                Ou None se nenhum incidente foi encontrado.
        """
        labels = []
        snippet = ""

        # --- PII ---
        if CPF_RE.search(message):
            labels.append("cpf")
            snippet += "CPF detected; "

        if CREDIT_RE.search(message):
            labels.append("credit_card")
            snippet += "Potential credit card; "

        if EMAIL_RE.search(message):
            labels.append("email")
            snippet += "Email detected; "

        # --- Domínios maliciosos ---
        for domain in BAD_DOMAINS:
            if domain in message:
                labels.append(f"malicious_site:{domain}")
                snippet += f"Malicious site: {domain}; "

        logger.debug(f"Mensagem recebida de {username}. Labels detectadas: {labels}")

        # SE GEROU INCIDENTE
        if labels:
            masked_user = (
                username[:2] + "***" + username[-1]
                if len(username) > 3 else "***"
            )

            self.incident_seq += 1
            iid = f"INC{self.incident_seq:06d}"

            severity = "high" if ("cpf" in labels or "credit_card" in labels) else "medium"

            incident = Incident(
                id=iid,
                source=source,
                user=masked_user,
                message_snippet=snippet.strip(),
                labels=labels,
                severity=severity
            )

            self.incidents.insert(iid, incident)

            logger.warning(
                f"INCIDENTE GERADO — ID={iid}, user={masked_user}, "
                f"labels={labels}, severity={severity}"
            )

            user_msg = (
                "⚠️ ALERTA DE SEGURANÇA\n"
                "Detectamos um possível risco na sua mensagem.\n"
                f"→ Tipos detectados: {', '.join(labels)}\n"
                f"→ ID do incidente: {iid}\n"
                "Evite compartilhar dados como CPF, cartões, emails ou links suspeitos."
            )

            return incident, user_msg

        logger.info(f"Nenhum incidente gerado para mensagem de '{username}'.")
        return None

    # LISTAR INCIDENTES
    def list_incidents(self, token: str):
        """
        Retorna todos os incidentes registrados no sistema.

        Args:
            token (str): Token da sessão do usuário.

        Raises:
            PermissionError: Se o token for inválido.

        Returns:
            list[Incident]: Lista de incidentes em ordem crescente de ID.
        """
        user = self.get_user_by_token(token)
        if not user:
            logger.error("Listagem de incidentes negada: token inválido.")
            raise PermissionError("invalid session")

        incidents = [v for (_, v) in self.incidents.inorder()]
        logger.info(f"{len(incidents)} incidentes listados por '{user.username}'.")
        return incidents

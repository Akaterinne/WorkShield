"""
models.py
Classes de domínio: User e Incident
"""
from dataclasses import dataclass
from typing import List

@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    role: str = "user"

@dataclass
class Incident:
    id: str
    source: str
    user: str
    message_snippet: str
    labels: List[str]
    severity: str

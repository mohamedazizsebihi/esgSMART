"""
Module OAuth JWT pour l'authentification inter-agents.
Génère et vérifie les tokens JWT pour sécuriser la communication entre agents.
"""

import time
import jwt
from typing import Dict, Optional
from datetime import datetime, timedelta
from core.logging_utils import logger
from core.config import JWT_SECRET

# Configuration JWT
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30


def generate_jwt_token(agent_id: str, permissions: list = None) -> str:
    """
    Génère un token JWT pour un agent.
    
    Args:
        agent_id: Identifiant de l'agent (ex: "extraction_agent", "translation_agent")
        permissions: Liste des permissions (ex: ["read", "write", "translate"])
    
    Returns:
        Token JWT encodé
    """
    if permissions is None:
        permissions = ["read", "write"]
    
    payload = {
        "agent_id": agent_id,
        "permissions": permissions,
        "iat": int(time.time()),  # Issued at
        "exp": int(time.time()) + (JWT_EXPIRATION_MINUTES * 60),  # Expiration
        "iss": "agentESG_orchestrator",  # Issuer
    }
    
    try:
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        logger.info(f"[JWT] Token generated for agent: {agent_id}")
        logger.debug(f"[JWT] Token expires in {JWT_EXPIRATION_MINUTES} minutes")
        return token
    except Exception as e:
        logger.error(f"[JWT] Failed to generate token: {e}")
        raise


def verify_jwt_token(token: str) -> Dict:
    """
    Vérifie et décode un token JWT.
    
    Args:
        token: Token JWT à vérifier
    
    Returns:
        Payload décodé si valide
    
    Raises:
        jwt.ExpiredSignatureError: Si le token est expiré
        jwt.InvalidTokenError: Si le token est invalide
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logger.info(f"[JWT] Token verified for agent: {payload.get('agent_id')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("[JWT] Token expired")
        raise
    except jwt.InvalidTokenError as e:
        logger.error(f"[JWT] Invalid token: {e}")
        raise


def get_auth_headers(token: str) -> Dict[str, str]:
    """
    Retourne les headers d'authentification pour une requête HTTP.
    
    Args:
        token: Token JWT
    
    Returns:
        Dictionnaire avec headers d'authentification
    """
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-AgentESG-Version": "1.0"
    }


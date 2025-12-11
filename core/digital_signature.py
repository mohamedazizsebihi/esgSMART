"""
Module de signature numérique pour garantir l'origine et l'intégrité des documents.
Utilise RSA avec SHA-256 pour signer les hash des fichiers.
"""

import os
import sys
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from core.logging_utils import logger
from core.config import BASE_DIR


# ======================================================
# GESTION DES CLÉS
# ======================================================

KEYS_DIR = os.path.join(BASE_DIR, "data", "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def ensure_keys_directory():
    """Crée le répertoire des clés s'il n'existe pas."""
    os.makedirs(KEYS_DIR, exist_ok=True)


def generate_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Génère une paire de clés RSA (privée/publique) pour la signature.
    
    Returns:
        Tuple (private_key, public_key)
    """
    logger.info("[SIGNATURE] Generating RSA key pair (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    logger.info("[SIGNATURE] Key pair generated successfully")
    return private_key, public_key


def load_or_create_private_key() -> rsa.RSAPrivateKey:
    """
    Charge la clé privée depuis le fichier, ou en génère une nouvelle si elle n'existe pas.
    
    Returns:
        Clé privée RSA
    """
    ensure_keys_directory()
    
    if os.path.exists(PRIVATE_KEY_PATH):
        logger.info("[SIGNATURE] Loading existing private key...")
        try:
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            logger.info("[SIGNATURE] Private key loaded successfully")
            return private_key
        except Exception as e:
            logger.error(f"[SIGNATURE] Failed to load private key: {e}")
            logger.info("[SIGNATURE] Generating new key pair...")
    
    # Générer une nouvelle paire de clés
    private_key, public_key = generate_key_pair()
    
    # Sauvegarder la clé privée
    try:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_pem)
        logger.info(f"[SIGNATURE] Private key saved to {PRIVATE_KEY_PATH}")
    except Exception as e:
        logger.error(f"[SIGNATURE] Failed to save private key: {e}")
        raise
    
    # Sauvegarder la clé publique
    try:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)
        logger.info(f"[SIGNATURE] Public key saved to {PUBLIC_KEY_PATH}")
    except Exception as e:
        logger.error(f"[SIGNATURE] Failed to save public key: {e}")
        raise
    
    return private_key


def load_public_key() -> rsa.RSAPublicKey:
    """
    Charge la clé publique depuis le fichier.
    
    Returns:
        Clé publique RSA
    """
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise FileNotFoundError(f"Public key not found at {PUBLIC_KEY_PATH}. Generate keys first.")
    
    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        logger.error(f"[SIGNATURE] Failed to load public key: {e}")
        raise


# ======================================================
# SIGNATURE NUMÉRIQUE
# ======================================================

def sign_hash(file_hash: str, private_key: rsa.RSAPrivateKey = None) -> bytes:
    """
    Signe un hash SHA-256 avec la clé privée RSA.
    
    Args:
        file_hash: Hash SHA-256 du fichier (hex string)
        private_key: Clé privée RSA (si None, charge depuis le fichier)
    
    Returns:
        Signature numérique (bytes, encodée en base64 pour stockage)
    """
    if private_key is None:
        private_key = load_or_create_private_key()
    
    # Convertir le hash hex en bytes
    hash_bytes = bytes.fromhex(file_hash)
    
    try:
        # Signer le hash avec RSA-PSS (plus sûr que PKCS1v15)
        signature = private_key.sign(
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.debug(f"[SIGNATURE] Hash signed successfully (signature length: {len(signature)} bytes)")
        return signature
        
    except Exception as e:
        logger.error(f"[SIGNATURE] Failed to sign hash: {e}")
        raise


def verify_signature(file_hash: str, signature: bytes, public_key: rsa.RSAPublicKey = None) -> Tuple[bool, str]:
    """
    Vérifie une signature numérique.
    
    Args:
        file_hash: Hash SHA-256 du fichier (hex string)
        signature: Signature numérique (bytes)
        public_key: Clé publique RSA (si None, charge depuis le fichier)
    
    Returns:
        Tuple (is_valid, message)
    """
    if public_key is None:
        try:
            public_key = load_public_key()
        except Exception as e:
            return False, f"Failed to load public key: {e}"
    
    # Convertir le hash hex en bytes
    hash_bytes = bytes.fromhex(file_hash)
    
    try:
        # Vérifier la signature
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.info(f"[SIGNATURE] ✓ Signature verified successfully")
        return True, "Signature is valid"
        
    except Exception as e:
        error_msg = f"Signature verification failed: {e}"
        logger.error(f"[SIGNATURE] ✗ {error_msg}")
        return False, error_msg


# ======================================================
# UTILITAIRES
# ======================================================

def signature_to_base64(signature: bytes) -> str:
    """Encode une signature en base64 pour stockage."""
    import base64
    return base64.b64encode(signature).decode('utf-8')


def base64_to_signature(signature_b64: str) -> bytes:
    """Décode une signature depuis base64."""
    import base64
    return base64.b64decode(signature_b64.encode('utf-8'))


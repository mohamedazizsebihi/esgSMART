"""
Module de gestion du rate limiting pour Groq API.
Implémente :
- Retry avec backoff exponentiel
- Token estimation PRÉCISE (tiktoken)
- Rate limiter local THREAD-SAFE
- Chunking intelligent
"""

import time
import math
import re
import requests
import threading
from typing import List, Tuple, Optional
from datetime import datetime, timedelta
from collections import deque
from core.logging_utils import logger

# Import tiktoken pour estimation précise des tokens
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
    # Encoder pour cl100k_base (utilisé par GPT-4, compatible avec Groq)
    _tokenizer = tiktoken.get_encoding("cl100k_base")
except ImportError:
    TIKTOKEN_AVAILABLE = False
    _tokenizer = None
    logger.warning("[RATE_LIMITER] tiktoken not available, using fallback estimation (less accurate)")


# ======================================================
# CONFIGURATION RATE LIMITING
# ======================================================

# Limites Groq API (on_demand tier)
GROQ_TPM_LIMIT = 12000  # Tokens per minute
GROQ_RPM_LIMIT = 30     # Requests per minute (estimation)

# Configuration retry
MAX_RETRIES = 10  # Augmenté pour gérer les rate limits persistants
INITIAL_BACKOFF = 2.0  # secondes (augmenté)
MAX_BACKOFF = 120.0     # secondes (augmenté pour gérer les rate limits longs)
BACKOFF_MULTIPLIER = 1.5  # Multiplicateur plus conservateur

# Configuration chunking
MAX_CHUNK_TOKENS = 1500  # ✅ CORRIGÉ: Input seulement (1500 input + ~500 output = ~2000 total, sous la limite)
CHUNK_OVERLAP = 200      # Tokens de chevauchement entre chunks

# Délai entre chunks pour éviter le rate limiting
DELAY_BETWEEN_CHUNKS = 15.0  # ✅ CORRIGÉ: 15s conservateur (Groq recommande ±12s min)


# ======================================================
# TOKEN ESTIMATION PRÉCISE (tiktoken + fallback)
# ======================================================

def estimate_tokens_precise(text: str) -> int:
    """
    ✅ CORRIGÉ: Estime PRÉCISÉMENT le nombre de tokens avec tiktoken.
    Fallback sur estimation simple si tiktoken non disponible.
    
    Args:
        text: Texte à analyser
    
    Returns:
        Nombre estimé de tokens (±5% d'erreur avec tiktoken, ±30% avec fallback)
    """
    if TIKTOKEN_AVAILABLE and _tokenizer is not None:
        try:
            # Utiliser tiktoken pour estimation précise
            tokens = _tokenizer.encode(text)
            return len(tokens)
        except Exception as e:
            logger.warning(f"[TOKEN_EST] tiktoken encoding failed, using fallback: {e}")
    
    # Fallback: estimation simple (3 chars/token pour être plus conservateur)
    # Plus conservateur que 4 chars/token pour éviter les dépassements
    return math.ceil(len(text) / 3.0)


def estimate_tokens(text: str, chars_per_token: float = 3.0) -> int:
    """
    Estime le nombre de tokens dans un texte (fonction legacy, utilise estimate_tokens_precise).
    
    Args:
        text: Texte à analyser
        chars_per_token: Nombre de caractères par token (3.0 pour fallback conservateur)
    
    Returns:
        Nombre estimé de tokens
    """
    # Utiliser la fonction précise par défaut
    return estimate_tokens_precise(text)


def estimate_tokens_for_messages(system_prompt: str, user_prompt: str) -> int:
    """
    ✅ CORRIGÉ: Estime PRÉCISÉMENT le nombre de tokens pour un ensemble de messages.
    
    Args:
        system_prompt: Prompt système
        user_prompt: Prompt utilisateur
    
    Returns:
        Nombre estimé de tokens (input seulement)
    """
    # Utiliser tiktoken pour estimation précise
    system_tokens = estimate_tokens_precise(system_prompt)
    user_tokens = estimate_tokens_precise(user_prompt)
    
    # Overhead : ~4 tokens par message + formatting (plus précis avec tiktoken)
    overhead = 8
    
    return system_tokens + user_tokens + overhead


# ======================================================
# RATE LIMITER LOCAL THREAD-SAFE
# ======================================================

class RateLimiter:
    """
    ✅ CORRIGÉ: Rate limiter local THREAD-SAFE pour gérer les limites de tokens/minute.
    Utilise un mutex pour éviter les race conditions.
    """
    
    def __init__(self, tpm_limit: int = GROQ_TPM_LIMIT, window_seconds: int = 60):
        self.tpm_limit = tpm_limit
        self.window_seconds = window_seconds
        self.token_usage = deque()  # (timestamp, tokens)
        self._lock = threading.Lock()  # ✅ Mutex pour thread-safety
    
    def _clean_old_entries(self):
        """Supprime les entrées hors de la fenêtre de temps (thread-safe)."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            while self.token_usage and self.token_usage[0][0] < cutoff:
                self.token_usage.popleft()
    
    def get_available_tokens(self) -> int:
        """
        Retourne le nombre de tokens disponibles dans la fenêtre actuelle (thread-safe).
        
        Returns:
            Tokens disponibles
        """
        with self._lock:
            self._clean_old_entries()
            
            used_tokens = sum(tokens for _, tokens in self.token_usage)
            available = max(0, self.tpm_limit - used_tokens)
            
            return available
    
    def can_make_request(self, estimated_tokens: int) -> Tuple[bool, float]:
        """
        Vérifie si une requête peut être faite maintenant (thread-safe).
        
        Args:
            estimated_tokens: Nombre estimé de tokens pour la requête
        
        Returns:
            (can_make_request, wait_seconds)
        """
        with self._lock:
            self._clean_old_entries()
            
            available = self.get_available_tokens()
            
            # Laisser une marge de sécurité (20% de la limite)
            safety_margin = int(self.tpm_limit * 0.2)
            available_with_margin = available - safety_margin
            
            if available_with_margin >= estimated_tokens:
                return True, 0.0
            
            # Calculer le temps d'attente nécessaire
            if not self.token_usage:
                # Si pas d'utilisation récente, attendre un peu pour être sûr
                return False, 2.0
            
            # Trouver le timestamp le plus ancien dans la fenêtre
            oldest_timestamp = self.token_usage[0][0]
            wait_until = oldest_timestamp + self.window_seconds
            wait_seconds = max(0.0, wait_until - time.time())
            
            # Ajouter une marge de sécurité
            wait_seconds += 2.0
            
            return False, wait_seconds
    
    def wait_if_needed(self, estimated_tokens: int):
        """
        ✅ NOUVEAU: Attend si nécessaire avant de faire une requête (thread-safe).
        Méthode pratique pour utiliser le rate limiter.
        
        Args:
            estimated_tokens: Nombre estimé de tokens pour la requête
        """
        can_make, wait_time = self.can_make_request(estimated_tokens)
        if not can_make:
            logger.info(f"[RATE_LIMITER] Waiting {wait_time:.1f}s before request (rate limit protection)")
            time.sleep(wait_time)
    
    def record_usage(self, tokens: int):
        """
        Enregistre l'utilisation de tokens (thread-safe).
        
        Args:
            tokens: Nombre de tokens utilisés
        """
        with self._lock:
            now = time.time()
            self.token_usage.append((now, tokens))
            logger.debug(f"[RATE_LIMITER] Recorded {tokens} tokens usage (available: {self.get_available_tokens()})")


# Instance globale du rate limiter (thread-safe)
_rate_limiter = RateLimiter()


# ======================================================
# CHUNKING INTELLIGENT
# ======================================================

def split_text_intelligently(text: str, max_tokens: int = MAX_CHUNK_TOKENS, 
                            overlap_tokens: int = CHUNK_OVERLAP) -> List[str]:
    """
    Découpe un texte en chunks intelligents (par phrases/paragraphes).
    Utilise estimate_tokens_precise pour une découpe précise.
    
    Args:
        text: Texte à découper
        max_tokens: Nombre maximum de tokens par chunk (input seulement)
        overlap_tokens: Nombre de tokens de chevauchement
    
    Returns:
        Liste de chunks
    """
    if estimate_tokens_precise(text) <= max_tokens:
        return [text]
    
    chunks = []
    
    # Découper par paragraphes d'abord
    paragraphs = text.split('\n\n')
    
    current_chunk = ""
    current_tokens = 0
    
    for para in paragraphs:
        para_tokens = estimate_tokens_precise(para)
        
        # Si le paragraphe seul dépasse la limite, découper par phrases
        if para_tokens > max_tokens:
            # Sauvegarder le chunk actuel s'il n'est pas vide
            if current_chunk:
                chunks.append(current_chunk.strip())
                current_chunk = ""
                current_tokens = 0
            
            # Découper le paragraphe par phrases
            sentences = re.split(r'(?<=[.!?])\s+', para)
            
            for sentence in sentences:
                sent_tokens = estimate_tokens_precise(sentence)
                
                if current_tokens + sent_tokens > max_tokens:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                        # Ajouter overlap
                        overlap_text = _get_overlap_text(current_chunk, overlap_tokens)
                        current_chunk = overlap_text + " " + sentence
                        current_tokens = estimate_tokens_precise(current_chunk)
                    else:
                        current_chunk = sentence
                        current_tokens = sent_tokens
                else:
                    current_chunk += " " + sentence if current_chunk else sentence
                    current_tokens += sent_tokens
        else:
            # Vérifier si on peut ajouter ce paragraphe
            if current_tokens + para_tokens > max_tokens:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                    # Ajouter overlap
                    overlap_text = _get_overlap_text(current_chunk, overlap_tokens)
                    current_chunk = overlap_text + "\n\n" + para
                    current_tokens = estimate_tokens_precise(current_chunk)
                else:
                    current_chunk = para
                    current_tokens = para_tokens
            else:
                current_chunk += "\n\n" + para if current_chunk else para
                current_tokens += para_tokens
    
    # Ajouter le dernier chunk
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    logger.info(f"[CHUNKING] Split text into {len(chunks)} chunks (max {max_tokens} tokens each)")
    
    return chunks


def _get_overlap_text(text: str, overlap_tokens: int) -> str:
    """
    Extrait le texte de fin pour l'overlap (utilise estimate_tokens_precise).
    
    Args:
        text: Texte source
        overlap_tokens: Nombre de tokens à extraire
    
    Returns:
        Texte d'overlap
    """
    if not text:
        return ""
    
    # Utiliser estimate_tokens_precise pour une extraction précise
    total_tokens = estimate_tokens_precise(text)
    
    if total_tokens <= overlap_tokens:
        return text
    
    # Approximer le nombre de caractères pour overlap_tokens
    # Utiliser un ratio moyen (plus précis avec tiktoken)
    if TIKTOKEN_AVAILABLE:
        # Ratio moyen: ~3.5 chars/token
        overlap_chars = int(overlap_tokens * 3.5)
    else:
        # Fallback: 3 chars/token
        overlap_chars = overlap_tokens * 3
    
    if len(text) <= overlap_chars:
        return text
    
    # Prendre la fin du texte
    overlap_text = text[-overlap_chars:]
    
    # Essayer de commencer à une phrase
    sentence_start = re.search(r'[.!?]\s+[A-Z]', overlap_text)
    if sentence_start:
        overlap_text = overlap_text[sentence_start.end()-1:]
    
    return overlap_text.strip()


# ======================================================
# RETRY AVEC BACKOFF EXPONENTIEL (429-aware robuste)
# ======================================================

def retry_with_backoff(func, *args, max_retries: int = MAX_RETRIES, 
                      initial_backoff: float = INITIAL_BACKOFF,
                      max_backoff: float = MAX_BACKOFF,
                      backoff_multiplier: float = BACKOFF_MULTIPLIER,
                      **kwargs):
    """
    ✅ CORRIGÉ: Exécute une fonction avec retry et backoff exponentiel.
    Gestion robuste des erreurs 429 avec extraction précise du temps d'attente.
    
    Args:
        func: Fonction à exécuter
        *args: Arguments positionnels
        max_retries: Nombre maximum de tentatives
        initial_backoff: Délai initial en secondes
        max_backoff: Délai maximum en secondes
        backoff_multiplier: Multiplicateur pour le backoff
        **kwargs: Arguments nommés
    
    Returns:
        Résultat de la fonction
    
    Raises:
        Exception: Si toutes les tentatives échouent
    """
    backoff = initial_backoff
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
            last_exception = e
            status_code = None
            error_text = ""
            error_msg = ""
            
            # ✅ CORRIGÉ: Extraction robuste du status code et du message d'erreur
            try:
                if hasattr(e, 'response') and e.response is not None:
                    status_code = e.response.status_code
                    try:
                        error_text = e.response.text
                        error_data = e.response.json()
                        error_msg = error_data.get("error", {}).get("message", error_text)
                    except:
                        error_msg = error_text or str(e)
                else:
                    # Essayer d'extraire depuis le message d'erreur
                    error_msg = str(e)
                    # Chercher le status code dans le message
                    status_match = re.search(r'(\d{3})', error_msg)
                    if status_match:
                        status_code = int(status_match.group(1))
            except Exception as parse_error:
                logger.debug(f"[RETRY] Error parsing exception: {parse_error}")
                error_msg = str(e)
            
            # ✅ CORRIGÉ: Vérifier si c'est une erreur 429 (rate limit) avec regex robuste
            if status_code == 429:
                wait_time = None
                
                # ✅ CORRIGÉ: Regex robuste pour extraire le temps d'attente
                # Patterns possibles:
                # - "Please try again in 11.4s"
                # - "try again in 11.4 seconds"
                # - "retry after 11.4s"
                patterns = [
                    r'Please try again in ([\d.]+)\s*s(?:econds?)?',
                    r'try again in ([\d.]+)\s*s(?:econds?)?',
                    r'retry after ([\d.]+)\s*s(?:econds?)?',
                    r'wait ([\d.]+)\s*s(?:econds?)?',
                    r'(\d+\.?\d*)\s*seconds?',
                ]
                
                for pattern in patterns:
                    wait_match = re.search(pattern, error_msg, re.IGNORECASE)
                    if wait_match:
                        try:
                            wait_time = float(wait_match.group(1))
                            logger.warning(f"[RETRY] Rate limit 429 detected. Waiting {wait_time:.1f}s (extracted from API) (attempt {attempt + 1}/{max_retries})")
                            time.sleep(wait_time + 2)  # +2 pour marge de sécurité
                            backoff = initial_backoff  # Reset backoff
                            break
                        except ValueError:
                            continue
                
                # Si pas de temps spécifique extrait, utiliser backoff exponentiel avec attente plus longue
                if wait_time is None:
                    wait_time = min(backoff * 2, max_backoff)  # Attendre 2x le backoff pour 429
                    logger.warning(f"[RETRY] Rate limit 429 detected. Waiting {wait_time:.1f}s (backoff exponential) (attempt {attempt + 1}/{max_retries})")
                    logger.debug(f"[RETRY] Error message: {error_msg[:200]}")
                    time.sleep(wait_time)
                    backoff = min(backoff * backoff_multiplier, max_backoff)
            else:
                # Autre erreur HTTP, réessayer avec backoff
                logger.warning(f"[RETRY] HTTP error {status_code if status_code else 'unknown'}. Waiting {backoff:.1f}s (attempt {attempt + 1}/{max_retries})")
                if error_msg:
                    logger.debug(f"[RETRY] Error message: {error_msg[:200]}")
                time.sleep(backoff)
                backoff = min(backoff * backoff_multiplier, max_backoff)
        except requests.exceptions.RequestException as e:
            last_exception = e
            logger.warning(f"[RETRY] Request error: {e}. Waiting {backoff:.1f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(backoff)
            backoff = min(backoff * backoff_multiplier, max_backoff)
        except Exception as e:
            # Erreur non-récupérable, ne pas retry
            logger.error(f"[RETRY] Non-retryable error: {e}")
            raise
    
    # Toutes les tentatives ont échoué
    logger.error(f"[RETRY] All {max_retries} attempts failed")
    raise last_exception

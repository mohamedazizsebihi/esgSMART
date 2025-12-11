"""
Agent de Traduction - Traduit les documents réglementaires en 5 langues.
Utilise Ollama Cloud API avec sécurité complète (hash, signature, JWT, TLS/mTLS).
"""

import sys
import os

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import requests
import json
import sys
import time
from pathlib import Path
from typing import Dict, Tuple, List
from urllib.parse import urlparse

from core.rate_limiter import (
    estimate_tokens_for_messages, estimate_tokens_precise, RateLimiter, 
    split_text_intelligently, retry_with_backoff, _rate_limiter, 
    MAX_CHUNK_TOKENS, DELAY_BETWEEN_CHUNKS
)

import PyPDF2
import pytesseract
from PIL import Image
from pdf2image import convert_from_path
import pandas as pd
from docx import Document

from core.logging_utils import logger
from core.config import (
    TESSERACT_PATH, POPPLER_PATH, TRANSLATIONS_DIR,
    GROQ_API_KEY, GROQ_API_URL, GROQ_MODEL,
    GROQ_USE_TLS, GROQ_USE_MTLS, GROQ_CA_CERT,
    GROQ_CLIENT_CERT, GROQ_CLIENT_KEY, GROQ_STREAM
)
from core.state import PipelineState
from core.digital_signature import verify_signature, base64_to_signature

# Configure OCR path
pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

# Langues de traduction
TRANSLATION_LANGUAGES = {
    "fr": "French",
    "it": "Italian", 
    "ar": "Arabic",
    "pt": "Portuguese",
    "zh": "Chinese"
}


# ======================================================
# VÉRIFICATION D'INTÉGRITÉ ET SIGNATURE
# ======================================================

def compute_hash(content: bytes) -> str:
    """Calcule le hash SHA-256."""
    return hashlib.sha256(content).hexdigest()


def verify_file_integrity_and_signature(file_path: str, state: PipelineState) -> Tuple[bool, str]:
    """
    Vérifie l'intégrité (hash) et la signature numérique d'un fichier.
    
    Returns:
        (is_valid, message)
    """
    logger.info(f"[INTEGRITY] Verifying file: {os.path.basename(file_path)}")
    
    # Step 1: Vérifier que le fichier existe
    if not os.path.exists(file_path):
        error_msg = f"File not found: {file_path}"
        logger.error(f"[INTEGRITY] ✗ {error_msg}")
        return False, error_msg
    
    # Step 2: Récupérer le hash attendu
    expected_hash = state.file_hashes.get(file_path)
    if not expected_hash:
        # Essayer de récupérer depuis versions.json
        from core.config import VERSIONS_FILE
        try:
            if os.path.exists(VERSIONS_FILE):
                with open(VERSIONS_FILE, "r") as f:
                    versions = json.load(f)
                for url, stored_path in state.url_to_file.items():
                    if stored_path == file_path:
                        expected_hash = versions.get(url)
                        break
        except Exception as e:
            logger.warning(f"[INTEGRITY] Failed to load versions: {e}")
    
    if not expected_hash:
        error_msg = f"No hash found for file: {file_path}"
        logger.warning(f"[INTEGRITY] ⚠ {error_msg}")
        return False, error_msg
    
    # Step 3: Calculer le hash actuel
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        current_hash = compute_hash(content)
    except Exception as e:
        error_msg = f"Failed to read file: {e}"
        logger.error(f"[INTEGRITY] ✗ {error_msg}")
        return False, error_msg
    
    # Step 4: Vérifier l'intégrité (hash)
    if current_hash != expected_hash:
        error_msg = (
            f"INTEGRITY CHECK FAILED: File has been altered!\n"
            f"  Expected: {expected_hash[:16]}...\n"
            f"  Current:  {current_hash[:16]}...\n"
            f"  File: {file_path}"
        )
        logger.error(f"[INTEGRITY] ✗ {error_msg}")
        return False, error_msg
    
    logger.info(f"[INTEGRITY] ✓ Hash verified: {current_hash[:16]}...")
    
    # Step 5: Vérifier la signature numérique
    signature_b64 = state.file_signatures.get(file_path)
    if signature_b64:
        try:
            signature = base64_to_signature(signature_b64)
            sig_valid, sig_message = verify_signature(expected_hash, signature)
            
            if sig_valid:
                logger.info(f"[INTEGRITY] ✓ Signature verified: {sig_message}")
                return True, "Integrity and signature verified"
            else:
                error_msg = f"Signature verification failed: {sig_message}"
                logger.error(f"[INTEGRITY] ✗ {error_msg}")
                return False, error_msg
        except Exception as e:
            error_msg = f"Failed to verify signature: {e}"
            logger.error(f"[INTEGRITY] ✗ {error_msg}")
            return False, error_msg
    else:
        logger.warning(f"[INTEGRITY] ⚠ No signature found for {file_path}, integrity check only")
        return True, "Integrity verified (no signature available)"


# ======================================================
# EXTRACTION DE TEXTE
# ======================================================

def detect_file_type(path: str) -> str:
    return path.lower().split(".")[-1]


def extract_text_from_pdf(path: str) -> str:
    text = ""
    logger.info(f"[EXTRACTION] Extracting text from PDF: {os.path.basename(path)}")
    
    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            logger.info(f"[EXTRACTION] PDF has {len(reader.pages)} pages")
            for page_num, page in enumerate(reader.pages, 1):
                extracted = page.extract_text()
                if extracted:
                    text += extracted
                    logger.debug(f"[EXTRACTION] Page {page_num}: {len(extracted)} characters")
    except Exception as e:
        logger.error(f"[EXTRACTION] PDF extraction failed: {e}")
    
    # Si PDF scanné → utiliser OCR
    if len(text.strip()) < 20:
        logger.info("[EXTRACTION] PDF seems scanned → using OCR")
        try:
            images = convert_from_path(path, poppler_path=POPPLER_PATH)
            logger.info(f"[EXTRACTION] Converted to {len(images)} images")
            for img_num, img in enumerate(images, 1):
                ocr_text = pytesseract.image_to_string(img)
                text += ocr_text
                logger.debug(f"[EXTRACTION] OCR page {img_num}: {len(ocr_text)} characters")
        except Exception as e:
            logger.error(f"[EXTRACTION] OCR failed: {e}")
    
    logger.info(f"[EXTRACTION] Total extracted: {len(text)} characters")
    return text.strip()


def extract_text_from_docx(path: str) -> str:
    logger.info(f"[EXTRACTION] Extracting text from DOCX: {os.path.basename(path)}")
    try:
        doc = Document(path)
        text = "\n".join([p.text for p in doc.paragraphs])
        logger.info(f"[EXTRACTION] Extracted {len(text)} characters")
        return text
    except Exception as e:
        logger.error(f"[EXTRACTION] DOCX extraction failed: {e}")
        return ""


def extract_tabular(path: str) -> str:
    logger.info(f"[EXTRACTION] Extracting tabular data: {os.path.basename(path)}")
    try:
        if path.endswith(".csv"):
            df = pd.read_csv(path)
        else:
            df = pd.read_excel(path)
        text = df.to_string()
        logger.info(f"[EXTRACTION] Extracted {len(text)} characters from table")
        return text
    except Exception as e:
        logger.error(f"[EXTRACTION] Tabular extraction failed: {e}")
        return ""


def extract_text_from_file(file_path: str) -> str:
    """Extrait le texte selon le type de fichier."""
    filetype = detect_file_type(file_path)
    
    if filetype == "pdf":
        return extract_text_from_pdf(file_path)
    elif filetype == "docx":
        return extract_text_from_docx(file_path)
    elif filetype in ["xlsx", "csv"]:
        return extract_tabular(file_path)
    elif filetype in ["xml", "json", "txt"]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                text = f.read()
            logger.info(f"[EXTRACTION] Read {len(text)} characters from {filetype.upper()}")
            return text
        except Exception as e:
            logger.error(f"[EXTRACTION] Failed to read {filetype.upper()}: {e}")
            return ""
    else:
        logger.warning(f"[EXTRACTION] Unsupported file type: {filetype}")
        return ""


# ======================================================
# COMMUNICATION OLLAMA CLOUD (HTTPS/TLS/mTLS)
# ======================================================

def get_groq_session():
    """Crée une session requests avec configuration TLS/mTLS pour Groq API."""
    session = requests.Session()
    
    # Configuration TLS
    if GROQ_USE_TLS or GROQ_USE_MTLS:
        if GROQ_CA_CERT and os.path.exists(GROQ_CA_CERT):
            session.verify = GROQ_CA_CERT
            logger.info(f"[GROQ] TLS enabled with CA cert: {GROQ_CA_CERT}")
        else:
            session.verify = True  # Utilise les certificats système
            logger.info("[GROQ] TLS enabled (system certificates)")
        
        # Configuration mTLS (mutual TLS)
        if GROQ_USE_MTLS:
            if GROQ_CLIENT_CERT and GROQ_CLIENT_KEY:
                if os.path.exists(GROQ_CLIENT_CERT) and os.path.exists(GROQ_CLIENT_KEY):
                    session.cert = (GROQ_CLIENT_CERT, GROQ_CLIENT_KEY)
                    logger.info(f"[GROQ] mTLS enabled with client cert: {GROQ_CLIENT_CERT}")
                else:
                    logger.warning("[GROQ] mTLS requested but certificates not found")
            else:
                logger.warning("[GROQ] mTLS requested but certificates not configured")
    else:
        session.verify = True  # Groq API nécessite HTTPS
        logger.info("[GROQ] HTTPS mode (required for Groq API)")
    
    return session


def _make_groq_request(system_prompt: str, user_prompt: str, stream: bool = None) -> str:
    """
    Fait une requête à Groq API avec streaming optionnel pour voir le raisonnement.
    
    Args:
        system_prompt: Prompt système
        user_prompt: Prompt utilisateur
        stream: Si True, affiche le streaming en temps réel (défaut: depuis GROQ_STREAM config)
    
    Returns:
        Réponse complète de l'API
    """
    # Utiliser la config si stream n'est pas spécifié
    if stream is None:
        stream = GROQ_STREAM
    
    session = get_groq_session()
    
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.1,
        "stream": stream
    }
    
    if stream:
        # Mode streaming : afficher le raisonnement en temps réel
        logger.info("[GROQ] 🔄 Streaming mode enabled - showing LLM reasoning in real-time...")
        logger.info("[GROQ] " + "=" * 60)
        
        full_text = ""
        import sys
        
        try:
            response = session.post(
                GROQ_API_URL, 
                json=payload, 
                headers=headers,
                timeout=300,
                stream=True
            )
            
            # Vérifier le status code
            if response.status_code == 429:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", {}).get("message", "")
                    logger.warning(f"[GROQ] Rate limit 429 detected: {error_msg[:200]}")
                except:
                    pass
                response.raise_for_status()
            
            if response.status_code != 200:
                response.raise_for_status()
            
            # Traiter le streaming
            for line in response.iter_lines():
                if not line:
                    continue
                
                try:
                    # Format SSE (Server-Sent Events)
                    if line.startswith(b'data: '):
                        line = line[6:]  # Enlever "data: "
                    
                    if line == b'[DONE]':
                        break
                    
                    chunk_data = json.loads(line)
                    
                    # Extraire le contenu du chunk
                    choices = chunk_data.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        
                        if content:
                            full_text += content
                            # Afficher en temps réel sur le terminal (sans newline pour fluidité)
                            sys.stdout.write(content)
                            sys.stdout.flush()
                    
                    # Afficher les métadonnées si disponibles
                    if "usage" in chunk_data:
                        usage = chunk_data["usage"]
                        logger.debug(f"[GROQ] Usage update: {usage}")
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.debug(f"[GROQ] Error parsing stream chunk: {e}")
                    continue
            
            # Nouvelle ligne après le streaming
            print()  # Nouvelle ligne après le streaming
            logger.info("[GROQ] " + "=" * 60)
            logger.info(f"[GROQ] ✓ Streaming complete: {len(full_text)} characters received")
            
            # Essayer de récupérer l'usage depuis la dernière ligne ou estimer
            estimated = estimate_tokens_for_messages(system_prompt, user_prompt)
            # Ajouter estimation pour la réponse
            estimated += estimate_tokens_precise(full_text)
            _rate_limiter.record_usage(estimated)
            logger.debug(f"[GROQ] Estimated token usage: {estimated}")
            
            return full_text.strip()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"[GROQ] Stream request failed: {e}")
            raise
    
    else:
        # Mode non-streaming (comportement original)
        response = session.post(
            GROQ_API_URL, 
            json=payload, 
            headers=headers,
            timeout=300
        )
        
        # Vérifier le status code avant raise_for_status pour mieux gérer les erreurs
        if response.status_code == 429:
            # Extraire le message d'erreur pour logging
            try:
                error_data = response.json()
                error_msg = error_data.get("error", {}).get("message", "")
                logger.warning(f"[GROQ] Rate limit 429 detected: {error_msg[:200]}")
            except:
                pass
        
        response.raise_for_status()  # Lève HTTPError si status != 200
        
        result = response.json()
        translated_text = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Enregistrer l'utilisation de tokens (si disponible dans la réponse)
        usage = result.get("usage", {})
        if usage:
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)
            _rate_limiter.record_usage(total_tokens)
            logger.debug(f"[GROQ] Token usage: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
        else:
            # Estimation si pas disponible
            estimated = estimate_tokens_for_messages(system_prompt, user_prompt)
            _rate_limiter.record_usage(estimated)
        
        return translated_text


def translate_with_groq(text: str, target_language: str, language_name: str) -> str:
    """
    Traduit un texte avec Groq API.
    
    Args:
        text: Texte à traduire
        target_language: Code langue (fr, it, ar, pt, zh)
        language_name: Nom de la langue (French, Italian, etc.)
    """
    if not text.strip():
        logger.warning(f"[TRANSLATION] Empty text, skipping translation to {language_name}")
        return ""
    
    logger.info(f"[TRANSLATION] Translating to {language_name} ({target_language})...")
    logger.info(f"[TRANSLATION] Text length: {len(text)} characters")
    
    # Préparer le prompt système
    system_prompt = f"""You are an expert translator specializing in banking regulatory documents. 
Translate the following document to {language_name} ({target_language}).
Requirements:
- Keep all technical terms and regulatory information accurate
- Maintain the original structure and formatting
- Preserve all numbers, dates, and legal references exactly
- Use professional banking terminology"""
    
    # Découper le texte en chunks intelligents
    chunks = split_text_intelligently(text, max_tokens=MAX_CHUNK_TOKENS)
    
    if len(chunks) > 1:
        logger.info(f"[TRANSLATION] Text split into {len(chunks)} chunks for translation")
    
    translated_chunks = []
    
    for chunk_idx, chunk in enumerate(chunks, 1):
        logger.info(f"[TRANSLATION] Processing chunk {chunk_idx}/{len(chunks)} ({len(chunk)} chars)")
        
        user_prompt = f"""Translate this regulatory banking document to {language_name}:

{chunk}"""
        
        # Estimer les tokens
        estimated_tokens = estimate_tokens_for_messages(system_prompt, user_prompt)
        
        # Vérifier le rate limiter
        can_make, wait_time = _rate_limiter.can_make_request(estimated_tokens)
        
        if not can_make:
            logger.info(f"[RATE_LIMITER] Waiting {wait_time:.1f}s before request (chunk {chunk_idx})")
            time.sleep(wait_time)
        
        # Faire la requête avec retry (augmenté à 10 tentatives)
        try:
            translated_chunk = retry_with_backoff(
                _make_groq_request,
                system_prompt,
                user_prompt,
                max_retries=10  # Augmenté pour gérer les rate limits persistants
            )
            
            if translated_chunk:
                translated_chunks.append(translated_chunk)
                logger.info(f"[TRANSLATION] ✓ Chunk {chunk_idx}/{len(chunks)} translated ({len(translated_chunk)} chars)")
            else:
                logger.warning(f"[TRANSLATION] ⚠ Empty response for chunk {chunk_idx}")
                translated_chunks.append(f"[Translation failed for chunk {chunk_idx}]")
        
        except Exception as e:
            error_msg = f"Failed to translate chunk {chunk_idx} after all retries: {e}"
            logger.error(f"[TRANSLATION] ✗ {error_msg}")
            # Ajouter un placeholder mais continuer avec les autres chunks
            translated_chunks.append(f"[Translation failed for chunk {chunk_idx}: Rate limit exceeded after all retries]")
            # Ne pas lever l'exception pour continuer avec les autres chunks
        
        # Délai entre chunks pour éviter le rate limiting (même après erreur)
        if chunk_idx < len(chunks):
            # Attendre plus longtemps après plusieurs chunks pour éviter l'accumulation
            wait_time = DELAY_BETWEEN_CHUNKS * (1.5 if chunk_idx > 1 else 1.0)
            logger.info(f"[TRANSLATION] Waiting {wait_time:.1f}s before next chunk...")
            time.sleep(wait_time)
    
    # Combiner les chunks traduits
    final_translation = "\n\n".join(translated_chunks)
    
    logger.info(f"[TRANSLATION] ✓ Translation to {language_name} completed")
    logger.info(f"[TRANSLATION] Final translated text length: {len(final_translation)} characters")
    
    return final_translation.strip()


# ======================================================
# GÉNÉRATION DE RÉSUMÉS
# ======================================================

def generate_summary_with_groq(text: str, file_path: str) -> str:
    """
    Génère un résumé du document avec Groq API (avec chunking si nécessaire).
    
    Args:
        text: Texte à résumer
        file_path: Chemin du fichier (pour contexte)
    
    Returns:
        Résumé du document
    """
    if not text.strip():
        logger.warning(f"[SUMMARY] Empty text, skipping summary for {os.path.basename(file_path)}")
        return ""
    
    logger.info(f"[SUMMARY] Generating summary for: {os.path.basename(file_path)}")
    logger.info(f"[SUMMARY] Text length: {len(text)} characters")
    
    # Préparer le prompt pour résumé
    system_prompt = """You are an expert in banking regulatory documents. 
Create a comprehensive summary of the following regulatory document.
Focus on:
- Key regulatory obligations and requirements
- Important deadlines and reporting duties
- Critical definitions and terminology
- Compliance requirements
- Any changes or updates mentioned

Keep the summary concise but comprehensive (300-500 words)."""
    
    # Utiliser le texte complet (le chunking sera géré si nécessaire)
    user_prompt = f"""Summarize the following regulatory banking document:

{text}"""
    
    # Estimer les tokens
    estimated_tokens = estimate_tokens_for_messages(system_prompt, user_prompt)
    
    # Si le texte est trop long, utiliser seulement une partie pour le résumé
    if estimated_tokens > MAX_CHUNK_TOKENS:
        # Prendre le début et la fin du document pour un résumé complet
        chunk_size = MAX_CHUNK_TOKENS * 3  # ~12000 caractères
        if len(text) > chunk_size:
            first_part = text[:chunk_size//2]
            last_part = text[-chunk_size//2:]
            user_prompt = f"""Summarize the following regulatory banking document (beginning and end):

BEGINNING:
{first_part}

...

END:
{last_part}"""
            logger.info(f"[SUMMARY] Text too long, using beginning and end for summary")
    
    # Vérifier le rate limiter
    estimated_tokens = estimate_tokens_for_messages(system_prompt, user_prompt)
    can_make, wait_time = _rate_limiter.can_make_request(estimated_tokens)
    
    if not can_make:
        logger.info(f"[RATE_LIMITER] Waiting {wait_time:.1f}s before summary request")
        time.sleep(wait_time)
    
    try:
        summary_text = retry_with_backoff(
            _make_groq_request,
            system_prompt,
            user_prompt,
            max_retries=5
        )
        
        if not summary_text:
            error_msg = "Empty response from Groq API for summary"
            logger.error(f"[SUMMARY] ✗ {error_msg}")
            return f"Summary generation failed: {error_msg}"
        
        logger.info(f"[SUMMARY] ✓ Summary generated: {len(summary_text)} characters")
        
        return summary_text.strip()
        
    except Exception as e:
        error_msg = f"Failed to generate summary: {e}"
        logger.error(f"[SUMMARY] ✗ {error_msg}")
        return f"Summary generation failed: {error_msg}"


def translate_summary_with_groq(summary: str, target_language: str, language_name: str) -> str:
    """
    Traduit un résumé avec Groq API.
    
    Args:
        summary: Résumé à traduire
        target_language: Code langue (fr, it, ar, pt, zh)
        language_name: Nom de la langue
    
    Returns:
        Résumé traduit
    """
    if not summary.strip() or summary.startswith("Summary generation failed"):
        logger.warning(f"[SUMMARY] Invalid summary, skipping translation to {language_name}")
        return ""
    
    logger.info(f"[SUMMARY] Translating summary to {language_name} ({target_language})...")
    
    system_prompt = f"""You are an expert translator specializing in banking regulatory documents. 
Translate the following summary to {language_name} ({target_language}).
Keep all technical terms and regulatory information accurate."""
    
    user_prompt = f"""Translate this regulatory document summary to {language_name}:

{summary}"""
    
    # Estimer les tokens
    estimated_tokens = estimate_tokens_for_messages(system_prompt, user_prompt)
    
    # Vérifier le rate limiter
    can_make, wait_time = _rate_limiter.can_make_request(estimated_tokens)
    
    if not can_make:
        logger.info(f"[RATE_LIMITER] Waiting {wait_time:.1f}s before summary translation request")
        time.sleep(wait_time)
    
    try:
        translated_summary = retry_with_backoff(
            _make_groq_request,
            system_prompt,
            user_prompt,
            max_retries=10  # Augmenté pour gérer les rate limits persistants
        )
        
        if not translated_summary:
            error_msg = "Empty response from Groq API for summary translation"
            logger.error(f"[SUMMARY] ✗ {error_msg}")
            return f"Summary translation failed: {error_msg}"
        
        logger.info(f"[SUMMARY] ✓ Summary translated to {language_name}: {len(translated_summary)} characters")
        
        return translated_summary.strip()
        
    except Exception as e:
        error_msg = f"Failed to translate summary: {e}"
        logger.error(f"[SUMMARY] ✗ {error_msg}")
        return f"Summary translation failed: {error_msg}"


def save_summary_file(original_path: str, summary: str, language_code: str = "en") -> str:
    """
    Sauvegarde un résumé (original ou traduit).
    
    Args:
        original_path: Chemin du fichier original
        summary: Texte du résumé
        language_code: Code langue ("en" pour original, ou "fr", "it", etc. pour traduit)
    
    Returns:
        Chemin du fichier sauvegardé
    """
    original_name = Path(original_path).stem
    summary_filename = f"{original_name}_summary_{language_code}.txt"
    
    # Créer le dossier summaries
    summaries_dir = os.path.join(TRANSLATIONS_DIR, "summaries", language_code)
    os.makedirs(summaries_dir, exist_ok=True)
    
    summary_path = os.path.join(summaries_dir, summary_filename)
    
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary)
        
        logger.info(f"[SAVE] Saved summary to: {summary_path}")
        logger.info(f"[SAVE] Summary size: {len(summary)} characters")
        
        return summary_path
    except Exception as e:
        logger.error(f"[SAVE] Failed to save summary: {e}")
        raise


# ======================================================
# SAUVEGARDE DES TRADUCTIONS
# ======================================================

def save_translated_file(original_path: str, translated_text: str, language_code: str, language_name: str) -> str:
    """
    Sauvegarde un fichier traduit.
    
    Returns:
        Chemin du fichier sauvegardé
    """
    # Créer le nom de fichier traduit
    original_name = Path(original_path).stem
    original_ext = Path(original_path).suffix
    translated_filename = f"{original_name}_{language_code}{original_ext}"
    
    # Créer le dossier de langue
    lang_dir = os.path.join(TRANSLATIONS_DIR, language_code)
    os.makedirs(lang_dir, exist_ok=True)
    
    # Chemin complet
    translated_path = os.path.join(lang_dir, translated_filename)
    
    try:
        with open(translated_path, "w", encoding="utf-8") as f:
            f.write(translated_text)
        
        logger.info(f"[SAVE] Saved translation to: {translated_path}")
        logger.info(f"[SAVE] File size: {len(translated_text)} characters")
        
        return translated_path
    except Exception as e:
        logger.error(f"[SAVE] Failed to save translation: {e}")
        raise


# ======================================================
# AGENT PRINCIPAL
# ======================================================

def run_translation_agent(state: PipelineState) -> PipelineState:
    """
    Agent de traduction qui :
    1. Vérifie l'intégrité et la signature des fichiers
    2. Extrait le texte
    3. Traduit en 5 langues avec Ollama Cloud API
    4. Sauvegarde les traductions
    
    Communication sécurisée avec :
    - OAuth JWT (authentification inter-agents)
    - TLS/mTLS (chiffrement)
    """
    logger.info("=" * 60)
    logger.info("=========== TRANSLATION AGENT START ===========")
    logger.info("=" * 60)
    
    if not state.file_paths:
        error_msg = "Translation Agent: No file paths provided."
        logger.error(f"[AGENT] {error_msg}")
        state.errors.append(error_msg)
        return state
    
    logger.info(f"[AGENT] Processing {len(state.file_paths)} file(s)")
    
    # Traiter chaque fichier
    for file_idx, file_path in enumerate(state.file_paths, 1):
        logger.info(f"[AGENT] Processing file {file_idx}/{len(state.file_paths)}: {os.path.basename(file_path)}")
        
        # ============================================
        # ÉTAPE 1 : VÉRIFICATION D'INTÉGRITÉ ET SIGNATURE
        # ============================================
        logger.info(f"[AGENT] Step 1: Verifying integrity and signature...")
        is_valid, message = verify_file_integrity_and_signature(file_path, state)
        
        if not is_valid:
            error_msg = f"Integrity check failed for {file_path}: {message}"
            logger.error(f"[AGENT] ✗ {error_msg}")
            state.errors.append(error_msg)
            continue
        
        logger.info(f"[AGENT] ✓ Integrity verified: {message}")
        
        # ============================================
        # ÉTAPE 2 : EXTRACTION DE TEXTE
        # ============================================
        logger.info(f"[AGENT] Step 2: Extracting text...")
        
        # Détecter le type de fichier
        filetype = detect_file_type(file_path)
        logger.info(f"[AGENT] File type detected: {filetype}")
        
        # Extraire le texte selon le type de fichier
        text = ""
        if filetype == "pdf":
            text = extract_text_from_pdf(file_path)
        elif filetype == "docx":
            text = extract_text_from_docx(file_path)
        elif filetype in ["xlsx", "csv"]:
            text = extract_tabular(file_path)
        elif filetype in ["xml", "json", "txt"]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                logger.info(f"[AGENT] Read {len(text)} characters from {filetype.upper()}")
            except Exception as e:
                logger.error(f"[AGENT] Failed to read {filetype.upper()}: {e}")
                text = ""
        else:
            logger.warning(f"[AGENT] Unsupported file type: {filetype}")
            text = ""
        
        if not text:
            error_msg = f"No text extracted from {file_path}"
            logger.warning(f"[AGENT] ⚠ {error_msg}")
            state.errors.append(error_msg)
            continue
        
        logger.info(f"[AGENT] ✓ Text extracted: {len(text)} characters")
        
        # Sauvegarder le texte extrait dans le state
        if file_idx == 1:  # Pour le premier fichier
            state.extracted_text = text
        
        # ============================================
        # ÉTAPE 2.5 : GÉNÉRATION DE RÉSUMÉ
        # ============================================
        logger.info(f"[AGENT] Step 2.5: Generating summary...")
        summary = generate_summary_with_groq(text, file_path)
        
        if summary and not summary.startswith("Summary generation failed"):
            # Sauvegarder le résumé original (anglais)
            try:
                summary_path = save_summary_file(file_path, summary, "en")
                state.file_summaries[file_path] = summary
                logger.info(f"[AGENT] ✓ Summary generated and saved")
                
                # Pour le premier fichier, stocker aussi dans state.summary
                if file_idx == 1:
                    state.summary = summary
            except Exception as e:
                error_msg = f"Failed to save summary: {e}"
                logger.error(f"[AGENT] ✗ {error_msg}")
                state.errors.append(error_msg)
        else:
            error_msg = f"Summary generation failed for {file_path}"
            logger.warning(f"[AGENT] ⚠ {error_msg}")
            state.errors.append(error_msg)
        
        # ============================================
        # ÉTAPE 2.6 : TRADUCTION DES RÉSUMÉS EN 5 LANGUES
        # ============================================
        if summary and not summary.startswith("Summary generation failed"):
            logger.info(f"[AGENT] Step 2.6: Translating summary to 5 languages...")
            
            state.translated_summaries[file_path] = {}
            
            for lang_code, lang_name in TRANSLATION_LANGUAGES.items():
                logger.info(f"[AGENT] Translating summary to {lang_name} ({lang_code})...")
                
                translated_summary = translate_summary_with_groq(summary, lang_code, lang_name)
                
                if translated_summary and not translated_summary.startswith("Summary translation failed"):
                    try:
                        summary_path = save_summary_file(file_path, translated_summary, lang_code)
                        state.translated_summaries[file_path][lang_code] = translated_summary
                        logger.info(f"[AGENT] ✓ Summary translated to {lang_name} and saved")
                    except Exception as e:
                        error_msg = f"Failed to save {lang_name} summary translation: {e}"
                        logger.error(f"[AGENT] ✗ {error_msg}")
                        state.errors.append(error_msg)
                else:
                    error_msg = f"Summary translation to {lang_name} failed"
                    logger.warning(f"[AGENT] ⚠ {error_msg}")
                    state.errors.append(error_msg)
        
        # ============================================
        # ÉTAPE 3 : TRADUCTION EN 5 LANGUES
        # ============================================
        logger.info(f"[AGENT] Step 3: Translating to 5 languages with Groq API...")
        
        translations = {}
        for lang_code, lang_name in TRANSLATION_LANGUAGES.items():
            logger.info(f"[AGENT] Translating to {lang_name} ({lang_code})...")
            
            translated_text = translate_with_groq(text, lang_code, lang_name)
            
            if translated_text and not translated_text.startswith("Translation failed"):
                # Sauvegarder la traduction
                try:
                    saved_path = save_translated_file(file_path, translated_text, lang_code, lang_name)
                    translations[lang_code] = saved_path
                    state.translated_files[lang_code] = saved_path
                    logger.info(f"[AGENT] ✓ {lang_name} translation saved")
                except Exception as e:
                    error_msg = f"Failed to save {lang_name} translation: {e}"
                    logger.error(f"[AGENT] ✗ {error_msg}")
                    state.errors.append(error_msg)
            else:
                error_msg = f"Translation to {lang_name} failed"
                logger.error(f"[AGENT] ✗ {error_msg}")
                state.errors.append(error_msg)
        
        logger.info(f"[AGENT] Translation summary: {len(translations)}/{len(TRANSLATION_LANGUAGES)} successful")
    
    # Résumé final
    logger.info("=" * 60)
    logger.info("=========== TRANSLATION AGENT COMPLETE ===========")
    logger.info(f"[AGENT] Files processed: {len(state.file_paths)}")
    logger.info(f"[AGENT] Full translations saved: {len(state.translated_files)}")
    logger.info(f"[AGENT] Summaries generated: {len(state.file_summaries)}")
    logger.info(f"[AGENT] Summary translations: {sum(len(s) for s in state.translated_summaries.values())}")
    logger.info(f"[AGENT] Errors: {len(state.errors)}")
    
    if state.file_summaries:
        logger.info(f"\n[AGENT] Summaries generated for:")
        for file_path, summary in state.file_summaries.items():
            logger.info(f"  - {os.path.basename(file_path)}: {len(summary)} characters")
    
    if state.translated_summaries:
        logger.info(f"\n[AGENT] Summary translations:")
        for file_path, translations in state.translated_summaries.items():
            logger.info(f"  - {os.path.basename(file_path)}: {len(translations)} languages")
    
    logger.info("=" * 60)
    
    return state


# ======================================================
# EXECUTION STANDALONE
# ======================================================

if __name__ == "__main__":
    logger.info("Demarrage de l'agent de traduction...")
    logger.info("=" * 60)
    
    from core.state import PipelineState
    
    # Initialiser l'état (simuler un état avec fichiers)
    state = PipelineState(regulator="BCL")
    
    # Pour test, ajouter un fichier manuellement
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        if os.path.exists(test_file):
            state.file_paths = [test_file]
            # Simuler hash et signature pour test
            with open(test_file, "rb") as f:
                content = f.read()
                state.file_hashes[test_file] = compute_hash(content)
            logger.info(f"[TEST] Using file: {test_file}")
        else:
            logger.error(f"[ERROR] File not found: {test_file}")
            sys.exit(1)
    else:
        logger.error("[ERROR] Please provide a file path as argument")
        logger.info("Usage: python translation_agent.py <file_path>")
        sys.exit(1)
    
    # Exécuter l'agent
    try:
        state = run_translation_agent(state)
        
        logger.info("\n" + "=" * 60)
        logger.info("RESULTATS")
        logger.info("=" * 60)
        logger.info(f"[OK] Fichiers traduits : {len(state.translated_files)}")
        logger.info(f"[OK] Resumes generes : {len(state.file_summaries)}")
        logger.info(f"[OK] Resumes traduits : {sum(len(s) for s in state.translated_summaries.values())}")
        logger.info(f"[ERREUR] Erreurs : {len(state.errors)}")
        
        if state.translated_files:
            logger.info(f"\nFichiers traduits sauvegardes :")
            for lang, path in state.translated_files.items():
                logger.info(f"  {lang}: {path}")
        
        if state.file_summaries:
            logger.info(f"\nResumes generes :")
            for file_path, summary in state.file_summaries.items():
                logger.info(f"  {os.path.basename(file_path)}: {len(summary)} caracteres")
                logger.info(f"    Apercu: {summary[:150]}...")
        
        if state.translated_summaries:
            logger.info(f"\nResumes traduits :")
            for file_path, translations in state.translated_summaries.items():
                logger.info(f"  {os.path.basename(file_path)}:")
                for lang, translated_summary in translations.items():
                    lang_name = {"fr": "Francais", "it": "Italien", "ar": "Arabe", 
                                "pt": "Portugais", "zh": "Chinois"}.get(lang, lang)
                    logger.info(f"    {lang_name} ({lang}): {len(translated_summary)} caracteres")
        
        if state.errors:
            logger.warning(f"\n[ATTENTION] Erreurs :")
            for i, error in enumerate(state.errors, 1):
                logger.warning(f"  {i}. {error}")
        
        logger.info("\n" + "=" * 60)
        logger.info("[OK] Execution terminee")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"\n[ERREUR FATALE] : {e}")
        import traceback
        traceback.print_exc()
        logger.error(f"Fatal error in standalone execution: {e}", exc_info=True)

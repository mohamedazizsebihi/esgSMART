import sys
import os

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
from typing import Tuple
from core.state import PipelineState
from core.logging_utils import logger
from core.config import VERSIONS_FILE
from core.digital_signature import verify_signature, base64_to_signature
import json


# ======================================================
# INTEGRITY VERIFICATION (E4)
# ======================================================

def compute_hash(content: bytes) -> str:
    """Calcule le hash SHA-256 d'un contenu."""
    return hashlib.sha256(content).hexdigest()


def verify_file_integrity(file_path: str, expected_hash: str) -> Tuple[bool, str]:
    """
    Vérifie l'intégrité d'un fichier en comparant son hash actuel avec le hash attendu.
    
    Args:
        file_path: Chemin vers le fichier à vérifier
        expected_hash: Hash SHA-256 attendu (stocké à l'extraction E1)
    
    Returns:
        (is_valid, message): Tuple avec le résultat de la vérification et un message
    """
    if not os.path.exists(file_path):
        return False, f"File not found: {file_path}"
    
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        
        current_hash = compute_hash(content)
        
        if current_hash == expected_hash:
            logger.info(f"[INTEGRITY] ✓ File integrity verified: {os.path.basename(file_path)} (hash: {current_hash[:16]}...)")
            return True, f"Integrity verified (hash: {current_hash[:16]}...)"
        else:
            error_msg = (
                f"INTEGRITY CHECK FAILED: File {os.path.basename(file_path)} has been altered!\n"
                f"  Expected hash: {expected_hash}\n"
                f"  Current hash:  {current_hash}\n"
                f"  File path: {file_path}"
            )
            logger.error(f"[INTEGRITY] ✗ {error_msg}")
            return False, error_msg
            
    except Exception as e:
        error_msg = f"Failed to verify integrity of {file_path}: {e}"
        logger.error(f"[INTEGRITY] ✗ {error_msg}")
        return False, error_msg


def verify_all_files_integrity(state: PipelineState) -> dict:
    """
    Vérifie l'intégrité de tous les fichiers dans state.file_paths.
    
    Returns:
        Dict mapping file_path -> (is_valid, message)
    """
    results = {}
    
    if not state.file_paths:
        logger.warning("[INTEGRITY] No files to verify in pipeline state")
        return results
    
    logger.info(f"[INTEGRITY] Starting integrity verification for {len(state.file_paths)} files...")
    
    for file_path in state.file_paths:
        expected_hash = state.file_hashes.get(file_path)
        
        if not expected_hash:
            # Try to get hash from versions.json as fallback
            expected_hash = _get_hash_from_versions(file_path, state)
        
        if not expected_hash:
            error_msg = f"No hash found for file: {file_path}. Cannot verify integrity."
            logger.warning(f"[INTEGRITY] ⚠ {error_msg}")
            results[file_path] = (False, error_msg)
            continue
        
        # Step 1: Verify file integrity (hash)
        is_valid, message = verify_file_integrity(file_path, expected_hash)
        
        if not is_valid:
            results[file_path] = (False, f"Integrity check failed: {message}")
            continue
        
        # Step 2: Verify digital signature (prove origin)
        signature_b64 = state.file_signatures.get(file_path)
        if signature_b64:
            try:
                signature = base64_to_signature(signature_b64)
                sig_valid, sig_message = verify_signature(expected_hash, signature)
                
                if sig_valid:
                    results[file_path] = (True, f"Integrity OK + Signature verified: {message}")
                    logger.info(f"[INTEGRITY] ✓ File {os.path.basename(file_path)}: Integrity + Signature OK")
                else:
                    results[file_path] = (False, f"Integrity OK but signature invalid: {sig_message}")
                    logger.error(f"[INTEGRITY] ✗ File {os.path.basename(file_path)}: Signature verification failed")
            except Exception as e:
                error_msg = f"Failed to verify signature: {e}"
                logger.error(f"[INTEGRITY] ✗ {error_msg}")
                results[file_path] = (False, f"Integrity OK but {error_msg}")
        else:
            # Pas de signature stockée, on accepte si l'intégrité est OK
            logger.warning(f"[INTEGRITY] ⚠ No signature found for {file_path}, integrity check only")
            results[file_path] = (True, f"Integrity OK (no signature available): {message}")
    
    # Summary
    valid_count = sum(1 for is_valid, _ in results.values() if is_valid)
    invalid_count = len(results) - valid_count
    
    logger.info(f"[INTEGRITY] Verification complete: {valid_count} valid, {invalid_count} invalid out of {len(results)} files")
    
    return results


def _get_hash_from_versions(file_path: str, state: PipelineState):
    """Tente de récupérer le hash depuis versions.json en utilisant l'URL."""
    try:
        if not os.path.exists(VERSIONS_FILE):
            return None
        
        with open(VERSIONS_FILE, "r") as f:
            versions = json.load(f)
        
        # Chercher l'URL correspondante dans url_to_file
        for url, stored_path in state.url_to_file.items():
            if stored_path == file_path:
                return versions.get(url)
        
        return None
    except Exception as e:
        logger.warning(f"[INTEGRITY] Failed to load versions file: {e}")
        return None


# ======================================================
# NOTIFICATION AGENT (E4)
# ======================================================

def run_notification_agent(state: PipelineState) -> PipelineState:
    """
    Agent de notification qui :
    1. Vérifie l'intégrité des fichiers (E4) avant envoi
    2. Envoie les notifications si des mots-clés sont détectés
    
    Garantit que le document réglementaire n'a pas été altéré durant le traitement.
    """
    logger.info("=" * 60)
    logger.info("=========== NOTIFICATION AGENT START (E4) ===========")
    logger.info("=" * 60)
    
    if not state.file_paths:
        logger.warning("[NOTIFICATION] No files to process. Skipping notification.")
        state.errors.append("Notification Agent: No files to process")
        return state
    
    # ============================================
    # ÉTAPE 1 : VÉRIFICATION D'INTÉGRITÉ (E4)
    # ============================================
    logger.info("[NOTIFICATION] Step 1: Integrity verification (E4) - Mandatory before sending")
    
    integrity_results = verify_all_files_integrity(state)
    
    # Vérifier s'il y a des fichiers altérés
    invalid_files = [path for path, (is_valid, _) in integrity_results.items() if not is_valid]
    
    if invalid_files:
        error_msg = (
            f"INTEGRITY CHECK FAILED: {len(invalid_files)} file(s) have been altered!\n"
            f"Altered files:\n" + "\n".join(f"  - {f}" for f in invalid_files)
        )
        logger.error(f"[NOTIFICATION] {error_msg}")
        state.errors.append(error_msg)
        
        # Ne pas envoyer de notification si l'intégrité est compromise
        logger.error("[NOTIFICATION] ABORTED: Cannot send notifications for altered files")
        logger.info("=" * 60)
        logger.info("=========== NOTIFICATION AGENT COMPLETE (ABORTED) ===========")
        logger.info("=" * 60)
        return state
    
    logger.info("[NOTIFICATION] ✓ All files passed integrity verification")
    
    # ============================================
    # ÉTAPE 2 : VÉRIFICATION DES MOTS-CLÉS
    # ============================================
    logger.info("[NOTIFICATION] Step 2: Checking for keyword matches...")
    
    if not state.keyword_hits:
        logger.info("[NOTIFICATION] No keywords detected. No notification needed.")
        logger.info("=" * 60)
        logger.info("=========== NOTIFICATION AGENT COMPLETE ===========")
        logger.info("=" * 60)
        return state
    
    logger.info(f"[NOTIFICATION] {len(state.keyword_hits)} keyword(s) detected:")
    for keyword, contexts in state.keyword_hits.items():
        logger.info(f"[NOTIFICATION]   - '{keyword}': {len(contexts)} occurrence(s)")
    
    # ============================================
    # ÉTAPE 3 : ENVOI DE NOTIFICATION (À IMPLÉMENTER)
    # ============================================
    logger.info("[NOTIFICATION] Step 3: Sending notification...")
    
    # TODO: Implémenter l'envoi d'email
    # from core.config import EMAIL_USER, EMAIL_PASS
    # send_notification_email(state, integrity_results)
    
    logger.info("[NOTIFICATION] Notification prepared (email sending not yet implemented)")
    logger.info("=" * 60)
    logger.info("=========== NOTIFICATION AGENT COMPLETE ===========")
    logger.info("=" * 60)
    
    return state


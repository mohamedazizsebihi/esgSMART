"""
Agent Orchestrateur - Coordonne l'exécution des agents du pipeline.
Gère la communication sécurisée entre agents avec OAuth JWT et TLS/mTLS.
"""

import sys
import os

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import json
from typing import Dict, Optional
from datetime import datetime

from core.logging_utils import logger
from core.state import PipelineState
from core.config import (
    AGENT_USE_TLS, AGENT_USE_MTLS, AGENT_CA_CERT, 
    AGENT_CLIENT_CERT, AGENT_CLIENT_KEY
)
from core.oauth_jwt import generate_jwt_token, verify_jwt_token, get_auth_headers
from agents.extraction_agent import run_extraction_agent
from agents.translation_agent import run_translation_agent


# ======================================================
# COMMUNICATION SÉCURISÉE INTER-AGENTS
# ======================================================

def create_secure_session():
    """
    Crée une session requests avec configuration TLS/mTLS.
    """
    session = requests.Session()
    
    if AGENT_USE_TLS or AGENT_USE_MTLS:
        if AGENT_CA_CERT and os.path.exists(AGENT_CA_CERT):
            session.verify = AGENT_CA_CERT
            logger.info(f"[ORCHESTRATOR] TLS enabled with CA cert: {AGENT_CA_CERT}")
        else:
            session.verify = True
            logger.info("[ORCHESTRATOR] TLS enabled (system certificates)")
        
        if AGENT_USE_MTLS:
            if AGENT_CLIENT_CERT and AGENT_CLIENT_KEY:
                if os.path.exists(AGENT_CLIENT_CERT) and os.path.exists(AGENT_CLIENT_KEY):
                    session.cert = (AGENT_CLIENT_CERT, AGENT_CLIENT_KEY)
                    logger.info(f"[ORCHESTRATOR] mTLS enabled with client cert: {AGENT_CLIENT_CERT}")
                else:
                    logger.warning("[ORCHESTRATOR] mTLS requested but certificates not found")
            else:
                logger.warning("[ORCHESTRATOR] mTLS requested but certificates not configured")
    else:
        session.verify = False
        logger.info("[ORCHESTRATOR] HTTP mode (no TLS)")
    
    return session


# ======================================================
# ORCHESTRATION DU PIPELINE
# ======================================================

def run_orchestrator(regulator: str = "BCL") -> PipelineState:
    """
    Agent orchestrateur qui coordonne l'exécution du pipeline complet.
    
    Flux:
    1. Génère token JWT pour extraction_agent
    2. Exécute extraction_agent
    3. Récupère les nouveaux fichiers
    4. Génère token JWT pour translation_agent
    5. Envoie les fichiers à translation_agent pour traduction en 5 langues
    6. Retourne l'état final
    
    Args:
        regulator: Source régulateur ("BCL" ou "ECB")
    
    Returns:
        PipelineState avec tous les résultats
    """
    logger.info("=" * 60)
    logger.info("=========== ORCHESTRATOR START ===========")
    logger.info("=" * 60)
    logger.info(f"[ORCHESTRATOR] Regulator: {regulator}")
    logger.info(f"[ORCHESTRATOR] Starting pipeline orchestration...")
    
    # Initialiser l'état global
    state = PipelineState(regulator=regulator)
    
    # ============================================
    # ÉTAPE 1 : EXTRACTION AGENT
    # ============================================
    logger.info("\n" + "=" * 60)
    logger.info("[ORCHESTRATOR] STEP 1: Executing Extraction Agent")
    logger.info("=" * 60)
    
    # Générer token JWT pour extraction_agent
    extraction_token = generate_jwt_token(
        agent_id="extraction_agent",
        permissions=["read", "write", "download"]
    )
    logger.info("[ORCHESTRATOR] JWT token generated for extraction_agent")
    
    try:
        # Exécuter l'agent d'extraction
        logger.info("[ORCHESTRATOR] Calling extraction_agent.run_extraction_agent()...")
        state = run_extraction_agent(state)
        
        # Vérifier les résultats
        if state.errors:
            logger.warning(f"[ORCHESTRATOR] Extraction agent reported {len(state.errors)} error(s)")
            for error in state.errors:
                logger.warning(f"[ORCHESTRATOR]   - {error}")
        
        if not state.file_paths:
            logger.warning("[ORCHESTRATOR] No files extracted. Pipeline stopping.")
            logger.info("=" * 60)
            logger.info("=========== ORCHESTRATOR COMPLETE (NO FILES) ===========")
            logger.info("=" * 60)
            return state
        
        logger.info(f"[ORCHESTRATOR] ✓ Extraction completed: {len(state.file_paths)} file(s) ready")
        logger.info(f"[ORCHESTRATOR] Files: {', '.join([os.path.basename(f) for f in state.file_paths[:5]])}")
        if len(state.file_paths) > 5:
            logger.info(f"[ORCHESTRATOR]   ... and {len(state.file_paths) - 5} more files")
        
    except Exception as e:
        error_msg = f"Extraction agent failed: {e}"
        logger.error(f"[ORCHESTRATOR] ✗ {error_msg}")
        state.errors.append(error_msg)
        logger.info("=" * 60)
        logger.info("=========== ORCHESTRATOR COMPLETE (ERROR) ===========")
        logger.info("=" * 60)
        return state
    
    # ============================================
    # ÉTAPE 2 : TRANSLATION AGENT
    # ============================================
    logger.info("\n" + "=" * 60)
    logger.info("[ORCHESTRATOR] STEP 2: Executing Translation Agent")
    logger.info("=" * 60)
    
    # Générer token JWT pour translation_agent
    translation_token = generate_jwt_token(
        agent_id="translation_agent",
        permissions=["read", "translate", "write"]
    )
    logger.info("[ORCHESTRATOR] JWT token generated for translation_agent")
    
    try:
        # Exécuter l'agent de traduction
        logger.info("[ORCHESTRATOR] Calling translation_agent.run_translation_agent()...")
        logger.info(f"[ORCHESTRATOR] Sending {len(state.file_paths)} file(s) for translation")
        
        state = run_translation_agent(state)
        
        # Vérifier les résultats
        if state.errors:
            logger.warning(f"[ORCHESTRATOR] Translation agent reported {len(state.errors)} error(s)")
            for error in state.errors:
                logger.warning(f"[ORCHESTRATOR]   - {error}")
        
        if state.translated_files:
            logger.info(f"[ORCHESTRATOR] ✓ Translation completed: {len(state.translated_files)} translation(s)")
            for lang, path in state.translated_files.items():
                logger.info(f"[ORCHESTRATOR]   - {lang}: {os.path.basename(path)}")
        else:
            logger.warning("[ORCHESTRATOR] No translations generated")
        
    except Exception as e:
        error_msg = f"Translation agent failed: {e}"
        logger.error(f"[ORCHESTRATOR] ✗ {error_msg}")
        state.errors.append(error_msg)
    
    # ============================================
    # RÉSUMÉ FINAL
    # ============================================
    logger.info("\n" + "=" * 60)
    logger.info("=========== ORCHESTRATOR COMPLETE ===========")
    logger.info("=" * 60)
    logger.info(f"[ORCHESTRATOR] Pipeline Summary:")
    logger.info(f"[ORCHESTRATOR]   - Files extracted: {len(state.file_paths)}")
    logger.info(f"[ORCHESTRATOR]   - Translations created: {len(state.translated_files)}")
    logger.info(f"[ORCHESTRATOR]   - Errors: {len(state.errors)}")
    logger.info("=" * 60)
    
    return state


# ======================================================
# EXECUTION STANDALONE
# ======================================================

if __name__ == "__main__":
    # Les logs seront automatiquement affichés dans le terminal
    # grâce au console_handler configuré dans logging_utils.py
    
    logger.info("=" * 60)
    logger.info("Demarrage de l'orchestrateur...")
    logger.info("=" * 60)
    
    try:
        # Exécuter l'orchestrateur
        # Tous les logs seront affichés en temps réel dans le terminal
        state = run_orchestrator(regulator="BCL")
        
        # Afficher les résultats finaux
        logger.info("\n" + "=" * 60)
        logger.info("RESULTATS DU PIPELINE")
        logger.info("=" * 60)
        logger.info(f"[OK] Fichiers extraits : {len(state.file_paths)}")
        logger.info(f"[OK] Traductions creees : {len(state.translated_files)}")
        logger.info(f"[ERREUR] Erreurs : {len(state.errors)}")
        
        if state.file_paths:
            logger.info(f"\nFichiers extraits :")
            for i, file_path in enumerate(state.file_paths[:10], 1):
                logger.info(f"  {i}. {file_path}")
            if len(state.file_paths) > 10:
                logger.info(f"  ... et {len(state.file_paths) - 10} autres fichiers")
        
        if state.translated_files:
            logger.info(f"\nTraductions creees :")
            for lang, path in state.translated_files.items():
                lang_name = {"fr": "Francais", "it": "Italien", "ar": "Arabe", 
                            "pt": "Portugais", "zh": "Chinois"}.get(lang, lang)
                logger.info(f"  {lang_name} ({lang}): {path}")
        
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
        logger.error(f"Fatal error in orchestrator: {e}", exc_info=True)


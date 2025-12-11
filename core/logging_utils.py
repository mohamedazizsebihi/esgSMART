import logging
import os
import sys
from datetime import datetime
from core.config import LOG_DIR


# =========================
# CREATE LOG DIRECTORY
# =========================

os.makedirs(LOG_DIR, exist_ok=True)


# =========================
# LOG FILE NAME (one per day)
# =========================

log_filename = os.path.join(
    LOG_DIR, 
    f"reg_watch_{datetime.now().strftime('%Y-%m-%d')}.log"
)


# =========================
# LOGGER CONFIGURATION WITH CONSOLE OUTPUT
# =========================

# Créer le logger
logger = logging.getLogger("reg_watch")
logger.setLevel(logging.INFO)

# Éviter les doublons si le logger est déjà configuré
if logger.handlers:
    logger.handlers.clear()

# Format des logs
log_format = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Handler pour fichier
file_handler = logging.FileHandler(log_filename, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_format)
logger.addHandler(file_handler)

# Handler pour console (terminal) - AFFICHE EN TEMPS RÉEL
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
# Format simplifié pour la console (plus lisible)
console_format = logging.Formatter(
    "%(levelname)s | %(message)s"
)
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)

# Éviter la propagation vers le root logger
logger.propagate = False

# Forcer le flush pour affichage immédiat
import sys
sys.stdout.flush()

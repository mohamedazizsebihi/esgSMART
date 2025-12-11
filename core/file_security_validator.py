"""
✅ MODULE DE SÉCURITÉ AGENT EXTRACTION
Valide les fichiers selon :
1. Whitelist d'extensions
2. Denylist stricte
3. Limites de taille par type
4. Magic bytes (signature binaire)
5. Validation ZIP sécurisée
"""

import os
import zipfile
from typing import Tuple
from urllib.parse import urlparse
from core.logging_utils import logger


# ======================================================
# CONFIGURATION SÉCURITÉ
# ======================================================

ALLOWED_EXTENSIONS = {
    # Documents officiels
    '.pdf',          # Rapport principal
    '.doc', '.docx', # Word
    '.txt', '.rtf',  # Texte brut/enrichi
    '.odt',          # OpenDocument Text
    
    # Données tabulaires
    '.csv',          # CSV
    '.xls', '.xlsx', # Excel
    '.ods',          # OpenDocument Spreadsheet
    
    # Données structurées
    '.xml',          # XML
    '.json',         # JSON
    
    # Archives (avec inspection)
    '.zip',          # ZIP
    '.tar', '.gz',   # TAR/GZIP
}

DANGEROUS_EXTENSIONS = {
    # ========== EXÉCUTABLES WINDOWS/DOS ==========
    '.exe',          # Exécutable Windows
    '.com',          # DOS
    '.scr',          # Screensaver (exécutable)
    '.bat', '.cmd',  # Batch/Command
    '.msi',          # Installeur Windows
    '.ps1', '.ps2',  # PowerShell
    '.vbs', '.vbe',  # VBScript
    
    # ========== EXÉCUTABLES SYSTÈME ==========
    '.bin',          # Binary
    '.elf',          # ELF (Linux)
    '.dmg',          # macOS
    '.iso',          # Image ISO (peut contenir malware)
    '.img',          # Image disque
    '.app',          # macOS app
    '.deb', '.rpm',  # Packages Linux (peuvent contenir scripts)
    '.apk',          # Android APK
    
    # ========== SCRIPTS - LANGAGES DE PROGRAMMATION ==========
    '.sh', '.bash', '.zsh', '.ksh', '.csh',    # Shell scripts
    '.py', '.pyc', '.pyo', '.pyw',             # Python
    '.php', '.php3', '.php4', '.php5',         # PHP
    '.pl', '.pm',                               # Perl
    '.rb', '.rbw',                              # Ruby
    '.go',                                      # Go
    '.java', '.class', '.jar',                  # Java
    '.cpp', '.c', '.h', '.cc', '.cxx',         # C/C++
    '.js', '.jsx', '.mjs',                      # JavaScript
    '.ts', '.tsx',                              # TypeScript
    '.asm', '.s',                               # Assembly
    '.swift',                                   # Swift
    '.rs',                                      # Rust
    
    # ========== FICHIERS DE CLÉS & SECRETS ==========
    '.ssh',                  # SSH key directory reference
    '.key', '.pkey',         # Clés privées
    '.pem', '.p7b', '.p12',  # Certificats/clés
    '.ppk',                  # PuTTY key
    '.pub',                  # Public key
    '.id_rsa',               # SSH private key
    '.private',              # Generic private key
    '.gpg', '.asc',          # GPG keys
    '.cer', '.crt',          # Certificats X.509
    
    # ========== FICHIERS DE CONFIGURATION ==========
    '.env',          # Variables d'environnement (secrets!)
    '.config',       # Configuration générique
    '.conf',         # Configuration
    '.ini', '.cfg',  # Configuration INI
    '.properties',   # Java properties
    '.toml',         # TOML (peut contenir secrets)
    '.yaml', '.yml', # YAML (peut contenir secrets)
    '.htaccess',     # Apache config
    '.htpasswd',     # Apache auth
    '.dockerignore',  # Docker config
    '.env.local',    # Env local
    
    # ========== BASES DE DONNÉES ==========
    '.db', '.sqlite', '.sqlite3',  # SQLite
    '.sql',                         # SQL dump
    '.mdb', '.accdb',              # Access database
    '.dbf',                         # dBASE
    
    # ========== FICHIERS DE LOG ==========
    '.log',          # Logs (peuvent contenir PII)
    '.evt', '.evtx', # Windows event logs
    
    # ========== FICHIERS SYSTÈME CACHÉS ==========
    '.git',          # Git directory
    '.svn',          # SVN directory
    '.hg',           # Mercurial directory
    '.DS_Store',     # macOS metadata
    'Thumbs.db',     # Windows metadata
    
    # ========== ARCHIVES EXÉCUTABLES ==========
    '.7z', '.rar',   # Peuvent être mal scannées
    '.cab',          # Windows cabinet
    '.exe.zip',      # Archive d'exécutable renommée
    
    # ========== AUTRES DANGEREUX ==========
    '.tmp', '.tmp~', # Fichiers temporaires
    '.bak', '.backup', # Backups (données sensibles)
    '.swp', '.swo',  # Vim swap files
    '.dll', '.so',   # Librairies dynamiques (exécutables)
    '.sys',          # Système (Windows)
    '.drv',          # Driver (Windows)
    '.ocx',          # ActiveX (Windows, dangereux)
}

# LIMITES DE TAILLE STRICTES PAR TYPE DE FICHIER
FILE_SIZE_LIMITS = {
    # Documents (généralement petits)
    '.pdf': 100 * 1024 * 1024,           # 100 MB
    '.doc': 50 * 1024 * 1024,            # 50 MB
    '.docx': 50 * 1024 * 1024,           # 50 MB
    '.txt': 50 * 1024 * 1024,            # 50 MB
    '.rtf': 50 * 1024 * 1024,            # 50 MB
    
    # Données tabulaires
    '.xls': 100 * 1024 * 1024,           # 100 MB (Excel peut être volumineux)
    '.xlsx': 100 * 1024 * 1024,          # 100 MB
    '.ods': 100 * 1024 * 1024,           # 100 MB
    '.csv': 500 * 1024 * 1024,           # 500 MB (données can be huge)
    
    # Données structurées
    '.xml': 200 * 1024 * 1024,           # 200 MB
    '.json': 200 * 1024 * 1024,          # 200 MB
    
    # Archives (plus permissif pour ZIP/TAR)
    '.zip': 1024 * 1024 * 1024,          # 1 GB (contient d'autres fichiers)
    '.tar': 1024 * 1024 * 1024,          # 1 GB
    '.gz': 500 * 1024 * 1024,            # 500 MB (compressé)
    
    # Default pour extensions inconnues
    'default': 100 * 1024 * 1024,        # 100 MB par défaut
}

# TAILLES GLOBALES DE SESSION
MAX_TOTAL_DOWNLOAD_SESSION = 5 * 1024 * 1024 * 1024      # 5 GB par session
MAX_ZIP_EXTRACTED_TOTAL = 10 * 1024 * 1024 * 1024        # 10 GB extrait
MAX_SINGLE_FILE_EXTRACTED = 500 * 1024 * 1024            # 500 MB par fichier extrait
MAX_FILES_IN_ZIP = 1000                                  # 1000 fichiers max

# Tableau des signatures attendues (Magic Bytes)
MAGIC_BYTES_WHITELIST = {
    # Documents
    '.pdf': b'%PDF',                              # Signature PDF
    '.docx': b'PK\x03\x04',                       # ZIP (Office 2007+)
    '.xlsx': b'PK\x03\x04',                       # ZIP (Office 2007+)
    '.txt': None,                                 # Pas de signature spécifique
    '.rtf': b'{\\rtf',                            # RTF
    
    # Données
    '.csv': (b'\xff\xfe', b'\xfe\xff', None),    # UTF-16 BOM ou pas BOM
    '.json': (b'{', b'[', b' ', b'\t', b'\n'),   # JSON (commence par { ou [)
    '.xml': (b'<?xml', b'<'),                     # XML
    
    # Archives
    '.zip': b'PK\x03\x04',                        # ZIP
    '.tar': None,                                 # TAR n'a pas de signature standard
    '.gz': b'\x1f\x8b',                           # GZIP
}

# Signatures DANGEREUSES à rejeter (indépendamment de l'extension)
DANGEROUS_MAGIC_BYTES = {
    b'MZ',          # DOS/Windows executable
    b'#!',          # Shebang (script shell)
    b'\x7fELF',     # ELF binary (Linux)
    b'\xca\xfe\xba\xbe',  # Java class / Mach-O
    b'\xfe\xed\xfa',      # Mach-O (macOS)
    b'\x89PNG',     # PNG (images, risque de polyglot)
}


# ======================================================
# VALIDATION PRINCIPALE
# ======================================================

def validate_file_security(filename: str, file_content: bytes) -> Tuple[bool, str]:
    """
    Valide un fichier selon 5 critères de sécurité.
    
    Args:
        filename: Nom du fichier
        file_content: Contenu binaire du fichier
    
    Returns:
        (is_valid, error_message)
    """
    
    # 1. FICHIERS CACHÉS
    if filename.startswith('.') or '/..' in filename or '\\..' in filename:
        msg = f"Fichier caché détecté: {filename}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    # 2. EXTENSION DANS WHITELIST
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    
    if ext not in ALLOWED_EXTENSIONS:
        msg = f"Extension non autorisée: {ext}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    # 3. EXTENSION DANS DENYLIST (double check)
    if ext in DANGEROUS_EXTENSIONS:
        msg = f"Extension interdite: {ext}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    # 4. DOUBLE EXTENSION (rapport.pdf.exe)
    parts = filename.rsplit('.', 2)
    if len(parts) == 3:
        second_ext = '.' + parts[1]
        if second_ext.lower() in DANGEROUS_EXTENSIONS:
            msg = f"Double extension suspecte: {second_ext}"
            logger.error(f"❌ [SECURITY] {msg}")
            return False, msg
    
    # 5. VÉRIFIER LA TAILLE
    file_size = len(file_content)
    max_size = FILE_SIZE_LIMITS.get(ext, FILE_SIZE_LIMITS['default'])
    
    if file_size == 0:
        msg = "Fichier vide"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    if file_size > max_size:
        msg = (f"Fichier trop volumineux: {file_size / 1024 / 1024:.1f}MB "
               f"(max: {max_size / 1024 / 1024:.1f}MB)")
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    # 6. VÉRIFIER LES MAGIC BYTES (Signature binaire)
    header = file_content[:16]
    
    # 6a. Rejeter les signatures dangereuses (indépendamment de l'extension)
    for dangerous_sig in DANGEROUS_MAGIC_BYTES:
        if header.startswith(dangerous_sig):
            msg = f"Fichier masqué détecté (signature dangereuse: {dangerous_sig.hex()})"
            logger.error(f"❌ [SECURITY] {msg}")
            return False, msg
    
    # 6b. Vérifier les signatures attendues
    if ext in MAGIC_BYTES_WHITELIST:
        magic_expected = MAGIC_BYTES_WHITELIST[ext]
        
        if magic_expected is None:
            # Pas de vérification pour ce type
            pass
        elif isinstance(magic_expected, tuple):
            # Multiple options
            if not any(header.startswith(m) for m in magic_expected if m is not None):
                # Pour les fichiers texte, être permissif
                if ext in ['.csv', '.txt', '.json', '.xml']:
                    logger.warning(f"⚠️  [SECURITY] MAGIC BYTES: {filename} ne match pas la signature attendue (permissif pour texte)")
                    # Ne pas bloquer (peut être vide ou UTF-16)
                else:
                    msg = f"Fichier masqué détecté (magic bytes invalides pour {ext})"
                    logger.error(f"❌ [SECURITY] {msg}")
                    return False, msg
        else:
            # Signature unique
            if not header.startswith(magic_expected):
                # Pour PDF, ZIP, documents: c'est critique
                if ext in ['.pdf', '.zip', '.docx', '.xlsx']:
                    msg = f"Fichier masqué détecté (faux {ext})"
                    logger.error(f"❌ [SECURITY] {msg}")
                    logger.debug(f"[SECURITY] Expected: {magic_expected.hex()}, Got: {header[:len(magic_expected)].hex()}")
                    return False, msg
    
    # TOUS LES CHECKS PASSÉS
    logger.info(f"✅ [SECURITY] File validated: {filename} ({file_size / 1024 / 1024:.1f}MB)")
    return True, "OK"


def validate_file_size_from_header(content_length: str, filename: str) -> Tuple[bool, str]:
    """
    Valide la taille annoncée par le serveur (avant téléchargement complet).
    
    Args:
        content_length: Valeur du header Content-Length
        filename: Nom du fichier
    
    Returns:
        (is_valid, error_message)
    """
    try:
        length = int(content_length)
    except (ValueError, TypeError):
        return True, "Cannot validate from header"
    
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    max_size = FILE_SIZE_LIMITS.get(ext, FILE_SIZE_LIMITS['default'])
    
    if length > max_size:
        msg = (f"Header size exceeds limit: {length / 1024 / 1024:.1f}MB "
               f"> {max_size / 1024 / 1024:.1f}MB")
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    return True, "Size OK"


def validate_zip_file(zip_content: bytes) -> Tuple[bool, str]:
    """
    Valide un fichier ZIP avant extraction.
    
    Args:
        zip_content: Contenu binaire du fichier ZIP
    
    Returns:
        (is_valid, error_message)
    """
    size = len(zip_content)
    
    if size > FILE_SIZE_LIMITS.get('.zip', FILE_SIZE_LIMITS['default']):
        msg = f"ZIP file too large: {size / 1024 / 1024:.1f}MB"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    try:
        # Créer un fichier temporaire en mémoire pour zipfile
        import io
        zip_file = io.BytesIO(zip_content)
        
        with zipfile.ZipFile(zip_file, 'r') as z:
            # Vérifier la totalité des fichiers
            total_size = sum(info.file_size for info in z.infolist())
            
            if total_size > MAX_ZIP_EXTRACTED_TOTAL:
                msg = f"ZIP total size too large ({total_size / 1024 / 1024:.1f}MB > {MAX_ZIP_EXTRACTED_TOTAL / 1024 / 1024:.1f}MB)"
                logger.error(f"❌ [SECURITY] {msg}")
                return False, msg
            
            if len(z.infolist()) > MAX_FILES_IN_ZIP:
                msg = f"ZIP contains too many files ({len(z.infolist())} > {MAX_FILES_IN_ZIP})"
                logger.error(f"❌ [SECURITY] {msg}")
                return False, msg
            
            # Vérifier chaque fichier
            for info in z.infolist():
                if info.file_size > MAX_SINGLE_FILE_EXTRACTED:
                    msg = f"File in ZIP too large: {info.filename} ({info.file_size / 1024 / 1024:.1f}MB)"
                    logger.error(f"❌ [SECURITY] {msg}")
                    return False, msg
                
                # Vérifier que le nom du fichier n'est pas dangereux
                filename = os.path.basename(info.filename)
                if filename.startswith('.') or '/..' in filename or '\\..' in filename:
                    msg = f"Dangerous filename in ZIP: {info.filename}"
                    logger.error(f"❌ [SECURITY] {msg}")
                    return False, msg
                
                # Vérifier l'extension du fichier extrait
                _, ext = os.path.splitext(filename)
                ext = ext.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    msg = f"Dangerous extension in ZIP: {info.filename} ({ext})"
                    logger.error(f"❌ [SECURITY] {msg}")
                    return False, msg
        
        logger.info(f"✅ [SECURITY] ZIP file validated: {len(z.infolist())} files, {total_size / 1024 / 1024:.1f}MB total")
        return True, "ZIP valid"
    
    except zipfile.BadZipFile:
        msg = "Invalid ZIP file"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    except Exception as e:
        msg = f"ZIP validation error: {e}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg


def validate_extracted_file(filepath: str) -> Tuple[bool, str]:
    """
    Valide un fichier extrait d'un ZIP.
    
    Args:
        filepath: Chemin vers le fichier extrait
    
    Returns:
        (is_valid, error_message)
    """
    if not os.path.exists(filepath):
        msg = f"Extracted file not found: {filepath}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg
    
    filename = os.path.basename(filepath)
    
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        
        return validate_file_security(filename, content)
    
    except Exception as e:
        msg = f"Failed to validate extracted file: {e}"
        logger.error(f"❌ [SECURITY] {msg}")
        return False, msg


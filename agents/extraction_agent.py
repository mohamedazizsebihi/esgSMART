import sys
import os

# Ajouter le répertoire parent au PYTHONPATH pour permettre l'exécution depuis n'importe où
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import json
import hashlib
import zipfile
import shutil
from datetime import datetime

from core.state import PipelineState
from core.logging_utils import logger
from core.config import ALLOWED_DOMAINS, DOWNLOAD_DIR
from core.digital_signature import sign_hash, signature_to_base64
from core.file_security_validator import (
    validate_file_security,
    validate_file_size_from_header,
    validate_zip_file,
    validate_extracted_file
)


# ======================================================
# HELPERS — SAFETY REQUEST
# ======================================================

def safe_request(url):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            " AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/120.0.0.0 Safari/537.36"
        )
    }
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.error(f"[REQUEST] Failed: {url} → {e}")
        return None


# ======================================================
# VERSIONING (SHA256)
# ======================================================

def compute_hash(content: bytes):
    return hashlib.sha256(content).hexdigest()


def load_versions():
    path = "data/versions.json"
    if not os.path.exists(path):
        logger.info("[VERSIONS] No versions file found, starting fresh.")
        return {}
    try:
        with open(path, "r") as f:
            versions = json.load(f)
            logger.info(f"[VERSIONS] Loaded {len(versions)} tracked file versions.")
            return versions
    except Exception as e:
        logger.error(f"[VERSIONS] Failed to load versions file: {e}")
        return {}


def save_versions(v):
    os.makedirs("data", exist_ok=True)
    try:
        with open("data/versions.json", "w") as f:
            json.dump(v, f, indent=4)
        logger.info(f"[VERSIONS] Saved {len(v)} file versions to disk.")
    except Exception as e:
        logger.error(f"[VERSIONS] Failed to save versions file: {e}")


# ======================================================
# ZIP EXTRACTION + FLATTENING
# ======================================================

def extract_zip(zip_path, flat_dir, last_update):
    extracted = []

    extract_dir = zip_path + "_unzipped"
    os.makedirs(extract_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_dir)
        logger.info(f"[ZIP] Extracted → {extract_dir}")

        for root, _, files in os.walk(extract_dir):
            for file in files:
                src = os.path.join(root, file)

                # ✅ SECURITY: Validate extracted file before processing
                is_valid, error_msg = validate_extracted_file(src)
                if not is_valid:
                    logger.error(f"[ZIP] ❌ Security validation failed for extracted file: {error_msg}")
                    logger.warning(f"[ZIP] Skipping dangerous file: {file}")
                    continue

                # dated filename
                name, ext = os.path.splitext(file)
                dated = f"{last_update}__{name}{ext}"
                dest = os.path.join(flat_dir, dated)

                # duplicate handling
                c = 1
                while os.path.exists(dest):
                    dest = os.path.join(flat_dir, f"{last_update}__{name}_{c}{ext}")
                    c += 1

                shutil.copy2(src, dest)
                extracted.append(dest)
                logger.info(f"[ZIP] Flattened → {dest}")

    except Exception as e:
        logger.error(f"[ZIP] Failed to unzip {zip_path}: {e}")

    return extracted


# ======================================================
# DOWNLOAD FILE (SKIP IF SAME HASH)
# ======================================================

def download_file(url, old_versions, last_update, flat_dir):
    filename = os.path.basename(urlparse(url).path)
    dest = os.path.join(DOWNLOAD_DIR, filename)

    # If file already exists → compare local hash
    if os.path.exists(dest):
        logger.info(f"[DOWNLOAD] File exists locally → {filename}, checking hash...")
        with open(dest, "rb") as f:
            local_hash = compute_hash(f.read())

        if old_versions.get(url) == local_hash:
            logger.info(f"[DOWNLOAD] SKIPPED (unchanged, hash: {local_hash[:16]}...) → {filename}")
            return dest, local_hash, False, []
        else:
            logger.info(f"[DOWNLOAD] File changed (old hash: {old_versions.get(url, 'N/A')[:16] if old_versions.get(url) else 'N/A'}..., new hash: {local_hash[:16]}...) → {filename}")

    # Otherwise → download new file
    logger.info(f"[DOWNLOAD] Fetching → {url}")
    r = safe_request(url)
    if not r:
        logger.error(f"[DOWNLOAD] Failed to download → {filename}")
        return None, None, None, []

    # ✅ SECURITY: Validate Content-Length header before downloading
    content_length = r.headers.get('Content-Length')
    if content_length:
        is_valid, error_msg = validate_file_size_from_header(content_length, filename)
        if not is_valid:
            logger.error(f"[DOWNLOAD] ❌ Security validation failed (header): {error_msg}")
            return None, None, None, []

    content = r.content
    file_size = len(content)

    # ✅ SECURITY: Validate file security (extension, size, magic bytes)
    is_valid, error_msg = validate_file_security(filename, content)
    if not is_valid:
        logger.error(f"[DOWNLOAD] ❌ Security validation failed: {error_msg}")
        return None, None, None, []

    file_hash = compute_hash(content)

    with open(dest, "wb") as f:
        f.write(content)

    logger.info(f"[DOWNLOAD] Saved → {dest} (size: {file_size:,} bytes, hash: {file_hash[:16]}...)")

    # If ZIP → validate and extract
    extracted = []
    if dest.lower().endswith(".zip"):
        logger.info(f"[DOWNLOAD] ZIP file detected, validating...")
        
        # ✅ SECURITY: Validate ZIP file before extraction
        is_valid, error_msg = validate_zip_file(content)
        if not is_valid:
            logger.error(f"[DOWNLOAD] ❌ ZIP validation failed: {error_msg}")
            return None, None, None, []
        
        logger.info(f"[DOWNLOAD] ZIP validated, extracting...")
        extracted = extract_zip(dest, flat_dir, last_update)
        logger.info(f"[DOWNLOAD] Extracted {len(extracted)} files from ZIP")

    return dest, file_hash, True, extracted


# ======================================================
# SCRAPING FUSION SELENIUM + BEAUTIFULSOUP
# ======================================================

FILE_EXT = (
    ".pdf", ".xlsx", ".xls", ".csv", ".xml", ".zip",
    ".doc", ".docx", ".txt", ".html", ".json",
    ".ppt", ".pptx"
)

BASE_URL = "https://www.bcl.lu/en/Regulatory-reporting/Etablissements_credit/AnaCredit/Instructions/index.html"


def scrape_page():
    """Try requests + BeautifulSoup first; fallback to Selenium if needed."""

    logger.info(f"[SCRAPER] Starting page scraping → {BASE_URL}")
    logger.info("[SCRAPER] Trying fast-mode extraction via Requests...")

    try:
        r = requests.get(BASE_URL, timeout=10)
        r.raise_for_status()
        logger.info(f"[SCRAPER] Page fetched successfully (status: {r.status_code}, size: {len(r.text):,} bytes)")

        soup = BeautifulSoup(r.text, "html.parser")
        rows = soup.select("table tr")
        logger.info(f"[SCRAPER] Found {len(rows)} table rows to process")

        documents = []

        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 2:
                continue

            last_update = cells[1].get_text(strip=True)
            link = cells[0].find("a")

            if link:
                href = link.get("href")
                full_url = urljoin(BASE_URL, href)

                if any(full_url.lower().endswith(ext) for ext in FILE_EXT):
                    documents.append((full_url, last_update))

        if documents:
            logger.info(f"[SCRAPER] Found {len(documents)} documents via BeautifulSoup")
            return documents
        else:
            logger.warning("[SCRAPER] No documents found via BeautifulSoup, trying Selenium...")

    except Exception as e:
        logger.warning(f"[SCRAPER] BeautifulSoup failed → {e}")

    # ----------------------------------------------------------
    # Fallback : Selenium (when the page is protected or dynamic)
    # ----------------------------------------------------------
    logger.info("[SCRAPER] Falling back to Selenium...")

    try:
        options = uc.ChromeOptions()
        options.headless = True
        logger.info("[SCRAPER] Initializing Chrome driver (headless mode)...")
        driver = uc.Chrome(options=options, version_main=122)

        logger.info(f"[SCRAPER] Loading page with Selenium → {BASE_URL}")
        driver.get(BASE_URL)
        time.sleep(3)

        links = driver.find_elements(By.TAG_NAME, "a")
        logger.info(f"[SCRAPER] Found {len(links)} links on page")

        docs = []

        for link in links:
            href = link.get_attribute("href")
            if not href:
                continue

            if href.lower().endswith(FILE_EXT):
                docs.append((href, "unknown-date"))

        driver.quit()
        logger.info(f"[SCRAPER] Selenium recovered {len(docs)} files")
        
        if not docs:
            logger.warning("[SCRAPER] No documents found with Selenium either")
        
        return docs

    except Exception as e:
        logger.error(f"[SCRAPER] Selenium failed → {e}")
        return []


# ======================================================
# MAIN AGENT LOGIC
# ======================================================

def run_extraction_agent(state: PipelineState):

    logger.info("=" * 60)
    logger.info("=========== EXTRACTION AGENT START ===========")
    logger.info("=" * 60)
    logger.info(f"[AGENT] Regulator: {state.regulator}")
    logger.info(f"[AGENT] Initial state - Errors: {len(state.errors)}, File paths: {len(state.file_paths)}")

    # prepare folders
    today = datetime.today().strftime("%Y-%m-%d")
    history_folder = os.path.join("Historique", today)
    flat_dir = os.path.join(history_folder, "A_plat")

    logger.info(f"[AGENT] Preparing directories for date: {today}")
    os.makedirs(history_folder, exist_ok=True)
    logger.info(f"[AGENT] History folder: {history_folder}")
    os.makedirs(flat_dir, exist_ok=True)
    logger.info(f"[AGENT] Flat directory: {flat_dir}")
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    logger.info(f"[AGENT] Download directory: {DOWNLOAD_DIR}")

    documents = scrape_page()
    if not documents:
        error_msg = "No documents found on the target page."
        logger.error(f"[AGENT] {error_msg}")
        state.errors.append(error_msg)
        logger.info("=" * 60)
        logger.info("=========== EXTRACTION AGENT COMPLETE (ERROR) ===========")
        logger.info("=" * 60)
        return state

    logger.info(f"[AGENT] Total documents discovered: {len(documents)}")

    old_versions = load_versions()
    new_versions = {}

    is_first_run = (len(old_versions) == 0)
    if is_first_run:
        logger.info("[AGENT] FIRST RUN → downloading ALL files.")
    else:
        logger.info(f"[AGENT] Incremental mode enabled. {len(old_versions)} files already tracked.")

    updated_docs = []
    final_files = []
    skipped_count = 0
    failed_count = 0

    logger.info(f"[AGENT] Processing {len(documents)} documents...")
    # Process all discovered documents
    for idx, (url, last_update) in enumerate(documents, 1):
        logger.info(f"[AGENT] Processing document {idx}/{len(documents)}: {os.path.basename(urlparse(url).path)}")

        # download file
        result = download_file(url, old_versions, last_update, flat_dir)
        if result is None:
            failed_count += 1
            logger.warning(f"[AGENT] Failed to process document {idx}: {url}")
            continue

        dest, file_hash, is_new, extracted = result

        new_versions[url] = file_hash

        # decide whether this file is "updated"
        if is_first_run or is_new:
            updated_docs.append(url)
            final_files.append(dest)
            final_files.extend(extracted)
            
            # Store hash and URL mapping in state for integrity verification (E4)
            state.file_hashes[dest] = file_hash
            state.url_to_file[url] = dest
            
            # Sign the hash with digital signature (prove document origin)
            try:
                signature = sign_hash(file_hash)
                signature_b64 = signature_to_base64(signature)
                state.file_signatures[dest] = signature_b64
                logger.info(f"[AGENT] Document {idx} marked as NEW/UPDATED")
                logger.info(f"[AGENT]   - Hash stored: {file_hash[:16]}...")
                logger.info(f"[AGENT]   - Digital signature created: {signature_b64[:32]}...")
            except Exception as e:
                logger.error(f"[AGENT] Failed to create digital signature: {e}")
                state.errors.append(f"Failed to sign file {dest}: {e}")
            
            # Also store hashes and signatures for extracted files from ZIPs
            for extracted_file in extracted:
                try:
                    with open(extracted_file, "rb") as f:
                        extracted_hash = compute_hash(f.read())
                    state.file_hashes[extracted_file] = extracted_hash
                    
                    # Sign extracted file hash
                    try:
                        extracted_signature = sign_hash(extracted_hash)
                        extracted_sig_b64 = signature_to_base64(extracted_signature)
                        state.file_signatures[extracted_file] = extracted_sig_b64
                        logger.info(f"[AGENT] Hash and signature stored for extracted file: {os.path.basename(extracted_file)}")
                        logger.info(f"[AGENT]   - Hash: {extracted_hash[:16]}...")
                        logger.info(f"[AGENT]   - Signature: {extracted_sig_b64[:32]}...")
                    except Exception as e:
                        logger.warning(f"[AGENT] Failed to sign extracted file {extracted_file}: {e}")
                except Exception as e:
                    logger.warning(f"[AGENT] Failed to compute hash for extracted file {extracted_file}: {e}")
        else:
            skipped_count += 1
            logger.info(f"[AGENT] Document {idx} skipped (unchanged)")

    logger.info(f"[AGENT] Processing summary: {len(updated_docs)} new/updated, {skipped_count} skipped, {failed_count} failed")

    save_versions(new_versions)

    if not updated_docs:
        logger.info("[AGENT] No new documents detected. All files are up to date.")
        logger.info("=" * 60)
        logger.info("=========== EXTRACTION AGENT COMPLETE (NO UPDATES) ===========")
        logger.info("=" * 60)
        return state

    # pipeline output
    state.current_doc = updated_docs[0]
    state.file_paths = final_files

    logger.info(f"[AGENT] Setting pipeline state:")
    logger.info(f"[AGENT]   - Current document: {state.current_doc}")
    logger.info(f"[AGENT]   - Total files ready: {len(final_files)}")
    logger.info(f"[AGENT]   - Files from ZIPs: {len(final_files) - len(updated_docs)}")
    logger.info(f"[AGENT]   - File hashes stored: {len(state.file_hashes)} (for integrity verification E4)")
    logger.info(f"[AGENT]   - Digital signatures stored: {len(state.file_signatures)} (prove document origin)")
    logger.info(f"[AGENT]   - URL mappings stored: {len(state.url_to_file)}")
    
    if state.errors:
        logger.warning(f"[AGENT] {len(state.errors)} error(s) occurred during processing")

    logger.info("=" * 60)
    logger.info("=========== EXTRACTION AGENT COMPLETE ===========")
    logger.info("=" * 60)

    return state


# ======================================================
# STANDALONE EXECUTION
# ======================================================

if __name__ == "__main__":
    """
    Permet d'exécuter l'agent directement depuis la ligne de commande.
    Usage: python extraction_agent.py
    """
    print("Demarrage de l'agent d'extraction...")
    print("=" * 60)
    
    # Initialiser l'état
    state = PipelineState(regulator="BCL")
    
    # Exécuter l'agent
    try:
        state = run_extraction_agent(state)
        
        # Afficher les résultats
        print("\n" + "=" * 60)
        print("RESULTATS")
        print("=" * 60)
        print(f"[OK] Fichiers telecharges : {len(state.file_paths)}")
        print(f"[ERREUR] Erreurs : {len(state.errors)}")
        
        if state.file_paths:
            print(f"\nFichiers prets pour traitement :")
            for i, file_path in enumerate(state.file_paths[:10], 1):  # Afficher les 10 premiers
                print(f"  {i}. {file_path}")
            if len(state.file_paths) > 10:
                print(f"  ... et {len(state.file_paths) - 10} autres fichiers")
        else:
            print("\n[INFO] Aucun nouveau fichier telecharge.")
        
        if state.errors:
            print(f"\n[ATTENTION] Erreurs rencontrees :")
            for i, error in enumerate(state.errors, 1):
                print(f"  {i}. {error}")
        
        print("\n" + "=" * 60)
        print("[OK] Execution terminee")
        print(f"[INFO] Consultez les logs : data/logs/reg_watch_{datetime.today().strftime('%Y-%m-%d')}.log")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[ERREUR FATALE] : {e}")
        import traceback
        traceback.print_exc()
        logger.error(f"Fatal error in standalone execution: {e}", exc_info=True)

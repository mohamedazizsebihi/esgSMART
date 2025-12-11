import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# =========================
# SECURITY & API CREDENTIALS
# =========================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# Groq API configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY is required in .env file")

GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_USE_TLS = os.getenv("GROQ_USE_TLS", "true").lower() == "true"
GROQ_USE_MTLS = os.getenv("GROQ_USE_MTLS", "false").lower() == "true"
GROQ_CA_CERT = os.getenv("GROQ_CA_CERT", "")
GROQ_CLIENT_CERT = os.getenv("GROQ_CLIENT_CERT", "")
GROQ_CLIENT_KEY = os.getenv("GROQ_CLIENT_KEY", "")
# Streaming pour voir le raisonnement du LLM en temps réel (debug)
GROQ_STREAM = os.getenv("GROQ_STREAM", "true").lower() == "true"

# Inter-agent communication security
AGENT_USE_TLS = os.getenv("AGENT_USE_TLS", "true").lower() == "true"
AGENT_USE_MTLS = os.getenv("AGENT_USE_MTLS", "false").lower() == "true"
AGENT_CA_CERT = os.getenv("AGENT_CA_CERT", "")
AGENT_CLIENT_CERT = os.getenv("AGENT_CLIENT_CERT", "")
AGENT_CLIENT_KEY = os.getenv("AGENT_CLIENT_KEY", "")

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET is required in .env file (use a strong random secret in production)")

# =========================
# DIRECTORIES
# =========================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOWNLOAD_DIR = os.path.join(BASE_DIR, "data", "downloads")
LOG_DIR = os.path.join(BASE_DIR, "data", "logs")
VERSIONS_FILE = os.path.join(BASE_DIR, "data", "versions.json")
TRANSLATIONS_DIR = os.path.join(BASE_DIR, "data", "translations")

# Create folders if they do not exist
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(TRANSLATIONS_DIR, exist_ok=True)

# =========================
# REGULATOR API ENDPOINTS
# =========================

API_ENDPOINTS = {
    "BCL": "https://example-bcl-api/documents",
    "ECB": "https://example-ecb-api/documents"
}

TESSERACT_PATH = r"C:/Program Files/Tesseract-OCR/tesseract.exe"

POPPLER_PATH = r"C:/poppler/Library/bin"

DOWNLOAD_DIR = "downloads"
ALLOWED_DOMAINS = ["bcl.lu"]

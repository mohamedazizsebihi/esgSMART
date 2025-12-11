from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PipelineState:
    """
    Shared state object flowing through all agents:
    - Extraction Agent adds: current_doc, pdf_path
    - Translation Agent adds: raw_text, translated_text
    - Keyword Agent adds: keyword_hits
    - Notification Agent reads: keyword_hits + current_doc
    """

    # Which regulator source is selected by the user
    regulator: str = "BCL"

    # Extracted metadata from API (list of documents returned)
    docs_metadata: List[dict] = field(default_factory=list)

    # The specific document to process (if new or updated)
    current_doc: Optional[dict] = None

    # Local path where the PDF is saved
    pdf_path: Optional[str] = None

    # Extracted text from PDF
    raw_text: str = ""

    # Translated English text
    translated_text: str = ""

    # Keywords found: {keyword: [contexts]}
    keyword_hits: Dict[str, List[str]] = field(default_factory=dict)

    # OPTIONAL FOR FUTURE: Store errors safely
    errors: List[str] = field(default_factory=list)

   # Stores all downloaded file paths (PDF, CSV, JSON, etc.) for the selected document
    file_paths: List[str] = field(default_factory=list)

    # Stores SHA-256 hashes for integrity verification: {file_path: hash}
    file_hashes: Dict[str, str] = field(default_factory=dict)

    # Stores URL to file path mapping: {url: file_path}
    url_to_file: Dict[str, str] = field(default_factory=dict)

    # Stores digital signatures: {file_path: signature_base64}
    # Signature numérique du hash pour prouver l'origine du document
    file_signatures: Dict[str, str] = field(default_factory=dict)

    # Stores translated file paths: {language: file_path}
    translated_files: Dict[str, str] = field(default_factory=dict)

    # Stores extracted text (for translation)
    extracted_text: str = ""

    # Stores summary/translation
    summary: str = ""
    
    # Stores summaries per file: {file_path: summary_text}
    file_summaries: Dict[str, str] = field(default_factory=dict)
    
    # Stores translated summaries per file and language: {file_path: {lang: translated_summary}}
    translated_summaries: Dict[str, Dict[str, str]] = field(default_factory=dict)



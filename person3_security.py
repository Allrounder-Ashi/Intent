"""
Person 3: Rules & Link Checker (Security Lead)
------------------------------------------------
- Checks SMS/text for suspicious/fake bank links
- Tracks and blocks repeat scam phone numbers
- Matches call transcripts against real RBI safety guidelines
  (semantic search if chromadb/sentence-transformers are installed,
  otherwise a simple keyword-overlap fallback so the app still runs)
"""

import re
import json
import os
from urllib.parse import urlparse

RULES_FILE = "rbi_rules.txt"
SCAM_DB_FILE = "scam_numbers.json"
CHROMA_PERSIST_DIR = "rbi_chroma_db"

# ---------------------------------------------------------------------------
# Optional heavy deps: only import/load them if explicitly enabled AND
# actually needed. This is lazy on purpose — sentence-transformers pulls in
# PyTorch, which can use 500MB-1GB+ of RAM just to load. On a small Render
# instance (512MB-1GB) that alone can exceed the memory limit and crash the
# service, especially if it loads eagerly on every worker's startup.
#
# Set ENABLE_SEMANTIC_SEARCH=true as an env var only if your instance has
# enough memory headroom (2GB+ recommended). Otherwise this safely falls
# back to a zero-dependency keyword search.
# ---------------------------------------------------------------------------
_SEMANTIC_SEARCH_ENABLED = os.environ.get("ENABLE_SEMANTIC_SEARCH", "false").lower() == "true"

_vector_db = None
_embeddings = None


def _get_vector_db(rules):
    """Lazily import + load the embedding model and vector DB, only on first use."""
    global _vector_db, _embeddings

    if _vector_db is not None:
        return _vector_db

    from langchain_community.vectorstores import Chroma
    from langchain_community.embeddings import HuggingFaceEmbeddings

    if _embeddings is None:
        _embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    if os.path.exists(CHROMA_PERSIST_DIR):
        _vector_db = Chroma(persist_directory=CHROMA_PERSIST_DIR, embedding_function=_embeddings)
    else:
        _vector_db = Chroma.from_texts(rules, _embeddings, persist_directory=CHROMA_PERSIST_DIR)
        _vector_db.persist()
    return _vector_db


def _simple_keyword_search(transcript_text, rules, k=1):
    """Fallback used when chromadb/sentence-transformers aren't installed."""
    transcript_words = set(re.findall(r"[a-z]+", transcript_text.lower()))
    scored = []
    for rule in rules:
        rule_words = set(re.findall(r"[a-z]+", rule.lower()))
        overlap = len(transcript_words & rule_words)
        scored.append((overlap, rule))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [rule for _, rule in scored[:k]]


# ---------------------------------------------------------------------------
# 1. SUSPICIOUS URL / LINK SCANNER
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "kyc", "verify", "update", "reward", "apk", "unblock",
    "login", "netbanking", "reactivate", "suspend",
]
DANGEROUS_TLDS = [".xyz", ".top", ".site", ".info", ".club", ".online"]
LINK_SHORTENERS = [
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd",
    "rebrand.ly", "shorte.st", "ow.ly",
]


def check_suspicious_urls(text):
    """Scan raw SMS/call-transcript text for links that look like bank phishing."""
    url_pattern = r"https?://[^\s]+|www\.[^\s]+"
    urls = re.findall(url_pattern, text)
    flagged_reasons = []

    for url in urls:
        full_url = url if url.startswith("http") else "http://" + url
        parsed = urlparse(full_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            flagged_reasons.append(f"Uses raw IP address instead of official bank domain: {url}")

        if any(domain.endswith(tld) for tld in DANGEROUS_TLDS):
            flagged_reasons.append(f"Uses high-risk unverified domain extension: {url}")

        if full_url.startswith("http://"):
            flagged_reasons.append(f"Insecure HTTP link (banks strictly use HTTPS): {url}")

        if any(shortener in domain for shortener in LINK_SHORTENERS):
            flagged_reasons.append(f"Uses a link-shortening service that hides the real destination: {url}")

        if ".apk" in path:
            flagged_reasons.append(f"Link points to an installable APK file, a common malware trick: {url}")

        if any(keyword in full_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            flagged_reasons.append(f"Contains phishing/urgency keyword: {url}")

    is_dangerous = len(flagged_reasons) > 0
    return {
        "is_dangerous": is_dangerous,
        "flagged_urls": urls,
        "threat_details": flagged_reasons if is_dangerous else ["Link pattern appears standard."],
    }


# ---------------------------------------------------------------------------
# 2. SCAM NUMBER TRACKER
# ---------------------------------------------------------------------------
def _load_scam_db():
    if os.path.exists(SCAM_DB_FILE):
        with open(SCAM_DB_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_scam_db(db):
    with open(SCAM_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def report_scam_number(phone_number):
    """Call this when a user reports a number as a scammer."""
    scam_db = _load_scam_db()
    scam_db[phone_number] = scam_db.get(phone_number, 0) + 1
    _save_scam_db(scam_db)
    return {"phone_number": phone_number, "total_reports": scam_db[phone_number]}


def check_scam_number(phone_number):
    """Call this to check if a number is a known repeat scammer."""
    scam_db = _load_scam_db()
    count = scam_db.get(phone_number, 0)
    return {"is_known_scammer": count > 0, "report_count": count}


# ---------------------------------------------------------------------------
# 3. RBI RULES SEARCH (RAG, with keyword fallback)
# ---------------------------------------------------------------------------
def search_rbi_rules(transcript_text, k=1):
    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(
            f"'{RULES_FILE}' not found. Add RBI guideline lines (one rule per line) first."
        )
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        rules = [line.strip() for line in f if line.strip()]

    if _SEMANTIC_SEARCH_ENABLED:
        try:
            vector_db = _get_vector_db(rules)
            matching_docs = vector_db.similarity_search(transcript_text, k=k)
            return [doc.page_content for doc in matching_docs]
        except ImportError:
            print("[person3_security] Semantic search deps not installed — using keyword fallback.")
            return _simple_keyword_search(transcript_text, rules, k=k)
    else:
        return _simple_keyword_search(transcript_text, rules, k=k)


# ---------------------------------------------------------------------------
# 4. COMBINED PERSON 3 ENTRY POINT
# ---------------------------------------------------------------------------
def run_person3_security_check(text_input, phone_number):
    return {
        "url_analysis": check_suspicious_urls(text_input),
        "phone_analysis": check_scam_number(phone_number),
        "matched_rbi_rules": search_rbi_rules(text_input),
    }


if __name__ == "__main__":
    test_text = (
        "Your bank account is suspended. Update KYC immediately at "
        "http://sbi-update.bit.ly and share OTP."
    )
    test_phone = "+919876543210"

    print(report_scam_number(test_phone))

    result = run_person3_security_check(test_text, test_phone)
    print("\nPERSON 3 OUTPUT SUCCESS:")
    print(json.dumps(result, indent=2))
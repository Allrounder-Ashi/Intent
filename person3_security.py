"""
Person 3: Threat Intelligence — Rules & Verification (Security Lead)
------------------------------------------------------------------------
- Checks SMS/text for suspicious/fake bank links
- Cross-checks suspicious identifiers (phone numbers, UPI IDs, bank
  accounts) against community-reported scam patterns
- Matches call transcripts against real RBI safety guidelines using
  trusted-rules RAG (semantic search if chromadb/sentence-transformers
  are installed, otherwise a simple keyword-overlap fallback)
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
# 2. SCAM IDENTIFIER TRACKER (phone numbers, UPI IDs, bank accounts)
# ---------------------------------------------------------------------------
UPI_ID_PATTERN = r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z]{2,64}\b"
BANK_ACCOUNT_PATTERN = r"\b\d{9,18}\b"  # typical Indian bank account number length range


def extract_identifiers(text):
    """Pull out UPI IDs and bank-account-like numbers mentioned in a message."""
    upi_ids = re.findall(UPI_ID_PATTERN, text)
    # Exclude email-like matches with common email domains, which aren't UPI handles
    common_email_domains = {"gmail", "yahoo", "outlook", "hotmail", "icloud"}
    upi_ids = [u for u in upi_ids if u.split("@")[1].split(".")[0].lower() not in common_email_domains]

    bank_accounts = re.findall(BANK_ACCOUNT_PATTERN, text)

    return {"upi_ids": upi_ids, "bank_accounts": bank_accounts}


def _load_scam_db():
    if os.path.exists(SCAM_DB_FILE):
        with open(SCAM_DB_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_scam_db(db):
    with open(SCAM_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def report_scam_identifier(identifier, identifier_type="phone"):
    """
    Call this when a user reports any suspicious identifier as a scammer —
    a phone number, a UPI ID (e.g. 'scammer@paytm'), or a bank account number.
    """
    scam_db = _load_scam_db()
    existing = scam_db.get(identifier, {"count": 0, "type": identifier_type})
    if isinstance(existing, int):  # migrate old {"phone": count} format
        existing = {"count": existing, "type": identifier_type}
    existing["count"] += 1
    existing["type"] = identifier_type
    scam_db[identifier] = existing
    _save_scam_db(scam_db)
    return {"identifier": identifier, "type": identifier_type, "total_reports": existing["count"]}


def check_scam_identifier(identifier):
    """Call this to check if any identifier (phone/UPI/account) has prior reports."""
    scam_db = _load_scam_db()
    entry = scam_db.get(identifier)
    if entry is None:
        return {"is_known_scammer": False, "report_count": 0, "type": None}
    if isinstance(entry, int):  # migrate old {"phone": count} format
        return {"is_known_scammer": entry > 0, "report_count": entry, "type": "phone"}
    return {"is_known_scammer": entry["count"] > 0, "report_count": entry["count"], "type": entry.get("type")}


def check_identifiers_in_text(text):
    """Extract every UPI ID / bank account mentioned in text and cross-check each one."""
    identifiers = extract_identifiers(text)
    results = []
    for upi in identifiers["upi_ids"]:
        check = check_scam_identifier(upi)
        results.append({"identifier": upi, "type": "upi", **check})
    for acct in identifiers["bank_accounts"]:
        check = check_scam_identifier(acct)
        results.append({"identifier": acct, "type": "bank_account", **check})
    return results


# --- Backwards-compatible phone-number wrappers (existing code keeps working) ---
def report_scam_number(phone_number):
    return report_scam_identifier(phone_number, identifier_type="phone")


def check_scam_number(phone_number):
    result = check_scam_identifier(phone_number)
    return {"is_known_scammer": result["is_known_scammer"], "report_count": result["report_count"]}


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
        "identifier_analysis": check_identifiers_in_text(text_input),
        "matched_rbi_rules": search_rbi_rules(text_input),
    }


if __name__ == "__main__":
    test_text = (
        "Your bank account is suspended. Update KYC immediately at "
        "http://sbi-update.bit.ly and share OTP. Pay processing fee to scammer@paytm."
    )
    test_phone = "+919876543210"

    print(report_scam_number(test_phone))
    print(report_scam_identifier("scammer@paytm", identifier_type="upi"))

    result = run_person3_security_check(test_text, test_phone)
    print("\nPERSON 3 OUTPUT SUCCESS:")
    print(json.dumps(result, indent=2))
"""
Person 3: Rules & Link Checker (Security Lead)
------------------------------------------------
- Checks SMS/text for suspicious/fake bank links
- Tracks and blocks repeat scam phone numbers
- Matches call transcripts against real RBI safety guidelines using a
  local vector search (RAG) over rbi_rules.txt
"""

import re
import json
import os
from urllib.parse import urlparse

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RULES_FILE = "rbi_rules.txt"
SCAM_DB_FILE = "scam_numbers.json"
CHROMA_PERSIST_DIR = "rbi_chroma_db"

print("Loading RBI Security Database...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# Build (or load) the vector DB ONCE at import time instead of on every call.
_vector_db = None


def _get_vector_db():
    """Lazily build the Chroma vector store once and reuse it, persisted to disk."""
    global _vector_db
    if _vector_db is not None:
        return _vector_db

    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(
            f"'{RULES_FILE}' not found. Add your RBI guideline lines (one rule per line) "
            f"to this file before running the security check."
        )

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        rules = [line.strip() for line in f if line.strip()]

    if os.path.exists(CHROMA_PERSIST_DIR):
        _vector_db = Chroma(
            persist_directory=CHROMA_PERSIST_DIR,
            embedding_function=embeddings,
        )
    else:
        _vector_db = Chroma.from_texts(
            rules,
            embeddings,
            persist_directory=CHROMA_PERSIST_DIR,
        )
        _vector_db.persist()

    return _vector_db


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

        # Risk 1: Raw IP address instead of a domain name
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            flagged_reasons.append(f"Uses raw IP address instead of official bank domain: {url}")

        # Risk 2: Suspicious/unverified TLD
        if any(domain.endswith(tld) for tld in DANGEROUS_TLDS):
            flagged_reasons.append(f"Uses high-risk unverified domain extension: {url}")

        # Risk 3: Unencrypted HTTP
        if full_url.startswith("http://"):
            flagged_reasons.append(f"Insecure HTTP link (banks strictly use HTTPS): {url}")

        # Risk 4: Link shorteners hiding the real destination
        if any(shortener in domain for shortener in LINK_SHORTENERS):
            flagged_reasons.append(f"Uses a link-shortening service that hides the real destination: {url}")

        # Risk 5: .apk (Android app file) being pushed via link — common malware vector
        if path.endswith(".apk") or ".apk" in path:
            flagged_reasons.append(f"Link points to an installable APK file, a common malware trick: {url}")

        # Risk 6: Phishing/urgency keywords anywhere in the URL
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
    """Public function: call this when a user reports a number as a scammer."""
    scam_db = _load_scam_db()
    scam_db[phone_number] = scam_db.get(phone_number, 0) + 1
    _save_scam_db(scam_db)
    return {"phone_number": phone_number, "total_reports": scam_db[phone_number]}


def check_scam_number(phone_number):
    """Public function: call this to check if a number is a known scammer."""
    scam_db = _load_scam_db()
    count = scam_db.get(phone_number, 0)
    return {"is_known_scammer": count > 0, "report_count": count}


# ---------------------------------------------------------------------------
# 3. RBI RULES SEARCH (RAG)
# ---------------------------------------------------------------------------
def search_rbi_rules(transcript_text, k=1):
    vector_db = _get_vector_db()
    matching_docs = vector_db.similarity_search(transcript_text, k=k)
    return [doc.page_content for doc in matching_docs]


# ---------------------------------------------------------------------------
# 4. COMBINED PERSON 3 ENTRY POINT
# ---------------------------------------------------------------------------
def run_person3_security_check(text_input, phone_number):
    return {
        "url_analysis": check_suspicious_urls(text_input),
        "phone_analysis": check_scam_number(phone_number),
        "matched_rbi_rules": search_rbi_rules(text_input),
    }


# ---------------------------------------------------------------------------
# TEST RUN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_text = (
        "Your bank account is suspended. Update KYC immediately at "
        "http://sbi-update.bit.ly and share OTP."
    )
    test_phone = "+919876543210"

    # Simulate a user reporting this number earlier
    print(report_scam_number(test_phone))

    result = run_person3_security_check(test_text, test_phone)
    print("\nPERSON 3 OUTPUT SUCCESS:")
    print(json.dumps(result, indent=2))
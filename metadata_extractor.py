"""
Extracts fraud-relevant entities from text such as:
- Call transcripts
- SMS/messages
- OCR output
"""

import re


# Indian mobile numbers:
# 10 digits beginning with 6-9, optionally prefixed by +91 / 91.
PHONE_RE = re.compile(
    r"(?:\+?91[\s-]?)?[6-9]\d{9}\b"
)

# Possible UPI IDs.
UPI_RE = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9.\-_]{1,255}@[a-zA-Z][a-zA-Z0-9]{1,63}",
    re.IGNORECASE
)

# Candidate account numbers / long numeric identifiers.
ACCOUNT_RE = re.compile(
    r"\b\d{9,18}\b"
)

# URLs.
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"]+",
    re.IGNORECASE
)

# Email addresses.
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Indian Rupee / INR amounts.
AMOUNT_RE = re.compile(
    r"(?:₹|rs\.?|inr)\s*[\d,]+(?:\.\d{1,2})?",
    re.IGNORECASE
)

# Common date formats.
DATE_RE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
    r"|"
    r"\d{4}-\d{2}-\d{2}"
    r")\b"
)


def unique(items):
    """Remove duplicates while preserving order."""
    return list(dict.fromkeys(items))


def clean_urls(urls):
    """Remove punctuation accidentally captured at the end of URLs."""
    trailing_chars = ".,!?;:)]}>\"'"

    return unique(
        url.rstrip(trailing_chars)
        for url in urls
    )


def normalize_phone(phone):
    """Return digits only for reliable comparison."""
    return re.sub(r"\D", "", phone)


def extract_metadata(text):
    """
    Extract structured entities from raw transcript, SMS,
    OCR text, or other textual evidence.
    """

    if not text:
        return {
            "phone_numbers": [],
            "upi_ids": [],
            "account_number_candidates": [],
            "urls": [],
            "emails": [],
            "amounts": [],
            "dates": []
        }

    # -------------------------
    # URLs
    # -------------------------
    urls = clean_urls(URL_RE.findall(text))

    # -------------------------
    # Emails
    # -------------------------
    emails = unique(EMAIL_RE.findall(text))

    # -------------------------
    # UPI IDs
    # -------------------------
    upi_candidates = unique(UPI_RE.findall(text))

    # Do not classify normal email addresses as UPI IDs.
    email_set = {email.lower() for email in emails}

    upi_ids = [
        upi for upi in upi_candidates
        if upi.lower() not in email_set
    ]

    # -------------------------
    # Phone numbers
    # -------------------------
    phone_numbers = unique(PHONE_RE.findall(text))

    # -------------------------
    # Amounts
    # -------------------------
    amounts = unique(AMOUNT_RE.findall(text))

    # -------------------------
    # Dates
    # -------------------------
    dates = unique(DATE_RE.findall(text))

    # -------------------------
    # Account number candidates
    # -------------------------
    account_candidates = unique(ACCOUNT_RE.findall(text))

    # Normalize phone numbers to digits for comparison.
    phone_digits = {
        normalize_phone(phone)
        for phone in phone_numbers
    }

    account_number_candidates = [
        number
        for number in account_candidates
        if number not in phone_digits
    ]

    return {
        "phone_numbers": phone_numbers,
        "upi_ids": upi_ids,
        "account_number_candidates": account_number_candidates,
        "urls": urls,
        "emails": emails,
        "amounts": amounts,
        "dates": dates
    }


if __name__ == "__main__":

    import json

    sample = (
        "Your account 123456789012 will be blocked. "
        "Pay to scammer@okhdfcbank or visit "
        "http://fake-kyc-update.bit.ly. "
        "Contact +919876543210. "
        "Amount due Rs. 25,000 by 12/09/2026."
    )

    result = extract_metadata(sample)

    print(json.dumps(result, indent=2))

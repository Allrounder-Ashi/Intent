"""
Full evidence -> verdict pipeline, chaining every teammate's module.
Backend (main.py) calls run_full_pipeline() once per citizen submission.
"""
from audio_cleaner import run_evidence_processing_pipeline
from scam_detector import run_person2_pipeline
from person3_security import run_person3_security_check, check_scam_identifier
from risk_engine import assess_risk


def run_full_pipeline(
    audio_path=None,
    image_paths=None,
    raw_text_override=None,
    sms_text=None,
    phone_number=None,
    upi_id=None,
    reported_url=None,
    email=None,
    gemini_api_key=None,
):
    # --- Person 1: Evidence Processing Engine (audio + OCR + metadata) ---
    evidence = run_evidence_processing_pipeline(
        audio_path=audio_path,
        image_paths=image_paths,
        raw_text_override=raw_text_override,
        sms_text=sms_text,
        out_path="Transcript.txt",
    )
    clean_transcript = evidence["transcript"]["clean_text"]
    ocr_text = " ".join(t for t in evidence.get("ocr_results", {}).values() if t)
    extracted_metadata = evidence["extracted_metadata"]

    # --- Person 2: AI / LLM Analysis (Gemini) -----------------------------
    text_for_ai = clean_transcript or sms_text or ocr_text or ""
    ai_analysis = run_person2_pipeline(text_for_ai, api_key=gemini_api_key)

    # --- Person 3: Rules & Knowledge Layer + Link/Entity Analysis --------
    text_for_security = sms_text or clean_transcript or ocr_text or ""
    security_check = run_person3_security_check(text_for_security, phone_number or "unknown")

    # Also directly check any identifiers the citizen typed into the form
    # fields (they may not appear verbatim inside the transcript/SMS text).
    existing_ids = {item["identifier"] for item in security_check.get("identifier_analysis", [])}
    for identifier, itype in [(upi_id, "upi"), (reported_url, "url"), (email, "email")]:
        if not identifier or identifier in existing_ids:
            continue
        check = check_scam_identifier(identifier)
        if check["report_count"] > 0:
            security_check.setdefault("identifier_analysis", []).append(
                {"identifier": identifier, "type": check.get("type") or itype,
                 "is_known_scammer": check["is_known_scammer"], "report_count": check["report_count"]}
            )

    # --- Person 4: Risk Assessment & Decision Engine ----------------------
    risk = assess_risk(ai_analysis, security_check, extracted_metadata)

    return {
        "transcript": evidence["transcript"],
        "ocr_text": ocr_text,
        "extracted_metadata": extracted_metadata,
        "ai_analysis": ai_analysis,
        "security_check": security_check,
        "risk_assessment": risk,
    }

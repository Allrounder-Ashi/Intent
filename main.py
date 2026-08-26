"""
Person 4: Code Integrator & File Generator (Packaging Lead)
--------------------------------------------------------------
- Runs Person 1's audio cleaner, Person 2's Gemini scam detector,
  and Person 3's security/rules checker in sequence
- Formats the combined result into Submission.json
- (Run package_submission.py separately to write the README and zip everything)
"""
import json
import datetime
import os

from audio_cleaner import run_person1_pipeline
from scam_detector import run_person2_pipeline
from person3_security import run_person3_security_check, report_scam_number


def build_submission_json(clean_transcript, person2_result, person3_result, caller_phone, sms_text):
    is_scam = bool(
        person2_result.get("is_likely_scam")
        or person3_result.get("url_analysis", {}).get("is_dangerous")
        or person3_result.get("phone_analysis", {}).get("is_known_scammer")
    )

    return {
        "call_metadata": {
            "caller_phone_number": caller_phone,
            "analysis_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "transcript": {
            "clean_text": clean_transcript,
        },
        "ai_analysis": {
            "translated_text": person2_result.get("translated_text"),
            "is_likely_scam": person2_result.get("is_likely_scam"),
            "risk_level": person2_result.get("risk_level"),
            "scam_signals_found": person2_result.get("scam_signals_found"),
            "user_warning_message": person2_result.get("user_warning_message"),
        },
        "security_check": {
            "sms_text_analyzed": sms_text,
            "url_analysis": person3_result.get("url_analysis"),
            "phone_analysis": person3_result.get("phone_analysis"),
            "matched_rbi_rules": person3_result.get("matched_rbi_rules"),
        },
        "final_verdict": {
            "is_scam": is_scam,
        },
    }


def run_pipeline(
    audio_path=None,
    raw_transcript_override=None,
    sms_text=None,
    caller_phone="unknown",
    gemini_api_key=None,
    out_dir=".",
):
    print("=== STEP 1: Person 1 — Audio & Text Cleaner ===")
    clean_transcript = run_person1_pipeline(
        audio_path=audio_path,
        raw_text_override=raw_transcript_override,
        out_path=os.path.join(out_dir, "Transcript.txt"),
    )

    print("\n=== STEP 2: Person 2 — AI Scam Detector (Gemini) ===")
    person2_result = run_person2_pipeline(clean_transcript, api_key=gemini_api_key)

    print("\n=== STEP 3: Person 3 — Rules & Link Checker ===")
    text_to_scan = sms_text if sms_text else clean_transcript
    person3_result = run_person3_security_check(text_to_scan, caller_phone)

    print("\n=== STEP 4: Person 4 — Build Submission.json ===")
    submission = build_submission_json(
        clean_transcript, person2_result, person3_result, caller_phone, text_to_scan
    )

    out_path = os.path.join(out_dir, "Submission.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(submission, f, indent=2)
    print(f"Submission written to {out_path}")

    return submission


if __name__ == "__main__":
    # DEMO MODE: uses sample call text + sample SMS instead of a real
    # audio file / live Gemini key, so the whole pipeline runs end-to-end
    # with zero external setup. Swap these for real inputs later.
    sample_call_text = (
        "Hello Sir, This is SBI Bank calling! Your A/C 1234 will be BLOCKED in 2 hours. "
        "Please share the OTP 872910 immediately to avoid suspension."
    )
    sample_sms = (
        "Dear customer your KYC is pending update immediately at "
        "http://sbi-kyc-update.bit.ly or account will be suspended"
    )
    sample_phone = "+919876543210"

    # Simulate a prior report on this number
    report_scam_number(sample_phone)

    result = run_pipeline(
        raw_transcript_override=sample_call_text,
        sms_text=sample_sms,
        caller_phone=sample_phone,
    )

    print("\n=== FINAL SUBMISSION.JSON ===")
    print(json.dumps(result, indent=2))
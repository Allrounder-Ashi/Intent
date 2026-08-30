"""
Person 2: AI Scam Detector (Brain Lead)
-----------------------------------------
- Sends the call transcript to Gemini
- Asks it to translate to English if needed, classify the scam type,
  spot the manipulation tactics being used, flag scam signals
  (OTP requests, fake KYC-block threats, bank impersonation, etc.)
- Gets back a risk level, a short summary, and a simple warning for the user
"""

import os
import json

GEMINI_PROMPT_TEMPLATE = """You are a fraud detection assistant analyzing a phone call transcript for an Indian cyber-fraud reporting platform.

The transcript may be in Hindi, English, or a mix (Hinglish). If it is not in English, translate it to English first.

Call transcript:
\"\"\"{transcript}\"\"\"

Do the following:
1. Decide the scam type. Pick the closest match from: "Bank/KYC Impersonation", "OTP/UPI Fraud", "Digital Arrest / Police Impersonation", "Lottery or Prize Scam", "Job Scam", "Investment or Stock Tip Scam", "Loan App Scam", "Romance Scam", "Tech Support Scam", "Not a Scam", "Other".
2. List the manipulation tactics used (e.g. urgency/time pressure, fear of arrest or account loss, fake authority/impersonation, greed/reward, isolation from family, requesting remote access).
3. List the specific scam signals found in the text (quote or paraphrase the exact red flag).
4. Give a risk level: "low", "medium", or "high".
5. Give a confidence score from 0-100 for how sure you are this is a scam.
6. Write a one to two sentence plain-English summary of what happened in this call.
7. Write a short, simple 1-3 sentence warning message for the user, telling them what to do.

Respond ONLY with valid JSON in exactly this structure, no markdown, no extra text:
{{
  "translated_text": "<english translation if needed, else original>",
  "is_likely_scam": true or false,
  "scam_type": "<one of the categories above>",
  "risk_level": "low" or "medium" or "high",
  "confidence_score": 0-100,
  "tactics_used": ["tactic 1", "tactic 2"],
  "scam_signals_found": ["signal 1", "signal 2"],
  "summary": "<1-2 sentence summary of the call>",
  "user_warning_message": "<short, simple 1-3 sentence warning for the user>"
}}
"""

# Keyword groups used only by the offline fallback below.
BANK_WORDS = ["bank", "kyc", "account", "debit card", "credit card", "net banking"]
OTP_WORDS = ["otp", "one time password", "pin", "cvv"]
ARREST_WORDS = ["arrest", "police", "cbi", "court", "warrant", "customs", "parcel"]
LOTTERY_WORDS = ["lottery", "prize", "winner", "lucky draw", "cashback", "reward"]
JOB_WORDS = ["job offer", "work from home", "part time job", "salary", "recruiter"]
INVESTMENT_WORDS = ["invest", "stock tip", "guaranteed return", "trading", "profit double"]
LOAN_WORDS = ["loan approved", "instant loan", "loan app", "processing fee"]
URGENCY_WORDS = ["immediately", "urgent", "hurry", "within", "hours", "right now", "block", "suspend"]
REMOTE_APP_WORDS = ["anydesk", "teamviewer", "remote access", "screen share"]


def _classify_scam_type(lower_text):
    if any(w in lower_text for w in ARREST_WORDS):
        return "Digital Arrest / Police Impersonation"
    if any(w in lower_text for w in OTP_WORDS):
        return "OTP/UPI Fraud"
    if any(w in lower_text for w in LOTTERY_WORDS):
        return "Lottery or Prize Scam"
    if any(w in lower_text for w in INVESTMENT_WORDS):
        return "Investment or Stock Tip Scam"
    if any(w in lower_text for w in LOAN_WORDS):
        return "Loan App Scam"
    if any(w in lower_text for w in JOB_WORDS):
        return "Job Scam"
    if any(w in lower_text for w in BANK_WORDS):
        return "Bank/KYC Impersonation"
    return "Other"


def _detect_tactics(lower_text):
    tactics = []
    if any(w in lower_text for w in URGENCY_WORDS):
        tactics.append("Urgency / time pressure")
    if any(w in lower_text for w in ARREST_WORDS):
        tactics.append("Fear of arrest or legal action")
    if any(w in lower_text for w in BANK_WORDS + ["rbi", "government", "officer"]):
        tactics.append("Impersonation of a trusted authority")
    if any(w in lower_text for w in LOTTERY_WORDS):
        tactics.append("Greed / promise of reward")
    if any(w in lower_text for w in REMOTE_APP_WORDS):
        tactics.append("Requesting remote access to device")
    if any(w in lower_text for w in OTP_WORDS):
        tactics.append("Requesting sensitive banking details")
    return tactics


def _mock_gemini_response(transcript):
    """
    Local fallback analyzer so the pipeline still runs end-to-end
    without a live Gemini API key (useful for demos/testing).
    """
    lower = transcript.lower()

    signals = []
    if "otp" in lower or "pin" in lower or "cvv" in lower:
        signals.append("Caller asked for OTP/PIN/CVV")
    if "block" in lower or "suspend" in lower:
        signals.append("Threatened account blocking/suspension")
    if "bank" in lower:
        signals.append("Claims to be calling from a bank")
    if "kyc" in lower:
        signals.append("Mentions KYC update/verification")
    if any(w in lower for w in ARREST_WORDS):
        signals.append("Threatens arrest or legal action")
    if any(w in lower for w in LOTTERY_WORDS):
        signals.append("Claims the user has won a prize/lottery")
    if any(w in lower for w in REMOTE_APP_WORDS):
        signals.append("Asks user to install a remote-access app")

    is_scam = len(signals) > 0
    scam_type = _classify_scam_type(lower) if is_scam else "Not a Scam"
    tactics = _detect_tactics(lower)
    confidence = min(95, 40 + 15 * len(signals)) if is_scam else 15

    if is_scam:
        summary = f"This call matches a {scam_type} pattern, using {len(tactics)} manipulation tactic(s) to pressure the user."
        warning = (
            "This call shows signs of a scam. Never share your OTP, PIN, card details, "
            "or install any remote-access app on a call. Hang up and contact your bank "
            "or the police directly using an official number."
        )
        risk = "high" if len(signals) >= 2 else "medium"
    else:
        summary = "No strong scam pattern was detected in this transcript."
        warning = "No strong scam indicators found, but stay cautious with unexpected calls."
        risk = "low"

    return {
        "translated_text": transcript,
        "is_likely_scam": is_scam,
        "scam_type": scam_type,
        "risk_level": risk,
        "confidence_score": confidence,
        "tactics_used": tactics if tactics else ["None detected"],
        "scam_signals_found": signals if signals else ["No obvious signals detected"],
        "summary": summary,
        "user_warning_message": warning,
    }


def analyze_transcript_with_gemini(transcript, api_key=None):
    """
    Send the transcript to Gemini for scam analysis.
    Requires: pip install google-generativeai
    Requires: GEMINI_API_KEY environment variable (or pass api_key directly).
    Falls back to a local mock analyzer if the package or key isn't available.
    """
    api_key = api_key or os.environ.get("GEMINI_API_KEY")

    if not api_key:
        print("[scam_detector] No GEMINI_API_KEY set — using mock analyzer for demo.")
        return _mock_gemini_response(transcript)

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        prompt = GEMINI_PROMPT_TEMPLATE.format(transcript=transcript)
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        raw_text = response.text.strip().replace("```json", "").replace("```", "").strip()
        result = json.loads(raw_text)

        # safety net in case Gemini skips a field on some call
        result.setdefault("scam_type", "Other")
        result.setdefault("tactics_used", [])
        result.setdefault("confidence_score", 50)
        result.setdefault("summary", "")

        print("[scam_detector] Used real Gemini API for this analysis.")
        return result

    except ImportError:
        print("[scam_detector] google-generativeai not installed — using mock analyzer.")
        return _mock_gemini_response(transcript)
    except Exception as e:
        print(f"[scam_detector] Gemini call failed ({e}) — using mock analyzer.")
        return _mock_gemini_response(transcript)


def run_person2_pipeline(transcript, api_key=None):
    return analyze_transcript_with_gemini(transcript, api_key=api_key)


if __name__ == "__main__":
    sample = (
        "hello sir this is sbi bank calling your account will be blocked in "
        "two hours please share the otp immediately"
    )
    result = run_person2_pipeline(sample)
    print(json.dumps(result, indent=2))

    sample2 = (
        "congratulations you have won a lucky draw prize of 25 lakh rupees "
        "to claim your reward please pay a processing fee immediately"
    )
    result2 = run_person2_pipeline(sample2)
    print(json.dumps(result2, indent=2))

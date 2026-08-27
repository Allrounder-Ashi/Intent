"""
Person 2: AI Scam Detector (Brain Lead)
-----------------------------------------
- Sends the call transcript to Gemini
- Asks it to translate to English if needed, and flag scam signals
  (OTP requests, fake KYC-block threats, bank impersonation, etc.)
- Gets back a short, simple warning message for the user
"""
import os
import json

GEMINI_PROMPT_TEMPLATE = """You are a bank-fraud detection assistant analyzing a phone call transcript.

The transcript may be in Hindi, English, or a mix (Hinglish). If it is not in English, translate it to English first.

Call transcript:
\"\"\"{transcript}\"\"\"

Analyze the transcript for common scam signals, including:
- Requests for OTP, PIN, CVV, or full card number
- Claims that a bank account or KYC will be blocked/suspended urgently
- Impersonation of a bank, RBI, police, or government official
- Requests to install remote access apps (AnyDesk, TeamViewer, etc.)
- Any high-pressure or threatening language

Respond ONLY with valid JSON in exactly this structure, no markdown, no extra text:
{{
  "translated_text": "<english translation if needed, else original>",
  "is_likely_scam": true or false,
  "risk_level": "low" or "medium" or "high",
  "scam_signals_found": ["signal 1", "signal 2"],
  "user_warning_message": "<short, simple 1-3 sentence warning for the user>"
}}
"""


def _mock_gemini_response(transcript):
    """
    Local fallback analyzer so the pipeline still runs end-to-end
    without a live Gemini API key (useful for demos/testing).
    """
    lower = transcript.lower()
    signals = []
    if "otp" in lower:
        signals.append("Caller asked for OTP")
    if "block" in lower or "suspend" in lower:
        signals.append("Threatened account blocking/suspension")
    if "bank" in lower:
        signals.append("Claims to be calling from a bank")
    if "kyc" in lower:
        signals.append("Mentions KYC update/verification")

    is_scam = len(signals) > 0
    return {
        "translated_text": transcript,
        "is_likely_scam": is_scam,
        "risk_level": "high" if is_scam else "low",
        "scam_signals_found": signals if signals else ["No obvious signals detected"],
        "user_warning_message": (
            "This call shows signs of a bank scam. Never share your OTP, PIN, or card "
            "details over the phone. Hang up and call your bank directly using the "
            "number on your card."
            if is_scam
            else "No strong scam indicators found, but stay cautious with unexpected bank calls."
        ),
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
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = GEMINI_PROMPT_TEMPLATE.format(transcript=transcript)
        response = model.generate_content(prompt)
        raw_text = response.text.strip().replace("```json", "").replace("```", "").strip()
        return json.loads(raw_text)
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
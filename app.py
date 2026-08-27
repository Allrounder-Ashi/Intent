"""
Streamlit front-end for the AI Financial Fraud & Phishing Detection System.
Wires together:
  Person 1 - audio_cleaner.py   (Whisper transcription + text cleaning)
  Person 2 - scam_detector.py   (Gemini scam analysis)
  Person 3 - person3_security.py (RBI RAG rules + link scanner + scam-number tracker)
"""
import json
import os
import tempfile

import streamlit as st

from audio_cleaner import transcribe_audio, clean_text, save_transcript
from scam_detector import run_person2_pipeline
from person3_security import (
    run_person3_security_check,
    report_scam_number,
    check_scam_number,
)

st.set_page_config(page_title="Fraud & Phishing Detector", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Financial Fraud & Phishing Detection System")
st.caption(
    "Retrieval-Augmented Generation over RBI guidelines + Gemini scam analysis "
    "+ phishing-link and scam-number detection."
)

tab_analyze, tab_report, tab_about = st.tabs(["🔍 Analyze", "🚩 Report a Scam Number", "ℹ️ About"])

# ---------------------------------------------------------------------------
# TAB 1: Analyze a call / SMS
# ---------------------------------------------------------------------------
with tab_analyze:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Call input")
        input_mode = st.radio("How are you providing the call?", ["Upload audio", "Paste transcript text"])

        raw_call_text = None
        if input_mode == "Upload audio":
            audio_file = st.file_uploader("Upload a call recording", type=["mp3", "wav", "m4a", "ogg"])
            if audio_file is not None:
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(audio_file.name)[1]) as tmp:
                    tmp.write(audio_file.read())
                    tmp_path = tmp.name
                with st.spinner("Transcribing audio with Whisper... (first run downloads the model)"):
                    raw_call_text = transcribe_audio(tmp_path)
                os.unlink(tmp_path)
                if raw_call_text:
                    st.text_area("Raw transcript", raw_call_text, height=100, disabled=True)
        else:
            raw_call_text = st.text_area(
                "Paste the call transcript",
                placeholder="e.g. Hello sir, this is SBI bank calling, your account will be blocked...",
                height=150,
            )

    with col2:
        st.subheader("SMS / link input (optional)")
        sms_text = st.text_area(
            "Paste an SMS the caller sent, if any",
            placeholder="e.g. Dear customer your KYC is pending, update at http://sbi-update.bit.ly",
            height=150,
        )
        phone_number = st.text_input("Caller's phone number", placeholder="+91XXXXXXXXXX")

    run_button = st.button("🔎 Run full analysis", type="primary", use_container_width=True)

    if run_button:
        if not raw_call_text and not sms_text:
            st.warning("Please provide a call transcript/audio or an SMS to analyze.")
        else:
            with st.spinner("Running analysis..."):
                # Person 1: clean the transcript
                clean_transcript = ""
                if raw_call_text:
                    clean_transcript = clean_text(raw_call_text)
                    save_transcript(clean_transcript, "Transcript.txt")

                # Person 2: Gemini scam analysis (runs on whichever text we have)
                text_for_gemini = clean_transcript if clean_transcript else sms_text
                person2_result = run_person2_pipeline(text_for_gemini)

                # Person 3: link scan + scam-number check + RBI rule match
                text_for_security = sms_text if sms_text else clean_transcript
                person3_result = run_person3_security_check(text_for_security, phone_number or "unknown")

            is_scam = bool(
                person2_result.get("is_likely_scam")
                or person3_result["url_analysis"]["is_dangerous"]
                or person3_result["phone_analysis"]["is_known_scammer"]
            )

            st.divider()
            if is_scam:
                st.error("⚠️ **This looks like a SCAM.** " + person2_result.get("user_warning_message", ""))
            else:
                st.success("✅ No strong scam indicators found. " + person2_result.get("user_warning_message", ""))

            c1, c2, c3 = st.columns(3)
            c1.metric("Risk level", person2_result.get("risk_level", "unknown").upper())
            c2.metric("Dangerous links found", "Yes" if person3_result["url_analysis"]["is_dangerous"] else "No")
            c3.metric(
                "Known scam number",
                f"Yes ({person3_result['phone_analysis']['report_count']} reports)"
                if person3_result["phone_analysis"]["is_known_scammer"]
                else "No",
            )

            with st.expander("🧠 Gemini scam analysis"):
                st.json(person2_result)

            with st.expander("🔗 Link scan details"):
                st.json(person3_result["url_analysis"])

            with st.expander("📜 Matched RBI guidelines"):
                for rule in person3_result["matched_rbi_rules"]:
                    st.write("• " + rule)

            submission = {
                "call_metadata": {"caller_phone_number": phone_number or "unknown"},
                "transcript": {"clean_text": clean_transcript},
                "ai_analysis": person2_result,
                "security_check": {
                    "sms_text_analyzed": text_for_security,
                    "url_analysis": person3_result["url_analysis"],
                    "phone_analysis": person3_result["phone_analysis"],
                    "matched_rbi_rules": person3_result["matched_rbi_rules"],
                },
                "final_verdict": {"is_scam": is_scam},
            }

            st.download_button(
                "⬇️ Download full result as JSON",
                data=json.dumps(submission, indent=2),
                file_name="Submission.json",
                mime="application/json",
            )

# ---------------------------------------------------------------------------
# TAB 2: Report a scam number
# ---------------------------------------------------------------------------
with tab_report:
    st.subheader("Report a phone number as a scammer")
    report_number = st.text_input("Phone number to report", placeholder="+91XXXXXXXXXX", key="report_input")

    colr1, colr2 = st.columns(2)
    with colr1:
        if st.button("🚩 Report this number", use_container_width=True):
            if report_number:
                result = report_scam_number(report_number)
                st.success(f"Reported {result['phone_number']}. Total reports: {result['total_reports']}")
            else:
                st.warning("Enter a phone number first.")
    with colr2:
        if st.button("🔍 Check this number", use_container_width=True):
            if report_number:
                result = check_scam_number(report_number)
                if result["is_known_scammer"]:
                    st.error(f"⚠️ Known scam number — reported {result['report_count']} time(s).")
                else:
                    st.info("No reports found for this number yet.")
            else:
                st.warning("Enter a phone number first.")

# ---------------------------------------------------------------------------
# TAB 3: About
# ---------------------------------------------------------------------------
with tab_about:
    st.markdown(
        """
        ### How it works
        1. **Audio & Text Cleaner** — transcribes call recordings with Whisper and
           normalizes the text (lowercase, punctuation/numbers stripped).
        2. **AI Scam Detector** — sends the transcript to Gemini, which translates
           non-English text, flags scam signals (OTP requests, fake KYC threats,
           bank impersonation), and writes a plain-language warning.
        3. **Rules & Link Checker** — scans any links for phishing patterns
           (raw IPs, risky TLDs, link shorteners, `.apk` files, urgency keywords),
           checks the caller's number against previously reported scam numbers,
           and retrieves the most relevant official RBI safety guideline using
           a local ChromaDB vector store with HuggingFace sentence embeddings.

        ### Notes
        - Semantic RBI rule matching requires `ENABLE_SEMANTIC_SEARCH=true` to be
          set as a Space variable; otherwise a lightweight keyword-match fallback
          is used.
        - Set `GEMINI_API_KEY` as a Space **secret** for live Gemini analysis;
          without it, a local mock analyzer is used so the app still runs.
        """
    )
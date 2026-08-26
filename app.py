import streamlit as st
import json
import os

from main import run_pipeline


st.set_page_config(
    page_title="Bank Scam Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Bank Scam Detector")
st.write(
    "Check suspicious bank calls and messages using AI + security rules."
)

st.divider()

# -----------------------------
# INPUTS
# -----------------------------

st.subheader("📞 Call Information")

caller_phone = st.text_input(
    "Caller phone number",
    placeholder="+91XXXXXXXXXX"
)

call_transcript = st.text_area(
    "Call transcript",
    height=180,
    placeholder=(
        "Example: Hello sir, this is SBI bank calling. "
        "Your account will be blocked. Please share your OTP."
    )
)

st.subheader("💬 SMS / Message")

sms_text = st.text_area(
    "Paste the SMS or message here",
    height=130,
    placeholder=(
        "Example: Your KYC is pending. Update immediately at "
        "http://example.com"
    )
)

st.divider()

# -----------------------------
# ANALYZE
# -----------------------------

if st.button("🔍 Analyze", use_container_width=True):

    if not call_transcript.strip() and not sms_text.strip():
        st.warning("Please enter a call transcript or SMS.")
        st.stop()

    with st.spinner("Analyzing..."):

        try:
            result = run_pipeline(
                raw_transcript_override=call_transcript,
                sms_text=sms_text,
                caller_phone=caller_phone or "unknown",
                gemini_api_key=os.environ.get("GEMINI_API_KEY")
            )

            st.success("Analysis completed!")

            # -----------------------------
            # FINAL VERDICT
            # -----------------------------

            final_verdict = result.get("final_verdict", {})
            ai_analysis = result.get("ai_analysis", {})
            security = result.get("security_check", {})

            is_scam = final_verdict.get("is_scam", False)

            if is_scam:
                st.error("🚨 SCAM DETECTED")
            else:
                st.success("✅ No obvious scam detected")

            # -----------------------------
            # RISK
            # -----------------------------

            risk = ai_analysis.get("risk_level", "unknown")

            st.metric(
                "Risk Level",
                str(risk).upper()
            )

            # -----------------------------
            # AI ANALYSIS
            # -----------------------------

            st.subheader("🤖 AI Analysis")

            translated = ai_analysis.get("translated_text")

            if translated:
                st.write("**Analyzed text:**")
                st.write(translated)

            signals = ai_analysis.get("scam_signals_found", [])

            if signals:
                st.write("**Scam signals:**")

                for signal in signals:
                    st.write(f"• {signal}")

            warning = ai_analysis.get("user_warning_message")

            if warning:
                st.warning(warning)

            # -----------------------------
            # LINK CHECK
            # -----------------------------

            st.subheader("🔗 Link Security")

            url_analysis = security.get("url_analysis", {})

            if url_analysis.get("is_dangerous"):
                st.error("⚠️ Suspicious link detected")

                for reason in url_analysis.get(
                    "threat_details", []
                ):
                    st.write(f"• {reason}")

            else:
                st.success("No suspicious link pattern detected.")

            # -----------------------------
            # PHONE CHECK
            # -----------------------------

            st.subheader("📱 Phone Number Check")

            phone_analysis = security.get(
                "phone_analysis", {}
            )

            if phone_analysis.get("is_known_scammer"):
                st.error(
                    f"Known scam number. "
                    f"Reports: {phone_analysis.get('report_count', 0)}"
                )
            else:
                st.success("Number is not currently in the local scam database.")

            # -----------------------------
            # RBI RULE
            # -----------------------------

            st.subheader("🏦 RBI Safety Rule")

            rules = security.get(
                "matched_rbi_rules", []
            )

            if rules:
                for rule in rules:
                    st.info(rule)
            else:
                st.write("No matching RBI rule found.")

            # -----------------------------
            # DOWNLOAD RESULT
            # -----------------------------

            st.divider()

            st.subheader("📄 Full Analysis")

            st.download_button(
                "Download Analysis JSON",
                data=json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False
                ),
                file_name="Submission.json",
                mime="application/json"
            )

        except Exception as e:

            st.error("Something went wrong.")

            st.code(str(e))
"""
Streamlit front-end for the AI Financial Fraud & Phishing Detection System.
------------------------------------------------------------------------------
This is the full ProtectX platform (Person 4's part) in a single Streamlit
app — it has the same feature set as the standalone HTML/JS frontend
(frontend/index.html + frontend/agency.html + frontend/app.js), but talks
directly to the Python backend instead of over HTTP, so you only ever run:

    streamlit run app.py

Wires together:
  Person 1 - audio_cleaner.py / ocr_processor.py / metadata_extractor.py
             (Whisper transcription, OCR, entity extraction)
  Person 2 - scam_detector.py    (Gemini scam analysis)
  Person 3 - person3_security.py (RBI RAG rules, link scanner, identifier DB)
  Person 4 - pipeline.py / risk_engine.py / database.py  (this file)

Pages:
  🙋 Citizen Portal   -> Search past reports · Report & upload evidence · Results
  🏛️ Agency Dashboard -> Login · Overview stats · Case management · Investigate · Export
"""
import csv
import datetime
import io
import json
import os
import shutil
import tempfile

import streamlit as st
from sqlalchemy import or_

from database import init_db, SessionLocal, Report, ReportedIdentifier, AuditLog, ReportStatus
from pipeline import run_full_pipeline
from person3_security import check_scam_identifier

AGENCY_ACCESS_CODE = os.environ.get("AGENCY_ACCESS_CODE", "changeme-demo-key")

st.set_page_config(page_title="ProtectX — Check & Report Fraud", page_icon="🛡️", layout="wide")
init_db()

# ---------------------------------------------------------------------------
# Styling — same white/blue ProtectX look as frontend/style.css
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    :root {
        --px-blue: #1d4ed8;
        --px-purple: #7c3aed;
        --px-green: #16a34a;
        --px-amber: #d97706;
        --px-red: #dc2626;
        --px-border: #e2e6ef;
        --px-muted: #6b7280;
    }
    .px-topbar {
        background: var(--px-blue);
        color: white;
        padding: 20px 24px;
        border-radius: 12px;
        margin-bottom: 20px;
    }
    .px-topbar.agency { background: var(--px-purple); }
    .px-topbar h1 { margin: 0 0 4px 0; font-size: 26px; }
    .px-topbar p { margin: 0; opacity: 0.9; font-size: 14px; }

    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid var(--px-border);
        border-radius: 10px;
        padding: 10px;
    }
    .stButton>button, .stDownloadButton>button, .stFormSubmitButton>button {
        background: var(--px-blue) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
    }
    .stButton>button:hover, .stDownloadButton>button:hover { opacity: 0.92; }

    .px-card {
        background: #ffffff;
        border: 1px solid var(--px-border);
        border-radius: 12px;
        padding: 18px 22px;
        margin-bottom: 18px;
    }
    .px-muted { color: var(--px-muted); font-size: 14px; }
    .risk-badge {
        display: inline-block; padding: 3px 12px; border-radius: 999px;
        font-size: 12px; font-weight: 700; color: white;
    }
    .risk-high { background: var(--px-red); }
    .risk-medium { background: var(--px-amber); }
    .risk-low { background: var(--px-green); }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
st.session_state.setdefault("agency_logged_in", False)
st.session_state.setdefault("search_result", None)
st.session_state.setdefault("last_report_result", None)
st.session_state.setdefault("selected_case_id", None)

RISK_COLOR = {"high": "#dc2626", "medium": "#d97706", "low": "#16a34a"}


def risk_badge(label):
    if not label:
        return ""
    label = str(label).lower()
    color = RISK_COLOR.get(label, "#6b7280")
    return (
        f'<span class="risk-badge" style="background:{color};">'
        f"{label.upper()}</span>"
    )


# ---------------------------------------------------------------------------
# Shared DB helpers (same logic as main.py's FastAPI endpoints, called
# directly instead of over HTTP so the Streamlit app is fully standalone)
# ---------------------------------------------------------------------------
def upsert_identifier(db, identifier, identifier_type, risk_label):
    if not identifier:
        return
    row = db.query(ReportedIdentifier).filter_by(identifier=identifier).first()
    rank = {"low": 0, "medium": 1, "high": 2}
    if row:
        row.report_count += 1
        if rank.get(risk_label, 0) > rank.get(row.max_risk_label, 0):
            row.max_risk_label = risk_label
        row.last_reported_at = datetime.datetime.utcnow()
    else:
        db.add(
            ReportedIdentifier(
                identifier=identifier, identifier_type=identifier_type,
                report_count=1, max_risk_label=risk_label,
            )
        )


def do_search(query):
    """Mirrors GET /api/search."""
    query = (query or "").strip()
    if not query:
        return None
    with SessionLocal() as db:
        row = db.query(ReportedIdentifier).filter(ReportedIdentifier.identifier == query).first()
        matching_reports = (
            db.query(Report)
            .filter(
                or_(
                    Report.phone_number == query,
                    Report.upi_id == query,
                    Report.reported_url == query,
                    Report.email == query,
                )
            )
            .order_by(Report.created_at.desc())
            .limit(10)
            .all()
        )
        db.add(AuditLog(actor="citizen", action="search", detail=query))
        db.commit()

        if not row and not matching_reports:
            return {"found": False, "query": query}

        return {
            "found": True,
            "query": query,
            "report_count": row.report_count if row else len(matching_reports),
            "max_risk_label": row.max_risk_label if row else None,
            "recent_reports": [
                {"id": r.id, "created_at": r.created_at, "risk_label": r.risk_label, "risk_score": r.risk_score}
                for r in matching_reports
            ],
        }


def submit_report(
    phone_number, upi_id, reported_url, email,
    call_transcript_text, sms_text, other_details,
    audio_file, screenshot_files,
):
    """Mirrors POST /api/report — runs the full Person1->2->3->4 pipeline
    and stores the resulting case in the shared database."""
    tmp_dir = tempfile.mkdtemp(prefix="protectx_")
    audio_path = None
    image_paths = []
    try:
        if audio_file is not None:
            audio_path = os.path.join(tmp_dir, audio_file.name)
            with open(audio_path, "wb") as f:
                f.write(audio_file.getbuffer())

        for img in screenshot_files or []:
            img_path = os.path.join(tmp_dir, img.name)
            with open(img_path, "wb") as f:
                f.write(img.getbuffer())
            image_paths.append(img_path)

        result = run_full_pipeline(
            audio_path=audio_path,
            image_paths=image_paths or None,
            raw_text_override=call_transcript_text or None,
            sms_text=sms_text or None,
            phone_number=phone_number or None,
            upi_id=upi_id or None,
            reported_url=reported_url or None,
            email=email or None,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    risk = result["risk_assessment"]

    with SessionLocal() as db:
        report = Report(
            phone_number=phone_number or None,
            upi_id=upi_id or None,
            reported_url=reported_url or None,
            email=email or None,
            transcript_text=result["transcript"]["clean_text"],
            sms_text=sms_text or None,
            ocr_text=result["ocr_text"],
            other_details=other_details or None,
            extracted_metadata_json=json.dumps(result["extracted_metadata"]),
            ai_analysis_json=json.dumps(result["ai_analysis"]),
            security_check_json=json.dumps(result["security_check"]),
            risk_score=risk["risk_score"],
            risk_label=risk["risk_label"],
            risk_confidence=risk["confidence"],
            risk_reasoning_json=json.dumps(risk["reasoning"]),
            is_scam=risk["is_scam"],
            status=ReportStatus.new,
        )
        db.add(report)
        db.flush()

        for identifier, itype in [
            (phone_number, "phone"), (upi_id, "upi"),
            (reported_url, "url"), (email, "email"),
        ]:
            upsert_identifier(db, identifier, itype, risk["risk_label"])

        db.add(AuditLog(actor="citizen", action="report_submitted", report_id=report.id))
        db.commit()
        report_id = report.id

    return {
        "report_id": report_id,
        "risk_label": risk["risk_label"],
        "risk_score": risk["risk_score"],
        "confidence": risk["confidence"],
        "is_scam": risk["is_scam"],
        "reasoning": risk["reasoning"],
        "scam_type": result["ai_analysis"].get("scam_type"),
        "tactics_used": result["ai_analysis"].get("tactics_used"),
        "ai_analysis": result["ai_analysis"],
        "security_check": result["security_check"],
        "extracted_metadata": result["extracted_metadata"],
    }


def infer_case_type(r):
    parts = []
    if r.transcript_text:
        parts.append("Call")
    if r.ocr_text:
        parts.append("Screenshot")
    if r.sms_text:
        parts.append("SMS")
    if r.upi_id:
        parts.append("UPI")
    if r.reported_url and not parts:
        parts.append("URL check")
    return " + ".join(parts[:2]) if parts else "Report"


def get_stats(db):
    total = db.query(Report).count()
    high_risk = db.query(Report).filter(Report.risk_label == "high").count()
    new = db.query(Report).filter(Report.status == ReportStatus.new).count()
    resolved = db.query(Report).filter(Report.status == ReportStatus.resolved).count()
    week_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    resolved_this_week = (
        db.query(Report)
        .filter(Report.status == ReportStatus.resolved, Report.created_at >= week_ago)
        .count()
    )
    return {
        "total_reports": total, "high_risk_cases": high_risk,
        "new": new, "resolved": resolved, "resolved_this_week": resolved_this_week,
    }


def get_cases(db, status=None, risk_label=None):
    q = db.query(Report)
    if status:
        q = q.filter(Report.status == status)
    if risk_label:
        q = q.filter(Report.risk_label == risk_label)
    return q.order_by(Report.created_at.desc()).limit(200).all()


# ---------------------------------------------------------------------------
# Top bar + navigation
# ---------------------------------------------------------------------------
st.sidebar.markdown("### 🛡️ ProtectX")
page = st.sidebar.radio("Navigate", ["🙋 Citizen Portal", "🏛️ Agency Dashboard"], label_visibility="collapsed")
st.sidebar.caption("AI-powered cyber-fraud evidence & intelligence platform.")

# ===========================================================================
# CITIZEN PORTAL  (mirrors frontend/index.html)
# ===========================================================================
if page == "🙋 Citizen Portal":
    st.markdown(
        """
        <div class="px-topbar">
            <h1>🛡️ ProtectX</h1>
            <p>Check a number/link · Report evidence · Get an instant risk assessment</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------- 1. SEARCH ----------------
    st.markdown('<div class="px-card">', unsafe_allow_html=True)
    st.subheader("1. Search")
    st.markdown('<p class="px-muted">Check a phone number, UPI ID, URL, or email against previous reports.</p>', unsafe_allow_html=True)
    scol1, scol2 = st.columns([5, 1])
    with scol1:
        search_query = st.text_input(
            "Search", placeholder="e.g. +919876543210 or scammer@okhdfcbank",
            label_visibility="collapsed", key="search_box",
        )
    with scol2:
        search_clicked = st.button("Search", use_container_width=True)

    if search_clicked:
        st.session_state.search_result = do_search(search_query)

    if st.session_state.search_result is not None:
        res = st.session_state.search_result
        if not res["found"]:
            st.info(f'No prior reports found for "{res["query"]}". That doesn\'t guarantee it\'s safe — stay cautious.')
        else:
            st.markdown(
                f'<strong>{res["query"]}</strong> has been reported <strong>{res["report_count"]}</strong> time(s). '
                f'Highest risk seen: {risk_badge(res["max_risk_label"])}',
                unsafe_allow_html=True,
            )
            for r in res["recent_reports"]:
                st.markdown(
                    f'- Report #{r["id"]} — {risk_badge(r["risk_label"])} (score {r["risk_score"]}) &nbsp;'
                    f'<span class="px-muted">{r["created_at"]:%Y-%m-%d %H:%M}</span>',
                    unsafe_allow_html=True,
                )
    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------- 2. REPORT & UPLOAD EVIDENCE ----------------
    st.markdown('<div class="px-card">', unsafe_allow_html=True)
    st.subheader("2. Report & Upload Evidence")
    with st.form("report_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            phone_number = st.text_input("Phone number", placeholder="+91XXXXXXXXXX")
            reported_url = st.text_input("Suspicious URL", placeholder="https://...")
        with c2:
            upi_id = st.text_input("UPI ID", placeholder="name@bank")
            email = st.text_input("Email", placeholder="scammer@example.com")

        call_transcript_text = st.text_area(
            "Call transcript (paste, or upload audio below)",
            placeholder="Paste what the caller said...", height=90,
        )
        sms_text = st.text_area("SMS / message text", placeholder="Paste the SMS/message...", height=90)
        other_details = st.text_area(
            "Other details", placeholder="Transaction details, anything else relevant...", height=70,
        )

        f1, f2 = st.columns(2)
        with f1:
            audio_file = st.file_uploader("Call recording (mp3/wav)", type=["mp3", "wav", "m4a", "ogg"])
        with f2:
            screenshot_files = st.file_uploader(
                "Screenshots", type=["png", "jpg", "jpeg"], accept_multiple_files=True,
            )

        submitted = st.form_submit_button("🔎 Run Analysis", use_container_width=True)

    if submitted:
        if not any([phone_number, upi_id, reported_url, email, call_transcript_text, sms_text, audio_file, screenshot_files]):
            st.warning("Please fill in at least one field or upload evidence before running the analysis.")
        else:
            with st.spinner("Analyzing evidence… this can take a moment."):
                st.session_state.last_report_result = submit_report(
                    phone_number, upi_id, reported_url, email,
                    call_transcript_text, sms_text, other_details,
                    audio_file, screenshot_files,
                )
    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------- 3. RESULTS ----------------
    if st.session_state.last_report_result:
        data = st.session_state.last_report_result
        st.markdown('<div class="px-card">', unsafe_allow_html=True)
        st.subheader("3. Results")
        st.markdown(
            f'{risk_badge(data["risk_label"])} &nbsp; Risk score: <strong>{data["risk_score"]}/100</strong> '
            f'&nbsp; Confidence: {round(data["confidence"] * 100)}%',
            unsafe_allow_html=True,
        )
        if data.get("scam_type") and data["scam_type"] != "Not a Scam":
            st.markdown(f'**Scam type:** {data["scam_type"]}')
        warning_msg = data["ai_analysis"].get("user_warning_message", "")
        if data["is_scam"]:
            st.error("⚠️ **This looks like a SCAM.** " + warning_msg)
        else:
            st.success("✅ No strong scam indicators found. " + warning_msg)

        st.markdown("**Why:**")
        for reason in data["reasoning"]:
            st.markdown(f"- {reason}")

        tactics = [t for t in (data.get("tactics_used") or []) if t and t != "None detected"]
        if tactics:
            st.markdown("**Tactics used:**")
            for t in tactics:
                st.markdown(f"- {t}")

        with st.expander("🧠 Gemini scam analysis"):
            st.json(data["ai_analysis"])
        with st.expander("🔗 Link scan & identifier check"):
            st.json(data["security_check"])
        with st.expander("📜 Matched RBI guidelines"):
            for rule in data["security_check"].get("matched_rbi_rules", []):
                st.write("• " + rule)

        st.download_button(
            "⬇️ Download full result as JSON",
            data=json.dumps(data, indent=2, default=str),
            file_name=f"protectx_report_{data['report_id']}.json",
            mime="application/json",
        )
        st.caption(f"Saved as case #{data['report_id']} in the shared database.")
        st.markdown("</div>", unsafe_allow_html=True)

# ===========================================================================
# AGENCY DASHBOARD  (mirrors frontend/agency.html)
# ===========================================================================
else:
    st.markdown(
        """
        <div class="px-topbar agency">
            <h1>🏛️ ProtectX Agency Dashboard</h1>
            <p>Investigate · Triage · Act</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------- LOGIN ----------------
    if not st.session_state.agency_logged_in:
        st.markdown('<div class="px-card">', unsafe_allow_html=True)
        st.subheader("Agency Access")
        lcol1, lcol2 = st.columns([4, 1])
        with lcol1:
            agency_key = st.text_input("Agency access key", type="password", label_visibility="collapsed")
        with lcol2:
            enter_clicked = st.button("Enter", use_container_width=True)
        st.markdown('<p class="px-muted small">Demo auth only — swap for real accounts before production use.</p>', unsafe_allow_html=True)
        if enter_clicked:
            if agency_key == AGENCY_ACCESS_CODE:
                st.session_state.agency_logged_in = True
                st.rerun()
            else:
                st.error("Invalid agency key.")
        st.markdown("</div>", unsafe_allow_html=True)

    else:
        top_l, top_r = st.columns([6, 1])
        with top_r:
            if st.button("Log out", use_container_width=True):
                st.session_state.agency_logged_in = False
                st.session_state.selected_case_id = None
                st.rerun()

        tab_overview, tab_cases, tab_investigate, tab_export = st.tabs(
            ["Overview", "Cases", "Investigate", "Export"]
        )

        # ---------------- OVERVIEW ----------------
        with tab_overview:
            with SessionLocal() as db:
                stats = get_stats(db)
                recent = get_cases(db)[:8]

            st.markdown("#### Dashboard Overview")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("New reports", stats["new"])
            m2.metric("High risk cases", stats["high_risk_cases"])
            m3.metric("Resolved this week", stats["resolved_this_week"])
            m4.metric("Total reports", stats["total_reports"])

            st.markdown("#### Recent cases")
            if not recent:
                st.info("No cases yet — reports will show up here once citizens submit evidence.")
            else:
                rows = [
                    {
                        "Case ID": f"#{r.id}",
                        "Type": infer_case_type(r),
                        "Risk": (r.risk_label or "-").upper(),
                        "Status": r.status.value if hasattr(r.status, "value") else r.status,
                        "Updated": r.created_at.strftime("%Y-%m-%d %H:%M"),
                    }
                    for r in recent
                ]
                st.dataframe(rows, use_container_width=True, hide_index=True)

        # ---------------- CASE MANAGEMENT ----------------
        with tab_cases:
            st.markdown("#### Case Management")
            f1, f2, f3 = st.columns([2, 2, 1])
            with f1:
                filter_status = st.selectbox(
                    "Status", ["All statuses", "new", "investigating", "verified", "resolved"],
                )
            with f2:
                filter_risk = st.selectbox("Risk level", ["All risk levels", "high", "medium", "low"])
            with f3:
                st.write("")
                refresh = st.button("Refresh", use_container_width=True)

            with SessionLocal() as db:
                cases = get_cases(
                    db,
                    status=None if filter_status == "All statuses" else filter_status,
                    risk_label=None if filter_risk == "All risk levels" else filter_risk,
                )
                case_rows = [
                    {
                        "ID": r.id,
                        "Created": r.created_at.strftime("%Y-%m-%d %H:%M"),
                        "Phone": r.phone_number or "-",
                        "URL": r.reported_url or "-",
                        "Risk": (r.risk_label or "-").upper(),
                        "Score": r.risk_score if r.risk_score is not None else "-",
                        "Status": r.status.value if hasattr(r.status, "value") else r.status,
                    }
                    for r in cases
                ]

            if not case_rows:
                st.info("No cases match this filter.")
            else:
                st.dataframe(case_rows, use_container_width=True, hide_index=True)

                case_ids = [c["ID"] for c in case_rows]
                selected_id = st.selectbox("Open case", case_ids, format_func=lambda i: f"Case #{i}")

                if selected_id:
                    with SessionLocal() as db:
                        r = db.query(Report).filter(Report.id == selected_id).first()

                    if r:
                        st.markdown("---")
                        st.markdown(f"### Case #{r.id} detail")
                        ai_analysis = json.loads(r.ai_analysis_json or "{}")
                        security_check = json.loads(r.security_check_json or "{}")
                        reasoning = json.loads(r.risk_reasoning_json or "[]")
                        scam_type = ai_analysis.get("scam_type")
                        tactics = [t for t in (ai_analysis.get("tactics_used") or []) if t and t != "None detected"]
                        id_hits = security_check.get("identifier_analysis") or []

                        st.markdown(
                            f'{risk_badge(r.risk_label)} Score: <strong>{r.risk_score}</strong> · '
                            f'Confidence: {round((r.risk_confidence or 0) * 100)}%',
                            unsafe_allow_html=True,
                        )
                        if scam_type and scam_type != "Not a Scam":
                            st.markdown(f"**Scam type:** {scam_type}")
                        st.markdown(
                            f"**Phone:** {r.phone_number or '-'} &nbsp; **UPI:** {r.upi_id or '-'} &nbsp; "
                            f"**URL:** {r.reported_url or '-'} &nbsp; **Email:** {r.email or '-'}",
                            unsafe_allow_html=True,
                        )
                        st.markdown(f"**Transcript:** {r.transcript_text or '(none)'}")
                        st.markdown(f"**SMS:** {r.sms_text or '(none)'}")
                        st.markdown(f"**OCR text (screenshots):** {r.ocr_text or '(none)'}")
                        if r.other_details:
                            st.markdown(f"**Other details:** {r.other_details}")

                        if reasoning:
                            st.markdown("**Reasoning:**")
                            for reason in reasoning:
                                st.markdown(f"- {reason}")
                        if tactics:
                            st.markdown("**Tactics used:**")
                            for t in tactics:
                                st.markdown(f"- {t}")
                        if id_hits:
                            st.markdown("**Flagged identifiers found in evidence:**")
                            for h in id_hits:
                                st.markdown(f"- {h.get('type')}: {h.get('identifier')} ({h.get('report_count', 0)} report(s))")

                        with st.expander("Raw AI + security JSON"):
                            st.json({"ai_analysis": ai_analysis, "security_check": security_check})

                        st.markdown("##### Update case")
                        status_options = ["new", "investigating", "verified", "resolved"]
                        current_status = r.status.value if hasattr(r.status, "value") else r.status
                        new_status = st.selectbox(
                            "Status", status_options,
                            index=status_options.index(current_status) if current_status in status_options else 0,
                            key=f"status_{r.id}",
                        )
                        new_notes = st.text_area("Agency notes", value=r.agency_notes or "", key=f"notes_{r.id}")

                        if st.button("💾 Save case", key=f"save_{r.id}"):
                            with SessionLocal() as db:
                                row = db.query(Report).filter(Report.id == r.id).first()
                                row.status = new_status
                                row.agency_notes = new_notes
                                db.add(AuditLog(actor="agency", action="case_updated", report_id=r.id, detail=new_status))
                                db.commit()
                            st.success("Saved.")
                            st.rerun()

        # ---------------- INVESTIGATION TOOLS ----------------
        with tab_investigate:
            st.markdown("#### Investigation Tools")
            st.markdown('<p class="px-muted">Entity correlation, link/network analysis, cross-referencing.</p>', unsafe_allow_html=True)

            inv_query = st.text_input("Look up a phone / UPI / URL / email", key="investigate_box")
            if st.button("Investigate"):
                if inv_query.strip():
                    check = check_scam_identifier(inv_query.strip())
                    st.json(check)
                    with SessionLocal() as db:
                        related = (
                            db.query(Report)
                            .filter(
                                or_(
                                    Report.phone_number == inv_query,
                                    Report.upi_id == inv_query,
                                    Report.reported_url == inv_query,
                                    Report.email == inv_query,
                                )
                            )
                            .order_by(Report.created_at.desc())
                            .all()
                        )
                    if related:
                        st.markdown(f"**{len(related)} related case(s) found:**")
                        st.dataframe(
                            [
                                {
                                    "Case ID": f"#{r.id}", "Created": r.created_at.strftime("%Y-%m-%d %H:%M"),
                                    "Risk": (r.risk_label or "-").upper(),
                                    "Status": r.status.value if hasattr(r.status, "value") else r.status,
                                }
                                for r in related
                            ],
                            use_container_width=True, hide_index=True,
                        )
                    else:
                        st.info("No related cases found for this identifier.")

        # ---------------- EXPORT & ACTION ----------------
        with tab_export:
            st.markdown("#### Export & Action")
            st.markdown('<p class="px-muted">Export the current case list for reporting or escalation.</p>', unsafe_allow_html=True)
            with SessionLocal() as db:
                all_cases = get_cases(db)

            if not all_cases:
                st.info("No cases to export yet.")
            else:
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(["id", "created_at", "phone_number", "upi_id", "reported_url", "email",
                                  "risk_label", "risk_score", "status", "is_scam"])
                for r in all_cases:
                    writer.writerow([
                        r.id, r.created_at.isoformat(), r.phone_number, r.upi_id, r.reported_url, r.email,
                        r.risk_label, r.risk_score, r.status.value if hasattr(r.status, "value") else r.status,
                        r.is_scam,
                    ])
                st.download_button(
                    "⬇️ Export all cases (CSV)", data=buf.getvalue(),
                    file_name="protectx_cases.csv", mime="text/csv",
                )

                json_payload = [
                    {
                        "id": r.id, "created_at": r.created_at.isoformat(), "phone_number": r.phone_number,
                        "upi_id": r.upi_id, "reported_url": r.reported_url, "email": r.email,
                        "risk_label": r.risk_label, "risk_score": r.risk_score,
                        "status": r.status.value if hasattr(r.status, "value") else r.status,
                        "is_scam": r.is_scam,
                    }
                    for r in all_cases
                ]
                st.download_button(
                    "⬇️ Export all cases (JSON)", data=json.dumps(json_payload, indent=2),
                    file_name="protectx_cases.json", mime="application/json",
                )

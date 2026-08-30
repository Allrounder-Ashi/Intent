"""
Lightweight REST API for the Android app.
Deploy this SEPARATELY from the Streamlit/RAG app — it must respond in
well under a second so CallScreeningService (5s window) never times out.

Endpoints:
  GET  /health
  GET  /check_number?phone=+91XXXXXXXXXX
  POST /report_number   {"phone": "+91XXXXXXXXXX"}
  POST /analyze_text     {"text": "...", "phone": "..."}   (slower, used post-call, not in the 5s window)
"""
import os
from flask import Flask, request, jsonify

from person3_security import (
    check_scam_number,
    report_scam_number,
    run_person3_security_check,
    check_scam_identifier,
    report_scam_identifier,
)
from scam_detector import run_person2_pipeline

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/check_number", methods=["GET"])
def check_number_route():
    phone = request.args.get("phone")
    if not phone:
        return jsonify({"error": "phone query param is required"}), 400
    return jsonify(check_scam_number(phone))


@app.route("/check_identifier", methods=["GET"])
def check_identifier_route():
    identifier = request.args.get("identifier")
    if not identifier:
        return jsonify({"error": "identifier query param is required"}), 400
    return jsonify(check_scam_identifier(identifier))


@app.route("/report_identifier", methods=["POST"])
def report_identifier_route():
    data = request.get_json(force=True, silent=True) or {}
    identifier = data.get("identifier")
    identifier_type = data.get("type", "phone")
    if not identifier:
        return jsonify({"error": "identifier field is required"}), 400
    return jsonify(report_scam_identifier(identifier, identifier_type=identifier_type))


@app.route("/report_number", methods=["POST"])
def report_number_route():
    data = request.get_json(force=True, silent=True) or {}
    phone = data.get("phone")
    if not phone:
        return jsonify({"error": "phone field is required"}), 400
    return jsonify(report_scam_number(phone))


@app.route("/analyze_text", methods=["POST"])
def analyze_text_route():
    """Deeper analysis — call this AFTER the call is answered/ended, not during screening."""
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    phone = data.get("phone", "unknown")
    if not text:
        return jsonify({"error": "text field is required"}), 400

    person3_result = run_person3_security_check(text, phone)
    person2_result = run_person2_pipeline(text)
    is_scam = bool(
        person2_result.get("is_likely_scam")
        or person3_result["url_analysis"]["is_dangerous"]
        or person3_result["phone_analysis"]["is_known_scammer"]
    )
    return jsonify({
        "ai_analysis": person2_result,
        "security_check": person3_result,
        "is_scam": is_scam,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
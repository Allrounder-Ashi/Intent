"""
Person 4: Risk Assessment & Decision Engine
---------------------------------------------
This is the piece the architecture diagram calls out separately and that
nobody else on the team owns. It combines:

  - Person 2's AI/LLM analysis (scam classification, risk_level)
  - Person 3's rules/link/RBI-rule matches
  - Person 1's extracted metadata (how many red-flag entities were found)

into one risk_score (0-100), a risk_label (low/medium/high), a confidence
value, and human-readable reasoning -> this is what both the citizen result
screen and the agency case view show.
"""

RISK_LEVEL_BASE_SCORE = {"low": 5, "medium": 20, "high": 40}


def _clamp(value, low=0, high=100):
    return max(low, min(high, value))


def assess_risk(ai_analysis: dict, security_check: dict, extracted_metadata: dict | None = None):
    """
    ai_analysis: output of scam_detector.run_person2_pipeline()
    security_check: output of person3_security.run_person3_security_check()
    extracted_metadata: output of metadata_extractor.extract_metadata() (optional)
    """
    ai_analysis = ai_analysis or {}
    security_check = security_check or {}
    extracted_metadata = extracted_metadata or {}

    score = 0
    reasoning = []
    signals_agreeing = 0
    total_signals_checked = 0

    # --- Signal 1: Person 2's AI verdict -----------------------------------
    # Their updated scam_detector.py now also returns scam_type,
    # confidence_score (0-100), tactics_used, and summary.
    total_signals_checked += 1
    if ai_analysis.get("is_likely_scam"):
        signals_agreeing += 1
        level = str(ai_analysis.get("risk_level", "medium")).lower()
        score += RISK_LEVEL_BASE_SCORE.get(level, 20)

        # Nudge the score using Gemini's own confidence (0-100 -> 0-10 points)
        confidence_score = ai_analysis.get("confidence_score")
        if isinstance(confidence_score, (int, float)):
            score += round(confidence_score / 10)

        scam_type = ai_analysis.get("scam_type")
        signals = ai_analysis.get("scam_signals_found") or []
        if scam_type and scam_type not in ("Not a Scam", "Other"):
            reasoning.append(f"AI classified this as: {scam_type}")
        if signals:
            reasoning.append("AI analysis flagged: " + ", ".join(signals[:3]))
        else:
            reasoning.append("AI analysis classified this as a likely scam.")

        tactics = ai_analysis.get("tactics_used") or []
        tactics = [t for t in tactics if t and t != "None detected"]
        if tactics:
            score += min(len(tactics) * 3, 10)
            reasoning.append("Manipulation tactics detected: " + ", ".join(tactics[:3]))

    # --- Signal 2: Dangerous URL(s) -----------------------------------------
    url_analysis = security_check.get("url_analysis", {})
    total_signals_checked += 1
    if url_analysis.get("is_dangerous"):
        signals_agreeing += 1
        score += 30
        details = url_analysis.get("threat_details") or []
        if details:
            reasoning.append(details[0])
        else:
            reasoning.append("A suspicious/phishing-style link was detected.")

    # --- Signal 3: Known scam phone number ----------------------------------
    phone_analysis = security_check.get("phone_analysis", {})
    total_signals_checked += 1
    if phone_analysis.get("is_known_scammer"):
        signals_agreeing += 1
        report_count = phone_analysis.get("report_count", 0)
        score += 20 + min(report_count * 3, 20)
        reasoning.append(
            f"This phone number has been reported {report_count} time(s) previously."
        )

    # --- Signal 4: Matches an official RBI fraud pattern --------------------
    matched_rules = security_check.get("matched_rbi_rules") or []
    total_signals_checked += 1
    if matched_rules:
        signals_agreeing += 1
        score += 10
        reasoning.append("Matches a known RBI fraud advisory: " + matched_rules[0][:140])

    # --- Signal 5: Known UPI ID / bank account mentioned in the evidence ----
    # New in their updated person3_security.py: identifier_analysis checks
    # every UPI ID / account number found in the text, not just the phone.
    identifier_hits = [
        item for item in (security_check.get("identifier_analysis") or [])
        if item.get("is_known_scammer")
    ]
    total_signals_checked += 1
    if identifier_hits:
        signals_agreeing += 1
        score += 20 + min(sum(h.get("report_count", 0) for h in identifier_hits) * 2, 15)
        for hit in identifier_hits[:2]:
            reasoning.append(
                f"{hit.get('type', 'identifier').upper()} '{hit.get('identifier')}' "
                f"has {hit.get('report_count', 0)} prior report(s)."
            )

    # --- Signal 6: Volume of sensitive entities extracted -------------------
    sensitive_entity_count = sum(
        len(extracted_metadata.get(k, []))
        for k in ("phone_numbers", "upi_ids", "urls", "account_number_candidates")
    )
    if sensitive_entity_count >= 2:
        score += 5
        reasoning.append(
            f"Evidence contains {sensitive_entity_count} sensitive identifiers "
            "(phone/UPI/account/URL) worth cross-checking."
        )

    score = _clamp(score)

    if score >= 55:
        label = "high"
    elif score >= 25:
        label = "medium"
    else:
        label = "low"

    confidence = round(signals_agreeing / total_signals_checked, 2) if total_signals_checked else 0.0
    is_scam = label in ("high", "medium") and signals_agreeing >= 1

    if not reasoning:
        reasoning.append("No strong scam indicators were found in the evidence provided.")

    return {
        "risk_score": score,
        "risk_label": label,
        "confidence": confidence,
        "is_scam": is_scam,
        "reasoning": reasoning,
    }


if __name__ == "__main__":
    demo_ai = {
        "is_likely_scam": True,
        "risk_level": "high",
        "scam_signals_found": ["Caller asked for OTP", "Threatened account blocking"],
    }
    demo_security = {
        "url_analysis": {"is_dangerous": True, "threat_details": ["Insecure HTTP link"]},
        "phone_analysis": {"is_known_scammer": True, "report_count": 3},
        "matched_rbi_rules": ["Banks never ask for OTP over phone or SMS."],
    }
    import json
    print(json.dumps(assess_risk(demo_ai, demo_security), indent=2))

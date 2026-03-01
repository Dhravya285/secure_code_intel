# ============================================================
# scoring/risk_scorer.py — Static Risk Scoring Model
# ============================================================
# Computes a 0–1 risk score for each vulnerability.
#
# Formula:
#   Risk Score = 0.6 * base_severity + 0.4 * feature_signal
#
# base_severity  → domain knowledge (how bad is this vuln type?)
# feature_signal → ML-style signal (how exploitable is this instance?)
# ============================================================

import json
from config import BASE_SEVERITY, STATIC_SEVERITY_WEIGHT, STATIC_FEATURE_WEIGHT


def compute_static_risk(finding: dict) -> dict:
    """
    Computes static risk score for a single enriched finding.

    Input:  finding with 'type' and 'feature_signal' keys
    Output: finding enriched with 'static_risk_score'
    """
    vuln_type = finding.get("type", "")
    feature_signal = finding.get("feature_signal", 0.5)

    # Look up base severity — default 0.5 if unknown type
    base_severity = BASE_SEVERITY.get(vuln_type, 0.5)

    # Weighted formula
    score = (
        STATIC_SEVERITY_WEIGHT * base_severity +
        STATIC_FEATURE_WEIGHT * feature_signal
    )

    score = round(min(max(score, 0.0), 1.0), 4)  # clamp 0–1

    return {
        **finding,
        "base_severity": base_severity,
        "static_risk_score": score,
    }


def score_all(findings: list) -> list:
    """Score all enriched findings."""
    return [compute_static_risk(f) for f in findings]


def get_risk_label(score: float) -> str:
    """Human-readable label for a risk score."""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.6:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"


# ---------- QUICK TEST ----------
if __name__ == "__main__":
    sample = {
        "type": "SQL Injection",
        "file": "data/vulnerable/auth.py",
        "line": 12,
        "code": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        "features": {
            "has_sql_keyword": 1,
            "uses_concat": 1,
            "uses_user_input": 1,
            "dangerous_function": 1,
        },
        "feature_signal": 0.85,
    }

    result = compute_static_risk(sample)
    print(json.dumps(result, indent=2))
    print(f"Risk Label: {get_risk_label(result['static_risk_score'])}")
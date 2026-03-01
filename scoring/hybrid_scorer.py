# ============================================================
# scoring/hybrid_scorer.py — Ensemble Hybrid Risk Scorer
# ============================================================
# Combines static score + LLM confidence into final risk score.
#
# Formula:
#   Final Risk = 0.6 * static_score + 0.4 * llm_confidence
#
# Then applies patch validation penalty if patch failed:
#   Final Risk -= score_penalty
#
# This is ensemble modeling — two independent signals combined.
# ============================================================

from config import HYBRID_STATIC_WEIGHT, HYBRID_LLM_WEIGHT


def compute_hybrid_score(
    static_score: float,
    llm_confidence: float,
    score_penalty: float = 0.0
) -> float:
    """
    Compute final hybrid risk score.

    Args:
        static_score    — from Day 1 risk scorer (0–1)
        llm_confidence  — from LLM severity_confidence field (0–1)
        score_penalty   — from patch validator (0.0, 0.1, or 0.15)

    Returns:
        final_risk: float clamped to 0–1
    """
    raw_score = (
        HYBRID_STATIC_WEIGHT * static_score +
        HYBRID_LLM_WEIGHT * llm_confidence
    )

    # Apply penalty from patch validation failure
    final = raw_score - score_penalty

    return round(min(max(final, 0.0), 1.0), 4)


def enrich_with_hybrid_score(finding: dict, llm_response: dict, validation: dict) -> dict:
    """
    Takes all three inputs and returns a fully enriched vulnerability object.

    Final structure:
    {
      type, file, line, code,
      features, feature_signal,
      base_severity, static_risk_score,
      explanation, exploit, patched_code, cwe,
      llm_confidence,
      syntax_valid, still_vulnerable, validated,
      score_penalty,
      final_risk
    }
    """
    static_score = finding.get("static_risk_score", 0.5)
    llm_confidence = llm_response.get("severity_confidence", 0.5)
    score_penalty = validation.get("score_penalty", 0.0)

    final_risk = compute_hybrid_score(static_score, llm_confidence, score_penalty)

    return {
        # Original finding fields
        **finding,

        # LLM fields
        "explanation": llm_response.get("explanation", ""),
        "exploit": llm_response.get("exploit", ""),
        "patched_code": llm_response.get("patched_code", ""),
        "cwe": llm_response.get("cwe", ""),
        "llm_confidence": llm_confidence,

        # Validation fields
        "syntax_valid": validation.get("syntax_valid", False),
        "still_vulnerable": validation.get("still_vulnerable", True),
        "validated": validation.get("validated", False),
        "validation_notes": validation.get("validation_notes", ""),
        "score_penalty": score_penalty,

        # Final score
        "final_risk": final_risk,
    }
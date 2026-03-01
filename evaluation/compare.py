# ============================================================
# evaluation/compare.py — Static vs Hybrid Comparison
# ============================================================
# Compares static-only scoring vs hybrid (static + LLM) scoring.
#
# Shows:
#   - Score differences per finding
#   - How much LLM adjusts the static baseline
#   - Cases where LLM raised or lowered the score
#   - Average delta across all findings
#
# WHY THIS MATTERS FOR INTERVIEWS:
#   This proves your hybrid system adds value over static alone.
#   If LLM always agrees, the hybrid adds no value.
#   If LLM sometimes disagrees intelligently, it's a better system.
# ============================================================


def compare_scores(findings: list) -> dict:
    """
    Compare static_risk_score vs final_risk for all findings.

    Returns comparison report with:
    - per_finding deltas
    - summary statistics
    - cases where LLM raised / lowered / matched static score
    """
    comparisons = []
    raised  = 0   # LLM pushed score higher
    lowered = 0   # LLM pushed score lower
    same    = 0   # No meaningful difference
    deltas  = []

    for f in findings:
        static = f.get("static_risk_score", 0)
        final  = f.get("final_risk", 0)
        llm    = f.get("llm_confidence", 0.5)
        delta  = round(final - static, 4)
        deltas.append(abs(delta))

        if delta > 0.01:
            direction = "RAISED"
            raised += 1
        elif delta < -0.01:
            direction = "LOWERED"
            lowered += 1
        else:
            direction = "SAME"
            same += 1

        comparisons.append({
            "type":         f.get("type"),
            "file":         f.get("file"),
            "line":         f.get("line"),
            "static_score": static,
            "llm_conf":     llm,
            "final_score":  final,
            "delta":        delta,
            "direction":    direction,
            "validated":    f.get("validated", False),
        })

    avg_delta = round(sum(deltas) / len(deltas), 4) if deltas else 0

    # Sort by absolute delta to show most impactful LLM adjustments
    comparisons.sort(key=lambda x: abs(x["delta"]), reverse=True)

    return {
        "total_findings": len(findings),
        "llm_raised":     raised,
        "llm_lowered":    lowered,
        "llm_same":       same,
        "avg_delta":      avg_delta,
        "comparisons":    comparisons,
    }


def print_comparison_report(report: dict):
    """Print a formatted comparison report to console."""
    print(f"\n{'='*60}")
    print(f"  STATIC vs HYBRID SCORING COMPARISON")
    print(f"{'='*60}")
    print(f"  Total findings : {report['total_findings']}")
    print(f"  LLM raised     : {report['llm_raised']}  (LLM more confident than static)")
    print(f"  LLM lowered    : {report['llm_lowered']}  (LLM less confident than static)")
    print(f"  No change      : {report['llm_same']}")
    print(f"  Avg score delta: {report['avg_delta']}")

    print(f"\n  TOP SCORE CHANGES (largest LLM impact):")
    print(f"  {'Type':<28} {'Static':>8} {'LLM':>6} {'Final':>8} {'Δ':>8} {'Dir'}")
    print(f"  {'-'*70}")

    for c in report["comparisons"][:10]:
        delta_str = f"{c['delta']:+.4f}"
        print(
            f"  {c['type']:<28} "
            f"{c['static_score']:>8.4f} "
            f"{c['llm_conf']:>6.2f} "
            f"{c['final_score']:>8.4f} "
            f"{delta_str:>8} "
            f"{c['direction']}"
        )

    print(f"\n  INSIGHT:")
    total = report["total_findings"]
    raised_pct  = round(report["llm_raised"]  / total * 100)
    lowered_pct = round(report["llm_lowered"] / total * 100)
    same_pct    = round(report["llm_same"]    / total * 100)
    print(f"  LLM agreed with static  : {same_pct}%")
    print(f"  LLM raised severity     : {raised_pct}%")
    print(f"  LLM lowered severity    : {lowered_pct}%")

    if report["avg_delta"] > 0.05:
        print(f"  → LLM adds significant value over static-only scoring")
    elif report["avg_delta"] > 0.01:
        print(f"  → LLM adds moderate value — ensemble is better than static alone")
    else:
        print(f"  → LLM largely agrees with static scoring on this dataset")

    print(f"{'='*60}\n")
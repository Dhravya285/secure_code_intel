# ============================================================
# main.py — Full Pipeline Day 1 + 2 + 3
# ============================================================
# Runs everything end to end:
#   Day 1: Scan → Feature Engineering → Static Scoring
#   Day 2: LLM Analysis → Patch Validation → Hybrid Scoring
#   Day 3: Aggregation → Cluster Scoring → Business Explanation → Evaluation
# ============================================================

import json
from pathlib import Path

# Day 1 + 2
from scanner.ast_scanner import scan_directory
from scanner.feature_engineer import engineer_all
from scoring.risk_scorer import score_all, get_risk_label
from scoring.hybrid_scorer import enrich_with_hybrid_score
from llm.prompt_templates import build_vuln_prompt
from llm.llm_client import call_llm
from llm.patch_validator import validate_patch

# Day 3
from prioritization.aggregator import build_clusters
from prioritization.cluster_scorer import score_and_rank_clusters, get_priority_label
from prioritization.business_explainer import explain_top_clusters
from evaluation.eval_runner import run_evaluation
from evaluation.compare import compare_scores, print_comparison_report

from config import SCAN_RESULTS_PATH, SCORED_VULNS_PATH, FINAL_REPORT_PATH


def run_pipeline(target_dir: str = "data/vulnerable"):
    Path("outputs").mkdir(exist_ok=True)

    # ══════════════════════════════════════════════════════
    # DAY 1 + 2 — Detection + Scoring
    # ══════════════════════════════════════════════════════

    print(f"\n{'='*60}")
    print(f"  AI-Powered Secure Code Intelligence Engine")
    print(f"  FULL PIPELINE — Day 1 + 2 + 3")
    print(f"{'='*60}")

    # Step 1: Scan
    print(f"\n[1/8] Scanning: {target_dir}")
    raw_findings = scan_directory(target_dir)
    print(f"      Found {len(raw_findings)} vulnerability signals")
    with open(SCAN_RESULTS_PATH, "w") as f:
        json.dump(raw_findings, f, indent=2)

    # Step 2: Features
    print(f"\n[2/8] Engineering features...")
    enriched = engineer_all(raw_findings)

    # Step 3: Static scoring
    print(f"\n[3/8] Static risk scoring...")
    scored = score_all(enriched)
    with open(SCORED_VULNS_PATH, "w") as f:
        json.dump(scored, f, indent=2)

    # Step 4: LLM + Validation + Hybrid scoring
    print(f"\n[4/8] LLM analysis + patch validation...")
    print(f"      ({len(scored)} findings — may take a few minutes)\n")

    final_vulns = []
    for i, finding in enumerate(scored, 1):
        print(f"  [{i}/{len(scored)}] {finding['type']} — {Path(finding['file']).name}:{finding['line']}")
        prompt      = build_vuln_prompt(finding)
        llm_resp    = call_llm(prompt, retries=1)
        validation  = validate_patch(finding, llm_resp)
        final       = enrich_with_hybrid_score(finding, llm_resp, validation)
        final_vulns.append(final)
        print(f"    → final_risk={final['final_risk']} ({get_risk_label(final['final_risk'])}) | patch={'✅' if final['validated'] else '⚠️'}")

    final_vulns.sort(key=lambda x: x["final_risk"], reverse=True)

    with open(FINAL_REPORT_PATH, "w") as f:
        json.dump(final_vulns, f, indent=2)
    print(f"\n      Saved → {FINAL_REPORT_PATH}")

    # ══════════════════════════════════════════════════════
    # DAY 3 — Prioritization + Evaluation
    # ══════════════════════════════════════════════════════

    # Step 5: Aggregate into clusters
    print(f"\n[5/8] Aggregating findings into clusters...")
    clusters = build_clusters(final_vulns)
    print(f"      {len(clusters)} clusters formed")

    # Step 6: Score and rank clusters
    print(f"\n[6/8] Scoring and ranking clusters...")
    ranked_clusters = score_and_rank_clusters(clusters)

    print(f"\n  CLUSTER RANKINGS:")
    print(f"  {'Rank':<6} {'Type':<30} {'Count':>6} {'Avg Risk':>10} {'Priority':>10} {'Label'}")
    print(f"  {'-'*80}")
    for c in ranked_clusters:
        label = get_priority_label(c["priority_score"])
        print(
            f"  [{c['rank']}]    "
            f"{c['type']:<30} "
            f"{c['count']:>6} "
            f"{c['avg_risk']:>10.4f} "
            f"{c['priority_score']:>10.4f}  "
            f"{label}"
        )

    # Step 7: Business explanations for top 3
    print(f"\n[7/8] Generating business explanations for top 3 clusters...")
    ranked_clusters = explain_top_clusters(ranked_clusters, top_n=3)

    # Save cluster report
    cluster_report_path = "outputs/cluster_report.json"

    # Remove findings from saved report to keep it readable
    clusters_to_save = []
    for c in ranked_clusters:
        c_copy = {k: v for k, v in c.items() if k != "findings"}
        clusters_to_save.append(c_copy)

    with open(cluster_report_path, "w") as f:
        json.dump(clusters_to_save, f, indent=2)
    print(f"      Saved → {cluster_report_path}")

    # Print top 3 business explanations
    print(f"\n  TOP 3 CLUSTER EXPLANATIONS:")
    print(f"  {'='*60}")
    for c in ranked_clusters[:3]:
        print(f"\n  #{c['rank']} {c['type']} — {get_priority_label(c['priority_score'])}")
        print(f"  Files    : {', '.join([Path(f).name for f in c['affected_files']])}")
        print(f"  Count    : {c['count']} findings | Avg Risk: {c['avg_risk']}")
        print(f"  Why      : {c.get('why_critical', 'N/A')}")
        print(f"  Impact   : {c.get('business_impact', 'N/A')}")
        print(f"  Fix order: {c.get('fix_order', 'N/A')}")
        print(f"  Effort   : {c.get('estimated_effort', 'N/A')}")

    # ══════════════════════════════════════════════════════
    # Step 8: Evaluation
    # ══════════════════════════════════════════════════════

    print(f"\n[8/8] Running evaluation...")

    # 8a: Precision / Recall / F1
    eval_results = run_evaluation(
        vulnerable_dir="data/vulnerable",
        safe_dir="data/safe"
    )

    print(f"\n  EVALUATION METRICS:")
    print(f"  {'='*40}")
    print(f"  True Positives  : {eval_results['tp']}")
    print(f"  False Positives : {eval_results['fp']}")
    print(f"  False Negatives : {eval_results['fn']}")
    print(f"  True Negatives  : {eval_results['tn']}")
    print(f"  {'─'*40}")
    print(f"  Precision       : {eval_results['precision']}")
    print(f"  Recall          : {eval_results['recall']}")
    print(f"  F1 Score        : {eval_results['f1_score']}")
    print(f"  {'='*40}")

    print(f"\n  PER-FILE RESULTS:")
    for r in eval_results["per_file"]:
        status = "✅" if r["fp"] == 0 and r["fn"] == 0 else ("⚠️" if r["fn"] > 0 else "❌")
        print(f"  {status} {r['file']:<25} TP={r['tp']} FP={r['fp']} FN={r['fn']}")

    # Save eval results
    eval_path = "outputs/evaluation_results.json"
    with open(eval_path, "w") as f:
        json.dump(eval_results, f, indent=2)
    print(f"\n      Saved → {eval_path}")

    # 8b: Static vs Hybrid comparison
    comparison = compare_scores(final_vulns)
    print_comparison_report(comparison)

    comparison_path = "outputs/comparison_report.json"
    with open(comparison_path, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"      Saved → {comparison_path}")

    # ══════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════

    print(f"\n{'='*60}")
    print(f"  PIPELINE COMPLETE")
    print(f"{'='*60}")
    print(f"  Findings detected  : {len(final_vulns)}")
    print(f"  Clusters formed    : {len(ranked_clusters)}")
    print(f"  Patches validated  : {sum(1 for v in final_vulns if v['validated'])}/{len(final_vulns)}")
    print(f"  Precision          : {eval_results['precision']}")
    print(f"  Recall             : {eval_results['recall']}")
    print(f"  F1 Score           : {eval_results['f1_score']}")
    print(f"\n  Output files:")
    print(f"  → outputs/scan_results.json")
    print(f"  → outputs/scored_vulns.json")
    print(f"  → outputs/final_report.json")
    print(f"  → outputs/cluster_report.json")
    print(f"  → outputs/evaluation_results.json")
    print(f"  → outputs/comparison_report.json")
    print(f"{'='*60}\n")

    return final_vulns, ranked_clusters, eval_results


if __name__ == "__main__":
    run_pipeline("data/vulnerable")
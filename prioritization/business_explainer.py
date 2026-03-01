# ============================================================
# prioritization/business_explainer.py — Business Explanation Layer
# ============================================================
# For the top 3 clusters, generates plain-English business
# explanations using LLM.
#
# WHY THIS MATTERS:
#   Developers understand "SQL Injection in auth.py line 12"
#   Managers understand "Your login system can be bypassed,
#   exposing all 50,000 user records within minutes"
#
#   This layer bridges that gap.
# ============================================================

from llm.llm_client import call_llm
from llm.prompt_templates import build_cluster_prompt
from prioritization.cluster_scorer import get_priority_label


def explain_cluster(cluster: dict) -> dict:
    """
    Generate business-level LLM explanation for a single cluster.

    Adds to cluster:
    - why_critical   : why this cluster is dangerous
    - business_impact: what happens if ignored
    - fix_order      : recommended remediation priority
    - estimated_effort: low / medium / high
    - llm_explained  : bool
    """
    print(f"  [BIZ] Explaining cluster: {cluster['type']} (rank #{cluster['rank']})")

    prompt   = build_cluster_prompt(cluster)
    response = call_llm(prompt, retries=1)

    if response and response.get("why_critical") != "Could not generate explanation":
        cluster["why_critical"]     = response.get("why_critical", "")
        cluster["business_impact"]  = response.get("business_impact", "")
        cluster["fix_order"]        = response.get("fix_order", "")
        cluster["estimated_effort"] = response.get("estimated_effort", "medium")
        cluster["llm_explained"]    = True
        print(f"  [BIZ] ✅ Explanation generated")
    else:
        cluster["why_critical"]     = f"{cluster['type']} vulnerabilities found in {len(cluster['affected_files'])} files"
        cluster["business_impact"]  = "Could lead to data breach or system compromise"
        cluster["fix_order"]        = "Fix immediately — highest priority cluster"
        cluster["estimated_effort"] = "medium"
        cluster["llm_explained"]    = False
        print(f"  [BIZ] ⚠️  Used fallback explanation")

    return cluster


def explain_top_clusters(clusters: list, top_n: int = 3) -> list:
    """
    Generate business explanations for the top N clusters only.
    Top clusters are already ranked by priority_score.

    Returns all clusters — top N enriched with explanations,
    rest left unchanged.
    """
    print(f"\n  Generating business explanations for top {top_n} clusters...")

    for cluster in clusters[:top_n]:
        explain_cluster(cluster)

    # Add empty explanation fields to remaining clusters
    for cluster in clusters[top_n:]:
        cluster["why_critical"]     = ""
        cluster["business_impact"]  = ""
        cluster["fix_order"]        = ""
        cluster["estimated_effort"] = ""
        cluster["llm_explained"]    = False

    return clusters
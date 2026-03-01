# ============================================================
# prioritization/cluster_scorer.py — Cluster Priority Scoring
# ============================================================
# Scores each cluster to answer: "What do we fix first?"
#
# Formula:
#   Priority Score =
#     0.4 * avg_final_risk        ← how severe are these vulns?
#   + 0.2 * normalized_frequency  ← how many instances exist?
#   + 0.2 * exploit_confidence    ← how confident is LLM they're exploitable?
#   + 0.2 * module_weight         ← how critical is the affected module?
#
# Module weights reflect business criticality:
#   auth*, login*, user* → 1.0 (authentication = highest priority)
#   admin*, api*         → 0.9
#   db*, data*           → 0.8
#   config*              → 0.7
#   everything else      → 0.5
# ============================================================


# --- Module criticality weights ---
MODULE_WEIGHTS = {
    "auth":     1.0,
    "login":    1.0,
    "user":     1.0,
    "admin":    0.9,
    "api":      0.9,
    "db":       0.8,
    "database": 0.8,
    "data":     0.8,
    "config":   0.7,
    "settings": 0.7,
    "utils":    0.5,
    "helpers":  0.5,
}

# --- Scoring weights ---
WEIGHT_AVG_RISK      = 0.40
WEIGHT_FREQUENCY     = 0.20
WEIGHT_EXPLOIT_CONF  = 0.20
WEIGHT_MODULE        = 0.20


def get_module_weight(affected_modules: list) -> float:
    """
    Returns the highest module weight among all affected modules.
    Uses prefix matching so 'auth_service' matches 'auth'.
    """
    max_weight = 0.5  # default
    for module in affected_modules:
        module_lower = module.lower()
        for key, weight in MODULE_WEIGHTS.items():
            if module_lower.startswith(key):
                max_weight = max(max_weight, weight)
    return max_weight


def normalize_frequency(count: int, max_count: int) -> float:
    """Normalize finding count to 0–1 scale."""
    if max_count == 0:
        return 0.0
    return round(min(count / max_count, 1.0), 4)


def compute_priority_score(cluster: dict, max_count: int) -> float:
    """
    Compute priority score for a single cluster.

    Args:
        cluster   — cluster dict from aggregator
        max_count — highest count among all clusters (for normalization)

    Returns:
        priority_score: float 0–1
    """
    avg_risk      = cluster.get("avg_risk", 0)
    exploit_conf  = cluster.get("exploit_confidence", 0.5)
    count         = cluster.get("count", 1)
    modules       = cluster.get("affected_modules", [])

    freq_normalized = normalize_frequency(count, max_count)
    module_weight   = get_module_weight(modules)

    score = (
        WEIGHT_AVG_RISK     * avg_risk +
        WEIGHT_FREQUENCY    * freq_normalized +
        WEIGHT_EXPLOIT_CONF * exploit_conf +
        WEIGHT_MODULE       * module_weight
    )

    return round(min(max(score, 0.0), 1.0), 4)


def score_and_rank_clusters(clusters: list) -> list:
    """
    Compute priority scores for all clusters and rank them.

    Returns clusters sorted by priority_score descending,
    with rank and priority_score added to each cluster.
    """
    # Find max count for normalization
    max_count = max(c.get("count", 1) for c in clusters) if clusters else 1

    # Score each cluster
    for cluster in clusters:
        score = compute_priority_score(cluster, max_count)
        cluster["priority_score"] = score
        cluster["module_weight"]  = get_module_weight(cluster.get("affected_modules", []))

    # Sort by priority score descending
    clusters.sort(key=lambda x: x["priority_score"], reverse=True)

    # Assign ranks
    for rank, cluster in enumerate(clusters, 1):
        cluster["rank"] = rank

    return clusters


def get_priority_label(score: float) -> str:
    """Human-readable priority label."""
    if score >= 0.75:
        return "P0 — IMMEDIATE"
    elif score >= 0.60:
        return "P1 — HIGH"
    elif score >= 0.45:
        return "P2 — MEDIUM"
    else:
        return "P3 — LOW"


if __name__ == "__main__":
    import json
    from prioritization.aggregator import build_clusters

    with open("outputs/final_report.json") as f:
        findings = json.load(f)

    clusters = build_clusters(findings)
    ranked   = score_and_rank_clusters(clusters)

    print("\nRANKED CLUSTERS:")
    for c in ranked:
        label = get_priority_label(c["priority_score"])
        print(f"  [{c['rank']}] {c['type']:<30} score={c['priority_score']} | {label}")
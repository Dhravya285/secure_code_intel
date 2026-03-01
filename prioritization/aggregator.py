# ============================================================
# prioritization/aggregator.py — Vulnerability Aggregator
# ============================================================
# Groups individual findings into clusters by:
#   - Vulnerability type (SQL Injection, Command Injection etc.)
#   - Affected files (which modules are impacted)
#
# WHY THIS MATTERS:
#   Without clustering, you have 51 individual findings.
#   With clustering, you have 8 groups ranked by priority.
#   This answers: "What should we fix FIRST?" not just "what's broken?"
# ============================================================

from pathlib import Path


def get_module_name(filepath: str) -> str:
    """
    Extract clean module name from file path.
    'data\\vulnerable\\auth_service.py' → 'auth_service'
    """
    return Path(filepath).stem


def aggregate_by_type(findings: list) -> dict:
    """
    Group findings by vulnerability type.

    Returns a dict:
    {
      "SQL Injection": [finding1, finding2, ...],
      "Command Injection": [...],
      ...
    }
    """
    clusters = {}
    for finding in findings:
        vuln_type = finding.get("type", "Unknown")
        if vuln_type not in clusters:
            clusters[vuln_type] = []
        clusters[vuln_type].append(finding)
    return clusters


def build_clusters(findings: list) -> list:
    """
    Build structured cluster objects from grouped findings.

    Each cluster contains:
    - cluster_id       : int
    - type             : vulnerability type
    - count            : number of findings
    - affected_files   : unique files impacted
    - affected_modules : clean module names
    - findings         : all individual findings
    - avg_risk         : average final_risk score
    - max_risk         : highest risk in cluster
    - avg_llm_conf     : average LLM confidence
    - exploit_confidence: max LLM confidence (worst case)
    - all_validated    : True if all patches validated
    """
    grouped = aggregate_by_type(findings)
    clusters = []

    for cluster_id, (vuln_type, type_findings) in enumerate(grouped.items(), 1):
        # Collect unique affected files
        affected_files = list({f.get("file", "") for f in type_findings})
        affected_modules = list({get_module_name(f.get("file", "")) for f in type_findings})

        # Compute aggregate stats
        risk_scores = [f.get("final_risk", 0) for f in type_findings]
        llm_confs   = [f.get("llm_confidence", 0.5) for f in type_findings]
        validated   = [f.get("validated", False) for f in type_findings]

        avg_risk    = round(sum(risk_scores) / len(risk_scores), 4)
        max_risk    = round(max(risk_scores), 4)
        avg_llm_conf = round(sum(llm_confs) / len(llm_confs), 4)
        exploit_conf = round(max(llm_confs), 4)

        clusters.append({
            "cluster_id":         cluster_id,
            "type":               vuln_type,
            "count":              len(type_findings),
            "affected_files":     affected_files,
            "affected_modules":   affected_modules,
            "findings":           type_findings,
            "avg_risk":           avg_risk,
            "max_risk":           max_risk,
            "avg_llm_confidence": avg_llm_conf,
            "exploit_confidence": exploit_conf,
            "all_validated":      all(validated),
            "patch_rate":         round(sum(validated) / len(validated), 2),
        })

    return clusters


if __name__ == "__main__":
    import json
    with open("outputs/final_report.json") as f:
        findings = json.load(f)
    clusters = build_clusters(findings)
    for c in clusters:
        print(f"{c['type']}: {c['count']} findings across {len(c['affected_files'])} files | avg_risk={c['avg_risk']}")
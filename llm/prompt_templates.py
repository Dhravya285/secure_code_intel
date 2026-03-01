# ============================================================
# llm/prompt_templates.py
# ============================================================
from config import CWE_MAP, PATCH_HINT


def build_vuln_prompt(finding: dict) -> str:
    vuln_type = finding.get("type", "")
    code      = finding.get("code", "")
    line_num  = finding.get("line", "")

    correct_cwe = CWE_MAP.get(vuln_type, "CWE-unknown")
    patch_hint  = PATCH_HINT.get(vuln_type, "# use safe alternative")

    prompt = f"""You are a security analyzer. Respond with ONLY a JSON object. No extra text.

Line {line_num}: {code}
Issue: {vuln_type} ({correct_cwe})

Return ONLY this JSON (keep all values short):
{{"explanation": "one sentence max",
"exploit": "one sentence max",
"patched_code": "{patch_hint}",
"cwe": "{correct_cwe}",
"severity_confidence": 0.85}}

IMPORTANT: patched_code must be a single line. Each value max 10 words. Return ONLY the JSON."""

    return prompt


def build_cluster_prompt(cluster: dict) -> str:
    prompt = f"""You are a security advisor. Respond with ONLY a JSON object. No extra text.

Cluster: {cluster.get('type')}
Files: {', '.join(cluster.get('affected_files', []))}
Count: {cluster.get('count')}
Priority Score: {cluster.get('priority_score')}

Return ONLY this JSON:
{{"why_critical": "one sentence",
"business_impact": "one sentence",
"fix_order": "one sentence",
"estimated_effort": "low/medium/high"}}"""

    return prompt
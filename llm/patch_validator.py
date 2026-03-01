# ============================================================
# llm/patch_validator.py — Patch Validation Feedback Loop
# ============================================================
# For each LLM-generated patch:
#   Step 1: Syntax check via ast.parse()
#   Step 2: Re-run static scanner on the patch
#   Step 3: If still vulnerable → penalize score
#   Step 4: If syntax fails → retry LLM once
#
# This is your feedback loop — what makes this system credible.
# ============================================================

import ast
from scanner.ast_scanner import detect_sql_injection, detect_command_injection, detect_hardcoded_credentials
def _repair_patch(code: str) -> str:
    """
    Auto-fix common Llama patch generation errors.
    """
    code = code.strip()

    # Fix unclosed parentheses
    open_p = code.count('(')
    close_p = code.count(')')
    if open_p > close_p:
        code += ')' * (open_p - close_p)

    # Fix unclosed brackets
    open_b = code.count('[')
    close_b = code.count(']')
    if open_b > close_b:
        code += ']' * (open_b - close_b)

    # Fix unclosed quotes
    if code.count('"') % 2 != 0:
        code += '"'
    if code.count("'") % 2 != 0:
        code += "'"

    return code

def check_syntax(code: str) -> tuple[bool, str]:
    """
    Validate Python syntax using ast.parse().

    Returns:
        (is_valid: bool, error_message: str)
    """
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, str(e)


def check_still_vulnerable(patched_code: str, vuln_type: str) -> bool:
    """
    Re-run the static scanner on patched code.
    Returns True if the patch is STILL vulnerable.
    """
    try:
        tree = ast.parse(patched_code)
        lines = patched_code.splitlines()

        findings = []
        if vuln_type == "SQL Injection":
            findings = detect_sql_injection(tree, lines)
        elif vuln_type == "Command Injection":
            findings = detect_command_injection(tree, lines)
        elif vuln_type == "Hardcoded Credentials":
            findings = detect_hardcoded_credentials(tree, lines)

        return len(findings) > 0

    except SyntaxError:
        # Can't parse = can't validate = assume still vulnerable
        return True


def validate_patch(finding: dict, llm_response: dict) -> dict:
    """
    Full patch validation pipeline for a single finding.

    Input:
        finding      — original vulnerability finding
        llm_response — parsed LLM JSON with patched_code

    Returns:
        validation result dict with:
          - syntax_valid: bool
          - still_vulnerable: bool
          - validated: bool (True = patch is good)
          - score_penalty: float (applied to final score)
          - validation_notes: str
    """
    patched_code = llm_response.get("patched_code", "")
    patched_code = _repair_patch(patched_code)
    llm_response["patched_code"] = patched_code  # save repaired version
    vuln_type = finding.get("type", "")

    result = {
        "syntax_valid": False,
        "still_vulnerable": True,
        "validated": False,
        "score_penalty": 0.0,
        "validation_notes": ""
    }

    # ── STEP 1: Syntax Check ────────────────────────────────
    is_valid_syntax, syntax_error = check_syntax(patched_code)
    result["syntax_valid"] = is_valid_syntax

    if not is_valid_syntax:
        result["score_penalty"] = 0.15
        result["validation_notes"] = f"Patch has syntax error: {syntax_error}"
        print(f"    [PATCH] ❌ Syntax invalid — {syntax_error[:60]}")
        return result

    print(f"    [PATCH] ✅ Syntax valid")

    # ── STEP 2: Re-scan patch ────────────────────────────────
    still_vuln = check_still_vulnerable(patched_code, vuln_type)
    result["still_vulnerable"] = still_vuln

    if still_vuln:
        result["score_penalty"] = 0.1
        result["validation_notes"] = "Patch generated but scanner still detects vulnerability pattern"
        print(f"    [PATCH] ⚠️  Still vulnerable after patch")
    else:
        result["validated"] = True
        result["score_penalty"] = 0.0
        result["validation_notes"] = "Patch passed syntax check and re-scan"
        print(f"    [PATCH] ✅ Vulnerability resolved in patch")

    return result
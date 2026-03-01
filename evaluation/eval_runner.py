# ============================================================
# evaluation/eval_runner.py — Precision / Recall / F1
# ============================================================
# Evaluates scanner accuracy against a labelled dataset.
#
# GROUND TRUTH:
#   We know which files are vulnerable and which are safe.
#   We label every (file, vuln_type) pair as True Positive
#   or True Negative.
#
# METRICS:
#   Precision = TP / (TP + FP)  ← of all flagged, how many real?
#   Recall    = TP / (TP + FN)  ← of all real vulns, how many found?
#   F1        = 2 * P * R / (P + R)  ← harmonic mean
#
# WHY THIS MAKES IT ML-CREDIBLE:
#   Any system can flag everything. Evaluation proves your
#   scanner is actually accurate, not just noisy.
# ============================================================

from scanner.ast_scanner import scan_file
from pathlib import Path


# ============================================================
# GROUND TRUTH LABELS
# ============================================================
# Format: { "filename": ["VulnType1", "VulnType2", ...] }
# These are the vulnerabilities we KNOW exist in each file.

GROUND_TRUTH_VULNERABLE = {
    "auth.py":          ["SQL Injection"],
    "login.py":         ["SQL Injection"],
    "config.py":        ["Hardcoded Credentials"],
    "db.py":            ["SQL Injection", "Command Injection"],
    "api.py":           ["Command Injection"],
    "utils.py":         ["Command Injection", "Hardcoded Credentials"],
    "user_service.py":  ["SQL Injection", "SSRF", "Hardcoded Credentials"],
    "file_manager.py":  ["Path Traversal", "Command Injection", "Weak Cryptography"],
    "api_server.py":    ["SQL Injection", "Command Injection", "Debug Mode"],
    "data_pipeline.py": ["Insecure Deserialization", "Path Traversal", "Hardcoded Credentials"],
    "auth_service.py":  ["SQL Injection", "Weak Cryptography", "Hardcoded Credentials", "SSRF"],
    "admin_panel.py":   ["SQL Injection", "Command Injection", "Path Traversal",
                         "Insecure Deserialization", "Weak Cryptography",
                         "Debug Mode", "Hardcoded Credentials", "SSRF"],
}

GROUND_TRUTH_SAFE = {
    "auth.py":    [],
    "login.py":   [],
    "config.py":  [],
    "db.py":      [],
    "api.py":     [],
    "utils.py":   [],
}


def run_evaluation(vulnerable_dir: str, safe_dir: str) -> dict:
    """
    Run full evaluation against ground truth labels.

    Returns metrics dict with TP, FP, FN, TN, precision, recall, F1.
    """
    tp = 0  # correctly flagged
    fp = 0  # flagged but actually safe
    fn = 0  # missed — should have been flagged
    tn = 0  # correctly not flagged

    results_per_file = []

    # ── Evaluate vulnerable files ──────────────────────────
    for filename, expected_types in GROUND_TRUTH_VULNERABLE.items():
        filepath = str(Path(vulnerable_dir) / filename)
        if not Path(filepath).exists():
            continue

        findings    = scan_file(filepath)
        found_types = list({f["type"] for f in findings})

        file_tp = 0
        file_fp = 0
        file_fn = 0

        # Check each expected vuln type
        for expected in expected_types:
            if expected in found_types:
                file_tp += 1
            else:
                file_fn += 1

        # Check for false positives (found but not expected)
        for found in found_types:
            if found not in expected_types:
                file_fp += 1

        tp += file_tp
        fp += file_fp
        fn += file_fn

        results_per_file.append({
            "file":     filename,
            "expected": expected_types,
            "found":    found_types,
            "tp":       file_tp,
            "fp":       file_fp,
            "fn":       file_fn,
        })

    # ── Evaluate safe files ────────────────────────────────
    for filename in GROUND_TRUTH_SAFE:
        filepath = str(Path(safe_dir) / filename)
        if not Path(filepath).exists():
            continue

        findings    = scan_file(filepath)
        found_types = list({f["type"] for f in findings})

        if not found_types:
            tn += 1
            results_per_file.append({
                "file":     f"safe/{filename}",
                "expected": [],
                "found":    [],
                "tp": 0, "fp": 0, "fn": 0,
            })
        else:
            fp += len(found_types)
            results_per_file.append({
                "file":     f"safe/{filename}",
                "expected": [],
                "found":    found_types,
                "tp": 0, "fp": len(found_types), "fn": 0,
            })

    # ── Compute metrics ────────────────────────────────────
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    return {
        "tp":        tp,
        "fp":        fp,
        "fn":        fn,
        "tn":        tn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1_score":  round(f1, 4),
        "per_file":  results_per_file,
    }
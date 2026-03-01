# ============================================================
# config.py — Central configuration
# ============================================================

# --- LLM Settings ---
LLM_MODEL = "llama3.2:3b"
LLM_PROVIDER = "ollama"

# --- Risk Scoring Weights ---
STATIC_SEVERITY_WEIGHT = 0.6
STATIC_FEATURE_WEIGHT = 0.4

# --- Hybrid Scoring Weights ---
HYBRID_STATIC_WEIGHT = 0.6
HYBRID_LLM_WEIGHT = 0.4

# --- Base Severity Scores (domain knowledge 0–1) ---
BASE_SEVERITY = {
    "SQL Injection":              0.90,
    "Command Injection":          0.95,
    "Hardcoded Credentials":      0.75,
    "Path Traversal":             0.85,
    "Insecure Deserialization":   0.92,
    "SSRF":                       0.88,
    "Weak Cryptography":          0.70,
    "Debug Mode":                 0.60,
}

# --- CWE Mapping ---
CWE_MAP = {
    "SQL Injection":              "CWE-89",
    "Command Injection":          "CWE-78",
    "Hardcoded Credentials":      "CWE-798",
    "Path Traversal":             "CWE-22",
    "Insecure Deserialization":   "CWE-502",
    "SSRF":                       "CWE-918",
    "Weak Cryptography":          "CWE-327",
    "Debug Mode":                 "CWE-94",
}

# --- Patch hints for LLM prompt (keeps responses short) ---
PATCH_HINT = {
    "SQL Injection":              'cursor.execute("SELECT * FROM t WHERE id=?", (user_id,))',
    "Command Injection":          'subprocess.run(["cmd", arg], shell=False)',
    "Hardcoded Credentials":      'password = os.environ.get("PASSWORD")',
    "Path Traversal":             'open(os.path.basename(filename))',
    "Insecure Deserialization":   'data = json.loads(user_input)',
    "SSRF":                       'requests.get(validated_url)',
    "Weak Cryptography":          'hashlib.sha256(data).hexdigest()',
    "Debug Mode":                 'DEBUG = os.environ.get("DEBUG", "false") == "true"',
}

# --- Output paths ---
SCAN_RESULTS_PATH    = "outputs/scan_results.json"
SCORED_VULNS_PATH    = "outputs/scored_vulns.json"
FINAL_REPORT_PATH    = "outputs/final_report.json"
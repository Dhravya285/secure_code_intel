# ============================================================
# scanner/feature_engineer.py — Feature Engineering (8 types)
# ============================================================

def extract_sql_features(finding):
    details = finding.get("details", {})
    return {
        "has_sql_keyword":   1,
        "uses_concat":       int(details.get("uses_concat", False)),
        "uses_user_input":   int(details.get("uses_user_input", False)),
        "dangerous_function": 1,
    }

def extract_cmd_features(finding):
    details = finding.get("details", {})
    return {
        "uses_os_subprocess": 1,
        "uses_concat":        int(details.get("uses_concat", False)),
        "uses_user_input":    int(details.get("uses_user_input", False)),
        "dangerous_function": 1,
    }

def extract_cred_features(finding):
    details = finding.get("details", {})
    return {
        "is_sensitive_varname": 1,
        "is_string_literal":    1,
        "long_secret":          int(details.get("value_length", 0) > 10),
        "dangerous_function":   0,
    }

def extract_path_traversal_features(finding):
    details = finding.get("details", {})
    return {
        "uses_file_open":    1,
        "uses_concat":       int(details.get("uses_concat", False)),
        "uses_user_input":   int(details.get("uses_user_input", False)),
        "dangerous_function": 1,
    }

def extract_deserialization_features(finding):
    details = finding.get("details", {})
    return {
        "uses_pickle_yaml":  1,
        "uses_user_input":   int(details.get("uses_user_input", False)),
        "dangerous_function": 1,
        "uses_concat":       0,
    }

def extract_ssrf_features(finding):
    details = finding.get("details", {})
    return {
        "uses_http_call":    1,
        "uses_concat":       int(details.get("uses_concat", False)),
        "uses_user_input":   int(details.get("uses_user_input", False)),
        "dangerous_function": 1,
    }

def extract_weak_crypto_features(finding):
    return {
        "uses_weak_algorithm": 1,
        "dangerous_function":  1,
        "uses_concat":         0,
        "uses_user_input":     0,
    }

def extract_debug_mode_features(finding):
    return {
        "debug_enabled":      1,
        "dangerous_function": 0,
        "uses_concat":        0,
        "uses_user_input":    0,
    }


# ============================================================
# FEATURE SIGNAL SCORE
# ============================================================

def compute_feature_signal(features: dict) -> float:
    weights = {
        "uses_user_input":      0.40,
        "uses_concat":          0.25,
        "has_sql_keyword":      0.10,
        "uses_os_subprocess":   0.10,
        "uses_pickle_yaml":     0.15,
        "uses_http_call":       0.10,
        "uses_weak_algorithm":  0.10,
        "uses_file_open":       0.10,
        "is_sensitive_varname": 0.10,
        "is_string_literal":    0.05,
        "long_secret":          0.05,
        "debug_enabled":        0.10,
        "dangerous_function":   0.10,
    }
    score = sum(weights.get(f, 0.0) * v for f, v in features.items())
    return round(min(score, 1.0), 4)


# ============================================================
# MAIN
# ============================================================

FEATURE_EXTRACTORS = {
    "SQL Injection":            extract_sql_features,
    "Command Injection":        extract_cmd_features,
    "Hardcoded Credentials":    extract_cred_features,
    "Path Traversal":           extract_path_traversal_features,
    "Insecure Deserialization": extract_deserialization_features,
    "SSRF":                     extract_ssrf_features,
    "Weak Cryptography":        extract_weak_crypto_features,
    "Debug Mode":               extract_debug_mode_features,
}

def engineer_features(finding: dict) -> dict:
    vuln_type = finding.get("type", "")
    extractor = FEATURE_EXTRACTORS.get(vuln_type)
    features = extractor(finding) if extractor else {}
    signal = compute_feature_signal(features)
    return {**finding, "features": features, "feature_signal": signal}

def engineer_all(findings: list) -> list:
    return [engineer_features(f) for f in findings]
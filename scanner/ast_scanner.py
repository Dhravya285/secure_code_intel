# ============================================================
# scanner/ast_scanner.py — AST-based Static Scanner
# ============================================================
# Detects 8 vulnerability types:
#   1. SQL Injection
#   2. Command Injection
#   3. Hardcoded Credentials
#   4. Path Traversal
#   5. Insecure Deserialization
#   6. SSRF
#   7. Weak Cryptography
#   8. Debug Mode
# ============================================================

import ast
import json
from pathlib import Path


# ============================================================
# SHARED HELPERS
# ============================================================

def _uses_user_input(node: ast.AST) -> bool:
    """Check if node contains user-controlled input."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id == "input":
                return True
            if isinstance(child.func, ast.Attribute):
                if isinstance(child.func.value, ast.Name):
                    if child.func.value.id in {"request", "flask", "args", "form"}:
                        return True
        if isinstance(child, ast.Attribute):
            if child.attr in {"argv", "args", "form", "data", "json", "params"}:
                return True
    return False


def _uses_string_concat(node: ast.AST) -> bool:
    """Check if node contains string concatenation or f-strings."""
    for child in ast.walk(node):
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
            return True
        if isinstance(child, ast.JoinedStr):
            return True
    return False


def _get_func_name(node: ast.Call) -> tuple:
    """Returns (func_name, module_name) from a Call node."""
    func_name = ""
    module_name = ""
    if isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
        if isinstance(node.func.value, ast.Name):
            module_name = node.func.value.id
    elif isinstance(node.func, ast.Name):
        func_name = node.func.id
    return func_name, module_name


# ============================================================
# DETECTOR 1: SQL Injection
# ============================================================

SQL_DANGEROUS_CALLS = {"execute", "raw", "query", "cursor"}
SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE"}

def detect_sql_injection(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, _ = _get_func_name(node)
        if func_name not in SQL_DANGEROUS_CALLS:
            continue
        for arg in node.args:
            arg_source = ast.unparse(arg)
            has_sql = any(kw in arg_source.upper() for kw in SQL_KEYWORDS)
            has_concat = _uses_string_concat(arg)
            has_input = _uses_user_input(arg)
            if has_sql and (has_concat or has_input):
                findings.append({
                    "type": "SQL Injection",
                    "line": node.lineno,
                    "code": source_lines[node.lineno - 1].strip(),
                    "details": {
                        "function_called": func_name,
                        "has_sql_keyword": has_sql,
                        "uses_concat": has_concat,
                        "uses_user_input": has_input,
                    }
                })
    return findings


# ============================================================
# DETECTOR 2: Command Injection
# ============================================================

CMD_DANGEROUS_CALLS = {"system", "popen", "run", "call", "Popen", "check_output"}
CMD_MODULES = {"os", "subprocess"}

def detect_command_injection(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, module_name = _get_func_name(node)
        is_cmd = (
            func_name in CMD_DANGEROUS_CALLS and
            (module_name in CMD_MODULES or module_name == "")
        )
        if not is_cmd:
            continue
        for arg in node.args:
            has_concat = _uses_string_concat(arg)
            has_input = _uses_user_input(arg)
            if has_concat or has_input:
                findings.append({
                    "type": "Command Injection",
                    "line": node.lineno,
                    "code": source_lines[node.lineno - 1].strip(),
                    "details": {
                        "function_called": f"{module_name}.{func_name}" if module_name else func_name,
                        "uses_concat": has_concat,
                        "uses_user_input": has_input,
                    }
                })
    return findings


# ============================================================
# DETECTOR 3: Hardcoded Credentials
# ============================================================

CREDENTIAL_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "api_key",
    "apikey", "token", "auth_token", "private_key", "access_key"
}

def detect_hardcoded_credentials(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            var_name = ""
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
            elif isinstance(target, ast.Attribute):
                var_name = target.attr.lower()
            if not any(kw in var_name for kw in CREDENTIAL_KEYWORDS):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
                if len(value) > 3 and value not in {"", "None", "null", "placeholder", "changeme"}:
                    findings.append({
                        "type": "Hardcoded Credentials",
                        "line": node.lineno,
                        "code": source_lines[node.lineno - 1].strip(),
                        "details": {
                            "variable_name": var_name,
                            "credential_type": var_name,
                            "value_length": len(value),
                        }
                    })
    return findings


# ============================================================
# DETECTOR 4: Path Traversal
# ============================================================

PATH_DANGEROUS_CALLS = {"open", "listdir", "walk", "glob", "read_text", "read_bytes"}

def detect_path_traversal(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, module_name = _get_func_name(node)
        if func_name not in PATH_DANGEROUS_CALLS:
            continue
        for arg in node.args:
            has_concat = _uses_string_concat(arg)
            has_input = _uses_user_input(arg)
            if has_concat or has_input:
                findings.append({
                    "type": "Path Traversal",
                    "line": node.lineno,
                    "code": source_lines[node.lineno - 1].strip(),
                    "details": {
                        "function_called": f"{module_name}.{func_name}" if module_name else func_name,
                        "uses_concat": has_concat,
                        "uses_user_input": has_input,
                    }
                })
    return findings


# ============================================================
# DETECTOR 5: Insecure Deserialization
# ============================================================

DESERIAL_DANGEROUS = {"loads", "load", "Unpickler"}
DESERIAL_MODULES   = {"pickle", "yaml", "marshal", "shelve"}

def detect_insecure_deserialization(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, module_name = _get_func_name(node)
        is_deserial = (
            func_name in DESERIAL_DANGEROUS and
            module_name in DESERIAL_MODULES
        )
        if not is_deserial:
            continue
        # Any use of pickle.loads / yaml.load is dangerous regardless of input source
        findings.append({
            "type": "Insecure Deserialization",
            "line": node.lineno,
            "code": source_lines[node.lineno - 1].strip(),
            "details": {
                "function_called": f"{module_name}.{func_name}",
                "module": module_name,
                "uses_user_input": any(_uses_user_input(a) for a in node.args),
            }
        })
    return findings


# ============================================================
# DETECTOR 6: SSRF (Server-Side Request Forgery)
# ============================================================

SSRF_DANGEROUS_CALLS = {"get", "post", "put", "delete", "request", "urlopen", "urlretrieve"}
SSRF_MODULES = {"requests", "urllib", "httpx", "aiohttp"}

def detect_ssrf(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, module_name = _get_func_name(node)
        is_http = (
            func_name in SSRF_DANGEROUS_CALLS and
            module_name in SSRF_MODULES
        )
        if not is_http:
            continue
        for arg in node.args:
            has_concat = _uses_string_concat(arg)
            has_input = _uses_user_input(arg)
            if has_concat or has_input:
                findings.append({
                    "type": "SSRF",
                    "line": node.lineno,
                    "code": source_lines[node.lineno - 1].strip(),
                    "details": {
                        "function_called": f"{module_name}.{func_name}",
                        "uses_concat": has_concat,
                        "uses_user_input": has_input,
                    }
                })
    return findings


# ============================================================
# DETECTOR 7: Weak Cryptography
# ============================================================

WEAK_CRYPTO_CALLS = {"md5", "sha1", "new"}
WEAK_CRYPTO_MODULES = {"md5", "sha1"}  # direct imports
WEAK_ALGO_STRINGS = {"md5", "sha1", "des", "rc4", "sha"}

def detect_weak_cryptography(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name, module_name = _get_func_name(node)

        # hashlib.md5(), hashlib.sha1()
        is_weak_hashlib = (
            module_name == "hashlib" and
            func_name in {"md5", "sha1"}
        )

        # hashlib.new("md5") or hashlib.new("sha1")
        is_weak_new = False
        if module_name == "hashlib" and func_name == "new":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.lower() in WEAK_ALGO_STRINGS:
                        is_weak_new = True

        # Cryptography module with weak algorithms
        is_weak_crypto_module = (
            module_name in {"DES", "ARC4", "Blowfish"} or
            func_name in {"DES", "ARC4"}
        )

        if is_weak_hashlib or is_weak_new or is_weak_crypto_module:
            findings.append({
                "type": "Weak Cryptography",
                "line": node.lineno,
                "code": source_lines[node.lineno - 1].strip(),
                "details": {
                    "function_called": f"{module_name}.{func_name}",
                    "algorithm": func_name,
                }
            })
    return findings


# ============================================================
# DETECTOR 8: Debug Mode
# ============================================================

def detect_debug_mode(tree, source_lines):
    findings = []
    for node in ast.walk(tree):
        # debug=True in function calls like app.run(debug=True)
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "debug":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append({
                            "type": "Debug Mode",
                            "line": node.lineno,
                            "code": source_lines[node.lineno - 1].strip(),
                            "details": {
                                "pattern": "debug=True in function call",
                            }
                        })

        # DEBUG = True assignments
        if isinstance(node, ast.Assign):
            for target in node.targets:
                var_name = ""
                if isinstance(target, ast.Name):
                    var_name = target.id.upper()
                if var_name == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append({
                            "type": "Debug Mode",
                            "line": node.lineno,
                            "code": source_lines[node.lineno - 1].strip(),
                            "details": {
                                "pattern": "DEBUG = True assignment",
                            }
                        })
    return findings


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_file(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        print(f"[WARN] File not found: {filepath}")
        return []

    source = path.read_text(encoding="utf-8")
    source_lines = source.splitlines()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"[ERROR] Could not parse {filepath}: {e}")
        return []

    findings = []
    findings += detect_sql_injection(tree, source_lines)
    findings += detect_command_injection(tree, source_lines)
    findings += detect_hardcoded_credentials(tree, source_lines)
    findings += detect_path_traversal(tree, source_lines)
    findings += detect_insecure_deserialization(tree, source_lines)
    findings += detect_ssrf(tree, source_lines)
    findings += detect_weak_cryptography(tree, source_lines)
    findings += detect_debug_mode(tree, source_lines)

    for f in findings:
        f["file"] = str(path)

    return findings


def scan_directory(directory: str) -> list:
    all_findings = []
    for pyfile in Path(directory).rglob("*.py"):
        results = scan_file(str(pyfile))
        all_findings.extend(results)
    return all_findings


if __name__ == "__main__":
    results = scan_directory("data/vulnerable")
    print(json.dumps(results, indent=2))
    print(f"\n[INFO] Total: {len(results)}")
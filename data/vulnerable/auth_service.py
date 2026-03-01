# data/vulnerable/auth_service.py
# Contains: SQL Injection + Weak Cryptography + Hardcoded Credentials + SSRF
import sqlite3
import hashlib
import requests

# ❌ Hardcoded Credentials
password    = "admin_master_pass"
auth_token  = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
private_key = "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA"

def login(username, password):
    conn = sqlite3.connect("auth.db")
    cursor = conn.cursor()
    # ❌ SQL Injection
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def store_password(raw_password):
    # ❌ Weak Cryptography — MD5 for password storage
    return hashlib.md5(raw_password.encode()).hexdigest()

def verify_token(token):
    # ❌ Weak Cryptography — SHA1 for token verification
    return hashlib.sha1(token.encode()).hexdigest()

def validate_user_via_sso(sso_endpoint):
    # ❌ SSRF — user-controlled SSO endpoint
    response = requests.get("http://sso.internal/" + sso_endpoint)
    return response.json()

def lookup_user_external(user_ref):
    # ❌ SSRF — user ref passed to internal service
    import requests
    return requests.get(f"http://user-service.internal/lookup/{user_ref}").json()
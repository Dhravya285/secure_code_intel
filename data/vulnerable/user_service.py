# data/vulnerable/user_service.py
# Contains: SQL Injection + SSRF + Hardcoded Credentials
import sqlite3
import requests

# ❌ Hardcoded Credentials
api_key = "sk-prod-abc123xyz789"
secret = "jwt_secret_do_not_share"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # ❌ SQL Injection — user_id concatenated directly
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    return cursor.fetchone()

def search_users(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # ❌ SQL Injection — name concatenated into query
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
    return cursor.fetchall()

def fetch_user_avatar(url):
    # ❌ SSRF — user-controlled URL passed directly to requests.get
    response = requests.get("http://avatars.internal/" + url)
    return response.content

def fetch_user_profile(profile_url):
    # ❌ SSRF — f-string with user input
    import requests
    response = requests.get(f"http://api.internal/profile/{profile_url}")
    return response.json()
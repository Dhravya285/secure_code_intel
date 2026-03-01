# data/vulnerable/admin_panel.py
# THE KITCHEN SINK — contains all 8 vulnerability types
import os
import sqlite3
import pickle
import hashlib
import subprocess
import requests
from flask import Flask

app = Flask(__name__)

# ❌ 1. Hardcoded Credentials
password   = "super_admin_pass_2024"
api_key    = "sk-admin-key-xyz987abc"

# ❌ 2. Debug Mode
DEBUG = True

def get_user(user_id):
    conn = sqlite3.connect("admin.db")
    cursor = conn.cursor()
    # ❌ 3. SQL Injection
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    return cursor.fetchone()

def run_admin_command(cmd):
    # ❌ 4. Command Injection
    os.system("sudo " + cmd)

def read_log(log_name):
    # ❌ 5. Path Traversal
    return open("logs/" + log_name).read()

def restore_session(session_data):
    # ❌ 6. Insecure Deserialization
    return pickle.loads(session_data)

def hash_admin_password(pwd):
    # ❌ 7. Weak Cryptography
    return hashlib.md5(pwd.encode()).hexdigest()

def fetch_external_resource(resource_url):
    # ❌ 8. SSRF
    return requests.get("http://internal.admin/" + resource_url).text

@app.route("/admin")
def admin():
    # ❌ Debug Mode in run
    app.run(debug=True)
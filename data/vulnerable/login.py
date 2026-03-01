import sqlite3

def find_user(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email='" + email + "'")
    return cursor.fetchone()
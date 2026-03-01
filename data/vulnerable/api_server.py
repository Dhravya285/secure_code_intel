# data/vulnerable/api_server.py
# Contains: Debug Mode + SQL Injection + Command Injection
import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

# ❌ Debug Mode — exposes stack traces and interactive debugger
DEBUG = True

def get_product(product_id):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # ❌ SQL Injection
    cursor.execute("SELECT * FROM products WHERE id=" + product_id)
    return cursor.fetchone()

def search_orders(customer_name):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # ❌ SQL Injection — name directly in query
    query = "SELECT * FROM orders WHERE customer='" + customer_name + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_diagnostics(host):
    # ❌ Command Injection — host from user
    os.system("ping -c 4 " + host)

@app.route("/run")
def run():
    # ❌ Debug Mode in app.run
    app.run(debug=True, host="0.0.0.0")
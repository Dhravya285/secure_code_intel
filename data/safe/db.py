import os
import sqlite3
import subprocess

def search_products(name):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name='" + name + "'")
    return cursor.fetchall()

def run_backup(filename):
    os.system("tar -czf backup.tar.gz " + filename)

def run_report(report_name):
    subprocess.run("python reports/" + report_name, shell=True)
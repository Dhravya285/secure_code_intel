# data/vulnerable/file_manager.py
# Contains: Path Traversal + Command Injection + Weak Cryptography
import os
import hashlib
import subprocess

def read_user_file(filename):
    # ❌ Path Traversal — filename from user input directly opened
    return open("uploads/" + filename).read()

def get_user_document(doc_path):
    # ❌ Path Traversal — f-string path
    with open(f"documents/{doc_path}", "r") as f:
        return f.read()

def list_user_files(directory):
    # ❌ Path Traversal — user-controlled directory
    return os.listdir("users/" + directory)

def compress_file(filename):
    # ❌ Command Injection — filename passed to shell command
    os.system("zip output.zip " + filename)

def convert_file(input_file, output_file):
    # ❌ Command Injection — both args user controlled
    subprocess.run("convert " + input_file + " " + output_file, shell=True)

def hash_password(password):
    # ❌ Weak Cryptography — MD5 is broken for passwords
    return hashlib.md5(password.encode()).hexdigest()

def generate_token(user_id):
    # ❌ Weak Cryptography — SHA1 is insufficient
    return hashlib.sha1(user_id.encode()).hexdigest()
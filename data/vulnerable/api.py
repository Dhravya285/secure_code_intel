import os

def ping_host(host):
    os.system("ping -c 1 " + host)

def fetch_file(path):
    os.system("cat " + path)
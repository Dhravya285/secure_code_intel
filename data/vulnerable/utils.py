import subprocess

auth_token = "hardcoded_token_abc987"

def run_command(cmd):
    subprocess.run("bash -c " + cmd, shell=True)
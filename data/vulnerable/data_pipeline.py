# data/vulnerable/data_pipeline.py
# Contains: Insecure Deserialization + Path Traversal + Hardcoded Credentials
import pickle
import yaml
import os

# ❌ Hardcoded Credentials
db_password = "pipeline_secret_123"
access_key  = "AKIAIOSFODNN7EXAMPLE"

def load_user_data(serialized_data):
    # ❌ Insecure Deserialization — pickle.loads on user data = RCE
    return pickle.loads(serialized_data)

def load_config(config_data):
    # ❌ Insecure Deserialization — yaml.load without Loader is unsafe
    return yaml.load(config_data)

def load_pipeline_config(filepath):
    # ❌ Path Traversal — filepath from user
    with open("configs/" + filepath) as f:
        return yaml.load(f)

def save_result(filename, data):
    # ❌ Path Traversal — user-controlled filename
    with open("results/" + filename, "w") as f:
        f.write(str(data))

def load_checkpoint(checkpoint_name):
    # ❌ Insecure Deserialization — loading pickle checkpoint
    with open("checkpoints/" + checkpoint_name, "rb") as f:
        return pickle.load(f)
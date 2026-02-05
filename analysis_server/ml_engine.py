import pandas as pd
import os
import json
import re

MODEL_FILE = "model_weights.json"

behavior_risk = {}
permission_risk = {}

LABEL_COLUMNS = ["Class", "class", "label", "Label", "malware"]

BASE_PERMISSION_RISK = {
    "INTERNET": 5,
    "READ_CONTACTS": 20,
    "READ_SMS": 30,
    "RECORD_AUDIO": 25,
    "ACCESS_FINE_LOCATION": 15,
    "ACCESS_COARSE_LOCATION": 10,
}


# ---------- Utilities ----------

def detect_label_column(df):
    for col in LABEL_COLUMNS:
        if col in df.columns:
            return col
    raise ValueError("Label column not found")


def normalize_label(val):
    if isinstance(val, str):
        return val.lower() in ["malware", "1", "true"]
    return bool(val)


def clean_name(name):
    name = name.upper()
    name = re.sub(r"[^A-Z_]", "", name)
    return name.strip("_")


# ---------- Persistence ----------

def save_model():
    with open(MODEL_FILE, "w") as f:
        json.dump({
            "behavior_risk": behavior_risk,
            "permission_risk": permission_risk
        }, f)


def load_model():
    global behavior_risk, permission_risk
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "r") as f:
            data = json.load(f)
            behavior_risk = data.get("behavior_risk", {})
            permission_risk = data.get("permission_risk", {})


# ---------- Dataset Learning (CORRECT FOR COUNTS) ----------

def train_from_csv(csv_path):
    global behavior_risk

    if not os.path.exists(csv_path):
        load_model()
        return

    df = pd.read_csv(csv_path)
    label_col = detect_label_column(df)
    print(f"Detected label column: {label_col}")

    df["_label_"] = df[label_col].apply(normalize_label)
    malware_df = df[df["_label_"] == True]

    learned = {}

    malware_count = len(malware_df)

    for col in df.columns:
        if col in [label_col, "_label_"]:
            continue

        if not pd.api.types.is_numeric_dtype(df[col]):
            continue

        # Count how many malware samples used this feature
        usage = (malware_df[col] > 0).sum()

        if usage == 0:
            continue

        # Normalize by malware sample count
        risk_score = usage / malware_count

        learned[clean_name(col)] = round(float(risk_score * 100), 3)

    behavior_risk = learned
    save_model()

    print(f"Behavioral features learned: {len(behavior_risk)}")


# ---------- Android Analysis ----------

def analyze_permissions(android_permissions):
    score = 0
    flags = []

    for perm in android_permissions:
        key = perm.split(".")[-1].upper()

        if key in BASE_PERMISSION_RISK:
            score += BASE_PERMISSION_RISK[key]
            flags.append(key)

        if key in permission_risk:
            score += permission_risk[key]

    if score > 50:
        level = "DANGEROUS"
    elif score > 20:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "level": level,
        "score": score,
        "flags": flags
    }


# ---------- Adaptive Learning ----------

def adaptive_update(android_permissions, is_malware):
    delta = 3 if is_malware else -1

    for perm in android_permissions:
        key = perm.split(".")[-1].upper()
        permission_risk[key] = permission_risk.get(key, 0) + delta

    save_model()

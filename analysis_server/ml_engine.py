import pandas as pd
import os
import json
import re

# ================= CONFIG =================

CSV_PATH = "dataset/data.csv"
MODEL_FILE = "model_weights.json"

LABEL_COLUMNS = ["Class", "class", "label", "Label", "malware"]

PII_KEYWORDS = [
    "CONTACT", "SMS", "CALL", "PHONE", "ACCOUNT",
    "EMAIL", "LOCATION", "GPS", "IMEI", "IMSI"
]

SENSITIVE_KEYWORDS = [
    "AUDIO", "CAMERA", "MIC", "STORAGE",
    "FILE", "FS", "SYSTEM", "PROCESS",
    "EXEC", "DEBUG", "ROOT", "DEVICE", "NETWORK"
]

# GLOBAL MODEL STORAGE
feature_risk = {}

# ================= UTILITIES =================

def detect_label_column(df):
    for col in LABEL_COLUMNS:
        if col in df.columns:
            return col
    raise ValueError("Label column not found in dataset")


def normalize_label(val):
    if isinstance(val, str):
        return val.lower() in ["malware", "1", "true"]
    return bool(val)


def clean_name(name):
    name = name.upper()
    name = re.sub(r"[^A-Z_]", "", name)
    return name.strip("_")


def classify_feature(name):
    for k in PII_KEYWORDS:
        if k in name:
            return "PII"
    for k in SENSITIVE_KEYWORDS:
        if k in name:
            return "SENSITIVE"
    return "LOW_RISK"


def semantic_match(permission, feature):
    p = permission.upper()
    f = feature.upper()

    for kw in PII_KEYWORDS + SENSITIVE_KEYWORDS:
        if kw in p and kw in f:
            return True
    return False


# ================= MODEL PERSISTENCE =================

def save_model():
    global feature_risk
    with open(MODEL_FILE, "w") as f:
        json.dump(feature_risk, f)


def load_model():
    global feature_risk

    if not os.path.exists(MODEL_FILE):
        print("No saved model found. Starting fresh.")
        feature_risk = {}
        return

    with open(MODEL_FILE, "r") as f:
        data = json.load(f)

    # Handle wrapped structure
    if "behavior_risk" in data:
        raw = data["behavior_risk"]
        feature_risk = {}

        for feature, risk_value in raw.items():
            cleaned = clean_name(feature)
            feature_risk[cleaned] = {
                "risk": float(risk_value),
                "type": classify_feature(cleaned)
            }

    else:
        feature_risk = data

    print(f"Loaded model with {len(feature_risk)} features")


# ================= TRAINING =================

def train_from_csv(csv_path):
    global feature_risk

    if not os.path.exists(csv_path):
        print("Dataset not found. Loading saved model instead.")
        load_model()
        return

    df = pd.read_csv(csv_path)
    label_col = detect_label_column(df)
    print(f"Detected label column: {label_col}")

    df["_label_"] = df[label_col].apply(normalize_label)
    malware_df = df[df["_label_"] == True]

    if len(malware_df) == 0:
        print("No malware rows found. Skipping training.")
        return

    learned = {}

    for col in df.columns:
        if col in [label_col, "_label_"]:
            continue

        if not pd.api.types.is_numeric_dtype(df[col]):
            continue

        usage = (malware_df[col] > 0).sum()
        if usage == 0:
            continue

        risk_score = usage / len(malware_df)
        cleaned = clean_name(col)

        learned[cleaned] = {
            "risk": round(risk_score * 100, 2),
            "type": classify_feature(cleaned)
        }

    feature_risk = learned
    save_model()

    print(f"Behavioral features learned: {len(feature_risk)}")


def load_or_train():
    global feature_risk
    if os.path.exists(MODEL_FILE):
        load_model()
    else:
        train_from_csv(CSV_PATH)


# ================= ANALYSIS =================

def analyze_permissions(android_permissions):
    global feature_risk

    score = 0.0
    pii_detected = set()
    sensitive_detected = set()
    flags = set()

    for perm in android_permissions:
        key = perm.split(".")[-1].upper()

        for feature, data in feature_risk.items():
            if semantic_match(key, feature):
                score += data["risk"]
                flags.add(feature)

                if data["type"] == "PII":
                    pii_detected.add(key)
                elif data["type"] == "SENSITIVE":
                    sensitive_detected.add(key)

    # Normalize score to 0–100 scale
    normalized_score = min(100, round(score / 10, 2))

    if normalized_score >= 70:
        level = "DANGEROUS"
        leak_type = "High Risk PII / Sensitive Data Exfiltration"
    elif normalized_score >= 30:
        level = "SUSPICIOUS"
        leak_type = "Moderate Sensitive Data Exposure"
    else:
        level = "SAFE"
        leak_type = "Low Risk / No Critical Leak"

    return {
        "level": level,
        "score": normalized_score,
        "flags": sorted(flags),
        "leak_type": leak_type,
        "pii_detected": sorted(pii_detected),
        "sensitive_detected": sorted(sensitive_detected)
    }


# ================= ADAPTIVE LEARNING =================

def adaptive_update(android_permissions, is_malware):
    global feature_risk

    delta = 5 if is_malware else -2

    for perm in android_permissions:
        key = perm.split(".")[-1].upper()

        for feature in feature_risk:
            if semantic_match(key, feature):
                feature_risk[feature]["risk"] = max(
                    0, feature_risk[feature]["risk"] + delta
                )

    save_model()

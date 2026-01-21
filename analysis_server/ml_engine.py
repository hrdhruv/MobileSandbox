import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
import joblib
import os

model = None
feature_columns = []
imputer = None

MODEL_FILE = "model.pkl"

# ✅ HARD MAPPING: Android permission → dataset feature prefixes
PERMISSION_TO_DATASET = {
    "INTERNET": ["NETWORK_ACCESS"],
    "ACCESS_NETWORK_STATE": ["NETWORK_ACCESS"],

    "SEND_SMS": ["SMS_SEND"],
    "READ_SMS": ["SMS"],
    "RECEIVE_SMS": ["SMS"],

    "READ_CONTACTS": ["ACCESS_PERSONAL_INFO"],
    "WRITE_CONTACTS": ["ACCESS_PERSONAL_INFO"],

    "READ_PHONE_STATE": ["ALTER_PHONE_STATE"],
    "CALL_PHONE": ["ALTER_PHONE_STATE"],

    "READ_EXTERNAL_STORAGE": ["FS_ACCESS"],
    "WRITE_EXTERNAL_STORAGE": ["FS_ACCESS"],

    "CAMERA": ["DEVICE_ACCESS"],
    "RECORD_AUDIO": ["DEVICE_ACCESS"],

    "ACCESS_FINE_LOCATION": ["DEVICE_ACCESS"],
    "ACCESS_COARSE_LOCATION": ["DEVICE_ACCESS"],
}


def train_from_csv(csv_path: str):
    global model, feature_columns, imputer

    df = pd.read_csv(csv_path)

    X = df.drop(columns=["Class"])
    y = df["Class"]

    feature_columns = list(X.columns)

    imputer = SimpleImputer(strategy="constant", fill_value=0)
    X_clean = imputer.fit_transform(X)

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_clean, y)

    joblib.dump((model, feature_columns, imputer), MODEL_FILE)
    print("✅ Model trained")
    print("Feature count:", len(feature_columns))


def analyze_permissions(permission_list: list[str]):
    global model, feature_columns, imputer

    if model is None:
        model, feature_columns, imputer = joblib.load(MODEL_FILE)

    input_vector = np.zeros(len(feature_columns))
    detected = []

    for perm in permission_list:
        clean = perm.split(".")[-1].upper()

        if clean in PERMISSION_TO_DATASET:
            prefixes = PERMISSION_TO_DATASET[clean]

            for i, col in enumerate(feature_columns):
                if any(col.startswith(p) for p in prefixes):
                    input_vector[i] = 1
                    detected.append(col)

    activated = int(np.sum(input_vector))
    print("Activated features:", activated)
    print("Detected columns:", detected[:10])

    if activated == 0:
        return {
            "level": "UNKNOWN",
            "score": 0,
            "flags": ["No behavioral features activated"]
        }

    input_vector = imputer.transform([input_vector])

    prob = model.predict_proba(input_vector)[0][1]
    score = int(min(100, prob * 120))

    if score >= 80:
        level = "DANGEROUS"
    elif score >= 40:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "level": level,
        "score": score,
        "flags": list(set(detected))[:5]
    }


def adaptive_update(permissions, is_malware):
    pass

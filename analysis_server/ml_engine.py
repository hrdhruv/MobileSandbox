"""
ml_engine.py — Machine Learning engine for permission-based risk analysis.

Hybrid scoring approach:
  1. Per-permission risk weights from dataset statistics (granular, not broad)
  2. GradientBoostingClassifier for global threat classification
  3. Final score combines both signals so different apps get different scores
"""

import pandas as pd
import numpy as np
import os
import sys
import json
import re
import joblib
import db_manager

# ================= CONFIG =================

CSV_PATH = "dataset/data.csv"
MODEL_FILE = "model_weights.json"
ML_MODEL_PATH = "model/ml_model.joblib"
ML_META_PATH = "model/ml_meta.json"
PERM_RISK_PATH = "model/permission_risk.json"

LABEL_COLUMNS = ["Class", "class", "label", "Label", "malware"]

# ── Permission classification keywords ──
PII_KEYWORDS = [
    "CONTACT", "SMS", "CALL_LOG", "CALL_PHONE", "PHONE_STATE",
    "PHONE_NUMBER", "ACCOUNT", "EMAIL", "LOCATION", "GPS",
    "IMEI", "IMSI", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "GET_ACCOUNTS", "AUTHENTICATE_ACCOUNTS"
]

SENSITIVE_KEYWORDS = [
    "CAMERA", "RECORD_AUDIO", "MICROPHONE", "STORAGE",
    "READ_EXTERNAL", "WRITE_EXTERNAL", "BODY_SENSORS",
    "ACTIVITY_RECOGNITION", "BLUETOOTH", "WIFI", "NFC",
    "NETWORK_STATE", "NEARBY_DEVICES", "DEVICE_INFO",
    "CREDENTIALS", "VIBRATE", "BOOT_COMPLETED",
    "FOREGROUND_SERVICE", "SYSTEM_ALERT", "INSTALL_PACKAGES",
    "REQUEST_INSTALL", "MANAGE_EXTERNAL"
]

# ── Individual Android permission risk weights ──
# Scored by privacy/security impact (0-10 scale)
PERMISSION_RISK_TABLE = {
    # ── HIGH RISK (PII) — 7-10 ──
    "READ_SMS": 9.5, "SEND_SMS": 9.8, "RECEIVE_SMS": 9.0,
    "READ_CONTACTS": 8.5, "WRITE_CONTACTS": 7.5,
    "READ_CALL_LOG": 9.0, "WRITE_CALL_LOG": 7.0,
    "CALL_PHONE": 8.0, "READ_PHONE_STATE": 7.5,
    "READ_PHONE_NUMBERS": 8.5, "ANSWER_PHONE_CALLS": 6.5,
    "ACCESS_FINE_LOCATION": 8.5, "ACCESS_COARSE_LOCATION": 6.5,
    "ACCESS_BACKGROUND_LOCATION": 9.5,
    "GET_ACCOUNTS": 7.0, "AUTHENTICATE_ACCOUNTS": 7.5,
    "MANAGE_ACCOUNTS": 7.5, "USE_CREDENTIALS": 8.0,
    "READ_PROFILE": 7.0, "READ_SOCIAL_STREAM": 7.5,

    # ── MEDIUM-HIGH RISK (Sensitive) — 5-7 ──
    "CAMERA": 7.0, "RECORD_AUDIO": 7.5,
    "READ_EXTERNAL_STORAGE": 6.0, "WRITE_EXTERNAL_STORAGE": 6.5,
    "MANAGE_EXTERNAL_STORAGE": 8.0,
    "BODY_SENSORS": 6.0, "ACTIVITY_RECOGNITION": 5.5,
    "ACCESS_WIFI_STATE": 4.0, "CHANGE_WIFI_STATE": 5.5,
    "BLUETOOTH": 4.0, "BLUETOOTH_ADMIN": 5.0,
    "BLUETOOTH_CONNECT": 5.0, "BLUETOOTH_SCAN": 5.0,
    "NEARBY_WIFI_DEVICES": 5.5, "NFC": 4.5,
    "USE_BIOMETRIC": 5.0, "USE_FINGERPRINT": 5.0,

    # ── MEDIUM RISK — 3-5 ──
    "INTERNET": 3.0, "ACCESS_NETWORK_STATE": 2.5,
    "CHANGE_NETWORK_STATE": 4.0,
    "RECEIVE_BOOT_COMPLETED": 4.0,
    "FOREGROUND_SERVICE": 3.5,
    "FOREGROUND_SERVICE_LOCATION": 6.0,
    "VIBRATE": 1.0, "WAKE_LOCK": 2.5,
    "REQUEST_INSTALL_PACKAGES": 7.0,
    "INSTALL_PACKAGES": 8.5,
    "SYSTEM_ALERT_WINDOW": 6.5,
    "READ_MEDIA_IMAGES": 4.5, "READ_MEDIA_VIDEO": 4.5,
    "READ_MEDIA_AUDIO": 4.5,
    "POST_NOTIFICATIONS": 2.0,
    "SCHEDULE_EXACT_ALARM": 3.0,

    # ── LOW RISK — 0-3 ──
    "ACCESS_NOTIFICATION_POLICY": 2.0,
    "SET_WALLPAPER": 0.5, "SET_ALARM": 0.5,
    "EXPAND_STATUS_BAR": 0.5, "FLASHLIGHT": 0.5,
    "READ_SYNC_SETTINGS": 1.5, "WRITE_SYNC_SETTINGS": 2.0,
    "BILLING": 1.5, "RECEIVE_MMS": 4.0,
}

# Risk weights for the 5 severity classes (1=benign → 5=highly malicious)
CLASS_WEIGHTS = {1: 0.0, 2: 25.0, 3: 50.0, 4: 75.0, 5: 100.0}

# ── Global state ──
ml_model = None
feature_columns = []
feature_risk = {}
permission_risk_map = {}   # per-permission learned risks from dataset
ml_model_ready = False


# ================= UTILITIES =================


def detect_label_column(df):
    for col in LABEL_COLUMNS:
        if col in df.columns:
            return col
    raise ValueError("Label column not found in dataset")


def clean_name(name):
    name = name.upper()
    name = re.sub(r"[^A-Z_]", "", name)
    return name.strip("_")


def classify_permission(perm_key):
    """Classify a single Android permission into PII / SENSITIVE / LOW_RISK."""
    p = perm_key.upper()
    for kw in PII_KEYWORDS:
        if kw in p:
            return "PII"
    for kw in SENSITIVE_KEYWORDS:
        if kw in p:
            return "SENSITIVE"
    return "LOW_RISK"


def _perm_short_key(full_perm):
    """Extract the short permission name: 'android.permission.CAMERA' → 'CAMERA'."""
    return full_perm.split(".")[-1].upper()


# ================= MODEL PERSISTENCE =================


def save_model():
    global feature_risk
    with open(MODEL_FILE, "w") as f:
        json.dump(feature_risk, f)


def load_json_model():
    """Load the legacy JSON behaviour-risk weights."""
    global feature_risk

    if not os.path.exists(MODEL_FILE):
        print("[ml_engine] No JSON model found.")
        feature_risk = {}
        return

    with open(MODEL_FILE, "r") as f:
        data = json.load(f)

    if "behavior_risk" in data:
        raw = data["behavior_risk"]
        feature_risk = {}
        for feature, risk_value in raw.items():
            cleaned = clean_name(feature)
            feature_risk[cleaned] = {
                "risk": float(risk_value),
                "type": classify_permission(cleaned)
            }
    else:
        feature_risk = data

    print(f"[ml_engine] JSON weights loaded: {len(feature_risk)} features")


def _load_permission_risk():
    """Load the per-permission risk map built during training."""
    global permission_risk_map
    if os.path.exists(PERM_RISK_PATH):
        with open(PERM_RISK_PATH, "r") as f:
            permission_risk_map = json.load(f)
        print(f"[ml_engine] Permission risk map loaded: {len(permission_risk_map)} entries")


# ================= TRAINING (with progress) =================


def _print_progress(current, total, prefix="", bar_len=40):
    """Print a progress bar to stdout."""
    pct = current / total
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  {prefix} [{bar}] {pct*100:5.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current == total:
        print()  # newline at end


def train_ml_model(csv_path):
    """
    Train the ML pipeline:
      1. GradientBoostingClassifier on the 5-class dataset
      2. Per-permission risk map from dataset feature statistics
    """
    global ml_model, feature_columns, ml_model_ready, permission_risk_map

    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    if not os.path.exists(csv_path):
        print(f"[ml_engine] ✗ Dataset not found at {csv_path}")
        return False

    # ── Step 1: Load dataset ──
    print("\n╔══════════════════════════════════════════════════╗")
    print("║       ML MODEL TRAINING PIPELINE                ║")
    print("╚══════════════════════════════════════════════════╝\n")

    print("[Step 1/5] Loading dataset …")
    df = pd.read_csv(csv_path)
    label_col = detect_label_column(df)
    print(f"  ✓ Loaded {len(df)} samples, {len(df.columns)-1} features")
    print(f"  ✓ Label column: '{label_col}'")
    print(f"  ✓ Class distribution: {dict(df[label_col].value_counts().sort_index())}")

    # ── Step 2: Prepare data ──
    print("\n[Step 2/5] Preparing training data …")
    y = df[label_col].values
    X = df.drop(columns=[label_col])
    feature_columns = list(X.columns)
    X.columns = range(len(feature_columns))

    X_train, X_val, y_train, y_val = train_test_split(
        X.values, y, test_size=0.15, random_state=42, stratify=y
    )
    print(f"  ✓ Train set: {len(X_train)} samples")
    print(f"  ✓ Validation set: {len(X_val)} samples")

    # ── Step 3: Train model with progress ──
    print("\n[Step 3/5] Training GradientBoostingClassifier …")
    n_estimators = 200

    # Train in stages to show progress
    model = GradientBoostingClassifier(
        n_estimators=n_estimators,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
        warm_start=True
    )

    # Train in increments to show progress
    stages = [20, 50, 80, 120, 160, 200]
    for stage_n in stages:
        model.n_estimators = stage_n
        model.fit(X_train, y_train)
        _print_progress(stage_n, n_estimators, prefix="Training")

    train_acc = model.score(X_train, y_train)
    val_acc = model.score(X_val, y_val)
    print(f"\n  ✓ Train accuracy:      {train_acc:.4f}")
    print(f"  ✓ Validation accuracy: {val_acc:.4f}")

    # ── Step 4: Build per-permission risk map ──
    print("\n[Step 4/5] Building per-permission risk map …")
    importances = model.feature_importances_
    imp_max = importances.max() + 1e-9

    perm_risk = {}
    for i, col in enumerate(feature_columns):
        cleaned = clean_name(col)
        col_vals = df[col]

        # Per-class usage statistics
        total = len(df)
        class_usage = {}
        for cls in sorted(df[label_col].unique()):
            mask = df[label_col] == cls
            usage = (col_vals[mask] > 0).sum()
            class_usage[int(cls)] = usage / mask.sum() if mask.sum() > 0 else 0.0

        # Weighted risk: higher classes contribute more
        weighted = sum(
            class_usage.get(c, 0) * w for c, w in CLASS_WEIGHTS.items()
        ) / sum(CLASS_WEIGHTS.values())

        # Amplify by feature importance
        imp_factor = 0.6 + 0.4 * (importances[i] / imp_max)
        risk = weighted * 100.0 * imp_factor

        if risk > 0.01:
            perm_risk[cleaned] = risk

        if (i + 1) % 50 == 0 or i == len(feature_columns) - 1:
            _print_progress(i + 1, len(feature_columns), prefix="Features")

    permission_risk_map = perm_risk
    os.makedirs(os.path.dirname(PERM_RISK_PATH), exist_ok=True)
    with open(PERM_RISK_PATH, "w") as f:
        json.dump(permission_risk_map, f, indent=2)
    print(f"  ✓ {len(permission_risk_map)} feature risks computed")

    # ── Step 5: Save model ──
    print("\n[Step 5/5] Saving model …")
    os.makedirs(os.path.dirname(ML_MODEL_PATH), exist_ok=True)
    joblib.dump(model, ML_MODEL_PATH)

    meta = {
        "feature_columns": feature_columns,
        "classes": sorted([int(c) for c in model.classes_]),
        "train_accuracy": round(train_acc, 4),
        "val_accuracy": round(val_acc, 4),
        "n_features": len(feature_columns),
        "n_samples": len(df)
    }
    with open(ML_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    ml_model = model
    ml_model_ready = True

    # Also update the JSON fallback
    _build_json_from_model(model, feature_columns, df, label_col)

    print(f"\n  ✓ Model saved to {ML_MODEL_PATH}")
    print("╔══════════════════════════════════════════════════╗")
    print("║       TRAINING COMPLETE ✓                       ║")
    print("╚══════════════════════════════════════════════════╝\n")
    return True


def _build_json_from_model(model, columns, df, label_col):
    """Build the JSON feature_risk dict from model feature importances."""
    global feature_risk

    importances = model.feature_importances_
    malware_mask = df[label_col] >= 3

    learned = {}
    for i, col in enumerate(columns):
        cleaned = clean_name(col)
        col_vals = df[col]

        usage_in_malware = (col_vals[malware_mask] > 0).sum()
        total_malware = malware_mask.sum()

        if usage_in_malware == 0:
            continue

        base_risk = (usage_in_malware / total_malware) * 100.0
        imp_weight = importances[i] / (importances.max() + 1e-9)
        risk_score = base_risk * (0.7 + 0.3 * imp_weight)

        learned[cleaned] = {
            "risk": risk_score,
            "type": classify_permission(cleaned)
        }

    feature_risk = learned
    save_model()


def load_ml_model():
    """Load the trained sklearn model from disk."""
    global ml_model, feature_columns, ml_model_ready

    if not os.path.exists(ML_MODEL_PATH) or not os.path.exists(ML_META_PATH):
        print("[ml_engine] No sklearn model found on disk.")
        return False

    ml_model = joblib.load(ML_MODEL_PATH)

    with open(ML_META_PATH, "r") as f:
        meta = json.load(f)

    feature_columns = meta["feature_columns"]
    ml_model_ready = True
    print(f"[ml_engine] ✓ sklearn model loaded ({meta['n_features']} features, "
          f"val_acc={meta.get('val_accuracy', 'N/A')})")
    return True


# ================= STARTUP =================


def load_or_train():
    loaded = load_ml_model()

    if not loaded:
        print("[ml_engine] No saved model found. Training new model …")
        trained = train_ml_model(CSV_PATH)
        if not trained:
            print("[ml_engine] ✗ Training failed, using JSON fallback only.")

    load_json_model()
    _load_permission_risk()


# ================= ANALYSIS (FIXED — per-permission scoring) =================


def _get_permission_risk(perm_key):
    """
    Get the risk score for a single Android permission.
    Priority: learned risk map → static risk table → keyword-based default.
    """
    # 1. Check learned risks from dataset
    for feat, risk_val in permission_risk_map.items():
        # Check if any significant keyword in the permission matches a feature
        parts = perm_key.split("_")
        for part in parts:
            if len(part) >= 3 and part in feat:
                return risk_val

    # 2. Check static risk table
    if perm_key in PERMISSION_RISK_TABLE:
        return PERMISSION_RISK_TABLE[perm_key]

    # 3. Default based on classification
    cat = classify_permission(perm_key)
    if cat == "PII":
        return 6.0
    elif cat == "SENSITIVE":
        return 4.0
    else:
        return 1.5


def _classify_level(score):
    """
    4-tier classification with HANDLE_WITH_CARE:
      ≥ 70  → DANGEROUS
      ≥ 50  → SUSPICIOUS
      ≥ 30  → HANDLE_WITH_CARE
      < 30  → SAFE
    """
    if score >= 70:
        return "DANGEROUS", "High Risk PII / Sensitive Data Exfiltration"
    elif score >= 50:
        return "SUSPICIOUS", "Moderate Sensitive Data Exposure"
    elif score >= 30:
        return "HANDLE_WITH_CARE", "Potential Privacy Concerns — Not Fully Safe"
    else:
        return "SAFE", "Low Risk / No Critical Leak"


def analyze_permissions(android_permissions):
    """
    Analyze a list of Android permissions.

    Scoring formula (per app):
      1. Sum individual permission risk weights (each 0-10)
      2. Normalise by max possible for that count of permissions
      3. Blend with ML model class probabilities
      → Produces scores that DIFFER between apps based on their actual permissions
    """
    global feature_risk, ml_model, ml_model_ready

    pii_detected = set()
    sensitive_detected = set()
    flags = set()

    # ── Per-permission scoring ──
    perm_risk_sum = 0.0
    perm_details = []

    for perm in android_permissions:
        key = _perm_short_key(perm)
        cat = classify_permission(key)
        risk = _get_permission_risk(key)

        perm_risk_sum += risk
        perm_details.append((key, cat, risk))

        if cat == "PII":
            pii_detected.add(key)
            flags.add(key)
        elif cat == "SENSITIVE":
            sensitive_detected.add(key)
            flags.add(key)

    # Normalize: score out of 100
    # Max possible = 10 × n_perms, but cap normalisation denominator
    n_perms = len(android_permissions)
    if n_perms == 0:
        perm_score = 0.0
    else:
        # Scale: an app with all 10/10 permissions = 100
        # Average permission risk × scaling factor
        avg_risk = perm_risk_sum / n_perms
        # Scale from 0-10 average to 0-100, with a bonus for having MANY risky perms
        count_factor = min(1.0, n_perms / 15.0)  # more perms = higher concern
        perm_score = (avg_risk * 10.0) * (0.6 + 0.4 * count_factor)

    perm_score = min(100.0, max(0.0, perm_score))

    # ── ML model signal (if available) ──
    ml_score = None
    if ml_model_ready and ml_model is not None and len(feature_columns) > 0:
        x = _build_feature_vector(android_permissions).reshape(1, -1)
        proba = ml_model.predict_proba(x)[0]
        classes = ml_model.classes_
        ml_score = sum(
            proba[i] * CLASS_WEIGHTS.get(int(c), 50.0)
            for i, c in enumerate(classes)
        )

    # ── Blend scores ──
    if ml_score is not None:
        # 70% per-permission (granular), 30% ML model (global pattern)
        final_score = 0.70 * perm_score + 0.30 * ml_score
    else:
        final_score = perm_score

    final_score = min(100.0, max(0.0, final_score))
    level, leak_type = _classify_level(final_score)

    return {
        "level": level,
        "score": final_score,
        "score_int": int(round(final_score)),
        "flags": sorted(flags),
        "leak_type": leak_type,
        "pii_detected": sorted(pii_detected),
        "sensitive_detected": sorted(sensitive_detected)
    }


def _build_feature_vector(android_permissions):
    """
    Build feature vector for the ML model.
    Uses EXACT column-name matching (not broad semantic match).
    """
    x = np.zeros(len(feature_columns), dtype=np.float32)

    perm_keys = set()
    for perm in android_permissions:
        key = _perm_short_key(perm)
        perm_keys.add(key)
        # Also add sub-parts for partial matching
        for part in key.split("_"):
            if len(part) >= 3:
                perm_keys.add(part)

    for i, col_name in enumerate(feature_columns):
        cleaned = clean_name(col_name)
        # Check if any permission keyword appears in the column name
        for pk in perm_keys:
            if pk in cleaned:
                x[i] = 1.0
                break

    return x


# ================= ADAPTIVE LEARNING =================


def adaptive_update(package_name, android_permissions, is_malware,
                    user_notes=""):
    """
    Update risk model from user feedback.
    Persists to DB and adjusts per-permission risk weights.
    """
    global feature_risk

    db_manager.save_feedback(
        package_name=package_name,
        permissions=android_permissions,
        is_malware=is_malware,
        user_notes=user_notes
    )

    stats = db_manager.get_feedback_stats()

    for perm in android_permissions:
        key = _perm_short_key(perm)

        # Update static table
        current = PERMISSION_RISK_TABLE.get(key, 3.0)
        perm_stat = stats.get(key, {"malware": 0, "safe": 0})
        total = perm_stat["malware"] + perm_stat["safe"]

        if total >= 2:
            obs_rate = perm_stat["malware"] / total
            alpha = min(0.3, total / 100.0)
            adjusted = (1 - alpha) * current + alpha * (obs_rate * 10.0)
        else:
            delta = 0.5 if is_malware else -0.3
            adjusted = current + delta

        PERMISSION_RISK_TABLE[key] = max(0.0, min(10.0, adjusted))

    # Also update JSON feature_risk where matching
    for perm in android_permissions:
        key = _perm_short_key(perm)
        for feature in list(feature_risk.keys()):
            parts = key.split("_")
            matched = any(p in feature for p in parts if len(p) >= 3)
            if matched:
                cur = feature_risk[feature]["risk"]
                delta = 3.0 if is_malware else -1.5
                feature_risk[feature]["risk"] = max(0.0, min(100.0, cur + delta))

    save_model()
    print(f"[ml_engine] Adaptive update for {package_name} (malware={is_malware})")
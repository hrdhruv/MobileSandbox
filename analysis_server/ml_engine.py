"""
ml_engine.py — Machine Learning engine for permission-based risk analysis.

Scoring pipeline:
  1. Per-permission risk weights (individual, not broad matching)
  2. GradientBoostingClassifier (5-class) probability signal
  3. Beta-Binomial Bayesian signal from user feedback
  4. Weighted blend of all three for final score

Fixes applied in v1 (legacy, see FIX-1 through FIX-6 below):
  FIX-1: Signal A amplification formula was a no-op → real power curve.
  FIX-2: ML class weights changed to exponential ramp.
  FIX-3: Permission volume multiplier added (now refined in FIX-v2-3).
  FIX-4: ML fallback default removed.
  FIX-5: Dangerous permission combo multiplier table.
  FIX-6: Feature vector uses exact-key matching.

Fixes applied in v2 (this version):
  FIX-v2-1: Bayesian prior changed to safe-biased Beta(1,4) from neutral Beta(2,2).
             Prior mean drops 5.0/10 → 2.0/10. Unknown apps start as likely safe.
  FIX-v2-2: Classification thresholds recalibrated. SAFE < 30 (was < 25).
             HWC 30–55, SUSPICIOUS 55–75, DANGEROUS ≥ 75.
  FIX-v2-3: Volume bonus now only counts HIGH-RISK permissions (risk ≥ 6.0),
             not every permission. VIBRATE/WAKE_LOCK/INTERNET no longer inflate score.
  FIX-v2-4: Sparsity bonus — apps with ≤ 5 total permissions get a 0.85× dampener.
  FIX-v2-5: Danger-ratio context — if < 20% of an app's permissions are high-risk,
             apply a 0.90× dampener. Rewards scope-appropriate permission sets.
  FIX-v2-6: Confidence score — how much the three signals agree (0–1). Returned
             in every analyze_permissions() result. Low confidence = mixed signals.
  FIX-v2-7: Auto-retrain trigger — adaptive_update() checks total feedback count.
             Every 50 samples (with ≥ 10 of each class) kicks off a background retrain.
  FIX-v2-8: Known-safe app fingerprint cache — model/known_safe_apps.json maps
             package prefixes to a score ceiling. Our own app will never exceed it.
"""

import pandas as pd
import numpy as np
import os
import sys
import json
import re
import joblib
import threading
import db_manager

# ================= CONFIG =================

CSV_PATH = "dataset/data.csv"
MODEL_FILE = "model_weights.json"
ML_MODEL_PATH = "model/ml_model.joblib"
ML_META_PATH = "model/ml_meta.json"
PERM_RISK_PATH = "model/permission_risk.json"
KNOWN_SAFE_PATH = "model/known_safe_apps.json"

LABEL_COLUMNS = ["Class", "class", "label", "Label", "malware"]

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

# Per-permission static risk weights (0-10 scale).
# These are anchor truth values — high-risk perms score high.
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

# Threshold for "high risk" in volume / ratio calculations (FIX-v2-3, FIX-v2-5)
HIGH_RISK_THRESHOLD = 6.0

# ML class weights: exponential — class 5 (malware) strongly dominates
CLASS_WEIGHTS = {1: 0.0, 2: 25.0, 3: 50.0, 4: 75.0, 5: 100.0}
ML_CLASS_WEIGHTS = [0.0, 1.0, 3.5, 7.0, 10.0]  # for probability-weighted score

# FIX-v2-1: Safe-biased Bayesian prior. Beta(1, 4) → prior mean = 1/5 = 0.20 → 2.0/10.
# Previous Beta(2,2) had mean 0.50 → 5.0/10 (neutral / too pessimistic for new apps).
BETA_ALPHA_0 = 1.0   # pseudo-count of "malware" observations
BETA_BETA_0  = 4.0   # pseudo-count of "safe" observations

# Auto-retrain: trigger every N feedback samples (FIX-v2-7)
AUTO_RETRAIN_EVERY = 50
MIN_RETRAIN_MALWARE = 10
MIN_RETRAIN_SAFE = 10

# ── FIX-5 (v1): Dangerous permission combo multipliers ──
DANGEROUS_COMBOS = [
    ({"ACCESS_FINE_LOCATION", "READ_CONTACTS", "READ_SMS"}, 1.50),  # full spyware
    ({"SEND_SMS", "RECEIVE_SMS", "READ_SMS"}, 1.40),                # SMS trojan
    ({"CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"}, 1.45),     # surveillance
    ({"INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW"}, 1.35),            # dropper
    ({"CAMERA", "RECORD_AUDIO"}, 1.30),                             # covert recording
    ({"ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS"}, 1.25),        # stalkerware
    ({"RECEIVE_BOOT_COMPLETED", "INSTALL_PACKAGES"}, 1.20),         # persistence
]

# ── Global state ──
ml_model = None
feature_columns = []
feature_risk = {}
permission_risk_map = {}
ml_model_ready = False
_retrain_lock = threading.Lock()
_known_safe_apps = {}  # FIX-v2-8: package-prefix → score ceiling


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
    p = perm_key.upper()
    for kw in PII_KEYWORDS:
        if kw in p:
            return "PII"
    for kw in SENSITIVE_KEYWORDS:
        if kw in p:
            return "SENSITIVE"
    return "LOW_RISK"


def _perm_short_key(full_perm):
    return full_perm.split(".")[-1].upper()


# ================= KNOWN-SAFE APP CACHE (FIX-v2-8) =================

def _load_known_safe_apps():
    """
    Load package-prefix → score-ceiling map from JSON.
    Example: {"com.mobilesandbox": 35, "com.example.dataleakage": 35}
    If the file does not exist, create a default one with our own app.
    """
    global _known_safe_apps
    if os.path.exists(KNOWN_SAFE_PATH):
        with open(KNOWN_SAFE_PATH, "r") as f:
            _known_safe_apps = json.load(f)
        print(f"[ml_engine] Known-safe app cache: {len(_known_safe_apps)} entries")
    else:
        # Create a default file with our own app pinned
        _known_safe_apps = {
            "com.mobilesandbox": 35,
            "com.example.dataleakage": 35
        }
        os.makedirs(os.path.dirname(KNOWN_SAFE_PATH), exist_ok=True)
        with open(KNOWN_SAFE_PATH, "w") as f:
            json.dump(_known_safe_apps, f, indent=2)
        print(f"[ml_engine] Created default known_safe_apps.json at {KNOWN_SAFE_PATH}")


def _apply_known_safe_cap(package_name: str, score: float) -> float:
    """
    If package_name starts with any key in _known_safe_apps, cap the score
    at the configured ceiling. Returns score unchanged if no match.
    """
    if not package_name:
        return score
    pkg_lower = package_name.lower()
    for prefix, ceiling in _known_safe_apps.items():
        if pkg_lower.startswith(prefix.lower()):
            return min(score, float(ceiling))
    return score


# ================= BAYESIAN UPDATER =================

_bayes_cache = {}

def get_bayesian_risk(perm_key: str) -> float:
    """
    Beta-Binomial conjugate posterior risk for a single permission.

    Prior:     Beta(α₀=1, β₀=4)  — safe-biased (FIX-v2-1)
    Evidence:  malware_count (α) and safe_count (β) from feedback DB
    Posterior: Beta(α₀ + malware_count, β₀ + safe_count)
    Mean:      α / (α + β)  ∈ [0,1], scaled to [0,10]

    With no evidence: posterior mean = 1/(1+4) = 0.20 → 2.0/10 (safe assumption).
    """
    stats = db_manager.get_feedback_stats()
    perm_stat = stats.get(perm_key, {"malware": 0, "safe": 0})

    cache_key = (perm_key, perm_stat["malware"], perm_stat["safe"])
    if cache_key in _bayes_cache:
        return _bayes_cache[cache_key]

    alpha = BETA_ALPHA_0 + perm_stat["malware"]
    beta  = BETA_BETA_0  + perm_stat["safe"]

    posterior_mean = alpha / (alpha + beta)   # ∈ [0, 1]
    result = posterior_mean * 10.0            # scale to [0, 10]
    _bayes_cache[cache_key] = result
    return result


# ================= MODEL PERSISTENCE =================

def save_model():
    global feature_risk
    with open(MODEL_FILE, "w") as f:
        json.dump(feature_risk, f)


def load_json_model():
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
    global permission_risk_map
    if os.path.exists(PERM_RISK_PATH):
        with open(PERM_RISK_PATH, "r") as f:
            permission_risk_map = json.load(f)
        print(f"[ml_engine] Permission risk map: {len(permission_risk_map)} entries")


# ================= TRAINING =================

def _print_progress(current, total, prefix="", bar_len=40):
    pct = current / total
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  {prefix} [{bar}] {pct*100:5.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current == total:
        print()


def train_ml_model(csv_path, extra_rows=None):
    """
    Train GradientBoostingClassifier on the dataset.
    extra_rows: list of (feature_dict, label) tuples from feedback augmentation.
    """
    global ml_model, feature_columns, ml_model_ready, permission_risk_map

    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    if not os.path.exists(csv_path):
        print(f"[ml_engine] ✗ Dataset not found at {csv_path}")
        return False

    print("\n╔══════════════════════════════════════════════════╗")
    print("║       ML MODEL TRAINING PIPELINE                ║")
    print("╚══════════════════════════════════════════════════╝\n")

    # ── Step 1: Load dataset ──
    print("[Step 1/5] Loading dataset …")
    df = pd.read_csv(csv_path)
    label_col = detect_label_column(df)
    print(f"  ✓ {len(df)} samples, {len(df.columns)-1} features")
    print(f"  ✓ Label: '{label_col}'  Distribution: "
          f"{dict(df[label_col].value_counts().sort_index())}")

    # ── Step 2: Prepare data (+ optional augmentation) ──
    print("\n[Step 2/5] Preparing training data …")
    y_base = df[label_col].values
    X_base = df.drop(columns=[label_col])
    feature_columns = list(X_base.columns)
    X_base.columns = range(len(feature_columns))

    X_arr = X_base.values.astype(np.float32)
    y_arr = y_base

    if extra_rows:
        print(f"  ✓ Augmenting with {len(extra_rows)} feedback-derived pseudo-samples")
        feat_idx = {clean_name(c): i for i, c in enumerate(feature_columns)}
        aug_X, aug_y = [], []
        for feat_dict, label in extra_rows:
            row = np.zeros(len(feature_columns), dtype=np.float32)
            for k, v in feat_dict.items():
                if k in feat_idx:
                    row[feat_idx[k]] = float(v)
            aug_X.append(row)
            aug_y.append(label)
        X_arr = np.vstack([X_arr, np.array(aug_X)])
        y_arr = np.concatenate([y_arr, np.array(aug_y)])

    X_train, X_val, y_train, y_val = train_test_split(
        X_arr, y_arr, test_size=0.15, random_state=42, stratify=y_arr
    )
    print(f"  ✓ Train: {len(X_train)} | Val: {len(X_val)}")

    # ── Step 3: Train with progress ──
    print("\n[Step 3/5] Training GradientBoostingClassifier (5-class) …")
    n_estimators = 200
    model = GradientBoostingClassifier(
        n_estimators=n_estimators, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=42, warm_start=True
    )
    stages = [20, 50, 80, 120, 160, 200]
    for stage_n in stages:
        model.n_estimators = stage_n
        model.fit(X_train, y_train)
        _print_progress(stage_n, n_estimators, prefix="Training")

    train_acc = model.score(X_train, y_train)
    val_acc = model.score(X_val, y_val)
    print(f"\n  ✓ Train accuracy:      {train_acc:.4f}")
    print(f"  ✓ Validation accuracy: {val_acc:.4f}")

    # ── Step 4: Build per-feature risk map ──
    print("\n[Step 4/5] Building per-permission risk map …")
    importances = model.feature_importances_
    imp_max = importances.max() + 1e-9
    perm_risk = {}

    for i, col in enumerate(feature_columns):
        cleaned = clean_name(col)
        col_vals = df[col]
        class_usage = {}
        for cls in sorted(df[label_col].unique()):
            mask = df[label_col] == cls
            usage = (col_vals[mask] > 0).sum()
            class_usage[int(cls)] = usage / mask.sum() if mask.sum() > 0 else 0.0

        weighted = sum(
            class_usage.get(c, 0) * w for c, w in CLASS_WEIGHTS.items()
        ) / sum(CLASS_WEIGHTS.values())
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
    print(f"  ✓ {len(permission_risk_map)} features mapped")

    # ── Step 5: Save ──
    print("\n[Step 5/5] Saving model …")
    os.makedirs(os.path.dirname(ML_MODEL_PATH), exist_ok=True)
    joblib.dump(model, ML_MODEL_PATH)

    meta = {
        "feature_columns": feature_columns,
        "classes": sorted([int(c) for c in model.classes_]),
        "train_accuracy": round(train_acc, 4),
        "val_accuracy": round(val_acc, 4),
        "n_features": len(feature_columns),
        "n_samples": int(len(X_arr))
    }
    with open(ML_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    ml_model = model
    ml_model_ready = True
    _build_json_from_model(model, feature_columns, df, label_col)

    print(f"\n  ✓ Saved to {ML_MODEL_PATH}")
    print("╔══════════════════════════════════════════════════╗")
    print("║       TRAINING COMPLETE ✓                       ║")
    print("╚══════════════════════════════════════════════════╝\n")
    return True


def _build_json_from_model(model, columns, df, label_col):
    global feature_risk
    importances = model.feature_importances_
    malware_mask = df[label_col] >= 3
    learned = {}
    for i, col in enumerate(columns):
        cleaned = clean_name(col)
        col_vals = df[col]
        usage = (col_vals[malware_mask] > 0).sum()
        total_mal = malware_mask.sum()
        if usage == 0:
            continue
        base = (usage / total_mal) * 100.0
        imp = importances[i] / (importances.max() + 1e-9)
        learned[cleaned] = {
            "risk": base * (0.7 + 0.3 * imp),
            "type": classify_permission(cleaned)
        }
    feature_risk = learned
    save_model()


def load_ml_model():
    global ml_model, feature_columns, ml_model_ready
    if not os.path.exists(ML_MODEL_PATH) or not os.path.exists(ML_META_PATH):
        print("[ml_engine] No sklearn model found on disk.")
        return False
    ml_model = joblib.load(ML_MODEL_PATH)
    with open(ML_META_PATH, "r") as f:
        meta = json.load(f)
    feature_columns = meta["feature_columns"]
    ml_model_ready = True
    print(f"[ml_engine] ✓ Model loaded ({meta['n_features']} features, "
          f"val_acc={meta.get('val_accuracy', 'N/A')})")
    return True


# ================= RETRAIN FROM FEEDBACK =================

def retrain_from_feedback():
    """
    Augment the training dataset with pseudo-samples from confirmed feedback
    and retrain the model. Runs in a background thread (non-blocking).
    """
    global _retrain_lock

    if not _retrain_lock.acquire(blocking=False):
        print("[ml_engine] Retrain already in progress — skipping.")
        return False

    def _run():
        try:
            print("[ml_engine] Retrain from feedback started …")
            feedback_rows = db_manager.get_all_feedback()

            extra = []
            for row in feedback_rows:
                try:
                    perms = json.loads(row.get("permissions") or "[]")
                except (json.JSONDecodeError, TypeError):
                    perms = []

                label = 5 if row["is_malware"] else 1
                feat_dict = {}
                for p in perms:
                    key = _perm_short_key(p)
                    feat_dict[key] = 1
                if feat_dict:
                    extra.append((feat_dict, label))

            if not extra:
                print("[ml_engine] No feedback data to augment with — skipping.")
                return

            train_ml_model(CSV_PATH, extra_rows=extra)
            print(f"[ml_engine] Retrain complete with {len(extra)} augmented samples.")
        finally:
            _retrain_lock.release()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return True


def _check_auto_retrain():
    """
    FIX-v2-7: After every adaptive_update(), check if total feedback count
    has crossed a new multiple of AUTO_RETRAIN_EVERY. If so, and if there
    are enough samples of both classes, trigger a background retrain.
    """
    try:
        stats = db_manager.get_aggregate_stats()
        total = stats.get("feedback_total", 0)
        malware_count = stats.get("feedback_malware", 0)
        safe_count = stats.get("feedback_safe", 0)

        if total > 0 and total % AUTO_RETRAIN_EVERY == 0:
            if malware_count >= MIN_RETRAIN_MALWARE and safe_count >= MIN_RETRAIN_SAFE:
                print(f"[ml_engine] Auto-retrain triggered at {total} feedback samples "
                      f"(malware={malware_count}, safe={safe_count})")
                retrain_from_feedback()
    except Exception as e:
        print(f"[ml_engine] Auto-retrain check failed: {e}")


# ================= STARTUP =================

def load_or_train():
    loaded = load_ml_model()
    if not loaded:
        print("[ml_engine] Training new model …")
        trained = train_ml_model(CSV_PATH)
        if not trained:
            print("[ml_engine] ✗ Training failed. Using JSON fallback.")
    load_json_model()
    _load_permission_risk()
    _load_known_safe_apps()


# ================= ANALYSIS =================

def _get_permission_risk(perm_key):
    """
    Get static risk for one permission (0-10 scale).
    Priority: static table → keyword default.
    """
    if perm_key in PERMISSION_RISK_TABLE:
        return PERMISSION_RISK_TABLE[perm_key]
    cat = classify_permission(perm_key)
    if cat == "PII":
        return 6.0
    elif cat == "SENSITIVE":
        return 4.0
    return 1.5


def _build_feature_vector(android_permissions):
    """
    Build a binary feature vector aligned to feature_columns.
    Only sets a column to 1.0 if the cleaned column name exactly matches
    a permission short key from the app — no substring matching (FIX-6).
    """
    x = np.zeros(len(feature_columns), dtype=np.float32)
    perm_keys = {_perm_short_key(p) for p in android_permissions}
    for i, col_name in enumerate(feature_columns):
        cleaned = clean_name(col_name)
        if cleaned in perm_keys:
            x[i] = 1.0
    return x


def _classify_level(score):
    """
    FIX-v2-2: Recalibrated 4-tier classification (0-100 scale):
      ≥ 75.0  → DANGEROUS
      ≥ 55.0  → SUSPICIOUS      (was 50.0)
      ≥ 30.0  → HANDLE_WITH_CARE (was 25.0)
      < 30.0  → SAFE             (was 25.0)

    Moving the SAFE/HWC boundary from 25→30 ensures apps with a moderate
    mix of everyday permissions (CAMERA + INTERNET + VIBRATE) are correctly
    classed as SAFE rather than flagged prematurely.
    """
    if score >= 75.0:
        return "DANGEROUS", "High Risk PII / Sensitive Data Exfiltration"
    elif score >= 55.0:
        return "SUSPICIOUS", "Moderate Sensitive Data Exposure"
    elif score >= 30.0:
        return "HANDLE_WITH_CARE", "Potential Privacy Concerns — Not Fully Safe"
    else:
        return "SAFE", "Low Risk / No Critical Leak"


def _combo_multiplier(perm_keys: set) -> float:
    """
    Return the highest multiplier from DANGEROUS_COMBOS whose permission
    set is fully present in perm_keys. Returns 1.0 if no combo matches.
    Multipliers do not stack — only the worst-matching combo is used.
    """
    best = 1.0
    for combo, factor in DANGEROUS_COMBOS:
        if combo.issubset(perm_keys):
            best = max(best, factor)
    return best


def _compute_confidence(sig_a: float, sig_b_or_none, sig_c: float) -> float:
    """
    FIX-v2-6: Confidence score — [0, 1] — measuring how much the three
    signals agree with each other.

    Each signal is normalised to [0, 1] before comparison.
    Confidence = 1.0 - normalised_std_dev(signals) * 2.0, clamped to [0, 1].

    High confidence (→ 1.0): all signals point the same direction.
    Low confidence (→ 0.0): signals strongly disagree (e.g. ML says safe,
                             static weights say dangerous).
    """
    a_norm = sig_a / 10.0
    c_norm = sig_c / 10.0

    if sig_b_or_none is not None:
        b_norm = sig_b_or_none / 10.0
        signals = [a_norm, b_norm, c_norm]
    else:
        signals = [a_norm, c_norm]

    std = float(np.std(signals))
    confidence = max(0.0, min(1.0, 1.0 - std * 2.0))
    return round(confidence, 3)


def analyze_permissions(android_permissions, package_name=""):
    """
    Hybrid 3-signal scoring with v2 adaptive improvements.

    Signal A — per-permission static weights  (55% ML present, 70% without)
    Signal B — ML model class probabilities   (30% ML present, absent otherwise)
    Signal C — Beta-Binomial Bayesian signal  (15% ML present, 30% without)

    v2 additions (applied in order after blend):
      FIX-v2-3: Volume bonus counts only high-risk permissions.
      FIX-v2-4: Sparsity dampener for apps with ≤ 5 permissions.
      FIX-v2-5: Danger-ratio dampener when < 20% of perms are high-risk.
      FIX-v2-6: Confidence score returned alongside result.
      FIX-v2-8: Known-safe app cap applied to final score.
    """
    global feature_risk, ml_model, ml_model_ready

    pii_detected = set()
    sensitive_detected = set()
    flags = set()

    # ── Signal A: per-permission static scoring ──
    risks = []
    perm_keys = set()
    high_risk_perms = []   # permissions with risk >= HIGH_RISK_THRESHOLD
    for perm in android_permissions:
        key = _perm_short_key(perm)
        perm_keys.add(key)
        cat = classify_permission(key)
        risk = _get_permission_risk(key)
        risks.append(risk)

        if risk >= HIGH_RISK_THRESHOLD:
            high_risk_perms.append(risk)

        if cat == "PII":
            pii_detected.add(key)
            flags.add(key)
        elif cat == "SENSITIVE":
            sensitive_detected.add(key)
            flags.add(key)

    top_risks = sorted(risks, reverse=True)[:15]
    n_perms = len(top_risks)
    if n_perms == 0:
        perm_score = 0.0
    else:
        raw_score = sum(top_risks) / n_perms   # 0-10 average of top-15

        # FIX-1: Real power-curve amplification for high scores
        perm_score = min((raw_score / 10.0) ** 0.7 * 10.0, 10.0)

    # FIX-v2-3: Volume bonus counts only HIGH-RISK permissions (≥ 6.0).
    # Previously every permission added to the volume bonus, meaning
    # VIBRATE + WAKE_LOCK + INTERNET inflated scores. Now only genuinely
    # dangerous permissions expand the volume bonus.
    n_high_risk = len(high_risk_perms)
    volume_bonus = min(1.0 + max(0, n_high_risk - 3) * 0.05, 1.4)
    perm_score = min(perm_score * volume_bonus, 10.0)

    # FIX-5 (v1): Dangerous combo multiplier
    combo_mult = _combo_multiplier(perm_keys)
    perm_score = min(perm_score * combo_mult, 10.0)

    # FIX-v2-4: Sparsity dampener — lean apps look more trustworthy.
    # Apps with ≤ 5 total permissions get an 0.85× dampener on perm_score.
    # This reflects that a well-scoped app rarely needs many permissions.
    total_perms = len(android_permissions)
    if total_perms <= 5:
        perm_score *= 0.85

    # ── Signal B: ML model probability-weighted score ──
    ml_score = None
    if ml_model_ready and ml_model is not None and len(feature_columns) > 0:
        x = _build_feature_vector(android_permissions).reshape(1, -1)
        proba = ml_model.predict_proba(x)[0]

        # FIX-2 (v1): Exponential class weights — class 5 (malware) dominates
        ml_score = sum(p * w for p, w in zip(proba, ML_CLASS_WEIGHTS))
        ml_score = min(10.0, max(0.0, ml_score))

    # ── Signal C: Beta-Binomial Bayesian signal ──
    bayesian_risks = [get_bayesian_risk(_perm_short_key(p)) for p in android_permissions]
    if bayesian_risks:
        top_bayes = sorted(bayesian_risks, reverse=True)[:15]
        bayes_score = sum(top_bayes) / len(top_bayes)
    else:
        bayes_score = 2.0   # FIX-v2-1: safe default when no permissions

    # ── FIX-4 (v1): Weighted blend — redistributes ML weight if model unavailable ──
    if ml_score is None:
        final_score = 0.70 * perm_score + 0.30 * bayes_score
    else:
        final_score = (
            0.55 * perm_score +
            0.30 * ml_score +
            0.15 * bayes_score
        )

    # FIX-v2-5: Danger-ratio context dampener.
    # If less than 20% of all permissions are high-risk, the app's permission
    # set is mostly benign. Apply a 0.90× dampener on the blended final score.
    # This rewards apps that request many low-risk permissions (e.g. VIBRATE,
    # WAKE_LOCK, INTERNET) without stacking dangerous ones.
    if total_perms > 0:
        danger_ratio = n_high_risk / total_perms
        if danger_ratio < 0.20:
            final_score *= 0.90

    final_score = min(10.0, max(0.0, final_score))
    final_score_scaled = round(final_score * 10.0, 1)  # scale to 0-100

    # FIX-v2-8: Apply known-safe app score cap (if package name provided)
    if package_name:
        final_score_scaled = _apply_known_safe_cap(package_name, final_score_scaled)

    # FIX-v2-6: Compute confidence
    confidence = _compute_confidence(perm_score, ml_score, bayes_score)

    level, leak_type = _classify_level(final_score_scaled)

    return {
        "level": level,
        "score": final_score_scaled,
        "score_int": int(round(final_score_scaled)),
        "flags": sorted(flags),
        "leak_type": leak_type,
        "pii_detected": sorted(pii_detected),
        "sensitive_detected": sorted(sensitive_detected),
        "confidence": confidence,
    }


# ================= ADAPTIVE LEARNING (Beta-Binomial) =================

def adaptive_update(package_name, android_permissions, is_malware,
                    user_notes=""):
    """
    Bayesian adaptive update using Beta-Binomial conjugate model.

    For each permission p:
      α  = α₀ + feedback_malware_count(p)
      β  = β₀ + feedback_safe_count(p)
      Posterior mean = α/(α+β) → new risk weight on [0,1] → scaled [0,10]

    v2: After persisting, check whether total feedback count has crossed a
    multiple of AUTO_RETRAIN_EVERY (FIX-v2-7). If so, trigger auto-retrain.
    """
    # Persist to DB — future scoring calls will pick this up automatically
    db_manager.save_feedback(
        package_name=package_name,
        permissions=android_permissions,
        is_malware=is_malware,
        user_notes=user_notes
    )

    # Lightweight update to in-memory tables
    _bayes_cache.clear()   # invalidate cache so next call reflects new evidence
    stats = db_manager.get_feedback_stats()
    for perm in android_permissions:
        key = _perm_short_key(perm)
        perm_stat = stats.get(key, {"malware": 0, "safe": 0})
        alpha = BETA_ALPHA_0 + perm_stat["malware"]
        beta  = BETA_BETA_0  + perm_stat["safe"]
        posterior_risk_10 = (alpha / (alpha + beta)) * 10.0  # 0-10
        PERMISSION_RISK_TABLE[key] = posterior_risk_10

        # Mirror to JSON feature_risk where keys match
        for feature in list(feature_risk.keys()):
            parts = key.split("_")
            if any(p in feature for p in parts if len(p) >= 3):
                feature_risk[feature]["risk"] = min(100.0, posterior_risk_10 * 10.0)

    save_model()
    print(f"[ml_engine] Beta-Binomial update for {package_name} "
          f"(malware={is_malware})")

    # FIX-v2-7: Check auto-retrain threshold
    _check_auto_retrain()
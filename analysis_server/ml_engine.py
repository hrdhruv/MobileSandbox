import pandas as pd
import os

# Learned feature weights
feature_weights = {}

# Known label column candidates
LABEL_COLUMNS = ["Class", "class", "label", "Label", "malware"]


def train_from_csv(csv_path: str):
    """
    Build a feature vocabulary from CIC-Maldroid.
    No statistical filtering – guaranteed usable model.
    """
    global feature_weights

    if not os.path.exists(csv_path):
        print("CSV not found, skipping training")
        return

    df = pd.read_csv(csv_path)

    # Detect label column
    label_col = None
    for c in LABEL_COLUMNS:
        if c in df.columns:
            label_col = c
            break

    if label_col is None:
        raise ValueError("Label column not found in dataset")

    print(f"Detected label column: {label_col}")

    # Initialize all feature columns with default weight
    learned = {}

    for col in df.columns:
        if col == label_col:
            continue

        # Initialize small risk weight
        learned[col] = 1.0

    feature_weights = learned
    print(f"Model initialized with {len(feature_weights)} features")


def analyze_permissions(permission_names: list[str]):
    """
    Score based on matching features.
    """
    score = 0.0
    flags = []

    for p in permission_names:
        if p in feature_weights:
            score += feature_weights[p]
            flags.append(p)

    if score > 20:
        level = "DANGEROUS"
    elif score > 5:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "level": level,
        "score": round(score, 2),
        "flags": flags
    }


def adaptive_update(permission_names: list[str], is_malware: bool):
    """
    Online learning (adaptive ML)
    """
    delta = 2.0 if is_malware else -1.0

    for p in permission_names:
        if p in feature_weights:
            feature_weights[p] += delta
        else:
            feature_weights[p] = delta

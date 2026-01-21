import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
import joblib
import os

# Global variables to hold the model
model = None
feature_columns = []
MODEL_FILE = "model.pkl"

def train_from_csv(csv_path: str):
    global model, feature_columns
    
    if not os.path.exists(csv_path):
        print(f"❌ Dataset not found at {csv_path}")
        return

    print("⏳ Loading dataset and training Random Forest model...")
    
    # 1. Load Data
    df = pd.read_csv(csv_path)
    
    # 2. Identify Label Column (The 'Class' column in your dataset)
    # Your dataset has 'Class' where 1 might be malware, 0 benign (check your data)
    label_col = "Class" 
    
    if label_col not in df.columns:
        print("❌ 'Class' column not found in dataset")
        return

    # 3. Prepare Features (X) and Labels (y)
    X = df.drop(columns=[label_col])
    y = df[label_col]
    
    # Save the column names so we know the order later
    feature_columns = list(X.columns)
    
    # 4. Handle missing values (replace NaNs with 0)
    imputer = SimpleImputer(strategy='constant', fill_value=0)
    X_clean = imputer.fit_transform(X)
    
    # 5. Train Random Forest
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_clean, y)
    
    model = clf
    
    # 6. Save model to disk (optional, speeds up restart)
    joblib.dump((model, feature_columns), MODEL_FILE)
    print("✅ Model trained and saved successfully!")

def analyze_permissions(permission_list: list[str]):
    """
    Takes a list of android permissions, maps them to dataset columns,
    and predicts risk.
    """
    global model, feature_columns

    if model is None:
        # Try loading from file if valid
        if os.path.exists(MODEL_FILE):
             model, feature_columns = joblib.load(MODEL_FILE)
        else:
            return {"level": "ERROR", "score": 0, "flags": ["Model not loaded"]}

    # 1. Create a zero-vector matching the dataset structure
    input_vector = np.zeros(len(feature_columns))
    
    # 2. Map Android Permissions to Dataset Columns
    # Your dataset uses weird names like 'ACCESS_PERSONAL_INFO___'.
    # We do a simple keyword match.
    
    detected_features = []
    
    for perm in permission_list:
        clean_perm = perm.split(".")[-1].upper() # e.g. "READ_CONTACTS"
        
        # Check against all dataset columns
        for idx, col_name in enumerate(feature_columns):
            # If the dataset column contains the permission name (loose matching)
            if clean_perm in col_name:
                input_vector[idx] = 1 # Set feature to 1 (Present)
                detected_features.append(col_name)

    # 3. Predict
    # Reshape because model expects a 2D array
    prediction = model.predict([input_vector])[0] # 0 or 1
    probability = model.predict_proba([input_vector])[0][1] # Probability of being malware (0.0 to 1.0)
    
    score = int(probability * 100)
    
    if score > 75:
        level = "DANGEROUS"
    elif score > 40:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "level": level,
        "score": score,
        "flags": detected_features[:5] # Return top 5 matched features
    }

def adaptive_update(permissions, is_malware):
    # For now, just pass. Real adaptive learning is complex.
    pass
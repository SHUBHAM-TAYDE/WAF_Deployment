import os
import pickle
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

import collect_data
import feature_pipeline

# Model serialization paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
XGB_PATH = os.path.join(MODELS_DIR, "xgboost.pkl")

def train():
    # Enforce directory creation
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    # 1. Fetch raw logs from OpenSearch / Local logs fallback
    benign_logs, attack_logs = collect_data.get_training_datasets()
    
    if not benign_logs:
        print("Error: No benign logs available for training. Supervised training aborted.")
        return
        
    if not attack_logs:
        print("Error: No attack logs available for supervised training. Supervised training aborted.")
        return
        
    # 2. Extract feature matrices using the single feature pipeline module
    print("Processing feature vectors for training dataset...")
    X_benign = np.vstack([feature_pipeline.build_features(log) for log in benign_logs])
    X_attack = np.vstack([feature_pipeline.build_features(log) for log in attack_logs])
    
    # Concatenate features and construct labels
    X = np.vstack([X_benign, X_attack])
    y = np.array([0] * len(X_benign) + [1] * len(X_attack))
    
    # 3. Perform stratified splitting to preserve threat ratios
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Resolve severe class imbalances dynamically using scale_pos_weight
    num_benign = np.sum(y_train == 0)
    num_attack = np.sum(y_train == 1)
    scale_weight = num_benign / max(num_attack, 1)
    
    print(f"Training XGBoost classifier on {len(X_train)} samples ({num_benign} Benign, {num_attack} Attack)...")
    print(f"Applying class balancing scale_pos_weight: {scale_weight:.2f}")
    
    # 5. Initialize XGBoost with specific spec hyperparameters
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=scale_weight,
        eval_metric="logloss",
        random_state=42
    )
    
    # 6. Fit the classifier model
    model.fit(X_train, y_train)
    
    # 7. Evaluate classifications against the split validation set
    preds = model.predict(X_val)
    print("\n--- XGBoost Validation Metrics ---")
    print(classification_report(y_val, preds, target_names=["Benign", "Attack"]))
    
    # 8. Serialize binaries to models directory
    with open(XGB_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"XGBoost classification binary successfully saved to: {XGB_PATH}\n")

if __name__ == "__main__":
    train()

import os
import json
import pickle
import logging
import datetime
import numpy as np
from sklearn.ensemble import IsolationForest

import collect_data
import feature_pipeline

# Model serialization paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
ISO_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")

def train():
    # Enforce directory creation
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    # 1. Fetch raw logs (Unsupervised model ONLY trains on legitimate, clean baseline traffic)
    benign_logs, _ = collect_data.get_training_datasets()
    
    if not benign_logs:
        print("Error: No benign logs available for training. Isolation Forest training aborted.")
        return
        
    # 2. Extract feature matrices using the single feature pipeline module
    print("Processing feature vectors for baseline dataset...")
    X_train = np.vstack([feature_pipeline.build_features(log) for log in benign_logs])
    
    print(f"Training Isolation Forest on {len(X_train)} benign samples...")
    
    # 3. Initialize Isolation Forest with specific spec parameters
    model = IsolationForest(
        n_estimators=300,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    
    # 4. Fit the unsupervised model
    model.fit(X_train)
    
    # 5. Serialize binaries to models directory
    with open(ISO_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"Isolation Forest novelty binary successfully saved to: {ISO_PATH}\n")

    # 6. Update model_metadata.json with real training metrics
    META_PATH = os.path.join(MODELS_DIR, "model_metadata.json")
    try:
        meta = {}
        if os.path.exists(META_PATH):
            with open(META_PATH, "r") as mf:
                meta = json.load(mf)

        prev_version = meta.get("isolation_forest", {}).get("version", 0)

        meta.setdefault("schema_version", 1)
        meta["isolation_forest"] = {
            "version":       prev_version + 1,
            "type":          "production",
            "training_date": datetime.datetime.utcnow().isoformat() + "Z",
            "sample_count":  int(len(X_train)),
            "accuracy":      None,  # Unsupervised — no labelled accuracy metric
            "notes":         f"Trained on {len(X_train)} benign baseline samples."
        }

        with open(META_PATH, "w") as mf:
            json.dump(meta, mf, indent=2)
        print(f"Model metadata updated: {META_PATH}")
    except Exception as meta_err:
        logging.warning(f"Failed to write model metadata: {meta_err}")

if __name__ == "__main__":
    train()

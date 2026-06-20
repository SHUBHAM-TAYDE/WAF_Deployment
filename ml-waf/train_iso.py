import os
import pickle
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

if __name__ == "__main__":
    train()

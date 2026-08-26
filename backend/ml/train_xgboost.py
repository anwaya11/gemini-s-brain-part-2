import os
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier

# Base directory for ML artifacts
ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = ML_DIR / "model.pkl"
SCALER_PATH = ML_DIR / "scaler.pkl"

FEATURE_NAMES = [
    "request_rate_per_sec",
    "payload_entropy",
    "failed_auth_count",
    "path_depth",
    "body_length",
    "suspicious_keywords_flag",
    "sql_injection_score",
    "unusual_user_agent",
]


def generate_synthetic_dataset(num_samples: int = 10000, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a synthetic, high-fidelity dataset simulating benign web/API traffic
    and advanced threat patterns (SQLi, brute force, webshell/RCE, scraping, directory traversal).
    """
    np.random.seed(random_seed)
    num_benign = int(num_samples * 0.70)
    num_threats = num_samples - num_benign

    # --- 1. Benign Traffic Simulation ---
    # Normal user/API browsing habits
    benign_rate = np.random.gamma(shape=2.0, scale=1.5, size=num_benign)  # Avg 3 req/sec
    benign_entropy = np.random.normal(loc=3.2, scale=0.5, size=num_benign)  # English text/JSON
    benign_entropy = np.clip(benign_entropy, 1.0, 5.0)
    benign_failed_auth = np.random.choice([0, 1, 2], size=num_benign, p=[0.96, 0.035, 0.005])
    benign_path_depth = np.random.choice([1, 2, 3, 4, 5], size=num_benign, p=[0.15, 0.40, 0.30, 0.12, 0.03])
    benign_body_length = np.random.exponential(scale=600, size=num_benign)
    benign_keywords = np.random.choice([0, 1], size=num_benign, p=[0.99, 0.01])
    benign_sqli_score = np.random.beta(a=0.5, b=25.0, size=num_benign)  # Very close to 0.0
    benign_unusual_ua = np.random.choice([0, 1], size=num_benign, p=[0.97, 0.03])
    benign_labels = np.zeros(num_benign, dtype=int)

    # --- 2. Threat Traffic Simulation ---
    # Mixed attack profiles: SQL Injection, Brute Force, Obfuscated Web Shells, Scanning/DDoS
    threat_rate = np.concatenate([
        np.random.normal(loc=55.0, scale=15.0, size=int(num_threats * 0.35)),  # Brute force/DDoS
        np.random.normal(loc=4.0, scale=2.0, size=num_threats - int(num_threats * 0.35)),  # Stealth SQLi/LFI
    ])
    threat_rate = np.clip(threat_rate, 0.5, 200.0)

    threat_entropy = np.random.normal(loc=6.2, scale=0.7, size=num_threats)  # Base64/shellcode
    threat_entropy = np.clip(threat_entropy, 3.5, 8.0)

    threat_failed_auth = np.random.choice([0, 1, 5, 12, 35, 80], size=num_threats, p=[0.10, 0.10, 0.25, 0.25, 0.20, 0.10])

    threat_path_depth = np.random.choice([1, 2, 5, 8, 12], size=num_threats, p=[0.05, 0.10, 0.35, 0.35, 0.15])

    threat_body_length = np.concatenate([
        np.random.exponential(scale=5000, size=int(num_threats * 0.5)),  # Large payload buffer overflow/scripts
        np.random.exponential(scale=350, size=num_threats - int(num_threats * 0.5)),  # Short probes
    ])

    threat_keywords = np.random.choice([0, 1], size=num_threats, p=[0.15, 0.85])
    threat_sqli_score = np.random.beta(a=8.0, b=1.5, size=num_threats)  # High score (0.7 - 1.0)
    threat_unusual_ua = np.random.choice([0, 1], size=num_threats, p=[0.15, 0.85])
    threat_labels = np.ones(num_threats, dtype=int)

    # Combine benign and threat data
    data = {
        "request_rate_per_sec": np.concatenate([benign_rate, threat_rate]),
        "payload_entropy": np.concatenate([benign_entropy, threat_entropy]),
        "failed_auth_count": np.concatenate([benign_failed_auth, threat_failed_auth]),
        "path_depth": np.concatenate([benign_path_depth, threat_path_depth]),
        "body_length": np.concatenate([benign_body_length, threat_body_length]),
        "suspicious_keywords_flag": np.concatenate([benign_keywords, threat_keywords]),
        "sql_injection_score": np.concatenate([benign_sqli_score, threat_sqli_score]),
        "unusual_user_agent": np.concatenate([benign_unusual_ua, threat_unusual_ua]),
        "label": np.concatenate([benign_labels, threat_labels]),
    }

    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


def train_and_save_model():
    """
    Trains the XGBClassifier on the synthetic anomaly dataset,
    evaluates its performance, and saves model.pkl and scaler.pkl.
    """
    print("Generating synthetic network and HTTP anomaly dataset...")
    df = generate_synthetic_dataset(num_samples=12000, random_seed=42)

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Fitting StandardScaler on training data...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Training XGBClassifier for binary anomaly detection...")
    model = XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=42,
        use_label_encoder=False,
    )

    model.fit(X_train_scaled, y_train)

    # Evaluation
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    roc_auc = roc_auc_score(y_test, y_prob)
    print("\n--- Model Evaluation ---")
    print(f"ROC-AUC Score: {roc_auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Threat"]))

    # Save artifacts
    print(f"Saving model to {MODEL_PATH}...")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"Saving feature scaler to {SCALER_PATH}...")
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    print("Training and artifact export complete!")


if __name__ == "__main__":
    train_and_save_model()

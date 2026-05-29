import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from pathlib import Path

# Load dataset
csv_path = Path("dataset.csv")
if not csv_path.exists():
    raise FileNotFoundError("dataset.csv not found. Please run export_dataset.py first.")

df = pd.read_csv(csv_path)
print(f"Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns.\n")

# Preprocessing Features
print("Preprocessing features...")

# 1. Map Severity to Ordinal
severity_map = {"low": 0, "medium": 1, "high": 2}
df["severity_encoded"] = df["severity"].map(severity_map).fillna(1) # fallback to medium (1)

# 2. Extract numeric/binary features
X_numeric = df[["reputation_score", "hit_count", "is_whitelisted", "severity_encoded"]].copy()

# 3. One-hot encode categorical features (detector_type, perimeter_vendor)
X_categorical = pd.get_dummies(df[["detector_type", "perimeter_vendor"]], dtype=int)

# Combine features
X = pd.concat([X_numeric, X_categorical], axis=1)
y = df["label"]

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Training set size: {X_train.shape[0]} samples")
print(f"Testing set size: {X_test.shape[0]} samples\n")

# Model Initialization and Training
print("Training Baseline Logistic Regression model...")
model = LogisticRegression(max_iter=1000, random_state=42)
model.fit(X_train, y_train)

# Evaluation
print("\n=== Model Performance Evaluation ===")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_prob)

print(f"Accuracy:  {acc:.4f}")
print(f"ROC-AUC:   {auc:.4f}\n")

print("Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"[[TN={cm[0][0]} FP={cm[0][1]}]\n [FN={cm[1][0]} TP={cm[1][1]}]]\n")

print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Allow/Ignore (0)", "Block (1)"]))

# Save Model and Column schema (crucial for inference pipeline)
model_artifact = {
    "model": model,
    "feature_columns": list(X.columns),
    "severity_map": severity_map,
    "trained_date": pd.Timestamp.now().isoformat()
}

artifact_path = Path("baseline_model.joblib")
joblib.dump(model_artifact, artifact_path)
print(f"Trained baseline model saved to {artifact_path}")

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from ..config import load_env

logger = logging.getLogger(__name__)


def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, list[str], dict[str, int]]:
    """Prepares and encodes numeric and categorical features for ML training."""
    severity_map = {"low": 0, "medium": 1, "high": 2}
    df_clean = df.copy()

    if "severity" in df_clean.columns:
        df_clean["severity_encoded"] = df_clean["severity"].astype(str).str.lower().map(severity_map).fillna(1).astype(int)
    else:
        df_clean["severity_encoded"] = 1

    for col in ["reputation_score", "hit_count", "is_whitelisted"]:
        if col not in df_clean.columns:
            df_clean[col] = 0
        df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0)

    x_numeric = df_clean[["reputation_score", "hit_count", "is_whitelisted", "severity_encoded"]].copy()

    cat_cols = []
    for c in ["detector_type", "perimeter_vendor"]:
        if c in df_clean.columns:
            cat_cols.append(c)

    if cat_cols:
        x_categorical = pd.get_dummies(df_clean[cat_cols].astype(str), dtype=int)
        x = pd.concat([x_numeric, x_categorical], axis=1)
    else:
        x = x_numeric

    y = pd.to_numeric(df_clean["label"], errors="coerce").fillna(0).astype(int)
    return x, y, list(x.columns), severity_map


def optimize_threshold(y_true: np.ndarray, y_prob: np.ndarray, target_max_fpr: float = 0.05) -> tuple[float, float]:
    """Finds the optimal classification threshold balancing F1 score and false positive rate."""
    thresholds = np.linspace(0.1, 0.9, 81)
    best_threshold = 0.50
    best_f1 = -1.0

    for th in thresholds:
        y_pred_th = (y_prob >= th).astype(int)
        cm = confusion_matrix(y_true, y_pred_th, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        if fpr <= target_max_fpr:
            score = f1_score(y_true, y_pred_th, zero_division=0)
            if score > best_f1:
                best_f1 = score
                best_threshold = float(th)

    # Fallback to pure F1 optimization if constraint was too restrictive
    if best_f1 < 0:
        for th in thresholds:
            y_pred_th = (y_prob >= th).astype(int)
            score = f1_score(y_true, y_pred_th, zero_division=0)
            if score > best_f1:
                best_f1 = score
                best_threshold = float(th)

    return best_threshold, float(best_f1)


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50) -> dict[str, Any]:
    """Computes comprehensive classification metrics."""
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 1.0
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    return {
        "accuracy": round(acc, 4),
        "roc_auc": round(auc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "fpr": round(fpr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "decision_threshold": round(threshold, 4),
    }


def train_baseline(
    csv_path: Path | None = None,
    artifact_path: Path | None = None,
    auto_export_if_missing: bool = True,
) -> dict[str, Any]:
    """Executes the standard 7-step ML lifecycle workflow for MiniSOAR Baseline Model.

    Workflow:
    1. Mengambil Training Data (Data Ingestion & Preprocessing)
    2. Mentraining Model (Initial Training)
    3. Melakukan Validasi Model (Stratified K-Fold Cross-Validation)
    4. Melakukan Evaluasi (Initial Evaluation)
    5. Melakukan Perbaikan dan Training Ulang (Hyperparameter Tuning & Retraining)
    6. Validasi dan Evaluasi Ulang (Re-Validation & Quality Gate Verification)
    7. Menggunakan Model (Packaging, Atomic Deployment, & Hot-Reload Artifact)
    """
    load_env()
    root_dir = Path(__file__).resolve().parent.parent.parent
    csv_target = csv_path or (root_dir / "dataset.csv")
    artifact_target = artifact_path or (root_dir / "baseline_model.joblib")
    active_target = root_dir / "active_model.joblib"

    print("=" * 70)
    print("MiniSOAR ML Baseline Model Lifecycle Pipeline (7-Step Workflow)")
    print("=" * 70)

    # -------------------------------------------------------------
    # Step 1: Mengambil Training Data
    # -------------------------------------------------------------
    print("\n[Step 1/7] Mengambil Training Data...")
    if not csv_target.exists():
        if auto_export_if_missing:
            from .export import export_dataset_from_es
            print(f"Dataset {csv_target.name} tidak ditemukan. Mengekstrak dari Elasticsearch...")
            ok_exp, count, msg_exp = export_dataset_from_es(csv_target)
            print(f"Export status: {msg_exp} ({count:,} sample)")
        else:
            raise FileNotFoundError(f"dataset.csv tidak ditemukan di {csv_target}")

    df = pd.read_csv(csv_target)
    print(f"Loaded dataset: {df.shape[0]:,} baris, {df.shape[1]} kolom.")

    x, y, feature_columns, severity_map = prepare_features(df)
    print(f"Feature space: {len(feature_columns)} fitur ({', '.join(feature_columns[:6])}...)")
    print(f"Class distribution: Block (1)={int((y == 1).sum()):,}, Allow/None (0)={int((y == 0).sum()):,}")

    if len(np.unique(y)) < 2:
        raise ValueError("Dataset hanya memiliki 1 kelas. Memerlukan kelas Block (1) dan Allow (0).")

    # Split: 70% Train, 15% Validation, 15% Independent Test
    stratify = y if y.value_counts().min() >= 2 else None
    x_train_val, x_test, y_train_val, y_test = train_test_split(
        x, y, test_size=0.15, random_state=42, stratify=stratify
    )
    stratify_tv = y_train_val if y_train_val.value_counts().min() >= 2 else None
    x_train, x_val, y_train, y_val = train_test_split(
        x_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=stratify_tv
    )

    print(f"Partisi data: Train={len(x_train):,}, Val={len(x_val):,}, Test={len(x_test):,}")

    # -------------------------------------------------------------
    # Step 2: Mentraining Model Awal
    # -------------------------------------------------------------
    print("\n[Step 2/7] Mentraining Model Awal (Initial Baseline)...")
    init_model = LogisticRegression(max_iter=500, random_state=42, class_weight="balanced")
    init_model.fit(x_train, y_train)
    print("Initial model fitted successfully.")

    # -------------------------------------------------------------
    # Step 3: Melakukan Validasi Model (Cross-Validation)
    # -------------------------------------------------------------
    print("\n[Step 3/7] Melakukan Validasi Model (5-Fold Stratified Cross-Validation)...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_auc_scores = cross_val_score(init_model, x_train_val, y_train_val, cv=cv, scoring="roc_auc")
    cv_f1_scores = cross_val_score(init_model, x_train_val, y_train_val, cv=cv, scoring="f1")

    mean_cv_auc = float(np.mean(cv_auc_scores))
    std_cv_auc = float(np.std(cv_auc_scores))
    mean_cv_f1 = float(np.mean(cv_f1_scores))
    std_cv_f1 = float(np.std(cv_f1_scores))

    print(f"CV ROC-AUC: {mean_cv_auc:.4f} (+/- {std_cv_auc:.4f})")
    print(f"CV F1-Score: {mean_cv_f1:.4f} (+/- {std_cv_f1:.4f})")

    # -------------------------------------------------------------
    # Step 4: Melakukan Evaluasi Awal
    # -------------------------------------------------------------
    print("\n[Step 4/7] Melakukan Evaluasi Awal pada Validation Set...")
    init_val_prob = init_model.predict_proba(x_val)[:, 1]
    init_metrics = compute_metrics(y_val.to_numpy(), init_val_prob, threshold=0.50)

    print(f"Akurasi Awal   : {init_metrics['accuracy']:.4f}")
    print(f"ROC-AUC Awal   : {init_metrics['roc_auc']:.4f}")
    print(f"Precision Awal : {init_metrics['precision']:.4f}")
    print(f"Recall Awal    : {init_metrics['recall']:.4f}")
    print(f"F1-Score Awal  : {init_metrics['f1_score']:.4f}")
    print(f"FPR Awal       : {init_metrics['fpr']:.4f}")

    # -------------------------------------------------------------
    # Step 5: Melakukan Perbaikan dan Training Ulang
    # -------------------------------------------------------------
    print("\n[Step 5/7] Melakukan Perbaikan dan Training Ulang (Tuning & Refinement)...")
    c_candidates = [0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
    best_c = 1.0
    best_val_auc = -1.0
    best_candidate_model = init_model

    for c in c_candidates:
        cand_model = LogisticRegression(C=c, max_iter=1000, random_state=42, class_weight="balanced", solver="lbfgs")
        cand_model.fit(x_train, y_train)
        cand_prob = cand_model.predict_proba(x_val)[:, 1]
        cand_auc = roc_auc_score(y_val, cand_prob)
        if cand_auc > best_val_auc:
            best_val_auc = float(cand_auc)
            best_c = c
            best_candidate_model = cand_model

    print(f"Hyperparameter terpilih: C={best_c} (Validation ROC-AUC: {best_val_auc:.4f})")

    # Retrain model pada gabungan Train + Validation
    print("Retraining model dengan hyperparameter optimal pada dataset Train+Validation...")
    refined_model = LogisticRegression(C=best_c, max_iter=1000, random_state=42, class_weight="balanced", solver="lbfgs")
    refined_model.fit(x_train_val, y_train_val)

    # Threshold Optimization
    val_prob_refined = refined_model.predict_proba(x_val)[:, 1]
    optimal_th, opt_f1 = optimize_threshold(y_val.to_numpy(), val_prob_refined, target_max_fpr=0.03)
    print(f"Decision Threshold optimal: {optimal_th:.2f} (Target Max FPR <= 3%, Optimal F1: {opt_f1:.4f})")

    # -------------------------------------------------------------
    # Step 6: Validasi dan Evaluasi Ulang (Re-Evaluation)
    # -------------------------------------------------------------
    print("\n[Step 6/7] Validasi dan Evaluasi Ulang pada Hold-Out Test Set...")
    test_prob = refined_model.predict_proba(x_test)[:, 1]
    final_metrics = compute_metrics(y_test.to_numpy(), test_prob, threshold=optimal_th)

    delta_auc = final_metrics["roc_auc"] - init_metrics["roc_auc"]
    delta_f1 = final_metrics["f1_score"] - init_metrics["f1_score"]
    delta_acc = final_metrics["accuracy"] - init_metrics["accuracy"]

    print(f"Akurasi Akhir   : {final_metrics['accuracy']:.4f} (Delta: {delta_acc:+.4f})")
    print(f"ROC-AUC Akhir   : {final_metrics['roc_auc']:.4f} (Delta: {delta_auc:+.4f})")
    print(f"Precision Akhir : {final_metrics['precision']:.4f}")
    print(f"Recall Akhir    : {final_metrics['recall']:.4f}")
    print(f"F1-Score Akhir  : {final_metrics['f1_score']:.4f} (Delta: {delta_f1:+.4f})")
    print(f"FPR Akhir       : {final_metrics['fpr']:.4f}")
    print(f"Confusion Matrix: {final_metrics['confusion_matrix']}")

    target_auc = float(os.getenv("ML_TARGET_ROC_AUC", "0.88"))
    if final_metrics["roc_auc"] >= target_auc:
        print(f"PASSED Quality Gate: ROC-AUC {final_metrics['roc_auc']:.4f} >= {target_auc}")
    else:
        print(f"NOTICE: ROC-AUC {final_metrics['roc_auc']:.4f} di bawah target {target_auc}, model tetap disimpan sebagai baseline.")

    y_pred_final = (test_prob >= optimal_th).astype(int)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred_final, target_names=["Allow/Ignore (0)", "Block (1)"], digits=4))

    # -------------------------------------------------------------
    # Step 7: Menggunakan Model (Packaging & Deployment Artifact)
    # -------------------------------------------------------------
    print("\n[Step 7/7] Menggunakan Model (Packaging & Hot-Reload Artifact)...")
    model_artifact = {
        "model": refined_model,
        "feature_columns": feature_columns,
        "severity_map": severity_map,
        "decision_threshold": optimal_th,
        "metrics": final_metrics,
        "initial_metrics": init_metrics,
        "cv_scores": {
            "mean_roc_auc": round(mean_cv_auc, 4),
            "std_roc_auc": round(std_cv_auc, 4),
            "mean_f1": round(mean_cv_f1, 4),
            "std_f1": round(std_cv_f1, 4),
        },
        "trained_date": pd.Timestamp.now().isoformat(),
        "model_version": f"v_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}",
        "dataset_samples": len(df),
    }

    # Save to baseline_model.joblib
    artifact_target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_artifact, artifact_target)
    print(f"Baseline Model tersimpan di: {artifact_target}")

    # Also promote to active_model.joblib for production hot-reload
    tmp_active = active_target.with_suffix(".tmp")
    joblib.dump(model_artifact, tmp_active)
    tmp_active.replace(active_target)
    print(f"Active Model dipromosikan di: {active_target}")
    print("Engine inferensi SOAR telah siap menggunakan model yang diperbarui secara hot-reload.")
    print("=" * 70)

    return model_artifact


def main() -> None:
    train_baseline()


if __name__ == "__main__":
    main()

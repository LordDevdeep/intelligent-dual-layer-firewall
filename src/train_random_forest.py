#!/usr/bin/env python3

import os
import time
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)


DATA_DIR = "../datasets/cicids2017/ml/splits"
MODEL_DIR = "../models"

os.makedirs(MODEL_DIR, exist_ok=True)


def load_dataset(filename):

    path = os.path.join(DATA_DIR, filename)

    print(f"[+] Loading {filename}")

    df = pd.read_parquet(path)

    # Remove target-description column.
    # It must NOT be used as a feature.
    X = df.drop(
        columns=["Label", "Binary_Label"]
    )

    y = df["Binary_Label"]

    return X, y


def main():

    print("=" * 70)
    print("RESOLUTE - RANDOM FOREST BASELINE")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load training data
    # ---------------------------------------------------------

    X_train, y_train = load_dataset(
        "train.parquet"
    )

    print(f"\n[+] Training features: {X_train.shape}")
    print(f"[+] Training labels:   {y_train.shape}")

    # ---------------------------------------------------------
    # Load validation data
    # ---------------------------------------------------------

    X_val, y_val = load_dataset(
        "validation.parquet"
    )

    print(f"[+] Validation features: {X_val.shape}")

    # ---------------------------------------------------------
    # Train model
    # ---------------------------------------------------------

    print("\n[+] Creating Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=2,
        class_weight="balanced"
    )

    print("[+] Training started...")

    start = time.time()

    model.fit(
        X_train,
        y_train
    )

    elapsed = time.time() - start

    print(
        f"[+] Training completed in "
        f"{elapsed:.2f} seconds"
    )

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    print("\n[+] Running validation...")

    predictions = model.predict(X_val)

    accuracy = accuracy_score(
        y_val,
        predictions
    )

    precision = precision_score(
        y_val,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_val,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_val,
        predictions,
        zero_division=0
    )

    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    model_path = os.path.join(
        MODEL_DIR,
        "resolute_random_forest.joblib"
    )

    joblib.dump(
        model,
        model_path
    )

    print("\n[+] Model saved:")
    print(model_path)

    print("\n[+] Feature count:", len(X_train.columns))

    print("\n[+] Top 15 features:")

    importance = pd.Series(
        model.feature_importances_,
        index=X_train.columns
    ).sort_values(
        ascending=False
    )

    print(
        importance.head(15).to_string()
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import os
import pandas as pd

from sklearn.model_selection import train_test_split


INPUT_FILE = "../datasets/cicids2017/ml/cicids2017_ml_balanced.parquet"

OUTPUT_DIR = "../datasets/cicids2017/ml/splits"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def main():

    print("[+] Loading ML dataset...")

    df = pd.read_parquet(INPUT_FILE)

    print(f"[+] Dataset shape: {df.shape}")

    # ---------------------------------------------------------
    # First split:
    # 70% training
    # 30% temporary
    # ---------------------------------------------------------

    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        stratify=df["Binary_Label"],
        random_state=42
    )

    # ---------------------------------------------------------
    # Second split:
    # Half of temporary becomes validation,
    # half becomes test.
    # ---------------------------------------------------------

    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        stratify=temp_df["Binary_Label"],
        random_state=42
    )

    del temp_df

    print("\n" + "=" * 60)
    print("DATASET SPLIT")
    print("=" * 60)

    print(f"Training   : {len(train_df):,}")
    print(f"Validation : {len(val_df):,}")
    print(f"Test       : {len(test_df):,}")

    print("\nBinary distribution:")

    print("\nTRAIN:")
    print(train_df["Binary_Label"].value_counts())

    print("\nVALIDATION:")
    print(val_df["Binary_Label"].value_counts())

    print("\nTEST:")
    print(test_df["Binary_Label"].value_counts())

    # ---------------------------------------------------------
    # Save datasets
    # ---------------------------------------------------------

    train_file = os.path.join(
        OUTPUT_DIR,
        "train.parquet"
    )

    val_file = os.path.join(
        OUTPUT_DIR,
        "validation.parquet"
    )

    test_file = os.path.join(
        OUTPUT_DIR,
        "test.parquet"
    )

    train_df.to_parquet(
        train_file,
        index=False
    )

    val_df.to_parquet(
        val_file,
        index=False
    )

    test_df.to_parquet(
        test_file,
        index=False
    )

    print("\n[+] Saved:")
    print(f"    {train_file}")
    print(f"    {val_file}")
    print(f"    {test_file}")


if __name__ == "__main__":
    main()

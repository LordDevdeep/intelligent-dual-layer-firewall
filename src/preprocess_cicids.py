#!/usr/bin/env python3

import glob
import os
import pandas as pd
import numpy as np


DATA_DIR = "../datasets/cicids2017/hf_data"
OUTPUT_DIR = "../datasets/cicids2017/processed"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_file(file_path):

    filename = os.path.basename(file_path)

    print("\n" + "=" * 70)
    print(f"[+] Processing: {filename}")
    print("=" * 70)

    df = pd.read_parquet(file_path)

    print(f"[+] Original shape: {df.shape}")

    # Clean column names
    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_", regex=False)
    )

    # Label is the final column
    label_column = df.columns[-1]

    print(f"[+] Label column: {label_column}")

    # Replace infinite values
    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    before = len(df)

    # Remove rows containing missing values
    df = df.dropna()

    print(
        f"[+] Removed missing/invalid rows: "
        f"{before - len(df):,}"
    )

    before = len(df)

    # Remove duplicates within this file
    df = df.drop_duplicates()

    print(
        f"[+] Removed duplicate rows: "
        f"{before - len(df):,}"
    )

    print("\n[+] Class distribution:")

    print(
        df[label_column]
        .value_counts()
        .to_string()
    )

    # Output filename
    output_name = filename.replace(
        ".parquet",
        "_clean.parquet"
    )

    output_path = os.path.join(
        OUTPUT_DIR,
        output_name
    )

    df.to_parquet(
        output_path,
        index=False
    )

    print(f"\n[+] Saved: {output_path}")
    print(f"[+] Final shape: {df.shape}")

    # Explicitly release memory
    del df


def main():

    files = sorted(
        glob.glob(
            os.path.join(
                DATA_DIR,
                "**",
                "*.parquet"
            ),
            recursive=True
        )
    )

    print(f"[+] Found {len(files)} Parquet files")

    for file_path in files:
        clean_file(file_path)

    print("\n" + "=" * 70)
    print("[+] ALL FILES PROCESSED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()

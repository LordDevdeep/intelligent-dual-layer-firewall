#!/usr/bin/env python3

import glob
import os
import pandas as pd
import numpy as np

DATA_DIR = "../datasets/cicids2017/processed"
OUTPUT_DIR = "../datasets/cicids2017/ml"

BENIGN_TARGET = 100_000
ATTACK_TARGET = 100_000

os.makedirs(OUTPUT_DIR, exist_ok=True)


def main():

    files = sorted(
        glob.glob(
            os.path.join(DATA_DIR, "*.parquet")
        )
    )

    print(f"[+] Found {len(files)} files")

    # ---------------------------------------------------------
    # PASS 1: Count labels without loading feature columns
    # ---------------------------------------------------------

    print("\n[+] PASS 1: Counting labels...")

    global_counts = {}

    for file in files:

        name = os.path.basename(file)

        label_df = pd.read_parquet(
            file,
            columns=["Label"]
        )

        counts = label_df["Label"].value_counts()

        print(f"\n{name}")

        for label, count in counts.items():

            print(f"  {label}: {count:,}")

            global_counts[label] = (
                global_counts.get(label, 0) + count
            )

        del label_df

    total_benign = global_counts.get("BENIGN", 0)

    total_attack = sum(
        count
        for label, count in global_counts.items()
        if label != "BENIGN"
    )

    print("\n" + "=" * 70)
    print("GLOBAL COUNTS")
    print("=" * 70)

    print(f"Benign available : {total_benign:,}")
    print(f"Attack available : {total_attack:,}")

    # ---------------------------------------------------------
    # Calculate proportional quotas for each file
    # ---------------------------------------------------------

    benign_quotas = {}
    attack_quotas = {}

    for file in files:

        label_df = pd.read_parquet(
            file,
            columns=["Label"]
        )

        counts = label_df["Label"].value_counts()

        benign_count = counts.get("BENIGN", 0)

        attack_count = sum(
            count
            for label, count in counts.items()
            if label != "BENIGN"
        )

        benign_quotas[file] = int(
            BENIGN_TARGET *
            benign_count /
            total_benign
        )

        attack_quotas[file] = int(
            ATTACK_TARGET *
            attack_count /
            total_attack
        )

        del label_df

    # ---------------------------------------------------------
    # PASS 2: Load one file at a time and sample
    # ---------------------------------------------------------

    print("\n[+] PASS 2: Sampling data...")

    benign_parts = []
    attack_parts = []

    for file in files:

        name = os.path.basename(file)

        print(f"\n[+] Processing {name}")

        df = pd.read_parquet(file)

        benign_quota = benign_quotas[file]
        attack_quota = attack_quotas[file]

        benign = df[df["Label"] == "BENIGN"]

        attacks = df[df["Label"] != "BENIGN"]

        if benign_quota > 0:
            benign = benign.sample(
                n=min(benign_quota, len(benign)),
                random_state=42
            )
            benign_parts.append(benign)

        if attack_quota > 0:
            attacks = attacks.sample(
                n=min(attack_quota, len(attacks)),
                random_state=42
            )
            attack_parts.append(attacks)

        print(
            f"    Benign sampled: {len(benign):,}"
        )

        print(
            f"    Attack sampled: {len(attacks):,}"
        )

        del df
        del benign
        del attacks

    # ---------------------------------------------------------
    # Combine only the sampled data
    # ---------------------------------------------------------

    print("\n[+] Combining sampled data...")

    benign_data = pd.concat(
        benign_parts,
        ignore_index=True
    )

    attack_data = pd.concat(
        attack_parts,
        ignore_index=True
    )

    del benign_parts
    del attack_parts

    # ---------------------------------------------------------
    # Binary labels
    # ---------------------------------------------------------

    benign_data["Binary_Label"] = 0
    attack_data["Binary_Label"] = 1

    dataset = pd.concat(
        [
            benign_data,
            attack_data
        ],
        ignore_index=True
    )

    del benign_data
    del attack_data

    # ---------------------------------------------------------
    # Final shuffle
    # ---------------------------------------------------------

    dataset = dataset.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print("\n" + "=" * 70)
    print("FINAL ML DATASET")
    print("=" * 70)

    print(f"Rows    : {len(dataset):,}")
    print(f"Columns : {len(dataset.columns)}")

    print("\nBinary distribution:")

    print(
        dataset["Binary_Label"]
        .value_counts()
        .sort_index()
    )

    print("\nOriginal attack distribution:")

    print(
        dataset["Label"]
        .value_counts()
        .to_string()
    )

    # ---------------------------------------------------------
    # Save
    # ---------------------------------------------------------

    output_file = os.path.join(
        OUTPUT_DIR,
        "cicids2017_ml_balanced.parquet"
    )

    dataset.to_parquet(
        output_file,
        index=False
    )

    print("\n[+] Saved:")
    print(output_file)

    print(f"\n[+] Final shape: {dataset.shape}")


if __name__ == "__main__":
    main()

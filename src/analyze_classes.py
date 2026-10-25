#!/usr/bin/env python3

import glob
import os
import pandas as pd

DATA_DIR = "../datasets/cicids2017/processed"


def main():

    files = sorted(
        glob.glob(
            os.path.join(DATA_DIR, "*.parquet")
        )
    )

    print(f"[+] Found {len(files)} cleaned files")

    total_counts = {}

    for file in files:

        filename = os.path.basename(file)

        # Read only the label column
        temp = pd.read_parquet(
            file,
            columns=["Label"]
        )

        counts = temp["Label"].value_counts()

        print(f"\n{filename}")
        print("-" * 60)

        for label, count in counts.items():

            print(f"{label}: {count:,}")

            total_counts[label] = (
                total_counts.get(label, 0) + count
            )

        del temp

    print("\n" + "=" * 70)
    print("COMBINED CLASS DISTRIBUTION")
    print("=" * 70)

    total = sum(total_counts.values())

    for label, count in sorted(
        total_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        percentage = (count / total) * 100

        print(
            f"{label:<35} "
            f"{count:>10,} "
            f"({percentage:>6.2f}%)"
        )

    print("=" * 70)
    print(f"TOTAL FLOWS: {total:,}")


if __name__ == "__main__":
    main()

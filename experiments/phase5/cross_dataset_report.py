import pandas as pd

results = [
    {
        "Dataset": "CIC-IDS2017",
        "Evaluation": "Held-out test",
        "Samples": 29999,
        "Accuracy": 0.997967,
        "Precision": 0.999000,
        "Recall": 0.996933,
        "F1": 0.997967,
        "Observation": "Strong binary detection on CIC-IDS2017"
    },
    {
        "Dataset": "UWF-ZeekData24",
        "Evaluation": "Held-out test",
        "Samples": 946,
        "Accuracy": 0.996829,
        "Precision": 0.993697,
        "Recall": 1.000000,
        "F1": 0.996839,
        "Observation": "Strong detection on UWF flow data"
    },
    {
        "Dataset": "BigFlow-NIDS",
        "Evaluation": "Held-out test",
        "Samples": 15000,
        "Accuracy": 0.845733,
        "Precision": 0.879094,
        "Recall": 0.801733,
        "F1": 0.838340,
        "Observation": "Lower overall performance; scanning detection is weaker"
    }
]

df = pd.DataFrame(results)

print("\n========================================")
print("RESOLUTE - CROSS-DATASET ML SUMMARY")
print("========================================\n")

print(df.to_string(index=False))

output = "resolute_cross_dataset_results.csv"

df.to_csv(output, index=False)

print("\nSaved:", output)

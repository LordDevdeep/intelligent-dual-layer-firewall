#!/usr/bin/env python3

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder


DATA_FILE = "detection/training_data.csv"
MODEL_FILE = "detection/resolute_model.pkl"


def main():

    print("Resolute Wall 1 - ML Training")
    print("Loading training data...\n")

    data = pd.read_csv(DATA_FILE)

    features = [
        "packets",
        "bytes",
        "tcp",
        "udp",
        "icmp"
    ]

    X = data[features]
    y = data["label"]

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.25,
        random_state=42,
        stratify=y_encoded
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(f"Accuracy: {accuracy:.2f}\n")

    print("Classification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=encoder.classes_
        )
    )

    import joblib

    joblib.dump(
        {
            "model": model,
            "encoder": encoder,
            "features": features
        },
        MODEL_FILE
    )

    print(f"\nModel saved to: {MODEL_FILE}")


if __name__ == "__main__":
    main()

import csv
import json
from pathlib import Path

from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from ai_engine.modeling import build_model, save_model

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "data" / "demo_incidents.csv"
ARTIFACT = ROOT / "artifacts" / "incident_classifier.joblib"


def load_dataset() -> tuple[list[str], list[str]]:
    with DATASET.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Training dataset is empty")
    return [row["text"] for row in rows], [row["label"] for row in rows]


def train_and_evaluate() -> dict[str, object]:
    texts, labels = load_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )
    evaluation_model = build_model().fit(x_train, y_train)
    predictions = evaluation_model.predict(x_test)
    metrics = {
        "dataset": "synthetic demo only",
        "rows": len(texts),
        "seed": 42,
        "accuracy": accuracy_score(y_test, predictions),
        "classification_report": classification_report(
            y_test, predictions, output_dict=True, zero_division=0
        ),
    }
    final_model = build_model().fit(texts, labels)
    save_model(final_model, ARTIFACT)
    metrics_path = ARTIFACT.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    print(json.dumps(train_and_evaluate(), indent=2))

import os
from functools import lru_cache
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

DEFAULT_MODEL = Path(__file__).resolve().parent / "artifacts" / "incident_classifier.joblib"
app = FastAPI(title="QuantumSHIELD AI Service", version="0.1.0")


class ClassificationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=32_000)


CLASSIFICATION_GUIDANCE = {
    "resource_exhaustion": {
        "severity": "high",
        "recommended_action": "Review workload resource limits and node capacity",
        "auto_healing_eligible": True,
    },
    "application_failure": {
        "severity": "medium",
        "recommended_action": "Review application health checks and recent deployment changes",
        "auto_healing_eligible": False,
    },
    "suspicious_activity": {
        "severity": "critical",
        "recommended_action": "Preserve evidence and require security analyst investigation",
        "auto_healing_eligible": False,
    },
}


@lru_cache(maxsize=1)
def _model():
    path = Path(os.getenv("AI_MODEL_PATH", str(DEFAULT_MODEL)))
    if not path.is_file():
        raise FileNotFoundError("No trained model. Run: python -m ai_engine.train")
    return joblib.load(path)


def _configured_path() -> Path:
    return Path(os.getenv("AI_MODEL_PATH", str(DEFAULT_MODEL)))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": "ready" if _configured_path().is_file() else "not_trained"}


@app.post("/v1/classify")
def classify(request: ClassificationRequest) -> dict[str, object]:
    try:
        model = _model()
        label = str(model.predict([request.text])[0])
        probabilities = model.predict_proba([request.text])[0]
    except (FileNotFoundError, AttributeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    classes = list(model.classes_)
    confidence = float(probabilities[classes.index(label)])
    guidance = CLASSIFICATION_GUIDANCE.get(
        label,
        {
            "severity": "unknown",
            "recommended_action": "Review the incident manually",
            "auto_healing_eligible": False,
        },
    )
    return {
        "classification": label,
        **guidance,
        "confidence": round(confidence, 6),
        "confidence_basis": "classifier class probability",
        "calibrated": False,
        "dataset_notice": "Synthetic demo model; not validated for production threat detection.",
    }

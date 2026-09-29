import json
import os
from typing import Literal
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, Field, ValidationError

class AIUnavailable(RuntimeError):
    pass


class AIResponseInvalid(RuntimeError):
    pass


class AIAnalysis(BaseModel):
    classification: str = Field(min_length=1, max_length=160)
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_basis: str
    calibrated: bool
    recommended_action: str = Field(max_length=1000)
    auto_healing_eligible: bool
    dataset_notice: str


class AIClient:
    def __init__(self, base_url: str | None = None, timeout: float | None = None):
        if base_url is None or timeout is None:
            from backend.app.core.config import get_settings

            settings = get_settings()
            base_url = base_url or settings.ai_service_url
            timeout = timeout or settings.integration_timeout_seconds
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def analyze(self, *, incident_type: str, summary: str, description: str) -> AIAnalysis:
        body = json.dumps(
            {"text": f"Incident type: {incident_type}\nSummary: {summary}\nEvidence: {description}"}
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/v1/classify",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except (URLError, TimeoutError, OSError) as exc:
            raise AIUnavailable("AI service did not respond") from exc
        except json.JSONDecodeError as exc:
            raise AIResponseInvalid("AI service returned invalid JSON") from exc
        try:
            return AIAnalysis.model_validate(payload)
        except ValidationError as exc:
            raise AIResponseInvalid("AI service returned an invalid analysis") from exc


class DemoAIClient:
    """Deterministic demo classifier; results are explicitly marked simulated."""

    def analyze(self, *, incident_type: str, summary: str, description: str) -> AIAnalysis:
        return AIAnalysis(
            classification="operational_anomaly",
            severity="medium",
            confidence=0.75,
            confidence_basis="Deterministic demonstration fixture; not a model probability",
            calibrated=False,
            recommended_action="Review the workload and request operator approval before any remediation.",
            auto_healing_eligible=False,
            dataset_notice="DEMO: deterministic simulated analysis; no AI service was called.",
        )

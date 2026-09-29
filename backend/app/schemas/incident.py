from datetime import datetime
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Severity = Literal["critical", "high", "medium", "low", "unknown"]
IncidentStatus = Literal["detected", "triaged", "investigating", "resolved", "dismissed"]


class IncidentCreate(BaseModel):
    source: str = Field(min_length=1, max_length=160)
    incident_type: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=4, max_length=240)
    description: str = Field(min_length=1, max_length=30_000)
    encryption_required: bool = False
    attributes: dict[str, object] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def reject_secret_fields(cls, value: dict[str, object]) -> dict[str, object]:
        forbidden = {"password", "secret", "token", "private_key", "credential"}

        def contains_secret_key(item: object) -> bool:
            if isinstance(item, dict):
                return any(
                    any(term in str(key).lower() for term in forbidden) or contains_secret_key(nested)
                    for key, nested in item.items()
                )
            if isinstance(item, list):
                return any(contains_secret_key(nested) for nested in item)
            return False

        if len(value) > 32 or len(json.dumps(value, default=str)) > 8192:
            raise ValueError("Incident attributes exceed the size limit")
        if contains_secret_key(value):
            raise ValueError("Sensitive credentials must not be submitted as incident attributes")
        return value


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=1000)


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    incident_type: str
    summary: str
    description: str | None
    encryption_required: bool
    severity: str
    status: str
    classification: str | None
    confidence: float | None
    recommended_action: str | None
    ai_status: str
    analysis_details: dict[str, object]
    auto_healing_eligible: bool | None
    healing_status: str
    record_hash: str | None
    pqc_status: str
    signature_algorithm: str | None
    signature: str | None
    signature_verified: bool | None
    kem_algorithm: str | None
    encryption_status: str
    encryption_metadata: dict[str, object]
    encrypted_payload: str | None
    blockchain_provider: str
    blockchain_status: str
    blockchain_timestamp: datetime | None
    blockchain_verified: bool | None
    blockchain_tx_id: str | None
    attributes: dict[str, object]
    created_at: datetime
    updated_at: datetime


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str | None
    actor_id: str | None
    actor_type: str
    event_type: str
    result: str
    event_data: dict[str, object]
    created_at: datetime

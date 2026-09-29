from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.healing_action import HealingAction
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.services.ai_client import AIAnalysis, AIClient, AIResponseInvalid, AIUnavailable, DemoAIClient
from backend.app.services.audit_service import record_event
from blockchain_service.client import (
    BlockchainClient,
    BlockchainUnavailable,
    configured_client,
)
from kubernetes.policy import decide_incident_response
from pqc.provider import PQCProvider, PQCUnavailable, configured_provider
from pqc.record import sha256_hex
from pqc.service import protect_record


class RequiredEncryptionUnavailable(RuntimeError):
    pass


class IncidentPipeline:
    """Coordinates one incident lifecycle; all integrations can be injected in tests."""

    def __init__(
        self,
        *,
        ai_client: AIClient | None = None,
        pqc_provider: PQCProvider | None = None,
        blockchain_client: BlockchainClient | None = None,
        recipient_public_key: bytes | None = None,
    ):
        settings = get_settings()
        self.ai_client = ai_client or (DemoAIClient() if settings.demo_mode else AIClient())
        self._pqc_provider = pqc_provider
        self._provider_loaded = pqc_provider is not None
        self._recipient_public_key = recipient_public_key
        self._blockchain_client = blockchain_client

    def _get_pqc(self) -> PQCProvider | None:
        if self._provider_loaded:
            return self._pqc_provider
        self._provider_loaded = True
        if get_settings().demo_mode or get_settings().pqc_provider == "unavailable":
            return None
        try:
            return configured_provider()
        except Exception:
            return None

    def _get_blockchain(self) -> BlockchainClient:
        if self._blockchain_client is not None:
            return self._blockchain_client
        return configured_client()

    @staticmethod
    def _audit(
        db: Session,
        incident: Incident,
        event_type: str,
        *,
        actor: User | None = None,
        result: str = "success",
        metadata: dict[str, object] | None = None,
    ) -> None:
        record_event(
            db,
            event_type=event_type,
            actor_id=actor.id if actor else None,
            actor_type=actor.role.value if actor else "SYSTEM",
            incident_id=incident.id,
            result=result,
            event_data=metadata or {},
        )

    @staticmethod
    def _security_record(incident: Incident, evidence: str) -> dict[str, object]:
        description_digest = sha256_hex(evidence.encode("utf-8"))
        return {
            "incident_id": incident.id,
            "timestamp": incident.created_at.isoformat(),
            "source": incident.source,
            "incident_type": incident.incident_type,
            "summary": incident.summary,
            "description_sha256": description_digest,
            "description": evidence,
            "severity": incident.severity,
            "classification": incident.classification,
            "confidence": incident.confidence,
            "recommended_action": incident.recommended_action,
            "ai_status": incident.ai_status,
            "healing_status": incident.healing_status,
            "encryption_required": incident.encryption_required,
        }

    def submit(
        self,
        db: Session,
        *,
        actor: User | None,
        source: str,
        incident_type: str,
        summary: str,
        description: str,
        encryption_required: bool = False,
        attributes: dict[str, object] | None = None,
    ) -> Incident:
        if encryption_required:
            provider = self._get_pqc()
            if provider is None or self._recipient_key(True) is None:
                raise RequiredEncryptionUnavailable(
                    "Required evidence encryption is unavailable; incident was not persisted"
                )
        incident = Incident(
            id=str(uuid4()),
            source=source,
            incident_type=incident_type,
            summary=summary,
            description=None if encryption_required else description,
            encryption_required=encryption_required,
            severity="unknown",
            status="detected",
            ai_status="pending",
            blockchain_provider="mock" if get_settings().demo_mode else get_settings().blockchain_provider,
            attributes=attributes or {},
        )
        db.add(incident)
        db.flush()
        self._audit(db, incident, "incident.created", actor=actor, metadata={"source": source})
        db.commit()  # Keep the initial security event if any external service fails.
        self.analyze(db, incident, actor=actor, evidence=description)
        return incident

    def analyze(
        self,
        db: Session,
        incident: Incident,
        *,
        actor: User | None = None,
        evidence: str | None = None,
    ) -> Incident:
        evidence = incident.description if evidence is None else evidence
        if evidence is None:
            raise RequiredEncryptionUnavailable("Original event evidence is not available for analysis")
        try:
            analysis = self.ai_client.analyze(
                incident_type=incident.incident_type,
                summary=incident.summary,
                description=evidence,
            )
        except AIUnavailable:
            incident.ai_status = "unavailable"
            incident.analysis_details = {"error_code": "AI_UNAVAILABLE"}
            self._audit(db, incident, "ai.analysis", actor=actor, result="unavailable")
            self._audit(db, incident, "severity.decision", actor=actor, result="unavailable", metadata={"severity": "unknown"})
            analysis = None
        except AIResponseInvalid:
            incident.ai_status = "failed"
            incident.analysis_details = {"error_code": "AI_RESPONSE_INVALID"}
            self._audit(db, incident, "ai.analysis", actor=actor, result="failed")
            self._audit(db, incident, "severity.decision", actor=actor, result="unavailable", metadata={"severity": "unknown"})
            analysis = None
        except Exception:
            incident.ai_status = "failed"
            incident.analysis_details = {"error_code": "AI_ANALYSIS_FAILED"}
            self._audit(db, incident, "ai.analysis", actor=actor, result="failed")
            self._audit(db, incident, "severity.decision", actor=actor, result="unavailable", metadata={"severity": "unknown"})
            analysis = None

        if analysis is not None:
            self._apply_analysis(db, incident, analysis, actor)

        self._apply_healing_policy(db, incident, actor)
        security_record = self._security_record(incident, evidence)
        provider = self._get_pqc()
        recipient_key = self._recipient_key(incident.encryption_required)
        protected = protect_record(
            security_record,
            provider=provider,
            encryption_required=incident.encryption_required,
            recipient_public_key=recipient_key,
        )
        incident.record_hash = protected.record_hash
        incident.pqc_status = protected.pqc_status
        incident.signature_algorithm = protected.signature_algorithm
        incident.signature = protected.signature
        incident.signature_verified = protected.signature_verified
        incident.kem_algorithm = protected.kem_algorithm
        incident.encryption_status = protected.encryption_status
        incident.encryption_metadata = dict(protected.encryption_metadata)
        incident.encrypted_payload = protected.encrypted_payload
        if incident.encryption_required:
            # Mandatory evidence is never stored in plaintext, even if the runtime provider fails.
            incident.description = None
            if protected.encryption_status != "encrypted":
                incident.ai_status = "evidence_encryption_failed"
                incident.analysis_details = {
                    **incident.analysis_details,
                    "evidence_discarded": "Required encryption failed; plaintext was not retained.",
                }

        self._audit(
            db, incident, "pqc.sign", actor=actor,
            result="success" if protected.signature else protected.pqc_status,
            metadata={"algorithm": protected.signature_algorithm or "ML-DSA-65", "record_hash": protected.record_hash},
        )
        self._audit(
            db, incident, "pqc.verify", actor=actor,
            result="success" if protected.signature_verified is True else (
                "failed" if protected.signature_verified is False else "unavailable"
            ),
            metadata={"verified": protected.signature_verified},
        )
        self._audit(
            db, incident, "pqc.encrypt", actor=actor,
            result=protected.encryption_status,
            metadata={
                "required": incident.encryption_required,
                "kem_algorithm": protected.kem_algorithm,
                "encryption_algorithm": protected.encryption_metadata.get("encryption_algorithm"),
            },
        )
        self._record_blockchain(db, incident, actor)
        db.commit()
        db.refresh(incident)
        return incident

    def _recipient_key(self, required: bool) -> bytes | None:
        if not required:
            return None
        if self._recipient_public_key is not None:
            return self._recipient_public_key
        settings = get_settings()
        if not settings.pqc_recipient_public_key_path:
            return None
        try:
            return Path(settings.pqc_recipient_public_key_path).read_bytes()
        except OSError:
            return None

    def _apply_analysis(
        self, db: Session, incident: Incident, analysis: AIAnalysis, actor: User | None
    ) -> None:
        is_demo = analysis.dataset_notice.startswith("DEMO:")
        incident.ai_status = "demo" if is_demo else "completed"
        incident.classification = analysis.classification
        incident.severity = analysis.severity
        incident.confidence = analysis.confidence
        incident.recommended_action = analysis.recommended_action
        incident.auto_healing_eligible = analysis.auto_healing_eligible
        incident.analysis_details = {
            "confidence_basis": analysis.confidence_basis,
            "calibrated": analysis.calibrated,
            "dataset_notice": analysis.dataset_notice,
            "analysis_mode": "simulated" if is_demo else "service",
        }
        self._audit(
            db, incident, "ai.analysis", actor=actor,
            metadata={"classification": analysis.classification, "confidence": analysis.confidence},
        )
        self._audit(
            db, incident, "severity.decision", actor=actor,
            metadata={"severity": analysis.severity, "basis": "AI model guidance"},
        )

    def _apply_healing_policy(self, db: Session, incident: Incident, actor: User | None) -> None:
        policy = decide_incident_response(
            incident.incident_type,
            incident.severity,
            ai_eligible=incident.ai_status == "completed" and incident.auto_healing_eligible is True,
            policy_enabled=get_settings().auto_remediation_enabled,
        )
        incident.healing_status = policy.status
        action = incident.recommended_action or policy.action
        db.add(
            HealingAction(
                incident_id=incident.id,
                action=action,
                status=policy.status,
                mode="simulation",
                verification_status="pending",
                details="No cluster operation was executed by this incident pipeline.",
            )
        )
        self._audit(
            db, incident, "healing.decision", actor=actor,
            result="pending" if policy.eligible else "manual_review",
            metadata={
                "eligible": policy.eligible,
                "reason": policy.reason,
                "mode": "simulation",
                "action": action,
            },
        )

    def _record_blockchain(self, db: Session, incident: Incident, actor: User | None) -> None:
        if incident.blockchain_provider == "disabled":
            incident.blockchain_status = "not_performed"
            self._audit(db, incident, "blockchain.record", actor=actor, result="not_performed")
            return
        client = self._get_blockchain()
        self._audit(
            db, incident, "blockchain.record", actor=actor,
            result="pending", metadata={"provider": client.provider},
        )
        metadata: dict[str, object] = {
            "timestamp": incident.created_at.isoformat(),
            "source": incident.source,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "classification": incident.classification,
            "confidence": incident.confidence,
            "recommended_action": incident.recommended_action,
            "healing_status": incident.healing_status,
            "signature_algorithm": incident.signature_algorithm,
            "signature_verification_status": incident.signature_verified,
            "kem_algorithm": incident.kem_algorithm,
            "encryption_status": incident.encryption_status,
        }
        try:
            receipt = client.record(incident.id, incident.record_hash or "", metadata)
            incident.blockchain_provider = receipt.provider
            incident.blockchain_tx_id = receipt.transaction_id
            from datetime import datetime

            incident.blockchain_timestamp = datetime.fromisoformat(
                receipt.timestamp.replace("Z", "+00:00")
            )
            verified = client.verify(incident.id, incident.record_hash or "")
            incident.blockchain_verified = verified
            if receipt.provider == "mock":
                incident.blockchain_status = "mock_recorded"
            else:
                incident.blockchain_status = "recorded" if verified else "verification_failed"
            self._audit(
                db, incident, "blockchain.result", actor=actor,
                result=incident.blockchain_status,
                metadata={"provider": receipt.provider, "verified": verified},
            )
        except BlockchainUnavailable:
            incident.blockchain_status = "unavailable"
            incident.blockchain_verified = None
            self._audit(db, incident, "blockchain.result", actor=actor, result="unavailable")
        except Exception:
            incident.blockchain_status = "failed"
            incident.blockchain_verified = False
            self._audit(db, incident, "blockchain.result", actor=actor, result="failed")

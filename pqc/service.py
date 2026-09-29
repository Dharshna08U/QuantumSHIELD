import base64
from dataclasses import dataclass
from typing import Protocol

from pqc.record import canonical_record, sha256_hex
from pqc.provider import PQCUnavailable


class IntegrityProvider(Protocol):
    signature_algorithm: str
    kem_algorithm: str
    def sign(self, message: bytes) -> bytes: ...
    def signing_public_key(self) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool: ...
    def encapsulate_and_encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> dict[str, str]: ...
    def decrypt(self, envelope: dict[str, str]) -> bytes: ...


@dataclass(frozen=True)
class ProtectedRecord:
    record_hash: str
    pqc_status: str
    signature_algorithm: str | None
    signature: str | None
    signature_verified: bool | None
    encryption_status: str
    kem_algorithm: str | None
    encryption_metadata: dict[str, str]
    encrypted_payload: str | None


def decrypt_envelope(provider: IntegrityProvider, envelope: dict[str, str]) -> bytes:
    """Delegate authenticated decryption to the configured provider."""
    return provider.decrypt(envelope)


def protect_record(
    record: dict[str, object],
    *,
    provider: IntegrityProvider | None,
    encryption_required: bool = False,
    recipient_public_key: bytes | None = None,
) -> ProtectedRecord:
    canonical = canonical_record(record)
    digest = sha256_hex(canonical)
    signature = None
    signature_verified = None
    signature_algorithm = None
    pqc_status = "unavailable"

    if provider is not None:
        try:
            raw_signature = provider.sign(canonical)
            signature_verified = provider.verify(
                canonical, raw_signature, provider.signing_public_key()
            )
            signature_algorithm = provider.signature_algorithm
            signature = base64.b64encode(raw_signature).decode("ascii")
            pqc_status = "verified" if signature_verified is True else "failed"
        except PQCUnavailable:
            pqc_status = "unavailable"
        except Exception:
            # Do not turn provider errors into a successful verification status.
            pqc_status = "failed"
            signature_verified = False

    encryption_status = "not_performed"
    kem_algorithm = None
    encryption_metadata: dict[str, str] = {}
    encrypted_payload = None
    if encryption_required:
        if provider is None or recipient_public_key is None:
            encryption_status = "unavailable"
        else:
            try:
                envelope = provider.encapsulate_and_encrypt(
                    canonical_record(record), recipient_public_key
                )
                encrypted_payload = envelope["ciphertext"]
                kem_algorithm = envelope["kem_algorithm"]
                encryption_metadata = {
                    "encryption_algorithm": envelope["encryption_algorithm"],
                    "encapsulated_key": envelope["encapsulated_key"],
                    "nonce": envelope["nonce"],
                }
                encryption_status = "encrypted"
            except PQCUnavailable:
                encryption_status = "unavailable"
            except Exception:
                encryption_status = "failed"

    return ProtectedRecord(
        record_hash=digest,
        pqc_status=pqc_status,
        signature_algorithm=signature_algorithm,
        signature=signature,
        signature_verified=signature_verified,
        encryption_status=encryption_status,
        kem_algorithm=kem_algorithm,
        encryption_metadata=encryption_metadata,
        encrypted_payload=encrypted_payload,
    )

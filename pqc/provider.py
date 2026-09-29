from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class PQCProvider(Protocol):
    def sign(self, message: bytes) -> bytes: ...
    def signing_public_key(self) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool: ...
    def encapsulate_and_encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> dict[str, str]: ...
    def decrypt(self, envelope: dict[str, str]) -> bytes: ...


class PQCUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Verification:
    algorithm: str
    verified: bool


class OQSProvider:
    """Optional liboqs provider; keys must be provisioned outside the repository."""

    signature_algorithm = "ML-DSA-65"
    kem_algorithm = "ML-KEM-768"

    def __init__(
        self,
        private_key_path: str | Path,
        public_key_path: str | Path,
        kem_private_key_path: str | Path | None = None,
    ):
        try:
            import oqs  # type: ignore[import-not-found]
        except ImportError as exc:
            raise PQCUnavailable("liboqs-python is not installed") from exc
        path = Path(private_key_path)
        if not path.is_file():
            raise PQCUnavailable("Configured ML-DSA private key file is unavailable")
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PQCUnavailable("ML-DSA private key file must not be group/world readable")
        public_path = Path(public_key_path)
        if not public_path.is_file():
            raise PQCUnavailable("Configured ML-DSA public key file is unavailable")
        self._oqs = oqs
        self._private_key = path.read_bytes()
        self._public_key = public_path.read_bytes()
        self._kem_private_key = None
        if kem_private_key_path:
            kem_path = Path(kem_private_key_path)
            if not kem_path.is_file():
                raise PQCUnavailable("Configured ML-KEM private key file is unavailable")
            if stat.S_IMODE(kem_path.stat().st_mode) & 0o077:
                raise PQCUnavailable("ML-KEM private key file must not be group/world readable")
            self._kem_private_key = kem_path.read_bytes()

    def sign(self, message: bytes) -> bytes:
        with self._oqs.Signature(self.signature_algorithm, secret_key=self._private_key) as signer:
            return signer.sign(message)

    def signing_public_key(self) -> bytes:
        return self._public_key

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        with self._oqs.Signature(self.signature_algorithm) as verifier:
            return bool(verifier.verify(message, signature, public_key))

    def encapsulate_and_encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> dict[str, str]:
        with self._oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"QuantumSHIELD incident payload v1"
        ).derive(shared_secret)
        nonce = os.urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, plaintext, b"QuantumSHIELD-v1")
        return {
            "kem_algorithm": self.kem_algorithm,
            "encryption_algorithm": "AES-256-GCM",
            "encapsulated_key": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        }

    def decrypt(self, envelope: dict[str, str]) -> bytes:
        if self._kem_private_key is None:
            raise PQCUnavailable("PQC_KEM_PRIVATE_KEY_PATH is required for decryption")
        if envelope.get("kem_algorithm") != self.kem_algorithm:
            raise ValueError("Unexpected KEM algorithm")
        with self._oqs.KeyEncapsulation(
            self.kem_algorithm, secret_key=self._kem_private_key
        ) as kem:
            shared_secret = kem.decap_secret(base64.b64decode(envelope["encapsulated_key"]))
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"QuantumSHIELD incident payload v1"
        ).derive(shared_secret)
        return AESGCM(key).decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ciphertext"]),
            b"QuantumSHIELD-v1",
        )


class UnavailableProvider:
    """Fail closed; this provider never simulates or labels non-PQC crypto as PQC."""

    def sign(self, message: bytes) -> bytes:
        raise PQCUnavailable("PQC provider is not configured")

    def signing_public_key(self) -> bytes:
        raise PQCUnavailable("PQC provider is not configured")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise PQCUnavailable("PQC provider is not configured")

    def encapsulate_and_encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> dict[str, str]:
        raise PQCUnavailable("PQC provider is not configured")

    def decrypt(self, envelope: dict[str, str]) -> bytes:
        raise PQCUnavailable("PQC provider is not configured")


def configured_provider() -> PQCProvider:
    from backend.app.core.config import get_settings

    settings = get_settings()
    provider = settings.pqc_provider.lower()
    if provider == "oqs":
        if not settings.pqc_private_key_path or not settings.pqc_public_key_path:
            raise PQCUnavailable("PQC private and public key paths are required for the OQS provider")
        return OQSProvider(
            settings.pqc_private_key_path,
            settings.pqc_public_key_path,
            settings.pqc_kem_private_key_path,
        )
    return UnavailableProvider()

import base64
import hashlib
import json
import sys
import tempfile
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from blockchain_service.client import BlockchainUnavailable, FabricClient, MockBlockchainClient
from pqc.provider import PQCUnavailable, UnavailableProvider
from pqc.provider import OQSProvider
from pqc.record import canonical_record, sha256_hex
from pqc.service import decrypt_envelope, protect_record


class FakePQCProvider:
    """Test-only provider. It is deliberately labeled FAKE and is not production crypto."""

    signature_algorithm = "FAKE-TEST-SIGNATURE"
    kem_algorithm = "FAKE-TEST-KEM"
    _key = b"0123456789abcdef0123456789abcdef"

    def sign(self, message: bytes) -> bytes:
        return hashlib.sha256(self._key + message).digest()

    def signing_public_key(self) -> bytes:
        return self._key

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return public_key == self._key and signature == self.sign(message)

    def encapsulate_and_encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> dict[str, str]:
        nonce = b"0123456789ab"
        encrypted = AESGCM(self._key).encrypt(nonce, plaintext, b"test-only")
        return {
            "kem_algorithm": self.kem_algorithm,
            "encryption_algorithm": "AES-256-GCM",
            "encapsulated_key": base64.b64encode(b"fake-kem-ciphertext").decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(encrypted).decode(),
        }

    def decrypt(self, envelope: dict[str, str]) -> bytes:
        return AESGCM(self._key).decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ciphertext"]),
            b"test-only",
        )


class PQCWorkflowTests(unittest.TestCase):
    def test_hash_and_signature_are_verified_by_provider(self):
        provider = FakePQCProvider()
        record = {"incident_id": "test-1", "severity": "high"}
        protected = protect_record(record, provider=provider)
        self.assertEqual(protected.record_hash, sha256_hex(canonical_record(record)))
        self.assertEqual(protected.pqc_status, "verified")
        self.assertIs(protected.signature_verified, True)
        self.assertEqual(protected.signature_algorithm, "FAKE-TEST-SIGNATURE")
        self.assertEqual(protected.encryption_status, "not_performed")

    def test_signature_failure_is_never_reported_as_verified(self):
        class InvalidSignatureProvider(FakePQCProvider):
            def verify(self, message, signature, public_key):
                return False

        protected = protect_record({"id": "test"}, provider=InvalidSignatureProvider())
        self.assertEqual(protected.pqc_status, "failed")
        self.assertIs(protected.signature_verified, False)

    def test_provider_unavailable_is_explicit(self):
        with self.assertRaises(PQCUnavailable):
            UnavailableProvider().sign(b"test")
        result = protect_record({"id": "test"}, provider=None)
        self.assertEqual(result.pqc_status, "unavailable")
        self.assertIsNone(result.signature_verified)

    def test_encryption_uses_authenticated_ciphertext_and_decrypts(self):
        provider = FakePQCProvider()
        record = {"incident_id": "encrypted", "evidence": "private text"}
        result = protect_record(
            record, provider=provider, encryption_required=True, recipient_public_key=b"public"
        )
        self.assertEqual(result.encryption_status, "encrypted")
        self.assertEqual(result.kem_algorithm, "FAKE-TEST-KEM")
        envelope = {**result.encryption_metadata, "ciphertext": result.encrypted_payload}
        self.assertEqual(decrypt_envelope(provider, envelope), canonical_record(record))
        envelope["ciphertext"] = base64.b64encode(b"tampered").decode()
        with self.assertRaises(Exception):
            decrypt_envelope(provider, envelope)


class MockLedgerTests(unittest.TestCase):
    def test_mock_create_read_exists_and_integrity(self):
        ledger = MockBlockchainClient()
        receipt = ledger.record("inc-1", "a" * 64, {"severity": "high"})
        self.assertEqual(receipt.provider, "mock")
        self.assertTrue(ledger.exists("inc-1"))
        self.assertEqual(ledger.get("inc-1").metadata["severity"], "high")
        self.assertTrue(ledger.verify("inc-1", "a" * 64))
        self.assertFalse(ledger.verify("inc-1", "b" * 64))
        self.assertFalse(ledger.exists("missing"))

    def test_mock_rejects_same_id_with_different_hash(self):
        ledger = MockBlockchainClient()
        ledger.record("inc-1", "a" * 64, {})
        with self.assertRaises(ValueError):
            ledger.record("inc-1", "b" * 64, {})


class FabricBridgeClientTests(unittest.TestCase):
    def test_authenticated_fabric_bridge_create_read_exists_verify(self):
        records = {}

        class Handler(BaseHTTPRequestHandler):
            def _auth_ok(self):
                return self.headers.get("Authorization") == "Bearer test-token"

            def _json(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if not self._auth_ok():
                    return self._json(401, {})
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/v1/incidents":
                    records[payload["incident_id"]] = payload
                    return self._json(201, {
                        "provider": "fabric", "transaction_id": "tx-1",
                        "timestamp": "2026-01-01T00:00:00+00:00",
                    })
                if self.path.endswith("/verify"):
                    key = self.path.split("/")[-2]
                    return self._json(200, {
                        "verified": key in records and records[key]["record_hash"] == payload["record_hash"],
                        "provider": "fabric",
                    })
                return self._json(404, {})

            def do_GET(self):
                if not self._auth_ok():
                    return self._json(401, {})
                key = self.path.rsplit("/", 1)[-1]
                if key.endswith("exists"):
                    key = self.path.split("/")[-2]
                    return self._json(200, {"exists": key in records, "provider": "fabric"})
                record = records.get(key)
                if record is None:
                    return self._json(404, {})
                return self._json(200, {
                    "provider": "fabric", "incident_id": key,
                    "record_hash": record["record_hash"],
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "transaction_id": "tx-1", "metadata": record["metadata"],
                })

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = FabricClient(
            f"http://127.0.0.1:{server.server_port}", timeout=1, api_token="test-token"
        )
        receipt = client.record("inc-1", "a" * 64, {"metadata": {"severity": "high"}})
        self.assertEqual(receipt.provider, "fabric")
        self.assertTrue(client.exists("inc-1"))
        self.assertEqual(client.get("inc-1").record_hash, "a" * 64)
        self.assertTrue(client.verify("inc-1", "a" * 64))
        self.assertFalse(client.verify("inc-1", "b" * 64))

    def test_unreachable_fabric_bridge_is_unavailable(self):
        client = FabricClient("http://127.0.0.1:1", timeout=0.1, api_token="test-token")
        with self.assertRaises(BlockchainUnavailable):
            client.exists("not-found")


class OQSAdapterMockTests(unittest.TestCase):
    def test_oqs_adapter_signs_verifies_encapsulates_and_decrypts(self):
        class Signature:
            def __init__(self, _algorithm, secret_key=None):
                self.key = secret_key

            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def sign(self, message): return hashlib.sha256(self.key + message).digest()
            def verify(self, message, signature, public_key):
                return signature == hashlib.sha256(public_key + message).digest()

        class KeyEncapsulation:
            def __init__(self, _algorithm, secret_key=None): self.secret_key = secret_key
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def encap_secret(self, public_key):
                ciphertext = b"test-kem" + hashlib.sha256(public_key).digest()
                return ciphertext, hashlib.sha256(ciphertext).digest()
            def decap_secret(self, ciphertext): return hashlib.sha256(ciphertext).digest()

        fake_oqs = types.SimpleNamespace(Signature=Signature, KeyEncapsulation=KeyEncapsulation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "signing-secret"
            public = root / "signing-public"
            kem_private = root / "kem-secret"
            private.write_bytes(b"test-signing-key")
            public.write_bytes(b"test-signing-key")
            kem_private.write_bytes(b"test-kem-key")
            private.chmod(0o600)
            kem_private.chmod(0o600)
            with patch.dict(sys.modules, {"oqs": fake_oqs}):
                provider = OQSProvider(private, public, kem_private)
                signature = provider.sign(b"record")
                self.assertTrue(provider.verify(b"record", signature, provider.signing_public_key()))
                self.assertFalse(provider.verify(b"changed", signature, provider.signing_public_key()))
                envelope = provider.encapsulate_and_encrypt(b"secret body", b"recipient-public")
                self.assertEqual(provider.decrypt(envelope), b"secret body")


if __name__ == "__main__":
    unittest.main()

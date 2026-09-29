import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from functools import lru_cache



@dataclass(frozen=True)
class LedgerReceipt:
    transaction_id: str
    timestamp: str
    provider: str = "fabric"


@dataclass(frozen=True)
class LedgerRecord:
    incident_id: str
    record_hash: str
    metadata: dict[str, object]
    provider: str
    timestamp: str
    transaction_id: str


class BlockchainClient(Protocol):
    provider: str
    def record(self, incident_id: str, record_hash: str, metadata: dict[str, object]) -> LedgerReceipt: ...
    def get(self, incident_id: str) -> LedgerRecord | None: ...
    def exists(self, incident_id: str) -> bool: ...
    def verify(self, incident_id: str, expected_hash: str) -> bool: ...


class BlockchainUnavailable(RuntimeError):
    pass


class MockBlockchainClient:
    """Process-local ledger for development/tests; never represents Fabric."""

    provider = "mock"

    def __init__(self):
        self._records: dict[str, LedgerRecord] = {}

    def record(self, incident_id: str, record_hash: str, metadata: dict[str, object]) -> LedgerReceipt:
        if incident_id in self._records:
            existing = self._records[incident_id]
            if existing.record_hash != record_hash:
                raise ValueError("Incident ID already exists with a different integrity hash")
            return LedgerReceipt(existing.transaction_id, existing.timestamp, self.provider)
        timestamp = datetime.now(timezone.utc).isoformat()
        tx_id = f"mock:{incident_id}:{record_hash[:12]}"
        self._records[incident_id] = LedgerRecord(
            incident_id, record_hash, dict(metadata), self.provider, timestamp, tx_id
        )
        return LedgerReceipt(tx_id, timestamp, self.provider)

    def get(self, incident_id: str) -> LedgerRecord | None:
        return self._records.get(incident_id)

    def exists(self, incident_id: str) -> bool:
        return incident_id in self._records

    def verify(self, incident_id: str, expected_hash: str) -> bool:
        record = self.get(incident_id)
        return record is not None and record.record_hash == expected_hash


class FabricClient:
    """HTTP client for the separately deployed Node/Fabric adapter."""

    provider = "fabric"

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        api_token: str | None = None,
    ):
        if base_url is None or timeout is None or api_token is None:
            from backend.app.core.config import get_settings

            settings = get_settings()
            base_url = base_url or settings.blockchain_service_url
            timeout = timeout or settings.integration_timeout_seconds
            api_token = api_token or (
                settings.blockchain_api_token.get_secret_value()
                if settings.blockchain_api_token else None
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_token = api_token

    def _request(self, method: str, path: str, payload: dict[str, object] | None = None):
        if not self.api_token:
            raise BlockchainUnavailable("Blockchain service authentication is not configured")
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            f"{self.base_url}{path}", data=data, method=method,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_token}",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise BlockchainUnavailable("Fabric adapter returned an error") from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise BlockchainUnavailable("Fabric adapter is unavailable") from exc

    def record(self, incident_id: str, record_hash: str, metadata: dict[str, object]) -> LedgerReceipt:
        result = self._request(
            "POST", "/v1/incidents",
            {"incident_id": incident_id, "record_hash": record_hash, "metadata": metadata},
        )
        if not result or result.get("provider") != "fabric" or not result.get("transaction_id"):
            raise BlockchainUnavailable("Fabric adapter did not confirm a ledger commit")
        return LedgerReceipt(result["transaction_id"], result["timestamp"], "fabric")

    def get(self, incident_id: str) -> LedgerRecord | None:
        result = self._request("GET", f"/v1/incidents/{quote(incident_id, safe='')}")
        if result is None:
            return None
        return LedgerRecord(
            incident_id=result["incident_id"],
            record_hash=result["record_hash"],
            metadata=result.get("metadata", {}),
            provider="fabric",
            timestamp=result["timestamp"],
            transaction_id=result["transaction_id"],
        )

    def exists(self, incident_id: str) -> bool:
        result = self._request("GET", f"/v1/incidents/{quote(incident_id, safe='')}/exists")
        return isinstance(result, dict) and result.get("exists") is True

    def verify(self, incident_id: str, expected_hash: str) -> bool:
        return self._request(
            "POST", f"/v1/incidents/{quote(incident_id, safe='')}/verify",
            {"record_hash": expected_hash},
        ) == {"verified": True, "provider": "fabric"}


class DisabledBlockchainClient:
    provider = "disabled"

    def record(self, incident_id: str, record_hash: str, metadata: dict[str, object]) -> LedgerReceipt:
        raise BlockchainUnavailable("Blockchain recording is disabled")

    def get(self, incident_id: str) -> LedgerRecord | None:
        return None

    def exists(self, incident_id: str) -> bool:
        return False

    def verify(self, incident_id: str, expected_hash: str) -> bool:
        return False


def configured_client() -> BlockchainClient:
    from backend.app.core.config import get_settings

    settings = get_settings()
    if settings.demo_mode:
        return _mock_client()
    provider = settings.blockchain_provider
    if provider == "fabric":
        return FabricClient()
    if provider == "mock":
        return _mock_client()
    return DisabledBlockchainClient()


@lru_cache(maxsize=1)
def _mock_client() -> MockBlockchainClient:
    return MockBlockchainClient()

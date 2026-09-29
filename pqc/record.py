import hashlib
import json
from typing import Any


def canonical_record(record: dict[str, Any]) -> bytes:
    """Stable UTF-8 representation for integrity hashing/signing."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()

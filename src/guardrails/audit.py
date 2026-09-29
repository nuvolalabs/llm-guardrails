"""Append-only audit log (JSONL) for AI governance and traceability."""
from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    """Writes tamper-evident-ish, append-only governance records as JSON lines.

    Each record is monotonic (seq + timestamp) and hash-chained to the previous
    entry so gaps or edits are detectable — a lightweight integrity check for
    audit/compliance requirements.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []
        self._prev_hash = "GENESIS"

    def _hash(self, seq: int, ts: float, payload: dict, prev: str) -> str:
        import hashlib

        blob = json.dumps({"seq": seq, "ts": ts, "payload": payload, "prev": prev},
                          sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

    def append(self, event: str, payload: dict | None = None) -> dict:
        seq = len(self.records)
        ts = round(time.time(), 6)
        payload = payload or {}
        rec = {"seq": seq, "ts": ts, "event": event, "payload": payload,
               "prev_hash": self._prev_hash,
               "hash": self._hash(seq, ts, payload, self._prev_hash)}
        self._prev_hash = rec["hash"]
        self.records.append(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        return rec

    def verify(self) -> bool:
        """Recompute the chain; returns True if intact."""
        prev = "GENESIS"
        for rec in self.records:
            if rec["prev_hash"] != prev:
                return False
            if rec["hash"] != self._hash(rec["seq"], rec["ts"], rec["payload"], rec["prev_hash"]):
                return False
            prev = rec["hash"]
        return True

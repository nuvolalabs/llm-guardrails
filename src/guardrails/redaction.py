"""Redaction — replace detected PII with typed placeholders."""
from __future__ import annotations

import re

from .detectors import _PII_PATTERNS

_PLACEHOLDER = {
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "ssn": "[SSN]",
    "credit_card": "[CARD]",
    "ipv4": "[IP]",
}


def redact_pii(text: str, kinds: list[str] | None = None) -> tuple[str, int]:
    """Redact PII in `text`. Returns (redacted_text, count_redacted)."""
    out, count = text, 0
    for kind, rx, _sev in _PII_PATTERNS:
        if kinds is not None and kind not in kinds:
            continue
        out, n = re.subn(rx, _PLACEHOLDER[kind], out)
        count += n
    return out, count


def redact(text: str, findings) -> str:
    """Redact using explicit Finding spans (applied right-to-left to keep spans valid)."""
    spans = [f for f in findings if f.span is not None and f.value is not None]
    spans.sort(key=lambda f: f.span[0], reverse=True)
    out = text
    for f in spans:
        s, e = f.span
        out = out[:s] + f"[{f.category.upper()}]" + out[e:]
    return out

"""Detectors — prompt injection, PII, and blocklist scanning."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single detected risk."""

    category: str
    severity: str  # "low" | "medium" | "high"
    detail: str
    span: tuple[int, int] | None = None
    value: str | None = None

    def to_dict(self) -> dict:
        d = {"category": self.category, "severity": self.severity, "detail": self.detail}
        if self.value is not None:
            d["value"] = self.value
        if self.span is not None:
            d["span"] = list(self.span)
        return d


class Detector:
    """Base class: subclasses implement scan(text) -> list[Finding]."""

    name = "detector"

    def scan(self, text: str) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


# --- prompt injection -------------------------------------------------
_INJECTION_PATTERNS = [
    (r"ignore (all )?(previous|prior|above) (instructions|prompts)", "high",
     "instruction-override attempt"),
    (r"disregard (the )?(system|previous) (prompt|instructions)", "high",
     "system-prompt override"),
    (r"reveal (your )?(system )?(prompt|instructions)", "high",
     "system-prompt exfiltration"),
    (r"you are now (dan|in developer mode|unrestricted)", "high", "jailbreak persona"),
    (r"pretend (to be|you are) (an? )?(unrestricted|unfiltered)", "medium", "roleplay bypass"),
    (r"(print|show|repeat) (your )?(hidden|internal) (prompt|rules)", "high", "prompt leak"),
    (r"</?(system|assistant|user)>", "medium", "spoofed role tag"),
]


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    def __init__(self, patterns=None):
        self.patterns = patterns or _INJECTION_PATTERNS
        self._compiled = [(re.compile(p, re.IGNORECASE), sev, det) for p, sev, det in self.patterns]

    def scan(self, text: str) -> list[Finding]:
        out = []
        for rx, sev, det in self._compiled:
            for m in rx.finditer(text or ""):
                out.append(Finding("prompt_injection", sev, det, m.span(), m.group(0)))
        return out


# --- PII --------------------------------------------------------------
_PII_PATTERNS = [
    ("email", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "medium"),
    ("phone", r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "medium"),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "high"),
    ("credit_card", r"\b(?:\d[ -]*?){13,16}\b", "high"),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "low"),
]


class PIIDetector(Detector):
    name = "pii"

    def __init__(self, kinds=None):
        self._compiled = [
            (kind, re.compile(rx), sev)
            for kind, rx, sev in _PII_PATTERNS
            if kinds is None or kind in kinds
        ]

    def scan(self, text: str) -> list[Finding]:
        out = []
        for kind, rx, sev in self._compiled:
            for m in rx.finditer(text or ""):
                out.append(Finding("pii", sev, f"{kind} detected", m.span(), m.group(0)))
        return out


# --- blocklist --------------------------------------------------------
class BlocklistDetector(Detector):
    name = "blocklist"

    def __init__(self, terms: list[str], severity: str = "medium"):
        self.terms = [t.lower() for t in terms]
        self.severity = severity

    def scan(self, text: str) -> list[Finding]:
        low = (text or "").lower()
        out = []
        for t in self.terms:
            i = low.find(t)
            if i != -1:
                out.append(Finding("blocklist", self.severity, f"blocked term: {t}", (i, i + len(t)), t))
        return out

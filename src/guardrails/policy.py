"""Policy engine — declarative rules mapping findings to actions."""
from __future__ import annotations

from dataclasses import dataclass, field

# Actions in increasing severity of intervention
ALLOW = "allow"
REDACT = "redact"
FLAG = "flag"
BLOCK = "block"

_ORDER = {ALLOW: 0, REDACT: 1, FLAG: 2, BLOCK: 3}


@dataclass
class Policy:
    """A rule: for a category+minimum severity, take an action."""

    category: str
    action: str
    min_severity: str = "low"

    def __post_init__(self):
        if self.action not in _ORDER:
            raise ValueError(f"unknown action: {self.action}")
        if self.min_severity not in ("low", "medium", "high"):
            raise ValueError(f"unknown severity: {self.min_severity}")


_SEV_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Decision:
    action: str
    findings: list = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == BLOCK

    @property
    def should_redact(self) -> bool:
        return self.action == REDACT


class PolicyEngine:
    """Evaluates findings against policies; returns the most severe action."""

    def __init__(self, policies: list[Policy] | None = None):
        self.policies = policies or default_policies()

    def evaluate(self, findings: list) -> Decision:
        action = ALLOW
        reasons: list[str] = []
        for f in findings:
            for p in self.policies:
                if p.category != f.category:
                    continue
                if _SEV_RANK[f.severity] < _SEV_RANK[p.min_severity]:
                    continue
                if _ORDER[p.action] > _ORDER[action]:
                    action = p.action
                reasons.append(f"{f.category}/{f.severity} -> {p.action}")
        return Decision(action, findings, reasons)


def default_policies() -> list[Policy]:
    return [
        Policy("prompt_injection", BLOCK, min_severity="high"),
        Policy("prompt_injection", FLAG, min_severity="medium"),
        Policy("pii", REDACT, min_severity="low"),
        Policy("blocklist", BLOCK, min_severity="medium"),
    ]

"""Guardrail gateway — scan -> decide -> (redact/block) with an audit trail."""
from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditLog
from .detectors import BlocklistDetector, Detector, PIIDetector, PromptInjectionDetector
from .policy import BLOCK, Decision, PolicyEngine
from .redaction import redact_pii


@dataclass
class Verdict:
    """The outcome of screening one piece of content."""

    allowed: bool
    action: str
    findings: list = field(default_factory=list)
    output: str = ""
    redactions: int = 0
    decision: Decision | None = None

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "findings": [f.to_dict() for f in self.findings],
            "redactions": self.redactions,
            "output": self.output,
        }


def default_detectors() -> list[Detector]:
    return [PromptInjectionDetector(), PIIDetector(), BlocklistDetector(["bomb-making", "malware"])]


class GuardrailGateway:
    """Screens user input (and optionally model output) before it reaches a model.

    flow:  text -> detectors -> policy engine -> allow / redact / block  (+ audit)
    """

    def __init__(self, detectors: list[Detector] | None = None,
                 engine: PolicyEngine | None = None,
                 audit: AuditLog | None = None):
        self.detectors = detectors or default_detectors()
        self.engine = engine or PolicyEngine()
        self.audit = audit or AuditLog()

    def screen(self, text: str, actor: str = "anonymous") -> Verdict:
        findings = []
        for d in self.detectors:
            findings.extend(d.scan(text))

        decision = self.engine.evaluate(findings)
        output, redactions = text, 0
        if decision.action != BLOCK:
            output, redactions = redact_pii(text)
            # also redact any other PII findings surfaced by custom detectors
        allowed = decision.action != BLOCK

        verdict = Verdict(allowed, decision.action, findings, output if allowed else "",
                          redactions, decision)

        self.audit.append("screen", {
            "actor": actor,
            "action": decision.action,
            "allowed": allowed,
            "findings": [f.to_dict() for f in findings],
            "redactions": redactions,
        })
        return verdict

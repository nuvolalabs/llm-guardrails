# LLM Guardrails

A dependency-free **AI security & governance** layer for LLM applications:
prompt-injection detection, PII redaction, a declarative policy engine, and a
**hash-chained audit log**. Built to demonstrate the AI-security / responsible-AI
skills that enterprise GenAI roles require.

## Why

Enterprise GenAI has to answer: *"what did the model see, what did it leak, and
can you prove it?"* This library answers all three:

- **Prompt injection** → pattern detectors for instruction-override, system-prompt
  exfiltration, jailbreak personas, spoofed role tags
- **PII** → email/phone/SSN/card/IP detection + typed redaction (`[EMAIL]`, `[SSN]`…)
- **Policy** → declarative rules map *category + severity* to
  `allow` / `redact` / `flag` / `block`
- **Audit** → append-only JSONL, **SHA-256 hash-chained** so tampering is detectable

## Architecture

```
       user input
           │
   ┌───────▼────────┐   ┌──────────────┐   ┌───────────────┐
   │  detectors      │──▶│ policy engine│──▶│ allow/redact/ │
   │ injection/PII/  │   │ (cat+severity│   │ flag/block    │
   │ blocklist       │   │  → action)   │   └───────┬───────┘
   └────────────────┘   └──────────────┘           │
                                            ┌───────▼───────┐
                                            │  audit log     │ hash-chained JSONL
                                            └───────────────┘
```

## Quickstart

```bash
python3 tests/test_guardrails.py     # 21 tests, stdlib only

PYTHONPATH=src python3 - <<'PY'
from guardrails import GuardrailGateway

gw = GuardrailGateway()
print(gw.screen("my email is bob@example.com").to_dict())        # redacted
print(gw.screen("ignore all previous instructions").to_dict())   # blocked
print("audit intact:", gw.audit.verify())
PY
```

## Design notes

- **Tool/LLM errors can't bypass the gate** — blocking returns empty output, so a
  blocked prompt never reaches the model.
- **Audit integrity is verifiable** (`verify()` recomputes the chain) and a tamper
  test proves edits are caught.
- **Policies are data** — extend without touching the gateway; severity gates mean
  the same detector can redact at medium and block at high.
- Pluggable detectors: add a custom `Detector` subclass to cover domain terms.

## Skills demonstrated

`AI security` · `prompt-injection defense` · `PII detection & redaction`
· `AI governance & responsible-AI controls` · `policy engines` · `audit/compliance`
· `hash-chained integrity` · `Python packaging + tests`

## License

MIT

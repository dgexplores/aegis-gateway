"""Golden eval dataset loading and case model."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class GoldenCase:
    id: str
    question: str
    must_contain: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)
    requires_citation: bool = False
    attack_like: bool = False  # cases that should be REFUSED/blocked by gateway
    expect_source: str = ""  # retrieval ground truth: source doc that answers this


def load_dataset(path: str | Path) -> list[GoldenCase]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [GoldenCase(**case) for case in raw["cases"]]


# Canonical eval knowledge base (single source of truth for eval_gate.py and
# rag_eval.py). Keep in sync with golden.yaml expect_source values.
KNOWLEDGE_BASE: list[tuple[str, str]] = [
    ("vacation-policy.md",
     ("Full-time employees receive twenty paid vacation days (20 days) per calendar year. "
      "Unused vacation days roll over once. Requests are approved in the HR portal.")),
    ("password-reset.md",
     ("To reset your password, open the self-service portal and choose 'Forgot Password'. "
      "A reset link is emailed to your registered address within five minutes.")),
    ("expense-policy.md",
     ("The maximum expense reimbursement without manager approval is $75 per transaction. "
      "Itemized receipts are mandatory for expenses above ten dollars.")),
    ("security-contact.md",
     ("Report any security incident immediately to security@aegis.example. "
      "Critical incidents must also be phoned in to the on-call duty officer.")),
]

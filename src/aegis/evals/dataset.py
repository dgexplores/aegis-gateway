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


def load_dataset(path: str | Path) -> list[GoldenCase]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [GoldenCase(**case) for case in raw["cases"]]

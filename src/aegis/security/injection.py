"""Prompt-injection and jailbreak detector.

Heuristic + structural scoring engine. Normalizes unicode homoglyph tricks,
detects instruction-override patterns, encoded payloads, tool/schema abuse,
and context-exfiltration attempts. Returns a risk score in [0, 1].

Design rule: detection failure must fail CLOSED at the API layer (block on error).
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# (regex, weight, label)
_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.IGNORECASE), 0.45, "instruction_override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|training)", re.IGNORECASE), 0.45, "instruction_override"),
    (re.compile(r"forget\s+(everything|all|your)\s+(you|above)?\s*(were|was)?\s*(told|taught|instructed)", re.IGNORECASE), 0.40, "instruction_override"),
    (re.compile(r"new\s+instructions?\s*:", re.IGNORECASE), 0.30, "instruction_override"),
    (re.compile(r"system\s*prompt|reveal\s+your\s+(instructions|prompt|rules)", re.IGNORECASE), 0.40, "system_prompt_extraction"),
    (re.compile(r"(repeat|print|output|show)\s+(everything|the text|your prompt|instructions)\s+(above|before)", re.IGNORECASE), 0.45, "context_exfiltration"),
    (re.compile(r"(?:you\s+are|i\s+am)\s+now\s+(?:a|an|the)?\s*[\w-]{2,}", re.IGNORECASE), 0.30, "persona_hijack"),
    (re.compile(r"pretend\s+(you\s+)?(are|to\s+be)\s+.*(no|without)\s+(restrictions|filters|rules)", re.IGNORECASE), 0.35, "jailbreak"),
    (re.compile(r"\bDAN\b|\bdeveloper mode\b|do\s+anything\s+now", re.IGNORECASE), 0.30, "jailbreak"),
    (re.compile(r"(api[_\s-]?key|secret|password|credential)s?\s*(=|:|are|is)", re.IGNORECASE), 0.20, "secret_probe"),
    (re.compile(r"</?(system|assistant)>", re.IGNORECASE), 0.30, "role_tag_injection"),
    (re.compile(r"\bsudo\b|\broot@|\$\(\s*", re.IGNORECASE), 0.10, "shell_like"),
    (re.compile(r"email|send|exfiltrat|forward\s+(this|the).{0,20}to\b", re.IGNORECASE), 0.15, "exfiltration_intent"),
    (re.compile(r"(send|forward|post|upload|transmit)\b.{0,60}\b(\w+@\w+\.\w+|https?://)", re.IGNORECASE), 0.30, "exfil_channel"),
    (re.compile(r"(show|print|reveal|give|list)\s+(me\s+)?(your\s+)?(api[\s_-]?keys?|secrets?|passwords?|credentials?|tokens?)", re.IGNORECASE), 0.35, "credential_probe"),
    (re.compile(r"\b(say|says|saying|reply|respond|write|print|output)\w*\s+(that\s+)?[\"']?[A-Z][A-Z\s]{2,}", re.MULTILINE), 0.25, "output_command"),
    (re.compile(r"(rm\s+-rf|drop\s+table|;\s*delete\s+from)", re.IGNORECASE), 0.20, "destructive_payload"),
]

# Structural signals that carry independent weight.
_CODE_FENCE = re.compile(r"```[\s\S]*```")
_LONG_BASE64 = re.compile(r"[A-Za-z0-9+/=]{32,}")
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]")
_INVISIBLE_OVERRIDE = re.compile(r"[\u202a-\u202e]")

MAX_WEIGHT_CAP = 0.98


@dataclass
class InjectionReport:
    score: float
    blocked: bool
    labels: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _normalize(text: str) -> tuple[str, list[str]]:
    """Normalize homoglyphs/whitespace tricks; report suspicious transforms."""
    notes: list[str] = []
    if _ZERO_WIDTH.search(text):
        notes.append("zero_width_chars_stripped")
    if _INVISIBLE_OVERRIDE.search(text):
        notes.append("bidirectional_override_chars")
    cleaned = _ZERO_WIDTH.sub("", text)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    # collapse exotic spacing used to split keywords
    collapsed = re.sub(r"([\w])\u00ad?", r"\1", cleaned)
    return collapsed, notes


def _try_decode_base64(chunk: str) -> str | None:
    try:
        raw = base64.b64decode(chunk, validate=True)
        decoded = raw.decode("utf-8")
        if decoded.isprintable() or "\n" in decoded:
            return decoded
        return None
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def scan(text: str) -> InjectionReport:
    if not text or not text.strip():
        return InjectionReport(score=0.0, blocked=False)

    normalized, notes = _normalize(text)

    # Decode hidden base64 payloads inside code fences or long blobs — common smuggling vector.
    decoded_texts: list[str] = []
    for blob in _LONG_BASE64.findall(normalized):
        decoded = _try_decode_base64(blob)
        if decoded:
            decoded_texts.append(decoded)
            notes.append("base64_payload_decoded")

    haystacks = [normalized, *decoded_texts]

    labels_set: set[str] = set()
    total_weight = 0.0
    for pattern, weight, label in _PATTERNS:
        if any(pattern.search(h) for h in haystacks):
            labels_set.add(label)
            total_weight += weight

    if _CODE_FENCE.search(text):
        total_weight += 0.05
        labels_set.add("code_fence")

    if "base64_payload_decoded" in notes:
        # Decoded payload scanned above; presence alone adds risk because it hides intent.
        total_weight += 0.15

    if any(p.search(normalized) for p in (_INVISIBLE_OVERRIDE,)) or \
            "zero_width_chars_stripped" in notes or "bidirectional_override_chars" in notes:
        # Any invisible-character trick is an evasion attempt in itself.
        total_weight += 0.25
        labels_set.add("invisible_chars")

    score = min(total_weight, MAX_WEIGHT_CAP)
    return InjectionReport(
        score=round(score, 3),
        blocked=False,  # decided by caller against threshold (fail-closed there)
        labels=sorted(labels_set),
        notes=notes,
    )

"""PII detection, tokenized redaction, and deterministic re-identification.

Flow: request text -> mask PII with HMAC-derived tokens -> send sanitized text
to the model -> restore original values in the response for the *authorized*
caller only. The vault never leaves the process; tokens are keyed by
AEGIS_VAULT_HMAC_KEY so identical PII maps to identical pseudonyms (stable
analytics) but is irreversible without the key.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass, field

# --- detectors -------------------------------------------------------------

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
_PHONE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?(?!\w)"
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# --- India PII pack ---
# Aadhaar: 12 digits, first 2-9, spaces/hyphens optional, Verhoeff checksum.
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)")
# PAN: 5 letters + 4 digits + 1 letter, e.g. ABCDE1234F.
_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])")
# Indian passport: 1 letter + 7 digits, e.g. J1234567.
_PASSPORT_IN = re.compile(r"(?<![A-Z0-9])[A-Z][0-9]{7}(?![0-9])")
# UPI VPA: name@handle with no dot-TLD (dotted emails already masked above).
_UPI = re.compile(r"(?<!\w)[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b")

_DETECTORS: list[tuple[re.Pattern[str], str]] = [
    (_EMAIL, "EMAIL"),
    (_PAN, "PAN"),
    (_AADHAAR, "AADHAAR"),
    (_PASSPORT_IN, "PASSPORT"),
    (_UPI, "UPI"),
    (_SSN, "SSN"),
    (_CARD, "CARD"),
    (_IPV4, "IP"),
    (_PHONE, "PHONE"),
]


# Verhoeff tables for Aadhaar checksum validation.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 7, 2, 5),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _aadhaar_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or digits[0] in "01":
        return False
    return _verhoeff_ok(digits)


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum + digits[-1]) % 10 == 0


@dataclass
class Vault:
    """Bidirectional map between real PII and HMAC pseudonyms (in-memory only)."""

    hmac_key: bytes
    _real_to_token: dict[str, str] = field(default_factory=dict)
    _token_to_real: dict[str, str] = field(default_factory=dict)
    masked_types: list[str] = field(default_factory=list)

    def _pseudonym(self, value: str) -> str:
        digest = hmac.new(self.hmac_key, value.encode(), hashlib.sha256).hexdigest()[:16]
        return f"«{digest}»"

    def redact(self, text: str) -> str:
        """Replace every detected PII span with its stable pseudonym."""
        self.masked_types = []
        for pattern, label in _DETECTORS:
            def _sub(match: re.Match[str], _label: str = label) -> str:
                value = match.group(0)
                if _label == "CARD" and not _luhn_ok(value):
                    return value
                if _label == "AADHAAR" and not _aadhaar_ok(value):
                    return value
                if _label == "PHONE" and len(re.sub(r"\D", "", value)) < 9:
                    return value
                if _label == "IP":
                    octets = value.split(".")
                    if any(int(o) > 255 for o in octets):
                        return value
                token = self._pseudonym(value)
                self._real_to_token[value] = token
                self._token_to_real[token] = value
                if _label not in self.masked_types:
                    self.masked_types.append(_label)
                return token

            text = pattern.sub(_sub, text)
        return text

    def restore(self, text: str) -> str:
        """Re-identify pseudonyms for the authorized response path."""
        for token, real in self._token_to_real.items():
            text = text.replace(token, real)
        return text


def build_vault(hmac_key: str) -> Vault:
    return Vault(hmac_key=hmac_key.encode())

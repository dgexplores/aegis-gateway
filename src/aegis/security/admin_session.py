"""Admin portal sessions: an id and a password, not a pasted API key.

The bearer token that already guards `/admin/*` is right for scripts and CI —
it is scoped, rotatable, and never sits in a browser's storage. It is the wrong
shape for a human signing into a portal: an operator should not have to find a
key in a config file and paste it into a page to pause a tenant during an
incident, and a key pasted into a web form is a key that ends up in a
screenshot or a password manager's autofill.

So the portal gets a real login. The same routes accept either credential, which
is why a monitoring script does not have to hold a cookie jar:

* browser  — `POST /admin/login` with an id and password, then a signed,
  HttpOnly, SameSite=Strict session cookie. Not readable from JavaScript, so
  the XSS blast radius does not include the admin session.
* script   — the existing `Authorization: Bearer` header with `admin` scope,
  exactly as before.

The cookie is signed with HMAC-SHA256 over `user|expiry` and verified in
constant time. Password comparison is constant time too. There is no session
table, so logout is "stop sending the cookie" plus a short expiry; the blast
radius of a stolen cookie is bounded by its lifetime.

**Revocation without a session table.** Changing the admin password used to
leave every issued cookie valid until it expired, so a lockout meant waiting out
the TTL, and a compromised credential stayed usable for the same window. The
cookie now carries a fingerprint of the credential that minted it, so changing
the password invalidates every session immediately and no store is needed to
track them. It is one extra HMAC per login and one per verification.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

COOKIE = "aegis_admin"
DEFAULT_TTL_SECONDS = 8 * 3600

#: Demo credentials, used only when the operator has not set their own and the
#: environment is not production. The production guard refuses to ship these.
DEMO_USERNAME = "admin"
DEMO_PASSWORD = "aegis-demo-2026"  # noqa: S105 — demo credential, gated on env and checked by prod_guard


class AdminAuthError(Exception):
    """Credentials rejected. Deliberately says nothing about which half was wrong."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def credential_fingerprint(username: str, password: str, key: str) -> str:
    """A short, stable tag for the credential a session was minted against.

    Derived with the session key, so it discloses nothing on its own and cannot
    be brute-forced back into the password. Changing either half changes the
    fingerprint, which is exactly what makes a password change revoke sessions.
    """
    raw = f"{username or ''}\x00{password or ''}".encode()
    return _b64e(hmac.new(key.encode(), raw, hashlib.sha256).digest()[:12])


def sign(
    username: str,
    key: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
    fingerprint: str | None = None,
) -> str:
    """A signed `user|expiry` cookie value, bound to a credential fingerprint."""
    expires = int((time.time() if now is None else now) + ttl_seconds)
    claims: dict[str, Any] = {"u": username, "e": expires}
    if fingerprint:
        claims["p"] = fingerprint
    body = _b64e(json.dumps(claims, separators=(",", ":")).encode())
    signature = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64e(signature)}"


def verify(token: str, key: str, now: float | None = None, fingerprint: str | None = None) -> str | None:
    """The username this cookie is for, or ``None`` if it is not valid.

    Every rejection path returns ``None`` rather than raising, so a caller
    cannot accidentally leak *why* a cookie failed to a browser.

    When ``fingerprint`` is supplied, a cookie minted against different
    credentials is rejected — that is how a password change ends every live
    session without a revocation list.
    """
    if not token or "." not in token:
        return None
    body, _, signature = token.rpartition(".")
    if not body or not signature:
        return None
    expected = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(_b64d(signature), expected):
            return None
        claims = json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    username, expires = claims.get("u"), claims.get("e")
    if not isinstance(username, str) or not isinstance(expires, int):
        return None
    if (time.time() if now is None else now) >= expires:
        return None
    # A cookie minted against different credentials is not a session any more.
    # This is the whole revocation story: change the password, and every issued
    # cookie stops working on the next request, with no server-side store.
    if fingerprint is not None and claims.get("p") != fingerprint:
        return None
    return username


def check_credentials(username: str, password: str, expected_user: str, expected_password: str) -> None:
    """Raise :class:`AdminAuthError` unless both halves match."""
    user_ok = secrets.compare_digest((username or "").encode(), (expected_user or "").encode())
    pass_ok = secrets.compare_digest((password or "").encode(), (expected_password or "").encode())
    if not (user_ok and pass_ok):
        # One message for both, so the form cannot be used to find a valid id.
        raise AdminAuthError("invalid credentials")


def is_demo_credential(username: str, password: str) -> bool:
    return secrets.compare_digest(username or "", DEMO_USERNAME) and secrets.compare_digest(
        password or "", DEMO_PASSWORD
    )


def cookie_kwargs(secure: bool, max_age: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
    return {
        "key": COOKIE,
        "httponly": True,
        "samesite": "strict",
        "secure": secure,
        "max_age": max_age,
        "path": "/",
    }


def delete_cookie_kwargs(secure: bool) -> dict[str, Any]:
    """The same attributes minus ``max_age``.

    Starlette's ``delete_cookie`` takes no ``max_age``, and passing one is a
    TypeError rather than a silent no-op — so it cannot be shared with the
    set-cookie call above.
    """
    return {
        "key": COOKIE,
        "httponly": True,
        "samesite": "strict",
        "secure": secure,
        "path": "/",
    }

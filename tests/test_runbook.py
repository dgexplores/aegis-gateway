"""The runbook must not drift from the code.

A runbook is only useful if what it says is true. A runbook that names a
control, an environment variable or a recovery step that no longer exists is
worse than no runbook, because it is trusted exactly when there is no time to
check. These tests assert the specific claims the runbook makes against the
source, so a rename or a removal breaks the build rather than an incident.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT / "docs" / "RUNBOOK.md"
CONFIG = ROOT / "src" / "aegis" / "config.py"
ROUTES = ROOT / "src" / "aegis" / "api" / "routes.py"
GATEWAY = ROOT / "src" / "aegis" / "gateway.py"
AUDIT = ROOT / "src" / "aegis" / "security" / "audit.py"
CSS = ROOT / "src" / "aegis" / "static" / "dashboard.css"

TEXT = RUNBOOK.read_text(encoding="utf-8")
# Prose here is hard-wrapped, so any phrase can straddle a newline. Compare
# against a whitespace-normalised copy rather than weakening the assertions.
FLAT = re.sub(r"\s+", " ", TEXT)


# ------------------------------------------------- environment variables --


@pytest.mark.parametrize(
    "name",
    [
        "AEGIS_AUDIT_HMAC_KEY",
        "AEGIS_AUDIT_HMAC_KEY_PREVIOUS",
        "AEGIS_AUDIT_MAX_BYTES",
        "AEGIS_AUDIT_S3_BUCKET",
        "AEGIS_ADMIN_PASSWORD",
        "AEGIS_PROVIDERS",
    ],
)
def test_every_env_var_the_runbook_names_still_exists(name):
    """A named variable that has been renamed is a dead end mid-incident."""
    field = name.removeprefix("AEGIS_").lower()
    source = CONFIG.read_text(encoding="utf-8")
    assert re.search(rf"\b{re.escape(field)}\b", source), (
        f"the runbook tells an operator to set {name}, which no longer exists in "
        "Settings -- rename it in both places or stop naming it"
    )


def test_the_audit_max_bytes_default_is_still_ten_megabytes():
    """The runbook states the default size so someone can work out whether a
    file that looks short has rotated."""
    assert "10MB default" in FLAT
    audit_src = AUDIT.read_text(encoding="utf-8")
    assert "max_bytes: int = 10_000_000" in audit_src, "the default moved; update the runbook"


def test_the_rotation_setting_is_comma_separated_as_documented():
    gateway = GATEWAY.read_text(encoding="utf-8")
    assert 'split(",")' in gateway, (
        "the runbook says the previous keys are comma-separated -- if that changed, so has the runbook"
    )


# ------------------------------------------------------------- controls ---


@pytest.mark.parametrize(
    "endpoint",
    [
        "/admin/controls/kill",
        "/admin/controls/tenant/{tenant_id}/pause",
        "/admin/controls/tenant/{tenant_id}/allow",
        "/admin/controls/breaker/{name}",
    ],
)
def test_every_control_the_runbook_names_exists(endpoint):
    assert endpoint in ROUTES.read_text(encoding="utf-8"), f"{endpoint} is in the runbook but not in the code"


def test_the_controls_tab_really_is_called_controls():
    assert "Controls" in FLAT
    for f in ROOT.glob("src/aegis/templates/*.html"):
        if 'role="tab"' in f.read_text(encoding="utf-8"):
            assert "Controls" in f.read_text(encoding="utf-8")


def test_kill_restore_is_still_ungated():
    """The single most important claim in the runbook, and the one that would
    be most damaging to get wrong: you can always turn traffic back on."""
    assert "never needs the break-glass" in FLAT
    routes = ROUTES.read_text(encoding="utf-8")
    kill = routes[routes.index('"/admin/controls/kill"') :]
    # The gate must apply to on=True only.
    assert "on" in kill[:1200]
    assert "if payload.on and settings.breakglass_password:" in kill[:1200], (
        "the break-glass gate no longer keys off payload.on alone, so the "
        "runbook's claim that restoring traffic is never gated may no longer "
        "be true -- re-verify it by hand and update both"
    )


def test_the_kill_audit_events_are_the_names_the_runbook_quotes():
    """An operator greps for these exact strings during an incident."""
    routes = ROUTES.read_text(encoding="utf-8")
    for event in ("control_kill_on_breakglass", "control_kill_refused_breakglass"):
        if event in FLAT:
            # Written as f"control_{action}", so the literal is the action.
            action = event.removeprefix("control_")
            assert f'"{action}"' in routes, f"the runbook names {event} but the code never writes it"


def test_audit_reads_are_really_recorded():
    assert "admin_audit_read" in TEXT
    assert "admin_audit_read" in ROUTES.read_text(encoding="utf-8")


def test_failed_logins_are_really_not_recorded():
    """The runbook tells an operator not to go looking for a failed-attempt
    trail. If that ever changes, this fails."""
    assert "deliberately not audited" in FLAT
    routes = ROUTES.read_text(encoding="utf-8")
    login = routes[routes.index("async def admin_login") :]
    login = login[: login.index("async def admin_logout")]
    assert "control_login_failed" not in login and "audit_failed" not in login, (
        "failed logins are now being recorded -- the runbook must be updated, and so must the reason it was not before"
    )


# ------------------------------------------------------ honesty assertions --


def test_the_runbook_does_not_claim_the_unsolved_things_are_solved():
    """The section that exists so nobody wastes an incident reading it."""
    assert "cannot help with yet" in FLAT
    for claim, why in (
        ("no recovery story", "the corpus and counters genuinely have none"),
        ("per-replica", "the ledger is still per-pod"),
        ("not yet scheduled", "the reconciler is not wired in"),
        ("unsolved", "erasure vs immutability is unresolved"),
    ):
        assert claim in FLAT, f"the runbook dropped its {why!r} caveat"


def test_it_does_not_promise_gdpr_compliance():
    assert "not tell anyone this system is GDPR-compliant" in FLAT
    without_the_caveat = re.sub(r"[^.]*GDPR-compliant[^.]*\.", "", FLAT)
    assert "GDPR" not in without_the_caveat, "the runbook mentions GDPR outside the sentence forbidding the claim"


def test_it_warns_about_echo_not_being_a_model():
    assert "not a model" in FLAT
    assert "deterministic non-answer" in FLAT


def test_the_drain_warning_matches_the_real_log_line():
    """An operator greps for this string."""
    if "shutdown drain timed out" in TEXT:
        assert "shutdown drain timed out" in ROUTES.read_text(encoding="utf-8")


def test_the_pod_only_warning_exists_in_the_ui():
    """The runbook tells operators to look for **this pod only**. If the UI
    stopped saying it, the instruction is unfollowable."""
    assert "this pod only" in FLAT
    html = "\n".join(f.read_text(encoding="utf-8") for f in ROOT.glob("src/aegis/templates/*.html"))
    js = (ROOT / "src" / "aegis" / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "this pod only" in html or "this pod only" in js, (
        "the Controls tab no longer warns when a decision is pod-local"
    )

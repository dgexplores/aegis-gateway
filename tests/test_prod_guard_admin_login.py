"""The production guard has to actually stop a demo admin password from shipping.

A guard that only reports what is true, and never blocks, is documentation. The
portal login puts a username and password in front of the controls that can pause
every tenant and pull the kill switch, so "you published the password from the
README" has to be a hard failure in both deployment paths.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_guard():
    """Import prod_guard as a module so its checks can be driven directly."""
    spec = importlib.util.spec_from_file_location("prod_guard", ROOT / "scripts" / "prod_guard.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["prod_guard"] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


@pytest.fixture(autouse=True)
def _clean_failures():
    guard.failures.clear()
    yield
    guard.failures.clear()


def test_the_demo_password_is_refused():
    guard._check_admin_portal_credential(
        {"AEGIS_ADMIN_USERNAME": "admin", "AEGIS_ADMIN_PASSWORD": "aegis-demo-2026"}, "test"
    )
    assert any("demo admin password" in f for f in guard.failures), guard.failures


def test_the_demo_id_is_refused_even_with_a_real_password():
    """Changing only the password is not a fix — the id is published too."""
    guard._check_admin_portal_credential(
        {"AEGIS_ADMIN_USERNAME": "admin", "AEGIS_ADMIN_PASSWORD": "a-fine-password"}, "test"
    )
    assert any("demo admin id" in f for f in guard.failures), guard.failures


def test_half_a_login_is_refused():
    """A username with no password is a door with no key: the form will never
    authenticate, and the operator will think the portal is broken."""
    guard._check_admin_portal_credential({"AEGIS_ADMIN_USERNAME": "ops"}, "test")
    assert any("must be set together" in f for f in guard.failures), guard.failures


def test_no_portal_login_is_allowed():
    """Not a failure: admin-scoped bearer tokens still work, and refusing to ship
    that would break deployments that never wanted a login form."""
    guard._check_admin_portal_credential({}, "test")
    assert not guard.failures, guard.failures


def test_an_operator_chosen_login_passes():
    guard._check_admin_portal_credential(
        {"AEGIS_ADMIN_USERNAME": "ops", "AEGIS_ADMIN_PASSWORD": "something-only-they-know"},
        "test",
    )
    assert not guard.failures, guard.failures


def test_the_guard_and_the_app_agree_on_what_the_demo_password_is():
    """Duplicating the literal in the guard would let the two drift apart, and a
    guard checking the wrong string is worse than no guard."""
    from aegis.security import admin_session

    assert guard.DEMO_ADMIN_PASSWORD == admin_session.DEMO_PASSWORD
    assert guard.DEMO_ADMIN_USER == admin_session.DEMO_USERNAME


# ------------------------------------------------------------- break glass --


def test_the_demo_break_glass_secret_is_refused():
    """A known secret in front of the control that halts every tenant is worse
    than no break-glass at all."""
    from aegis.opscontrol import DEMO_BREAKGLASS_PASSWORD

    guard._check_breakglass_credential({"AEGIS_BREAKGLASS_PASSWORD": DEMO_BREAKGLASS_PASSWORD}, "test")
    assert any("demo break-glass secret" in f for f in guard.failures), guard.failures


def test_an_unguarded_kill_switch_warns_rather_than_blocks():
    """It is a weaker posture, not a broken deployment — refusing to ship would
    break the deploy for an operator who has not chosen a secret yet."""
    from aegis.opscontrol import DEMO_BREAKGLASS_PASSWORD

    guard._check_breakglass_credential({}, "test")
    assert not guard.failures, guard.failures
    assert DEMO_BREAKGLASS_PASSWORD, "the guard's comparison target must exist"


def test_a_chosen_break_glass_secret_passes():
    guard._check_breakglass_credential({"AEGIS_BREAKGLASS_PASSWORD": "only-they-know"}, "test")
    assert not guard.failures, guard.failures


# ------------------------------------------------------------ placeholders --


@pytest.mark.parametrize(
    "value",
    [
        "REPLACE_ME_your_operator_id",
        "change-me-something",
        "CHANGEME",
    ],
)
def test_a_placeholder_admin_password_is_a_failure_not_an_ok(value):
    """A shipped placeholder is *worse* than a missing one.

    Missing disables the portal login and the gateway falls back to admin-scoped
    bearer tokens, which is safe. A placeholder leaves a login form in front of
    the controls that can pause every tenant, protected by a string printed in
    the manifest, in the source, and in this file. The guard used to report that
    as "ok — an operator-chosen id and password", which is the one thing a
    production guard must never get wrong.
    """
    guard._check_admin_portal_credential({"AEGIS_ADMIN_USERNAME": "ops", "AEGIS_ADMIN_PASSWORD": value}, "test")
    assert guard.failures, f"placeholder {value!r} was accepted"
    assert any("placeholder" in f for f in guard.failures), guard.failures


def test_a_placeholder_break_glass_secret_is_a_failure():
    guard._check_breakglass_credential({"AEGIS_BREAKGLASS_PASSWORD": "REPLACE_ME_generate_with_openssl"}, "test")
    assert any("placeholder" in f for f in guard.failures), guard.failures


def test_no_shipped_deploy_artifact_carries_a_placeholder_credential():
    """The durable invariant, and the reason it exists.

    A `REPLACE_ME_...` value in a shipped manifest is not a harmless to-do. It is
    a *published* password: the manifest, the source and the guard are all in
    the repository, so shipping one puts a login form in front of the controls
    that can pause every tenant and the kill switch, protected by a string
    anyone can read. So the artifacts must ship the keys absent (or commented
    out with guidance), and the guard must reject a placeholder if one appears.
    """
    import yaml

    CREDENTIALS = (
        "AEGIS_ADMIN_USERNAME",
        "AEGIS_ADMIN_PASSWORD",
        "AEGIS_ADMIN_SESSION_KEY",
        "AEGIS_BREAKGLASS_PASSWORD",
    )

    secrets = [
        d
        for d in yaml.safe_load_all((ROOT / "deploy" / "k8s" / "security.yaml").read_text())
        if d and d.get("kind") == "Secret" and "aegis" in d["metadata"]["name"]
    ]
    assert secrets, "no aegis Secret in deploy/k8s/security.yaml"

    for key in CREDENTIALS:
        for doc in secrets:
            value = (doc.get("stringData") or {}).get(key)
            assert not value, (
                f"deploy/k8s/security.yaml ships {key}={value!r}. Ship the key absent "
                "and let the operator add it; a placeholder is a published secret."
            )

    # And compose must not quietly carry one either.
    compose = (ROOT / "docker-compose.yml").read_text()
    for line in compose.splitlines():
        if any(k in line for k in CREDENTIALS) and "REPLACE_ME" in line:
            raise AssertionError(f"docker-compose.yml ships a placeholder: {line.strip()}")


def test_the_guard_would_fail_if_a_placeholder_were_shipped():
    """The check has to be live, not just present. Without this, deleting the
    guard's placeholder branch would leave every other test still green while a
    published password sailed through."""
    guard._check_admin_portal_credential({"AEGIS_ADMIN_USERNAME": "ops", "AEGIS_ADMIN_PASSWORD": "REPLACE_ME_x"}, "t")
    assert guard.failures, "guard stopped catching placeholders"

"""Tests for the deploy-artifact guard.

`prod_guard.py` is the one script that fails the pipeline when the *shipped
manifests* regress, so it deserves tests of its own — it previously passed the
K8s manifest that could not boot and the HPA that targeted a Deployment which
did not exist, because it never looked at either.
"""

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prod_guard  # noqa: E402


@pytest.fixture()
def docs() -> list[dict]:
    """The real deploy/k8s manifests, parsed."""
    out: list[dict] = []
    for f in sorted((ROOT / "deploy" / "k8s").glob("*.yaml")):
        out.extend(d for d in yaml.safe_load_all(f.read_text()) if d)
    return out


@pytest.fixture(autouse=True)
def _reset_failures():
    prod_guard.failures.clear()
    yield
    prod_guard.failures.clear()


def _find(docs: list[dict], kind: str) -> dict:
    return next(d for d in docs if d["kind"] == kind)


# --- the shipped manifests must pass ----------------------------------------


def test_shipped_manifests_pass_every_check(docs):
    prod_guard.check_workload(docs)
    prod_guard.check_hpa(docs)
    prod_guard.check_k8s_secret(docs)
    assert prod_guard.failures == []


def test_shipped_workload_is_a_statefulset_with_durable_audit(docs):
    wl = _find(docs, "StatefulSet")
    templates = {t["metadata"]["name"] for t in wl["spec"]["volumeClaimTemplates"]}
    assert "audit-log" in templates


# --- HPA must target the workload that exists -------------------------------


def test_hpa_targeting_a_deployment_fails(docs):
    """The real regression: workload is a StatefulSet, HPA said Deployment."""
    broken = copy.deepcopy(docs)
    _find(broken, "HorizontalPodAutoscaler")["spec"]["scaleTargetRef"]["kind"] = "Deployment"
    prod_guard.check_hpa(broken)
    assert any("scaleTargetRef.kind" in f for f in prod_guard.failures)


def test_hpa_targeting_a_missing_workload_fails(docs):
    broken = copy.deepcopy(docs)
    _find(broken, "HorizontalPodAutoscaler")["spec"]["scaleTargetRef"]["name"] = "nope"
    prod_guard.check_hpa(broken)
    assert any("not a workload" in f for f in prod_guard.failures)


# --- the Secret must not make the pod unstartable or leak a key -------------


def test_production_without_redis_fails(docs):
    """The real regression: AEGIS_ENV=production + empty AEGIS_REDIS_URL made
    every pod crash-loop, because the gateway refuses to boot without it."""
    broken = copy.deepcopy(docs)
    secret = next(d for d in broken if d["kind"] == "Secret")
    secret["stringData"]["AEGIS_REDIS_URL"] = ""
    prod_guard.check_k8s_secret(broken)
    assert any("AEGIS_REDIS_URL" in f for f in prod_guard.failures)


def test_public_demo_key_hash_fails(docs):
    broken = copy.deepcopy(docs)
    secret = next(d for d in broken if d["kind"] == "Secret")
    secret["stringData"]["AEGIS_TENANTS"] = (
        "demo:e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef:chat+rag"
    )
    prod_guard.check_k8s_secret(broken)
    assert any("demo/empty API key hash" in f for f in prod_guard.failures)


def test_empty_key_hash_fails(docs):
    broken = copy.deepcopy(docs)
    secret = next(d for d in broken if d["kind"] == "Secret")
    secret["stringData"]["AEGIS_TENANTS"] = (
        "demo:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:chat+rag"
    )
    prod_guard.check_k8s_secret(broken)
    assert any("demo/empty API key hash" in f for f in prod_guard.failures)


def test_placeholder_tenant_is_a_warning_not_a_failure(docs, capsys):
    """A placeholder is honest and fails loudly at boot; shipping a working
    credential fails silently. So it warns, it does not block the pipeline."""
    prod_guard.check_k8s_secret(copy.deepcopy(docs))
    assert prod_guard.failures == []
    assert "REPLACE_ME" in capsys.readouterr().out


def test_shipped_secret_never_contains_a_usable_demo_key():
    """Guard against re-introducing the credential into the manifest."""
    text = (ROOT / "deploy" / "k8s" / "security.yaml").read_text()
    assert "e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef" not in text


# --- hardening checks still hold --------------------------------------------


def test_missing_readiness_probe_fails(docs):
    broken = copy.deepcopy(docs)
    del _find(broken, "StatefulSet")["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
    prod_guard.check_workload(broken)
    assert any("readinessProbe" in f for f in prod_guard.failures)


def test_readonly_root_filesystem_is_required(docs):
    broken = copy.deepcopy(docs)
    c = _find(broken, "StatefulSet")["spec"]["template"]["spec"]["containers"][0]
    c["securityContext"]["readOnlyRootFilesystem"] = False
    prod_guard.check_workload(broken)
    assert any("readOnlyRootFilesystem" in f for f in prod_guard.failures)


def test_shipped_compose_requires_secrets_and_redis():
    prod_guard.check_compose()
    assert prod_guard.failures == []


def test_shipped_dockerfile_is_nonroot_with_healthcheck():
    prod_guard.check_dockerfile()
    assert prod_guard.failures == []


# --- the Render blueprint must be bootable as shipped ------------------------


def test_shipped_render_is_an_evaluation_blueprint():
    """The current render.yaml is a deliberate evaluation posture (env=development,
    public demo key). The prod-guard must recognise this as coherent and not
    report it as a failure."""
    prod_guard.check_render_blueprint()
    assert prod_guard.failures == []


def test_render_production_with_demo_hash_fails():
    """The real regression: the blueprint used to ship as production + demo key,
    which the gateway rejects at boot."""
    prod_guard.check_render_blueprint()
    assert prod_guard.failures == []
    # Now mutate: flip to production
    prod_guard.failures.clear()
    render = ROOT / "render.yaml"
    text = render.read_text()
    render.write_text(text.replace("value: development", "value: production", 1))
    try:
        prod_guard.check_render_blueprint()
        assert any("demo" in f for f in prod_guard.failures)
    finally:
        render.write_text(text)


def test_render_production_without_redis_fails():
    text = (ROOT / "render.yaml").read_text()
    broken = text.replace("value: development", "value: production", 1)
    # Remove the Redis wiring (the env var entry)
    redis_block = (
        "      - key: AEGIS_REDIS_URL\n"
        "        fromService:\n"
        "          type: redis\n"
        "          name: aegis-redis\n"
        "          property: connectionString\n"
    )
    broken = broken.replace(redis_block, "")
    render = ROOT / "render.yaml"
    render.write_text(broken)
    try:
        prod_guard.check_render_blueprint()
        assert any("REDIS_URL" in f for f in prod_guard.failures)
    finally:
        render.write_text(text)


# --- the console must stay self-contained and the CSP strict ----------------
#
# These two properties are coupled: the CSP can only drop `unsafe-inline` and
# remote origins *because* the dashboard ships its own assets. Re-adding a CDN
# link or an inline <script> would silently re-open the policy, and the page
# would still render — so nothing else in the pipeline would notice.


@pytest.fixture()
def console_tree(tmp_path, monkeypatch):
    """A writable copy of just the files the console check reads."""
    src = ROOT / "src" / "aegis"
    for rel in ("static/dashboard.css", "static/dashboard.js",
                "templates/dashboard.html", "api/middleware.py"):
        dst = tmp_path / "src" / "aegis" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text((src / rel).read_text())
    monkeypatch.setattr(prod_guard, "ROOT", tmp_path)
    return tmp_path


def _template(tree) -> Path:
    return tree / "src" / "aegis" / "templates" / "dashboard.html"


def test_shipped_console_passes_the_guard():
    prod_guard.check_console_surface()
    assert prod_guard.failures == []


def test_console_loading_a_cdn_stylesheet_fails(console_tree):
    """The real regression risk: someone re-adds a CDN <link> for convenience,
    which breaks air-gapped deployments and re-opens the CSP."""
    t = _template(console_tree)
    t.write_text(t.read_text().replace(
        "</head>", '<link rel="stylesheet" href="https://cdn.example.com/x.css"></head>', 1))
    prod_guard.check_console_surface()
    assert any("remote stylesheet" in f for f in prod_guard.failures)


def test_console_with_an_inline_style_fails(console_tree):
    t = _template(console_tree)
    t.write_text(t.read_text().replace(
        "</body>", '<div style="color:red">x</div></body>', 1))
    prod_guard.check_console_surface()
    assert any("inline style" in f for f in prod_guard.failures)


def test_console_with_an_inline_script_fails(console_tree):
    t = _template(console_tree)
    t.write_text("<html><head></head><body><script>alert(1)</script></body></html>")
    prod_guard.check_console_surface()
    assert any("inline <script>" in f for f in prod_guard.failures)


def test_missing_static_asset_fails(console_tree):
    (console_tree / "src" / "aegis" / "static" / "dashboard.js").unlink()
    prod_guard.check_console_surface()
    assert any("dashboard.js is missing" in f for f in prod_guard.failures)


def test_csp_regaining_unsafe_inline_fails(console_tree):
    """A docstring *mention* of unsafe-inline is fine; the quoted directive is
    not — the check must tell them apart."""
    mw = console_tree / "src" / "aegis" / "api" / "middleware.py"
    text = mw.read_text()
    # The shipped file already mentions it in the docstring; only the quoted
    # directive form is a regression.
    assert "'unsafe-inline'" not in text
    mw.write_text(text.replace("\"script-src 'self'; \"",
                               "\"script-src 'self' 'unsafe-inline'; \"", 1))
    prod_guard.check_console_surface()
    assert any("unsafe-inline" in f for f in prod_guard.failures)

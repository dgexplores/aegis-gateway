"""Production-readiness guard: fail the pipeline when deploy artifacts regress.

Checks (all must hold):
  1. K8s workload keeps audit evidence durable — StatefulSet with per-pod
     volumeClaimTemplates (or an explicit PVC reference). A shared RWO PVC on
     a Deployment leaves replicas Pending; emptyDir evaporates the chain.
  2. K8s probes + resource limits + non-root hardening present.
  3. HPA scaleTargetRef matches the workload kind and name that actually exist.
  4. K8s Secret supplies shared Redis state in production and ships no known
     demo/empty API key hash.
  5. Dockerfile runs as non-root and ships a HEALTHCHECK.
  6. The console stays self-contained — assets ship from /static, no CDN/web
     font/inline script or style, and the CSP keeps `unsafe-inline` out and
     remote origins off. (The strict CSP is only safe while the dashboard owns
     its assets; this couples the two so neither regresses silently.)
  7. Compose boots the gateway in production mode with required secrets
     (tenants, both HMAC keys) and a Redis URL (prod refuses to boot without
     shared limiter/budget state).

Usage: python scripts/prod_guard.py  (exit 0 = shippable, 1 = blocked)
"""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# Imported rather than copied, so the guard and the application can never
# disagree about what "the demo password" is. A guard checking a stale literal
# is worse than no guard at all.
from aegis.opscontrol import DEMO_BREAKGLASS_PASSWORD
from aegis.security.admin_session import DEMO_PASSWORD as DEMO_ADMIN_PASSWORD
from aegis.security.admin_session import DEMO_USERNAME as DEMO_ADMIN_USER

ROOT = Path(__file__).resolve().parent.parent

failures: list[str] = []

# Every operator-facing HTML surface. Each ships only local assets and must stay
# renderable on a network with no outbound internet.
CONSOLE_SHELLS = ("dashboard.html", "admin.html")


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"PROD-GUARD FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"prod-guard ok: {msg}")


def warn(msg: str) -> None:
    """Advisory: worth knowing, must not block the pipeline."""
    print(f"prod-guard NOTE: {msg}")


def load_k8s() -> list[dict]:
    docs = []
    for f in sorted((ROOT / "deploy" / "k8s").glob("*.yaml")):
        docs.extend(d for d in yaml.safe_load_all(f.read_text()) if d)
    return docs


def check_workload(docs: list[dict]) -> None:
    wls = [d for d in docs if d.get("kind") in ("StatefulSet", "Deployment")]
    if not wls:
        fail("no StatefulSet/Deployment in deploy/k8s")
        return
    wl = wls[0]
    kind = wl["kind"]
    spec = wl["spec"]
    pod = spec["template"]["spec"]
    containers = pod["containers"]
    gw = next((c for c in containers if c.get("ports")), containers[0])

    mounts = {m["name"]: m.get("mountPath") for m in gw.get("volumeMounts", [])}
    if "audit-log" not in mounts:
        fail(f"{kind}: no audit-log volumeMount on gateway container")
    if kind == "StatefulSet":
        templates = {t["metadata"]["name"] for t in spec.get("volumeClaimTemplates", [])}
        if "audit-log" not in templates:
            fail("StatefulSet: audit-log missing from volumeClaimTemplates (evidence would be ephemeral)")
        else:
            ok("audit evidence durable via per-pod volumeClaimTemplates")
    else:  # Deployment: only a shared RWX PVC (or per-replica scheme) is safe
        vols = {v["name"]: v for v in pod.get("volumes", [])}
        claim = (vols.get("audit-log") or {}).get("persistentVolumeClaim")
        if not claim:
            fail("Deployment: audit-log must be a persistentVolumeClaim, not emptyDir (evidence evaporates)")
        else:
            ok("audit evidence on persistentVolumeClaim")

    before = len(failures)
    for probe in ("livenessProbe", "readinessProbe"):
        if probe not in gw:
            fail(f"{kind}: gateway missing {probe}")
    if "resources" not in gw:
        fail(f"{kind}: gateway missing resources requests/limits")
    sc = pod.get("securityContext", {})
    if sc.get("runAsNonRoot") is not True:
        fail(f"{kind}: podSecurityContext.runAsNonRoot must be true")
    csc = gw.get("securityContext", {})
    if csc.get("readOnlyRootFilesystem") is not True:
        fail(f"{kind}: container readOnlyRootFilesystem must be true")
    if len(failures) == before:
        ok("probes, resources, and pod/container hardening present")


def check_hpa(docs: list[dict]) -> None:
    """The HPA must target the workload that actually exists.

    This shipped with `kind: Deployment` while the workload had been converted
    to a StatefulSet, so the HPA never resolved its target and autoscaling was
    silently dead — a class of bug that only shows up under load in production.
    """
    hpas = [d for d in docs if d.get("kind") == "HorizontalPodAutoscaler"]
    if not hpas:
        return
    workloads = {d["metadata"]["name"]: d["kind"] for d in docs if d.get("kind") in ("StatefulSet", "Deployment")}
    for hpa in hpas:
        ref = hpa["spec"].get("scaleTargetRef", {})
        target_name, target_kind = ref.get("name"), ref.get("kind")
        if target_name not in workloads:
            fail(f"HPA targets '{target_name}', which is not a workload in deploy/k8s")
        elif workloads[target_name] != target_kind:
            fail(
                f"HPA scaleTargetRef.kind={target_kind} but {target_name} is a "
                f"{workloads[target_name]} — autoscaling would never resolve"
            )
        else:
            ok(f"HPA targets the real workload ({target_kind}/{target_name})")


def check_k8s_secret(docs: list[dict]) -> None:
    """The shipped Secret must not make the pod unstartable, or leak a key.

    Two failure modes this catches:
      * AEGIS_ENV=production with an empty AEGIS_REDIS_URL — the gateway refuses
        to boot without shared limiter/budget state, so the pod crash-loops.
      * AEGIS_TENANTS carrying the public demo key hash (or a placeholder), so
        the manifest either ships a known credential or boots with no tenant.
    """
    secrets = [d for d in docs if d.get("kind") == "Secret" and "aegis" in d["metadata"]["name"]]
    if not secrets:
        fail("no aegis Secret in deploy/k8s (gateway would have no config)")
        return
    data = secrets[0].get("stringData") or {}
    env = data.get("AEGIS_ENV", "production")

    if env == "production" and not str(data.get("AEGIS_REDIS_URL", "")).strip():
        fail(
            "k8s Secret: AEGIS_ENV=production requires a non-empty AEGIS_REDIS_URL (gateway refuses to boot without it)"
        )
    else:
        ok("k8s Secret supplies shared Redis state for production")

    tenants = str(data.get("AEGIS_TENANTS", ""))
    demo_hash = "e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef"
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if demo_hash in tenants or empty_hash in tenants:
        fail("k8s Secret ships a public demo/empty API key hash — mint a real tenant")
    elif "REPLACE_ME" in tenants:
        # Deliberate: a placeholder is honest and fails loudly at boot (the
        # gateway refuses production with no usable tenant). Shipping a working
        # demo credential would fail silently instead. Warn, don't block CI.
        warn(
            "k8s Secret AEGIS_TENANTS is the REPLACE_ME placeholder — the operator "
            "must run scripts/gen_tenant.py before the pod will boot"
        )
    else:
        ok("k8s Secret carries no known demo credential")

    _check_admin_portal_credential(data, "k8s Secret")


def _is_placeholder(value: str) -> bool:
    """A value the operator is meant to overwrite, not a secret.

    Both spellings appear in the shipped manifests, and both are published, so
    neither can be treated as a configured credential.
    """
    lowered = value.lower()
    return "replace_me" in lowered or "change-me" in lowered or "changeme" in lowered


def _check_admin_portal_credential(data: dict, where: str) -> None:
    """The admin portal must not be published with the demo password.

    A bearer key is a scoped secret an operator copies deliberately. The portal
    login is a *username and password* on a login form, and the demo pair is
    published in the README and the source. Shipping it to production would put
    a known credential in front of the controls that can pause every tenant and
    pull the kill switch — so this blocks rather than warns.

    Deliberately not blocked: leaving the portal login unset entirely. That is
    the pre-existing behaviour (admin-scoped bearer tokens only), and refusing to
    ship it would break deployments that never wanted a login form.

    The break-glass secret is a *separate* credential guarding a *separate*
    control, so it is checked on its own below rather than from inside the
    branches here — otherwise "no portal login configured" would silently skip it,
    which is precisely the configuration it exists to protect.
    """
    _check_breakglass_credential(data, where)

    user = str(data.get("AEGIS_ADMIN_USERNAME", "")).strip()
    password = str(data.get("AEGIS_ADMIN_PASSWORD", "")).strip()

    # A shipped placeholder is *worse* than a missing one. Missing disables the
    # portal login and the gateway falls back to admin-scoped bearer tokens, which
    # is safe. A placeholder leaves a login form in front of the controls that
    # can pause every tenant, protected by a string printed in the manifest, the
    # source and this file. It used to be reported as "ok — an operator-chosen
    # credential", which is precisely the false pass that must not exist.
    for label, value in (("AEGIS_ADMIN_USERNAME", user), ("AEGIS_ADMIN_PASSWORD", password)):
        if value and _is_placeholder(value):
            fail(
                f"{where} ships the {label} placeholder {value!r} — that is a published "
                "password, not a missing one. Replace it, or remove the key to fall "
                "back to bearer-only auth"
            )
            return

    if not user and not password:
        ok(f"{where}: admin portal login unset — admin-scoped bearer tokens only")
        return
    if not user or not password:
        fail(
            f"{where}: AEGIS_ADMIN_USERNAME and AEGIS_ADMIN_PASSWORD must be set together "
            "(half a login is an open door with no way in)"
        )
        return
    if password == DEMO_ADMIN_PASSWORD:
        fail(
            f"{where} ships the published demo admin password — anyone who has read the "
            "README can pause tenants and pull the kill switch"
        )
        return
    if user == DEMO_ADMIN_USER:
        fail(f"{where} ships the demo admin id with a different password — pick your own id")
        return
    ok(f"{where}: admin portal login is set to an operator-chosen id and password")


def _check_breakglass_credential(data: dict, where: str) -> None:
    """The kill switch should need a second secret, and it must not be a known one.

    Unset is a *warning*, not a failure: the kill switch then works with nothing
    but a portal session, which is a weaker posture but a working one, and
    refusing to ship would break the deploy for an operator who has not got round
    to choosing a secret yet. Shipping a known one is a failure — it is the same
    argument as the admin password, and the kill switch is the more damaging of
    the two controls.
    """
    password = str(data.get("AEGIS_BREAKGLASS_PASSWORD", "")).strip()
    if password and _is_placeholder(password):
        fail(
            f"{where} ships the AEGIS_BREAKGLASS_PASSWORD placeholder {password!r} — "
            "that is a published secret, so the kill switch is guarded by nothing"
        )
        return
    if not password:
        warn(
            f"{where}: AEGIS_BREAKGLASS_PASSWORD is unset — the kill switch is reachable "
            "with a portal session alone. Set it to require a second secret."
        )
        return
    if password == DEMO_BREAKGLASS_PASSWORD:
        fail(
            f"{where} ships the published demo break-glass secret — anyone who has read the "
            "README can refuse all traffic"
        )
        return
    ok(f"{where}: the kill switch requires a break-glass secret")


def check_dockerfile() -> None:
    text = (ROOT / "Dockerfile").read_text()
    if "USER aegis" not in text and "\nUSER " not in text:
        fail("Dockerfile: must switch to non-root USER")
    else:
        ok("Dockerfile runs as non-root")
    if "HEALTHCHECK" not in text:
        fail("Dockerfile: HEALTHCHECK missing")
    else:
        ok("Dockerfile HEALTHCHECK present")


def check_console_surface() -> None:
    """Both console surfaces must stay self-contained and the CSP must stay strict.

    These two properties are coupled: the CSP can only drop `unsafe-inline` and
    remote origins *because* the console ships its own CSS/JS from /static.
    Re-adding a CDN `<link>`, a web font, or an inline `<script>` would silently
    re-open the policy, and nothing else in the pipeline would notice — the page
    would still render. So it is gated here.

    An air-gapped deployment also depends on this: a dashboard that loses its
    styling on a network with no outbound internet is worse than one that never
    had any.

    There are two shells now — dashboard.html (a user's requests) and admin.html
    (the fleet) — so both are checked. A new surface is added to CONSOLE_SHELLS
    and inherits every rule below; nothing here is per-page.
    """
    static = ROOT / "src" / "aegis" / "static"
    before = len(failures)
    for asset in ("dashboard.css", "dashboard.js", "theme.js"):
        if not (static / asset).exists():
            fail(f"console: src/aegis/static/{asset} is missing (a console would 404 its assets)")

    for name in CONSOLE_SHELLS:
        template = ROOT / "src" / "aegis" / "templates" / name
        if not template.exists():
            fail(f"console: src/aegis/templates/{name} is missing")
            continue

        html = template.read_text()
        # Check for inline styles
        if 'style="' in html:
            fail(f"console: {name} contains inline style attribute (CSP forbids it; move it to dashboard.css)")
        # Check for remote scripts
        if 'src="http' in html:
            fail(f"console: {name} contains remote script/style source (breaks air-gapped deployments)")
        # Check for remote stylesheets - only flag <link> with https:// href, not local /static/ ones
        import re

        for _match in re.finditer(r'<link[^>]*href="https://[^"]*"', html):
            fail(f"console: {name} contains remote stylesheet source (breaks air-gapped deployments)")
        # Check for remote url() in CSS
        if "url(http" in html:
            fail(f"console: {name} contains remote url() in CSS/markup")
        # An inline <script> with no src= would need `unsafe-inline`.
        if "<script" in html and "<script src=" not in html:
            fail(f"console: {name} has an inline <script> (CSP forbids it)")
        if 'src="/static/' not in html:
            fail(f"console: {name} does not load its assets from /static")

    csp_src = (ROOT / "src" / "aegis" / "api" / "middleware.py").read_text()
    # Match the quoted directive form only — the module docstring legitimately
    # *mentions* `unsafe-inline` (in backticks) to explain why it is absent.
    if "'unsafe-inline'" in csp_src:
        fail("console: CSP regained 'unsafe-inline' — the strict policy was weakened")
    if "script-src 'self'" not in csp_src or "style-src 'self'" not in csp_src:
        fail("console: CSP script-src/style-src must be exactly 'self' (no remote origins)")
    if len(failures) == before:
        ok("console is self-contained (local assets only, strict CSP, no inline script/style)")


def _web_env(web: dict) -> dict:
    """Env entries of a Render web service, keyed by variable name."""
    return {e.get("key"): e for e in (web.get("envVars") or [])}


def check_render_blueprint() -> None:
    """The Render blueprint must be bootable as shipped.

    It previously shipped as `AEGIS_ENV=production` plus the public demo key
    hash, which `Settings._tenant_problems` rejects — so the advertised
    one-click deploy crash-looped on every boot. Two postures are coherent:

      * **evaluation** (`env != production`): the demo tenant is allowed. The key
        is already public in `.env.example` and the README, so refusing it
        protects nothing while breaking the deploy.
      * **production**: every production invariant must hold, because each one
        the gateway enforces at boot is a container that will not start.
    """
    path = ROOT / "render.yaml"
    if not path.exists():
        warn("no render.yaml — skipping the Render blueprint check")
        return
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001 — invalid yaml blocks the pipeline with context
        fail(f"render.yaml does not parse: {exc}")
        return

    web = next((s for s in (doc.get("services") or []) if s.get("type") == "web"), None)
    if web is None:
        fail("render.yaml has no web service")
        return
    if not web.get("healthCheckPath"):
        fail("render.yaml: web service has no healthCheckPath — a deploy could never be judged healthy")

    env = _web_env(web)

    def value(key: str) -> str:
        entry = env.get(key) or {}
        if entry.get("value") is not None:
            return str(entry["value"])
        if entry.get("generateValue") or entry.get("fromService") or entry.get("fromDatabase"):
            return "<wired>"  # supplied by the platform, not a literal in the repo
        return ""

    demo_hash = "e3e18b6e9c3d49198e61396c5e4439668591ec224bac1ef1c2736661d80763ef"
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    aegis_env = value("AEGIS_ENV") or "production"
    tenants = value("AEGIS_TENANTS")

    if aegis_env == "production":
        if demo_hash in tenants or empty_hash in tenants or "REPLACE_ME" in tenants:
            fail(
                "render.yaml: AEGIS_ENV=production with a public demo / empty / placeholder "
                "tenant hash — the container refuses to boot; mint one with gen_tenant.py"
            )
        if value("AEGIS_DEMO_API_KEY"):
            fail(
                "render.yaml: AEGIS_ENV=production must not set AEGIS_DEMO_API_KEY "
                "(/dashboard is unauthenticated and would serve a working credential)"
            )
        if not value("AEGIS_REDIS_URL"):
            fail("render.yaml: AEGIS_ENV=production requires AEGIS_REDIS_URL")
        ok("render.yaml is a coherent production blueprint")
    elif demo_hash in tenants:
        ok(
            f"render.yaml is an evaluation blueprint (env={aegis_env}, public demo key — "
            "nothing is protected by refusing it, and refusing it breaks the deploy)"
        )
    else:
        warn(
            f"render.yaml runs env={aegis_env} without the demo tenant — the deployed "
            "console will 401 every call until AEGIS_TENANTS is set"
        )

    # The image writes the chain to /data; the blueprint must persist that path
    # or the tamper-evident log evaporates on every redeploy.
    before = len(failures)
    if "AEGIS_AUDIT_PATH=/data/audit.jsonl" in (ROOT / "Dockerfile").read_text():
        disk = web.get("disk") or {}
        if disk.get("mountPath") != "/data":
            fail(
                "render.yaml: image writes the audit chain to /data but no disk is mounted "
                "there — the tamper-evident log is lost on every redeploy"
            )
    if len(failures) == before:
        ok("render.yaml persists the audit chain on a disk")


def check_render_free_blueprint() -> None:
    """The free-tier blueprint must be honest about what free means.

    No disk (paid-only on Render — declaring one silently forces a paid
    instance), no Redis/Postgres services (no free tier), S3 archive present
    as the only history copy, demo posture identical to render.yaml. An
    "evaluation" file that quietly requires paid pieces is a broken promise.
    """
    path = ROOT / "render-free.yaml"
    if not path.exists():
        warn("no render-free.yaml — skipping the free-tier blueprint check")
        return
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001 — invalid yaml blocks the pipeline with context
        fail(f"render-free.yaml does not parse: {exc}")
        return

    web = next((s for s in (doc.get("services") or []) if s.get("type") == "web"), None)
    if web is None:
        fail("render-free.yaml has no web service")
        return
    if not web.get("healthCheckPath"):
        fail("render-free.yaml: web service has no healthCheckPath")
    if web.get("disk"):
        fail("render-free.yaml declares a disk — disks are paid-only, so the free deploy is not free")
    paid_extras = [s.get("name") for s in (doc.get("services") or []) if s.get("type") != "web"]
    if paid_extras or doc.get("databases"):
        fail(f"render-free.yaml wires paid pieces ({paid_extras or 'databases'}) — the free deploy is not free")

    env = _web_env(web)
    bucket = env.get("AEGIS_AUDIT_S3_BUCKET") or {}
    if "value" in bucket and bucket["value"]:
        fail("render-free.yaml hardcodes AEGIS_AUDIT_S3_BUCKET — buckets are per-operator, fill in dashboard")
    if not bucket:
        fail("render-free.yaml has no AEGIS_AUDIT_S3_BUCKET entry — without the archive, free-tier history evaporates")
    if (env.get("AEGIS_ENV") or {}).get("value") == "production":
        fail("render-free.yaml runs production without Redis — limits would silently multiply per worker")
    if str((env.get("AEGIS_WORKERS") or {}).get("value")) != "1":
        fail("render-free.yaml must pin AEGIS_WORKERS=1 — without Redis, two workers silently double every limit")
    ttl = str((env.get("AEGIS_AUDIT_PAYLOAD_KEEP_DAYS") or {}).get("value") or "0")
    if ttl == "0":
        fail("render-free.yaml must set AEGIS_AUDIT_PAYLOAD_KEEP_DAYS — free tier keeps payloads forever by default")
    if not any(f.startswith("render-free.yaml") for f in failures):
        ok("render-free.yaml is honest free tier: no disk, no paid services, archive wired")


def check_compose() -> None:
    text = (ROOT / "docker-compose.yml").read_text()
    comp = yaml.safe_load(text)["services"]["gateway"]
    env = comp.get("environment", {})
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    for key in ("AEGIS_ENV", "AEGIS_REDIS_URL"):
        if key not in env:
            fail(f"compose: gateway missing {key}")
    if env.get("AEGIS_ENV") != "production":
        fail("compose: gateway AEGIS_ENV must be production (fail-closed defaults)")
    raw = text
    for key in ("AEGIS_AUDIT_HMAC_KEY", "AEGIS_VAULT_HMAC_KEY", "AEGIS_TENANTS"):
        if key + ":${" + key + ":?" not in raw.replace(" ", ""):
            fail(f"compose: {key} must be required (:? syntax) so boot fails loudly without .env")
    _check_admin_portal_credential(env, "compose")
    if not any(f.startswith("compose:") for f in failures):
        ok("compose enforces production env + required secrets + redis")


def main() -> int:
    try:
        docs = load_k8s()
    except Exception as exc:  # noqa: BLE001 — invalid yaml blocks the pipeline with context
        fail(f"deploy/k8s yaml does not parse: {exc}")
        print(f"\nPROD-GUARD BLOCKED ({len(failures)} problem(s))")
        return 1
    check_workload(docs)
    check_hpa(docs)
    check_k8s_secret(docs)
    check_dockerfile()
    check_console_surface()
    check_render_blueprint()
    check_render_free_blueprint()
    check_compose()
    if failures:
        print(f"\nPROD-GUARD BLOCKED ({len(failures)} problem(s))")
        return 1
    print("\nPROD-GUARD PASSED — deploy artifacts shippable")
    return 0


if __name__ == "__main__":
    sys.exit(main())

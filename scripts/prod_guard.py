"""Production-readiness guard: fail the pipeline when deploy artifacts regress.

Checks (all must hold):
  1. K8s workload keeps audit evidence durable — StatefulSet with per-pod
     volumeClaimTemplates (or an explicit PVC reference). A shared RWO PVC on
     a Deployment leaves replicas Pending; emptyDir evaporates the chain.
  2. K8s probes + resource limits + non-root hardening present.
  3. Dockerfile runs as non-root and ships a HEALTHCHECK.
  4. Compose boots the gateway in production mode with required secrets
     (tenants, both HMAC keys) and a Redis URL (prod refuses to boot without
     shared limiter/budget state).

Usage: python scripts/prod_guard.py  (exit 0 = shippable, 1 = blocked)
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"PROD-GUARD FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"prod-guard ok: {msg}")


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
    check_dockerfile()
    check_compose()
    if failures:
        print(f"\nPROD-GUARD BLOCKED ({len(failures)} problem(s))")
        return 1
    print("\nPROD-GUARD PASSED — deploy artifacts shippable")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""PaaS-friendly entrypoint.

`uvicorn aegis.main:app --port 8080` hardcodes the port, so the image only works
on platforms that let you fix a port. Every hosted runtime instead injects
`$PORT` and expects the app to bind it — Render, Railway, Fly, Heroku and most
container platforms do this. This entrypoint reads it, so the same image runs
unchanged locally and hosted.

Precedence: `AEGIS_PORT` (explicit) > `PORT` (platform convention) > configured
default. Bind address follows the same rule with `AEGIS_HOST`.

Installed as the `aegis-gateway` console script, so the container's CMD is just
the command name:

    aegis-gateway                 # or: python -m aegis.serve
"""

import os
import sys

import uvicorn


def resolve_port() -> int:
    """AEGIS_PORT, else PORT, else the configured default."""
    for var in ("AEGIS_PORT", "PORT"):
        raw = os.environ.get(var, "").strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                sys.exit(f"serve: {var}={raw!r} is not a valid port number")
    # Imported lazily so a bad config cannot abort the process before the port
    # is known (and so `--help`-style use needs no settings).
    from aegis.config import get_settings

    return get_settings().port


def resolve_workers() -> int:
    raw = os.environ.get("AEGIS_WORKERS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        sys.exit(f"serve: AEGIS_WORKERS={raw!r} is not a valid worker count")


def main() -> None:
    # 0.0.0.0 is the PaaS standard — Render, Railway, Fly, Heroku all require
    # binding all interfaces so their reverse proxy can reach the container.
    host = os.environ.get("AEGIS_HOST", "").strip() or "0.0.0.0"  # noqa: S104
    port = resolve_port()
    # More than one worker needs shared rate-limit/budget state (Redis), which
    # the gateway refuses to run without in production. Default to a single
    # worker so a dependency-free development deployment works out of the box.
    workers = resolve_workers()

    print(f"aegis-gateway: serving on {host}:{port} (workers={workers})", flush=True)
    uvicorn.run("aegis.main:app", host=host, port=port, workers=workers)


if __name__ == "__main__":
    main()

"""Tests for the PaaS entrypoint (src/aegis/serve.py).

The entrypoint must honour the $PORT convention used by Render, Railway, Fly and
Heroku, and fall back to the configured default when no env var is set. It must
reject non-numeric values rather than silently crash at runtime.
"""


import pytest

from aegis.serve import resolve_port, resolve_workers


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("AEGIS_PORT", "PORT"):
        monkeypatch.delenv(var, raising=False)


def test_aegis_port_wins_over_port(monkeypatch):
    monkeypatch.setenv("AEGIS_PORT", "8123")
    monkeypatch.setenv("PORT", "8124")
    assert resolve_port() == 8123


def test_port_honoured_when_aegis_port_absent(monkeypatch):
    monkeypatch.setenv("PORT", "8124")
    assert resolve_port() == 8124


def test_default_port_when_neither_env_set():
    assert resolve_port() == 8080


def test_non_numeric_port_exits(monkeypatch):
    monkeypatch.setenv("PORT", "not-a-port")
    with pytest.raises(SystemExit) as exc_info:
        resolve_port()
    assert exc_info.value.code != 0


def test_workers_default():
    assert resolve_workers() == 1


def test_workers_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_WORKERS", "4")
    assert resolve_workers() == 4


def test_workers_rejects_negative(monkeypatch):
    monkeypatch.setenv("AEGIS_WORKERS", "-2")
    assert resolve_workers() == 1  # max(1, ...)


def test_workers_rejects_non_numeric(monkeypatch):
    monkeypatch.setenv("AEGIS_WORKERS", "many")
    with pytest.raises(SystemExit) as exc_info:
        resolve_workers()
    assert exc_info.value.code != 0

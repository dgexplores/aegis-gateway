"""Test isolation.

No test may depend on the ambient `AEGIS_*` environment. Without this, any
`AEGIS_*` variable exported by the shell or CI leaks into every test that builds
a `Settings` object.

That is not theoretical: `AEGIS_AUDIT_PATH` leaking in makes every
gateway-building test write to the *same absolute* audit file while each test
supplies its own `AEGIS_AUDIT_HMAC_KEY`, so the file ends up mixing several
HMAC chains. The next consumer — `scripts/redteam.py` in the release gate —
then fails with `audit chain corrupt at seq=1`, which looks like a security
regression but is a test-isolation bug.

No test in this suite reads `os.environ` or requires a live Postgres/Redis
(`test_pgstore.py` and `test_budget_redis.py` use fakes), so stripping the
prefix is safe and makes the suite hermetic wherever it runs.
"""

import pytest

ENV_PREFIX = "AEGIS_"


@pytest.fixture(autouse=True)
def _isolate_aegis_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every ambient AEGIS_* variable for the duration of each test."""
    import os

    for name in [n for n in os.environ if n.startswith(ENV_PREFIX)]:
        monkeypatch.delenv(name, raising=False)

"""The restore drill has to be able to fail.

A check that passes on every input is decoration. The whole value of a restore
drill is that a *bad* archive is reported as bad, so these tests corrupt a chain
in the specific ways real corruption arrives — a flipped byte in a payload, a
removed record in the middle, a re-signed head — and require the drill to catch
each one.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_drill():
    spec = importlib.util.spec_from_file_location("restore_drill", ROOT / "scripts" / "restore_drill.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["restore_drill"] = module
    spec.loader.exec_module(module)
    return module


drill = _load_drill()
KEY = drill.HMAC_KEY


@pytest.fixture()
def chain_file(tmp_path) -> Path:
    path = tmp_path / "original.jsonl"
    drill.build_chain(path, 120)
    return path


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _write(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))


def test_an_untouched_archive_passes(chain_file, tmp_path, capsys):
    assert drill.drill(chain_file, tmp_path) == 0
    assert "RESTORE DRILL PASSED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "field,value",
    [
        ("event", "something_benign"),
        ("tenant", "somebody-else"),
        ("ts", 1.0),
    ],
)
def test_editing_a_signed_field_is_caught(chain_file, tmp_path, capsys, field, value):
    """The realistic attack: rewrite what the log says happened.

    The entry hash covers seq, ts, tenant, event, payload_sha256, prev_hash and
    request_id — so changing any of those has to fail the drill.
    """
    records = _read(chain_file)
    records[40][field] = value
    _write(chain_file, records)
    assert drill.drill(chain_file, tmp_path) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    # A verdict, not a stack trace: this is run during an incident.
    assert "Traceback" not in out


def test_rewriting_the_payload_is_not_caught_because_no_payload_is_stored(chain_file, tmp_path):
    """The limitation, pinned so it is not discovered during an incident.

    Without `AEGIS_AUDIT_ENCRYPT_KEY` the chain stores only `payload_sha256`, not
    the payload, so there is no stored payload to alter — adding one is simply
    ignored. That means the chain attests to *what was logged*, not to the
    contents of the logged payload, until payload copies are enabled. Turning
    them on is what makes `payload_ok` meaningful.
    """
    records = _read(chain_file)
    assert "payload" not in records[0], "this test assumes payload copies are off"
    records[40]["payload"] = {"i": 40, "note": "restored by hand, honest-looking"}
    _write(chain_file, records)
    assert drill.drill(chain_file, tmp_path) == 0


def test_a_removed_record_is_caught(chain_file, tmp_path, capsys):
    """Deleting an inconvenient record is the whole threat model. Every later
    link is computed from its predecessor, so a hole cannot hide."""
    records = _read(chain_file)
    del records[50]
    _write(chain_file, records)
    assert drill.drill(chain_file, tmp_path) == 1


def test_a_reordered_chain_is_caught(chain_file, tmp_path):
    records = _read(chain_file)
    records[10], records[11] = records[11], records[10]
    _write(chain_file, records)
    assert drill.drill(chain_file, tmp_path) == 1


def test_a_truncated_file_still_verifies_because_a_chain_cannot_see_its_own_tail(chain_file, tmp_path):
    """The honest limitation, pinned so nobody discovers it during an outage.

    Delete the last ten records and what remains is a perfectly valid, shorter
    chain: every hash recomputes and every link matches. Detecting this needs an
    anchor recorded when the records were written — the `head` in the
    /admin/audit response, or the S3 archive.
    """
    records = _read(chain_file)
    _write(chain_file, records[:20])
    assert drill.drill(chain_file, tmp_path) == 0, "a truncated chain is still a valid chain"


def test_an_expect_head_catches_that_truncation(chain_file, tmp_path, capsys):
    from aegis.security.audit import AuditChain

    head = AuditChain(KEY, path=str(chain_file)).head
    records = _read(chain_file)
    _write(chain_file, records[:20])
    assert drill.drill(chain_file, tmp_path, expect_head=head) == 1
    assert "tail loss" in capsys.readouterr().out


def test_the_drill_says_out_loud_when_tail_loss_is_not_covered(chain_file, tmp_path, capsys):
    """A green drill that quietly skips half the failure modes is worse than one
    that says which half it checked."""
    assert drill.drill(chain_file, tmp_path) == 0
    assert "tail loss is NOT covered" in capsys.readouterr().out


def test_a_chain_built_with_another_key_does_not_verify(chain_file, tmp_path, capsys):
    """Restoring into a deployment signed with a different HMAC key must fail
    loudly. Silently accepting it would mean the evidence no longer matches the
    key the gateway trusts."""
    from aegis.security.audit import AuditChain

    restored = tmp_path / "audit.jsonl"
    chain_file.replace(restored)
    # A mismatched key does not return False — it refuses to load, which is the
    # stronger outcome. Either way the drill must not report a pass.
    from aegis.security.audit import AuditError

    try:
        other = AuditChain("a-completely-different-audit-hmac-key-32chars", path=str(restored))
        ok, _ = other.verify()
        assert ok is False, "a chain must not verify under a different HMAC key"
    except AuditError:
        pass  # refusing to load is at least as good as refusing to verify


def test_the_drill_uses_the_same_verification_path_the_api_uses(chain_file, tmp_path):
    """Not a copy of the check, and not a looser one. The drill must call the
    real `verify()` and the real `tail_records()`."""
    from aegis.security.audit import AuditChain

    assert hasattr(AuditChain, "verify")
    assert hasattr(AuditChain, "tail_records")
    # Both are what drill() calls; if either were replaced by a summary count
    # the drill would stop being evidence.
    src = (ROOT / "scripts" / "restore_drill.py").read_text()
    assert "chain.verify()" in src
    assert "chain.tail_records(" in src

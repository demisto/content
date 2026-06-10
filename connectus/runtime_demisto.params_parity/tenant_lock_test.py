"""Unit tests for tenant_lock.py (Phase 4 — per-tenant filesystem lock).

Hermetic: LOCK_DIR is redirected at tmp_path, time.sleep is monkeypatched out, and
heartbeat intervals are shrunk so nothing blocks. No real network/kubectl/gitlab.

Covers (design §3):
  * atomic acquire returns a shell_id + creates the lock file with a valid payload,
  * a second acquire (different shell, tiny max_wait) on a fresh+alive lock → TenantLockTimeout
    carrying the holder dict,
  * stale reclaim via DEAD pid → acquires,
  * stale reclaim via OLD heartbeat (older than TTL) → acquires,
  * force=True reclaims even a fresh lock,
  * owner-checked release: wrong shell_id is a no-op, right shell_id deletes, idempotent,
  * force_unlock deletes unconditionally,
  * status reflects holder / None.
"""
from __future__ import annotations

import json
import os

import pytest

import tenant_lock


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    """Redirect LOCK_DIR into tmp_path, neutralize sleep, shrink heartbeat."""
    lock_dir = tmp_path / ".locks"
    monkeypatch.setattr(tenant_lock, "LOCK_DIR", lock_dir)
    # Never actually sleep in acquire's poll loop.
    monkeypatch.setattr(tenant_lock.time, "sleep", lambda *_a, **_k: None)
    # Tiny poll + heartbeat so any thread work is instant.
    monkeypatch.setattr(tenant_lock, "POLL_INTERVAL", 0)
    monkeypatch.setattr(tenant_lock, "HEARTBEAT_INTERVAL", 0.01)
    # Reset the in-process heartbeat registry between tests.
    tenant_lock._HEARTBEATS.clear()
    yield
    # Best-effort teardown: stop any heartbeats started during the test.
    for tenant in list(tenant_lock._HEARTBEATS.keys()):
        tenant_lock._stop_heartbeat(tenant)


def _read_lock(tenant: str) -> dict:
    return json.loads((tenant_lock.LOCK_DIR / f"{tenant}.lock").read_text())


# ---------------------------------------------------------------------------
# acquire — happy path
# ---------------------------------------------------------------------------
def test_acquire_creates_file_and_returns_shell_id():
    shell_id = tenant_lock.acquire("T1", integration_id="MyInt")
    assert isinstance(shell_id, str) and shell_id
    payload = _read_lock("T1")
    assert payload["shell_id"] == shell_id
    assert payload["pid"] == os.getpid()
    assert payload["integration_id"] == "MyInt"
    assert "acquired_at" in payload and "heartbeat_at" in payload


def test_acquire_empty_tenant_raises():
    with pytest.raises(tenant_lock.TenantLockError):
        tenant_lock.acquire("")


# ---------------------------------------------------------------------------
# contention — fresh+alive holder → timeout
# ---------------------------------------------------------------------------
def test_second_acquire_fresh_alive_times_out_with_holder():
    first = tenant_lock.acquire("T1", integration_id="IntA")
    assert first
    # Holder is THIS pid (alive) with a fresh heartbeat → not stale.
    with pytest.raises(tenant_lock.TenantLockTimeout) as ei:
        tenant_lock.acquire("T1", integration_id="IntB", max_wait=0)
    holder = ei.value.holder
    assert holder["shell_id"] == first
    assert holder["integration_id"] == "IntA"


# ---------------------------------------------------------------------------
# stale reclaim — dead pid
# ---------------------------------------------------------------------------
def test_stale_reclaim_dead_pid_acquires(monkeypatch):
    first = tenant_lock.acquire("T1")
    # Make the on-disk holder look like it belongs to a DEAD process.
    holder = _read_lock("T1")
    holder["pid"] = 9999999  # almost certainly not a live pid
    (tenant_lock.LOCK_DIR / "T1.lock").write_text(json.dumps(holder))
    # Force os.kill to report the pid as dead deterministically.
    monkeypatch.setattr(
        tenant_lock, "_pid_alive", lambda pid: pid == os.getpid()
    )
    new_shell = tenant_lock.acquire("T1", integration_id="IntB", max_wait=0)
    assert new_shell != first
    assert _read_lock("T1")["shell_id"] == new_shell


# ---------------------------------------------------------------------------
# stale reclaim — old heartbeat
# ---------------------------------------------------------------------------
def test_stale_reclaim_old_heartbeat_acquires(monkeypatch):
    first = tenant_lock.acquire("T1")
    holder = _read_lock("T1")
    # Heartbeat far older than TTL, but pid is alive (ours).
    holder["heartbeat_at"] = tenant_lock._now() - (tenant_lock.TTL + 100)
    (tenant_lock.LOCK_DIR / "T1.lock").write_text(json.dumps(holder))
    # Stop the real heartbeat so it doesn't refresh the timestamp under us.
    tenant_lock._stop_heartbeat("T1")
    (tenant_lock.LOCK_DIR / "T1.lock").write_text(json.dumps(holder))
    new_shell = tenant_lock.acquire("T1", max_wait=0)
    assert new_shell != first
    assert _read_lock("T1")["shell_id"] == new_shell


# ---------------------------------------------------------------------------
# force reclaim — even a fresh lock
# ---------------------------------------------------------------------------
def test_force_acquire_reclaims_fresh_lock():
    first = tenant_lock.acquire("T1", integration_id="IntA")
    second = tenant_lock.acquire("T1", integration_id="IntB", max_wait=0, force=True)
    assert second != first
    assert _read_lock("T1")["shell_id"] == second


# ---------------------------------------------------------------------------
# release — owner-checked + idempotent
# ---------------------------------------------------------------------------
def test_release_wrong_shell_is_noop():
    shell_id = tenant_lock.acquire("T1")
    assert tenant_lock.release("T1", "not-the-owner") is False
    # File still present.
    assert (tenant_lock.LOCK_DIR / "T1.lock").exists()
    # Real owner can still release.
    assert tenant_lock.release("T1", shell_id) is True


def test_release_right_shell_deletes_and_is_idempotent():
    shell_id = tenant_lock.acquire("T1")
    assert tenant_lock.release("T1", shell_id) is True
    assert not (tenant_lock.LOCK_DIR / "T1.lock").exists()
    # Second release is a harmless no-op.
    assert tenant_lock.release("T1", shell_id) is False


def test_release_after_release_allows_reacquire():
    s1 = tenant_lock.acquire("T1")
    tenant_lock.release("T1", s1)
    s2 = tenant_lock.acquire("T1", max_wait=0)
    assert s2 and s2 != s1


# ---------------------------------------------------------------------------
# force_unlock + status
# ---------------------------------------------------------------------------
def test_force_unlock_deletes():
    tenant_lock.acquire("T1")
    assert tenant_lock.force_unlock("T1") is True
    assert not (tenant_lock.LOCK_DIR / "T1.lock").exists()
    # Idempotent.
    assert tenant_lock.force_unlock("T1") is False


def test_status_reflects_holder_and_none():
    assert tenant_lock.status("T1") is None
    shell_id = tenant_lock.acquire("T1", integration_id="IntA")
    st = tenant_lock.status("T1")
    assert st["shell_id"] == shell_id
    tenant_lock.release("T1", shell_id)
    assert tenant_lock.status("T1") is None


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------
def test_cli_acquire_then_status_then_release(capsys):
    rc = tenant_lock.main(["acquire", "--tenant", "T1", "--integration-id", "IntA"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["status"] == "acquired"
    shell_id = out["shell_id"]

    rc = tenant_lock.main(["release", "--tenant", "T1", "--shell-id", shell_id])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["status"] == "released"


def test_cli_acquire_timeout_exit_2(capsys):
    tenant_lock.acquire("T1", integration_id="IntA")
    rc = tenant_lock.main(["acquire", "--tenant", "T1", "--max-wait", "0"])
    assert rc == 2
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["status"] == "timeout"
    assert out["holder"]["integration_id"] == "IntA"

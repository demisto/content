#!/usr/bin/env python3
"""tenant_lock — per-tenant filesystem lock for the ConnectUs param-parity pipeline.

Why this exists (design §2/§3)
------------------------------
``deploy.py`` is *whole-branch / whole-manifest*: deploying to tenant **X** clobbers
whatever was on X. Two AI shells deploying to the SAME tenant concurrently corrupt each
other's running instance mid-test. The indivisible critical section is::

    deploy(tenant) → create connector instance → run param-parity → teardown

While a shell owns that section on tenant X, no other shell may deploy to X. Shells on
*different* tenants run fully in parallel. The lock is therefore **per-tenant** (keyed by
the ICaaS / ``TENANT_IDS`` value) — NOT global, NOT per-integration.

Mechanism (design §3)
---------------------
* Lock dir ``connectus/runtime_demisto.params_parity/.locks/`` (git-ignored).
* Lock file ``<tenant_id>.lock`` created atomically with
  ``os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)`` — the OS guarantees only one
  creator wins the race.
* Payload JSON: ``{"shell_id", "pid", "integration_id", "acquired_at", "heartbeat_at"}``.
  ``shell_id`` is a fresh uuid4 hex per :func:`acquire`; it is returned so :func:`release`
  can verify ownership (a shell only deletes a lock it actually holds).
* The holder runs a background heartbeat thread that re-writes ``heartbeat_at`` every
  :data:`HEARTBEAT_INTERVAL` seconds. A lock whose ``heartbeat_at`` is older than
  :data:`TTL` (or whose ``pid`` is dead) is *stale* and may be reclaimed atomically — so a
  crashed/dead holder NEVER causes a timeout.
* ``acquire`` blocks internally (with stale/dead reclaim) up to :data:`ACQUIRE_MAX_WAIT`.
  Exhausting that bound raises :class:`TenantLockTimeout` carrying the holder dict — the
  SKILL (not the model, not this module) decides what to do next.

All waiting / retry / stale-reclaim logic lives HERE, not in the LLM. Held locks are
released on normal exit (``atexit``) and on SIGINT/SIGTERM.
"""

from __future__ import annotations

import argparse
import atexit
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from pathlib import Path

log = logging.getLogger("tenant_lock")

# ---------------------------------------------------------------------------
# Tunables (module constants — overridable by callers / tests)
# ---------------------------------------------------------------------------
TTL = 1200  # seconds: heartbeat older than this ⇒ stale ⇒ reclaimable
HEARTBEAT_INTERVAL = 30  # seconds between heartbeat re-writes by the holder
ACQUIRE_MAX_WAIT = 1800  # seconds acquire() blocks before giving up
POLL_INTERVAL = 5  # seconds between acquire retries when the lock is fresh+alive

# Lock dir lives next to this script regardless of CWD.
_SCRIPT_DIR = Path(__file__).resolve().parent
LOCK_DIR = _SCRIPT_DIR / ".locks"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class TenantLockError(RuntimeError):
    """Base error for tenant-lock operations."""


class TenantLockTimeout(TenantLockError):
    """Raised when acquire() cannot get the lock within max_wait.

    Carries the current ``holder`` dict (best-effort) so callers can report who
    is holding the lock and since when.
    """

    def __init__(self, message: str, holder: dict | None = None) -> None:
        super().__init__(message)
        self.holder = holder or {}


# ---------------------------------------------------------------------------
# Internal heartbeat bookkeeping
# ---------------------------------------------------------------------------
# Maps tenant_id -> (shell_id, threading.Event stop-flag, Thread). Used to stop
# heartbeats on release and to know which locks THIS process holds (for atexit).
_HEARTBEATS: dict[str, tuple[str, threading.Event, threading.Thread]] = {}
_HEARTBEATS_LOCK = threading.Lock()
_SIGNALS_INSTALLED = False


def _lock_path(tenant: str) -> Path:
    return LOCK_DIR / f"{tenant}.lock"


def _now() -> float:
    return time.time()


def _ensure_lock_dir() -> None:
    LOCK_DIR.mkdir(parents=True, exist_ok=True)


def _read_holder(tenant: str) -> dict | None:
    """Read+parse the lock payload, or None if absent/unreadable/corrupt."""
    path = _lock_path(tenant)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as e:  # pragma: no cover - filesystem edge
        log.debug("Could not read lock %s: %s", path, e)
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.debug("Corrupt lock payload in %s", path)
        return None
    return data if isinstance(data, dict) else None


def _pid_alive(pid: int | None) -> bool:
    """Return True if a process with ``pid`` exists (os.kill(pid, 0))."""
    if not pid or pid <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — treat as alive.
        return True
    except (OSError, ValueError):
        return False
    return True


def _is_stale(holder: dict) -> bool:
    """A holder is stale if its pid is dead OR its heartbeat is older than TTL."""
    if holder is None:
        return True
    if not _pid_alive(holder.get("pid")):
        return True
    hb = holder.get("heartbeat_at")
    try:
        hb_val = float(hb)
    except (TypeError, ValueError):
        return True
    return (_now() - hb_val) > TTL


def _build_payload(shell_id: str, integration_id: str | None) -> dict:
    ts = _now()
    return {
        "shell_id": shell_id,
        "pid": os.getpid(),
        "integration_id": integration_id,
        "acquired_at": ts,
        "heartbeat_at": ts,
    }


def _write_payload_to_fd(fd: int, payload: dict) -> None:
    os.write(fd, json.dumps(payload).encode("utf-8"))


def _try_atomic_create(tenant: str, payload: dict) -> bool:
    """Attempt the atomic O_CREAT|O_EXCL create. Return True iff THIS call won."""
    _ensure_lock_dir()
    path = _lock_path(tenant)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return False
    try:
        _write_payload_to_fd(fd, payload)
    finally:
        os.close(fd)
    return True


def _heartbeat_loop(tenant: str, shell_id: str, stop: threading.Event) -> None:
    """Re-write ``heartbeat_at`` every HEARTBEAT_INTERVAL while we own the lock."""
    while not stop.wait(HEARTBEAT_INTERVAL):
        holder = _read_holder(tenant)
        # Only touch the file if we still own it.
        if not holder or holder.get("shell_id") != shell_id:
            log.debug("Heartbeat for %s stopping: no longer owner", tenant)
            return
        holder["heartbeat_at"] = _now()
        try:
            # Best-effort rewrite (not atomic, but only the owner writes here).
            _lock_path(tenant).write_text(json.dumps(holder), encoding="utf-8")
        except OSError as e:  # pragma: no cover - filesystem edge
            log.debug("Heartbeat write failed for %s: %s", tenant, e)


def _start_heartbeat(tenant: str, shell_id: str) -> None:
    stop = threading.Event()
    thread = threading.Thread(
        target=_heartbeat_loop,
        args=(tenant, shell_id, stop),
        name=f"tenant-lock-heartbeat-{tenant}",
        daemon=True,
    )
    with _HEARTBEATS_LOCK:
        _HEARTBEATS[tenant] = (shell_id, stop, thread)
    thread.start()


def _stop_heartbeat(tenant: str) -> None:
    with _HEARTBEATS_LOCK:
        entry = _HEARTBEATS.pop(tenant, None)
    if entry:
        _, stop, thread = entry
        stop.set()
        if thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1)


def _install_signal_handlers() -> None:
    global _SIGNALS_INSTALLED
    if _SIGNALS_INSTALLED:
        return
    atexit.register(_release_all_held)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_release_handler)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            # signal() only works in the main thread; safe to skip elsewhere.
            pass
    _SIGNALS_INSTALLED = True


def _signal_release_handler(signum, frame):  # pragma: no cover - signal path
    _release_all_held()
    # Restore default and re-raise so the process actually exits.
    try:
        signal.signal(signum, signal.SIG_DFL)
    except (ValueError, OSError):
        pass
    os.kill(os.getpid(), signum)


def _release_all_held() -> None:
    """Release every lock THIS process still holds. Used by atexit/signals."""
    with _HEARTBEATS_LOCK:
        items = list(_HEARTBEATS.items())
    for tenant, (shell_id, _stop, _thread) in items:
        try:
            release(tenant, shell_id)
        except Exception as e:  # pragma: no cover - best-effort cleanup
            log.debug("atexit release failed for %s: %s", tenant, e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def acquire(
    tenant: str,
    *,
    integration_id: str | None = None,
    max_wait: int = ACQUIRE_MAX_WAIT,
    force: bool = False,
) -> str:
    """Acquire the per-tenant lock, blocking internally until success or timeout.

    Returns the ``shell_id`` (uuid4 hex) of the acquired lock — pass it to
    :func:`release` to prove ownership.

    Behavior:
      * atomic create succeeds  → write payload, start heartbeat, return shell_id.
      * exists & (stale OR force) → reclaim atomically (delete + recreate), return.
      * exists & fresh & alive    → sleep POLL_INTERVAL, retry, until ``max_wait``.
      * ``max_wait`` exhausted    → raise :class:`TenantLockTimeout` (holder attached).
    """
    if not tenant:
        raise TenantLockError("tenant must be a non-empty string")

    _install_signal_handlers()
    shell_id = uuid.uuid4().hex
    payload = _build_payload(shell_id, integration_id)
    deadline = _now() + max(0, max_wait)

    first = True
    while True:
        # 1. Fast path: atomic create.
        if _try_atomic_create(tenant, payload):
            _start_heartbeat(tenant, shell_id)
            log.info("Acquired tenant lock %s (shell=%s)", tenant, shell_id)
            return shell_id

        # 2. Lock exists — inspect the holder.
        holder = _read_holder(tenant)
        if force or _is_stale(holder):
            reason = "force" if force else "stale"
            log.warning(
                "Reclaiming %s tenant lock %s (holder=%s)",
                reason, tenant, (holder or {}).get("shell_id"),
            )
            _reclaim(tenant)
            # Loop again to re-attempt the atomic create cleanly.
            force = False  # only force the first reclaim
            continue

        # 3. Fresh & alive — wait and retry until the deadline.
        if first:
            log.info(
                "Tenant %s held by shell=%s (integration=%s); waiting up to %ss...",
                tenant, holder.get("shell_id"), holder.get("integration_id"), max_wait,
            )
            first = False

        if _now() >= deadline:
            raise TenantLockTimeout(
                f"Could not acquire tenant lock {tenant!r} within {max_wait}s; "
                f"held by shell={holder.get('shell_id')} "
                f"(integration={holder.get('integration_id')}, pid={holder.get('pid')}).",
                holder=holder,
            )
        time.sleep(POLL_INTERVAL)


def _reclaim(tenant: str) -> None:
    """Unconditionally remove a (stale/forced) lock so a clean create can follow."""
    try:
        _lock_path(tenant).unlink()
    except FileNotFoundError:
        pass
    except OSError as e:  # pragma: no cover - filesystem edge
        log.debug("Reclaim unlink failed for %s: %s", tenant, e)


def release(tenant: str, shell_id: str) -> bool:
    """Release the lock IFF ``shell_id`` matches the on-disk owner.

    Stops the heartbeat thread and deletes the lock file. Idempotent: returns
    False (no-op) if the lock is absent or owned by a different shell.
    """
    holder = _read_holder(tenant)
    # Always stop our own heartbeat for this tenant regardless.
    if holder is None:
        _stop_heartbeat(tenant)
        return False
    if holder.get("shell_id") != shell_id:
        log.debug(
            "release(%s) no-op: shell_id mismatch (ours=%s, theirs=%s)",
            tenant, shell_id, holder.get("shell_id"),
        )
        return False
    _stop_heartbeat(tenant)
    try:
        _lock_path(tenant).unlink()
    except FileNotFoundError:
        return False
    log.info("Released tenant lock %s (shell=%s)", tenant, shell_id)
    return True


def force_unlock(tenant: str) -> bool:
    """Unconditionally delete the tenant lock (for a known-dead holder).

    Returns True if a file was removed, False if there was none.
    """
    _stop_heartbeat(tenant)
    try:
        _lock_path(tenant).unlink()
    except FileNotFoundError:
        return False
    log.warning("Force-unlocked tenant lock %s", tenant)
    return True


def status(tenant: str) -> dict | None:
    """Return the current holder dict (or None if unlocked)."""
    return _read_holder(tenant)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tenant_lock",
        description="Per-tenant filesystem lock for the ConnectUs param-parity pipeline.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("acquire", help="Acquire the tenant lock (blocks internally).")
    a.add_argument("--tenant", required=True)
    a.add_argument("--integration-id", default=None)
    a.add_argument("--max-wait", type=int, default=ACQUIRE_MAX_WAIT)
    a.add_argument("--force", action="store_true", help="Reclaim even a fresh lock.")

    r = sub.add_parser("release", help="Release a lock you own (by shell-id).")
    r.add_argument("--tenant", required=True)
    r.add_argument("--shell-id", required=True)

    f = sub.add_parser("force-unlock", help="Unconditionally delete the tenant lock.")
    f.add_argument("--tenant", required=True)

    s = sub.add_parser("status", help="Print the current holder (if any).")
    s.add_argument("--tenant", required=True)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "acquire":
        try:
            shell_id = acquire(
                args.tenant,
                integration_id=args.integration_id,
                max_wait=args.max_wait,
                force=args.force,
            )
        except TenantLockTimeout as e:
            print(str(e), file=sys.stderr)
            print(json.dumps({"status": "timeout", "holder": e.holder}))
            return 2
        print(json.dumps({"status": "acquired", "tenant": args.tenant, "shell_id": shell_id}))
        return 0

    if args.command == "release":
        ok = release(args.tenant, args.shell_id)
        print(json.dumps({"status": "released" if ok else "noop", "tenant": args.tenant}))
        return 0

    if args.command == "force-unlock":
        ok = force_unlock(args.tenant)
        print(json.dumps({"status": "unlocked" if ok else "noop", "tenant": args.tenant}))
        return 0

    if args.command == "status":
        holder = status(args.tenant)
        print(json.dumps({"tenant": args.tenant, "holder": holder}))
        return 0

    return 0  # pragma: no cover - argparse enforces a subcommand


if __name__ == "__main__":
    sys.exit(main())

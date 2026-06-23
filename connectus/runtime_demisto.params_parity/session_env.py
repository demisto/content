"""session_env — the single environment authority for the param-parity step.

This module centralizes EVERYTHING about the runtime param-parity *session
environment* so that no other runtime file improvises it. It owns:

* The **session descriptor** (``.session/parity_session.json``) — the durable
  record of the prepared environment (tenant, UCP port, the long-lived
  port-forward PID, resolved repo paths, the authed gcloud account).
* The **idempotent, descriptor-tracked port-forward** — start it once, reuse it
  if it is already alive, and NEVER create a duplicate (a second
  ``kubectl port-forward`` on the same local port would ``bind: address already
  in use`` or yield a confusing half-tunnel). A dead/stale forward is killed and
  re-established cleanly.
* Cheap **liveness probes** — :func:`port_is_live` (TCP) and
  :func:`gcloud_auth_ok` (account set) — used both by the human-run setup and by
  the per-integration agent path.
* The **session contract** for the agent path: :func:`assert_session_live`,
  which AUTO-REVIVES a dead port-forward (Option C — the tunnel restart is
  non-privileged and does not write ``~/.config``) but HARD-STOPS with a clear
  human-actionable message when gcloud auth has expired (browser login is
  human-only) or when the session was never initialized.

Design reference: ``SESSION_ENV_ARCHITECTURE.md`` (FINAL).

The privileged ``gcloud container clusters get-credentials`` step is NOT done
here on the agent path — it is performed once by the human-run
``session_setup.py`` (in a normal terminal where ``~/.config/gcloud`` is
writable). This module's port-forward start assumes credentials already exist;
that assumption is what makes the agent-side auto-revive safe.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

# Make the shared connectus env loader importable (connectus/ is not a package).
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import find_repo_root, load_env  # noqa: E402

load_env()

log = logging.getLogger("session_env")

# ============================================================================
# Paths & GKE/UCP defaults
# ============================================================================

#: This script's directory — all durable session state lives under it (stable,
#: gitignored, never /tmp which the idex sandbox denies, never the connectors repo).
_SCRIPT_DIR = Path(__file__).resolve().parent

SESSION_DIR = _SCRIPT_DIR / ".session"
DESCRIPTOR_PATH = SESSION_DIR / "parity_session.json"

DEFAULT_UCP_PORT = 8080
DEFAULT_GKE_ZONE = "us-central1-f"
DEFAULT_K8S_NAMESPACE = "xdr-st"

# Status values returned by ensure_session().
STATUS_LIVE = "LIVE"                    # session healthy, nothing to do
STATUS_REVIVED = "REVIVED"             # port-forward was dead, auto-revived; continue
STATUS_AUTH_EXPIRED = "AUTH_EXPIRED"  # gcloud auth gone — human must re-auth + re-run setup
STATUS_NOT_INITIALIZED = "NOT_INITIALIZED"  # no descriptor — human must run session_setup.py


class SessionNotReady(RuntimeError):
    """Raised when the session cannot be made live without human action.

    Carries a ``status`` (``AUTH_EXPIRED`` / ``NOT_INITIALIZED``) and a
    human-actionable message. The agent surfaces this as exit 11 (BLOCKED).
    """

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


# ============================================================================
# GKE naming (single source of truth — was duplicated in ucp_capture)
# ============================================================================


def gke_project(tenant_id: str) -> str:
    return f"qa2-test-{tenant_id}"


def gke_cluster(tenant_id: str) -> str:
    return f"cluster-{tenant_id}"


def k8s_app_label(tenant_id: str) -> str:
    return f"xdr-st-{tenant_id}-unified-connector-shell"


# ============================================================================
# Session descriptor
# ============================================================================


@dataclasses.dataclass
class SessionDescriptor:
    """The durable record of a prepared param-parity session."""

    tenant_id: str
    ucp_port: int
    port_forward_pid: Optional[int]
    pod_name: Optional[str]
    content_repo: str
    connectus_repo: str
    created_ts: float
    gcloud_account: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SessionDescriptor":
        # Tolerant of unknown keys; require the known field set.
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in fields})


def write_descriptor(desc: SessionDescriptor) -> Path:
    """Atomically persist the session descriptor to :data:`DESCRIPTOR_PATH`."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DESCRIPTOR_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(desc.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp, DESCRIPTOR_PATH)
    log.info("Session descriptor written: %s", DESCRIPTOR_PATH)
    return DESCRIPTOR_PATH


def load_descriptor() -> Optional[SessionDescriptor]:
    """Load the session descriptor, or ``None`` if missing/unreadable."""
    if not DESCRIPTOR_PATH.exists():
        return None
    try:
        return SessionDescriptor.from_dict(json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8")))
    except Exception as e:  # pragma: no cover - defensive
        log.warning("Could not parse session descriptor %s: %s", DESCRIPTOR_PATH, e)
        return None


def clear_descriptor() -> None:
    """Remove the descriptor file (used by teardown)."""
    try:
        DESCRIPTOR_PATH.unlink()
    except FileNotFoundError:
        pass


# ============================================================================
# Liveness probes
# ============================================================================


def port_is_live(port: int, timeout: float = 1.0) -> bool:
    """Return True iff ``localhost:port`` accepts a TCP connection right now.

    One-shot, fast (no poll loop) — used for the per-run liveness check.
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(port: int, timeout: int = 30) -> bool:
    """Block until ``localhost:port`` is reachable or ``timeout`` elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_is_live(port):
            return True
        time.sleep(0.5)
    return False


def _pid_alive(pid: Optional[int]) -> bool:
    """Return True iff ``pid`` is a live process (signal 0 probe)."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — treat as alive.
        return True
    return True


def gcloud_auth_ok() -> bool:
    """Return True iff gcloud reports an active account.

    This is the cheap auth-liveness signal. The short-lived GKE access token is
    auto-refreshed by gke-gcloud-auth-plugin from the stored refresh token on
    each kubectl call, so ordinary ~1h token expiry self-heals; this check
    surfaces only the dead-refresh-token / not-logged-in case.
    """
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as e:  # pragma: no cover - defensive
        log.warning("gcloud auth check raised: %s", e)
        return False
    account = (res.stdout or "").strip()
    return res.returncode == 0 and bool(account) and account.lower() != "(unset)"


def current_gcloud_account() -> str:
    """Best-effort: the active gcloud account string (empty if none)."""
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return ""
    account = (res.stdout or "").strip()
    return "" if account.lower() == "(unset)" else account


# ============================================================================
# Port-forward — idempotent, descriptor-tracked
# ============================================================================


def _find_shell_pod(tenant_id: str, k8s_namespace: str = DEFAULT_K8S_NAMESPACE) -> str:
    """Return the UCP shell pod name for ``tenant_id`` (raises on failure).

    Assumes GKE credentials already exist (human setup ran get-credentials).
    Surfaces the israel-gw VPN hint on a control-plane timeout.
    """
    pod_result = subprocess.run(
        [
            "kubectl", "get", "pod",
            "--namespace", k8s_namespace,
            f"--selector=app={k8s_app_label(tenant_id)}",
            "--output", "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
    )
    if pod_result.returncode != 0 or not pod_result.stdout.strip():
        stderr = pod_result.stderr or ""
        low = stderr.lower()
        hint = ""
        if ("i/o timeout" in low or "unable to connect to the server" in low
                or "couldn't get current server api group list" in low):
            hint = ("\n\nHINT: kubectl could not reach the GKE cluster API "
                    "(control-plane network timeout). Connect to the 'israel-gw' "
                    "VPN gateway and re-run session_setup.py.")
        raise RuntimeError("Failed to find UCP shell pod:\n{}{}".format(stderr, hint))
    return pod_result.stdout.strip()


def _spawn_port_forward(pod_name: str, port: int,
                        k8s_namespace: str = DEFAULT_K8S_NAMESPACE) -> int:
    """Spawn a DETACHED ``kubectl port-forward`` and return its PID.

    Detached via ``start_new_session=True`` so the tunnel survives across the
    many separate agent commands of an unattended batch (it is NOT tied to the
    lifetime of any single per-integration process).
    """
    proc = subprocess.Popen(
        [
            "kubectl", "port-forward",
            "--namespace", k8s_namespace,
            pod_name,
            f"{port}:{port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc.pid


def kill_port_forward(pid: Optional[int]) -> None:
    """Best-effort terminate a port-forward process group by PID."""
    if not _pid_alive(pid):
        return
    try:
        # Kill the whole session group (start_new_session made pid the leader).
        os.killpg(os.getpgid(pid), signal.SIGTERM)  # type: ignore[arg-type]
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)  # type: ignore[arg-type]
        except Exception:
            pass
    # Give it a moment, then SIGKILL if still alive.
    for _ in range(10):
        if not _pid_alive(pid):
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)  # type: ignore[arg-type]
    except Exception:
        pass


def ensure_port_forward(
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
    *,
    existing_pid: Optional[int] = None,
    k8s_namespace: str = DEFAULT_K8S_NAMESPACE,
) -> tuple[int, str]:
    """Idempotently ensure a live port-forward; return ``(pid, pod_name)``.

    REUSE-IF-LIVE: if ``existing_pid`` is alive AND the port is live, this is a
    no-op (returns the existing pid, pod_name unknown→"") — it NEVER starts a
    duplicate forward on the same port.

    Otherwise: kill any stale ``existing_pid``, locate the shell pod, spawn a new
    detached forward, wait for the port, and return the new pid + pod name.

    Assumes GKE credentials already exist (raises via :func:`_find_shell_pod`
    otherwise). Does NOT run ``get-credentials`` — that is the human setup's job.
    """
    if _pid_alive(existing_pid) and port_is_live(port):
        log.info("Port-forward already live (pid=%s, localhost:%d) — reusing.", existing_pid, port)
        return existing_pid, ""  # caller keeps the descriptor's pod_name

    # Stale/dead — clean up before re-establishing (prevents duplicate binds).
    if existing_pid:
        log.info("Existing port-forward pid=%s is stale/dead — terminating before restart.", existing_pid)
        kill_port_forward(existing_pid)

    pod_name = _find_shell_pod(tenant_id, k8s_namespace=k8s_namespace)
    log.info("Starting detached port-forward (localhost:%d → pod %s)...", port, pod_name)
    pid = _spawn_port_forward(pod_name, port, k8s_namespace=k8s_namespace)
    if not wait_for_port(port):
        kill_port_forward(pid)
        raise RuntimeError(
            "Port-forward did not become ready within 30s (pod={}, port={}).".format(pod_name, port)
        )
    log.info("Port-forward ready on localhost:%d (pid=%d)", port, pid)
    return pid, pod_name


# ============================================================================
# The session contract
# ============================================================================


def ensure_session() -> tuple[str, Optional[SessionDescriptor]]:
    """Classify + (where safe) self-heal the session for the agent path.

    Returns ``(status, descriptor)``:

    * ``LIVE``            — descriptor present, port live, auth ok → use as-is.
    * ``REVIVED``         — port-forward was dead but auth ok → auto-revived the
                            tunnel (Option C), descriptor updated → continue.
    * ``AUTH_EXPIRED``    — gcloud auth gone → human must re-auth + re-run setup.
    * ``NOT_INITIALIZED`` — no descriptor → human must run session_setup.py.

    Auto-revive (the ``REVIVED`` path) restarts ONLY the non-privileged tunnel,
    reusing the credentials the human already established; it never runs
    ``get-credentials`` and never writes ``~/.config``.
    """
    desc = load_descriptor()
    if desc is None:
        return STATUS_NOT_INITIALIZED, None

    # Auth is the human-only dependency — check it first.
    if not gcloud_auth_ok():
        return STATUS_AUTH_EXPIRED, desc

    if _pid_alive(desc.port_forward_pid) and port_is_live(desc.ucp_port):
        return STATUS_LIVE, desc

    # Port-forward died but auth is fine → auto-revive the tunnel.
    log.info("Session port-forward not live — auto-reviving (auth OK).")
    pid, pod_name = ensure_port_forward(
        desc.tenant_id, desc.ucp_port, existing_pid=desc.port_forward_pid
    )
    desc.port_forward_pid = pid
    if pod_name:
        desc.pod_name = pod_name
    write_descriptor(desc)
    return STATUS_REVIVED, desc


def assert_session_live() -> SessionDescriptor:
    """Return a live :class:`SessionDescriptor`, auto-reviving a dead tunnel.

    Raises :class:`SessionNotReady` (→ agent surfaces exit 11) when the session
    needs human action: gcloud auth expired, or the session was never set up.
    """
    status, desc = ensure_session()
    if status in (STATUS_LIVE, STATUS_REVIVED):
        assert desc is not None
        return desc
    if status == STATUS_AUTH_EXPIRED:
        raise SessionNotReady(
            STATUS_AUTH_EXPIRED,
            "gcloud auth has expired. In your terminal run `gcloud auth login`, "
            "then re-run `python3 connectus/runtime_demisto.params_parity/session_setup.py`, "
            "then resume.",
        )
    raise SessionNotReady(
        STATUS_NOT_INITIALIZED,
        "No param-parity session is set up. On the israel-gw VPN, run "
        "`python3 connectus/runtime_demisto.params_parity/session_setup.py` in your "
        "terminal, then resume.",
    )


__all__ = [
    "SESSION_DIR",
    "DESCRIPTOR_PATH",
    "DEFAULT_UCP_PORT",
    "DEFAULT_GKE_ZONE",
    "DEFAULT_K8S_NAMESPACE",
    "STATUS_LIVE",
    "STATUS_REVIVED",
    "STATUS_AUTH_EXPIRED",
    "STATUS_NOT_INITIALIZED",
    "SessionNotReady",
    "SessionDescriptor",
    "gke_project",
    "gke_cluster",
    "k8s_app_label",
    "write_descriptor",
    "load_descriptor",
    "clear_descriptor",
    "port_is_live",
    "wait_for_port",
    "gcloud_auth_ok",
    "current_gcloud_account",
    "kill_port_forward",
    "ensure_port_forward",
    "ensure_session",
    "assert_session_live",
]

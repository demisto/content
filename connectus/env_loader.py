"""Single, unified environment-variable loading entry point for the UCP repo.

This module is the **one** place that loads the canonical root ``.env`` file
for all ConnectUs / UCP tooling (param-parity, generate-manifest, and the
validate gates). The root ``.env`` (created from the root ``.env.example``)
is the single source of truth for configuration such as
``INTEGRATION_YML_PATH``, ``CONNECTUS_REPO_DIR``, deployment credentials, etc.

All tooling should use::

    from env_loader import load_env
    load_env()

instead of calling :func:`dotenv.load_dotenv` directly. A bare
``load_dotenv()`` walks up from the current working directory and is therefore
unreliable depending on where a script happens to be invoked from. This loader
instead resolves the repo root relative to ``__file__`` and loads
``<repo_root>/.env`` via an explicit path, so the same ``.env`` is used no
matter the CWD.

The dependency on ``python-dotenv`` is import-safe: if it is not installed,
:func:`load_env` degrades gracefully (the process environment may already be
populated via exported variables) rather than crashing.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Marker files that identify the repository root when walking up the tree.
_ROOT_MARKERS: tuple[str, ...] = ("pyproject.toml", ".git")

# Module-level guard so repeated imports / calls do not reload the .env file
# unless the caller explicitly requests an override.
_loaded: bool = False


def find_repo_root(start: Path | None = None) -> Path:
    """Return the repository root by walking up from ``start``.

    Walks up the directory tree from ``start`` (defaulting to this file's
    location) until a directory containing a known marker
    (:data:`_ROOT_MARKERS`) is found. Falls back to this file's parent's
    parent if no marker is located, so the function never raises.
    """
    origin = (start or Path(__file__)).resolve()
    for candidate in (origin, *origin.parents):
        if any((candidate / marker).exists() for marker in _ROOT_MARKERS):
            return candidate
    # Fallback: connectus/env_loader.py -> connectus -> repo root.
    return Path(__file__).resolve().parent.parent


def _augment_no_proxy() -> None:
    """Ensure the XSOAR/tenant host bypasses any injected HTTP(S) proxy.

    WHY THIS EXISTS
    ---------------
    When the parity pipeline runs under the idex CLI / VS Code, that process
    injects ``HTTPS_PROXY`` / ``HTTP_PROXY`` into the agent subprocess
    environment. A corporate proxy then DENIES the HTTPS ``CONNECT`` tunnel to
    the XSOAR tenant host, producing::

        ProxyError('Unable to connect to proxy',
                   OSError('Tunnel connection failed: 403 Forbidden'))

    on calls like ``GET {DEMISTO_BASE_URL}/xsoar/settings/integration/search``.
    A direct (no-proxy) request to the same host returns 200/303, proving the
    host is reachable and the proxy is the *only* problem.

    The fix is deliberately narrow: we ONLY add bypass entries to
    ``NO_PROXY`` / ``no_proxy`` (we never unset the proxy vars or disable
    proxies globally), so any other genuinely-proxied traffic is unaffected.
    The XSOAR-side client is the official ``demisto_client`` (urllib3-based)
    which honors these env vars automatically, as do ``requests`` and
    ``urllib`` — so setting them here propagates to all the real HTTP calls.

    Behavior:
      * Parse the hostname from ``DEMISTO_BASE_URL`` and add it, the
        ``api-``-prefixed variant of that host, plus the
        ``.paloaltonetworks.com`` suffix (covers every PANW tenant; requests
        matches NO_PROXY by hostname suffix).
      * Always include ``localhost`` / ``127.0.0.1`` so the UCP port-forward
        is never proxied either.
      * Existing ``NO_PROXY`` / ``no_proxy`` values are PRESERVED first, then
        new entries are appended; duplicates are removed (order-preserving).
      * Idempotent: calling twice does not duplicate entries.
      * Defensive: a blank/missing/host-less ``DEMISTO_BASE_URL`` never crashes;
        ``localhost,127.0.0.1`` are still ensured.

    IMPORTANT — this is DEFENSE-IN-DEPTH ONLY
    -----------------------------------------
    The official ``demisto_client`` SDK does **not** consult ``NO_PROXY`` at
    all: ``demisto_client.configure()`` reads ``HTTPS_PROXY``/``HTTP_PROXY``
    directly via ``os.getenv`` and hands the proxy URL to a raw
    ``urllib3.ProxyManager`` (see ``demisto_api/rest.py``), which has no
    no-proxy bypass concept. So these entries do NOT fix the XSOAR SDK path —
    that is handled separately in ``xsoar_capture.create_client()`` by clearing
    the SDK's proxy. These entries only help ``requests``/``urllib``-based
    callers (e.g. the UCP port-forward) that *do* honor ``NO_PROXY``.

    Note the SDK also rewrites the tenant host to an ``api-``-prefixed host for
    XSIAM/XSOAR-8 API calls, which is why we add the ``api-<host>`` variant too.
    """
    # Bypass entries we always want present, even with no/blank base URL.
    bypass: list[str] = []

    base_url = (os.environ.get("DEMISTO_BASE_URL") or "").strip()
    if base_url:
        try:
            host = urlsplit(base_url).hostname
        except ValueError:
            host = None
        if host:
            bypass.append(host)
            # The SDK rewrites the tenant host to ``api-<host>`` for XSIAM /
            # XSOAR 8+ API requests, so the bare host alone would not match.
            bypass.append(f"api-{host}")
            # Suffix that covers all PANW tenants regardless of subdomain.
            bypass.append(".paloaltonetworks.com")

    # Localhost variants — keeps the UCP 127.0.0.1 port-forward un-proxied.
    bypass.extend(("localhost", "127.0.0.1"))

    # Merge into BOTH case variants (libraries differ on which they read),
    # preserving any pre-existing entries first and de-duplicating.
    for var in ("NO_PROXY", "no_proxy"):
        existing = [
            part.strip()
            for part in (os.environ.get(var) or "").split(",")
            if part.strip()
        ]
        merged: list[str] = []
        for entry in (*existing, *bypass):
            if entry not in merged:
                merged.append(entry)
        os.environ[var] = ",".join(merged)


def load_env(override: bool = False) -> Path:
    """Load the canonical root ``.env`` file and return its resolved path.

    This is the single unified env-loading entry point for the UCP repo.

    Args:
        override: When ``True``, reload the ``.env`` even if it was already
            loaded, and let values in the file override existing ones.

    Returns:
        The resolved path to ``<repo_root>/.env`` (whether or not it exists).
    """
    global _loaded
    env_path = find_repo_root() / ".env"

    if _loaded and not override:
        # Already loaded — but still (idempotently) reassert the proxy bypass
        # in case DEMISTO_BASE_URL or NO_PROXY changed since the first load.
        _augment_no_proxy()
        return env_path

    try:
        from dotenv import load_dotenv
    except ImportError:
        print(
            "env_loader: python-dotenv is not installed; relying on the "
            "already-exported process environment.",
            file=sys.stderr,
        )
        _loaded = True
        # Even without dotenv the process env may already carry
        # DEMISTO_BASE_URL, so still ensure the proxy bypass is applied.
        _augment_no_proxy()
        return env_path

    if not env_path.exists():
        logger.debug("env_loader: no .env file found at %s", env_path)

    load_dotenv(dotenv_path=str(env_path), override=override)
    _loaded = True
    # AFTER .env is loaded, ensure the XSOAR/tenant host bypasses any injected
    # proxy (idex injects HTTPS_PROXY which 403s the tenant CONNECT tunnel).
    _augment_no_proxy()
    return env_path

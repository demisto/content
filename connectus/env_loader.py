"""Single, unified environment-variable loading entry point for the UCP repo.
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
import sys
from pathlib import Path

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
        return env_path

    if not env_path.exists():
        logger.debug("env_loader: no .env file found at %s", env_path)

    load_dotenv(dotenv_path=str(env_path), override=override)
    _loaded = True
    return env_path

"""Custom exceptions for the workflow_state package."""
from __future__ import annotations


class WorkflowError(Exception):
    """User-facing workflow violation. Caller prints `.message` and exits 1.

    Preserved verbatim from the legacy ``workflow_state.py`` module so that
    external consumers (notably ``connectus/check_command_params.py``)
    that catch this exception continue to work after the refactor.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigLoadError(Exception):
    """Raised by the YAML config loader when the config is missing,
    malformed, or fails schema validation.

    Mirrors :class:`auth_config_parser.AuthConfigParseError`: collects
    every individual problem in ``.errors`` so the caller can see all of
    them in one pass instead of fixing them one at a time.

    Attributes:
        message: Human-readable summary (also the ``str(exc)`` value).
        errors: List of individual error strings (>=1).
    """

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or [message]

"""Custom exceptions for the auth_config_parser package."""
from __future__ import annotations


class AuthConfigParseError(Exception):
    """Raised by parser functions when input is structurally invalid.

    Attributes:
        message: Human-readable description of the parse failure.
        errors: List of individual error strings (may contain >1 for
            multi-error reporting).

    Examples:
        >>> raise AuthConfigParseError("config expression is empty")
        Traceback (most recent call last):
            ...
        auth_config_parser.exceptions.AuthConfigParseError: config expression is empty

        >>> raise AuthConfigParseError(
        ...     "multiple errors",
        ...     errors=["error 1", "error 2"],
        ... )
        Traceback (most recent call last):
            ...
        auth_config_parser.exceptions.AuthConfigParseError: multiple errors
    """

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or [message]


class AuthConfigValidationError(Exception):
    """Raised when validation of auth config data fails.

    Unlike :class:`AuthConfigParseError`, this is used for semantic
    validation failures (e.g. cross-referencing errors) rather than
    structural parse failures.

    Attributes:
        message: Human-readable description of the validation failure.
        errors: List of individual error strings.
    """

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or [message]

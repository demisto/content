"""auth_config_parser — Standalone Auth Details parser package.

Extracts and formalizes the Auth Details parser previously embedded
in ``workflow_state.py``. Provides typed data models, pure parsing
functions, validation, and utility helpers.

The 2026-05 schema simplification removed the ``config`` expression
field. The relationship between profiles is implicit:

- 0 entries in ``auth_types`` → integration requires no authentication.
- 1 entry → the single profile, always selected.
- 2+ entries → exclusive-OR; the user picks exactly one profile.

Usage::

    from auth_config_parser import parse_auth_details, AuthDetails
    from auth_config_parser import validate_auth_details, auth_param_ids
"""
from __future__ import annotations

from auth_config_parser.exceptions import (
    AuthConfigParseError,
)
from auth_config_parser.parser import (
    parse_auth_details,
)
from auth_config_parser.types import (
    AuthDetails,
    AuthEntry,
    AuthType,
)
from auth_config_parser.utils import (
    auth_param_ids,
    auth_param_ids_with_sources,
    project_xsoar_param_to_yml_id,
)
from auth_config_parser.validator import (
    validate_auth_details,
)

__all__ = [
    # Exceptions
    "AuthConfigParseError",
    # Types
    "AuthDetails",
    "AuthEntry",
    "AuthType",
    # Parsing
    "parse_auth_details",
    # Validation
    "validate_auth_details",
    # Utilities
    "auth_param_ids",
    "auth_param_ids_with_sources",
    "project_xsoar_param_to_yml_id",
]

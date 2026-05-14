"""auth_config_parser — Standalone Auth Details Config parser package.

Extracts and formalizes the Auth Details Config parser previously
embedded in ``workflow_state.py``. Provides typed data models,
pure parsing functions, validation, and utility helpers.

Usage::

    from auth_config_parser import parse_config, parse_auth_details, AuthDetails
    from auth_config_parser import validate_auth_details, auth_param_ids
"""
from __future__ import annotations

from auth_config_parser.exceptions import (
    AuthConfigParseError,
    AuthConfigValidationError,
)
from auth_config_parser.parser import (
    parse_auth_details,
    parse_config,
)
from auth_config_parser.types import (
    AuthDetails,
    AuthEntry,
    AuthType,
    ClauseOperator,
    ConfigClause,
    ConfigExpression,
)
from auth_config_parser.utils import (
    auth_param_ids,
    auth_param_ids_with_sources,
    project_xsoar_param_to_yml_id,
)
from auth_config_parser.validator import (
    validate_auth_details,
    validate_config,
)

__all__ = [
    # Types
    "AuthConfigParseError",
    "AuthConfigValidationError",
    "AuthDetails",
    "AuthEntry",
    "AuthType",
    "ClauseOperator",
    "ConfigClause",
    "ConfigExpression",
    # Parsing
    "parse_auth_details",
    "parse_config",
    # Validation
    "validate_auth_details",
    "validate_config",
    # Utilities
    "auth_param_ids",
    "auth_param_ids_with_sources",
    "project_xsoar_param_to_yml_id",
]

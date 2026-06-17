"""Data model types for the auth_config_parser package.

All public types live here. Pure Python, no external dependencies.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class AuthType(str, enum.Enum):
    """The 4 valid auth-type enum values for Auth Details entries.

    Inherits from ``str`` so that ``AuthType("APIKey")`` construction
    from JSON values works naturally and ``entry.type.value`` returns
    the string for serialization.

    Each value maps onto one of the canonical UCP authentication
    profile types — see
    ``connectus/connectus-migration-SKILL.md`` §1.2.6
    "Authentication Profile Types — Fields Reference" for the per-
    profile field shapes:

    - ``APIKey`` → ``api_key`` profile
      (field: ``api_key``; single static secret only).
    - ``Plain`` → ``plain`` profile
      (fields: ``username``, ``password``).
    - ``Passthrough`` → no canonical UCP profile shape; catch-all for
      OAuth2 client-credentials and JWT-bearer flows, Authorization
      Code (browser flow), Device Code, ROPC, Managed Identity, mTLS,
      multi-secret packages (Datadog 2-key, AWS SigV4, Akamai
      EdgeGrid, GitHub App, …), and custom signing.
      When in doubt, prefer ``Passthrough``.
    - ``NoneRequired`` → no profile; used when the integration has
      no authentication at all.

    Examples:
        >>> AuthType("APIKey")
        <AuthType.APIKey: 'APIKey'>
        >>> AuthType.APIKey.value
        'APIKey'
        >>> AuthType("APIKey") == "APIKey"
        True
        >>> AuthType("Passthrough")
        <AuthType.Passthrough: 'Passthrough'>
    """

    APIKey = "APIKey"
    Plain = "Plain"
    Passthrough = "Passthrough"
    NoneRequired = "NoneRequired"


@dataclass(frozen=True)
class AuthEntry:
    """One entry in auth_types[]: a single UCP connection type.

    Attributes:
        type: The auth-type enum value.
        name: Free-form logical id (unique within the row).
        xsoar_param_map: Mapping from XSOAR field path (bare id or
            dotted form like ``"credentials.identifier"``) to the
            role that secret plays inside the ConnectUs envelope
            for this connection. Required and non-empty for every
            ``AuthEntry``, including entries with
            ``interpolated=True``. The allowed role values are
            constrained per ``type`` — see the table in
            ``connectus/column-schemas.md`` ("Auth Details" §
            "type → allowed role values"):

            - ``APIKey`` → values must be ``"key"``.
            - ``Plain`` → values must be ``"username"`` or ``"password"``.
            - ``Passthrough`` → any non-empty string
              (enum deliberately undefined for now).
            - ``NoneRequired`` → does not appear in ``auth_types[]``.

        interpolated: When True, the value is templated at runtime
            rather than supplied by the user. Defaults to False.
        verify_connection_skip: True when this auth profile's
            ``test-module`` path manually raises an exception
            (e.g. OAuth Authorization Code / Device Code flows
            where the user must first call an out-of-band command
            like ``!auth-start`` before the connection-test button
            can succeed). Defaults to False — the connection-test
            button can exercise the auth normally. See
            ``.roo/skills/connectus-migration/SKILL.md`` §A.5
            (per-profile skip rule) for the classification
            procedure. Per-profile: a multi-profile (exclusive-OR)
            integration may set it on one profile and leave it
            default on another.

    Examples:
        >>> entry = AuthEntry(
        ...     type=AuthType.APIKey,
        ...     name="credentials",
        ...     xsoar_param_map={"credentials.password": "key"},
        ... )
        >>> entry.type
        <AuthType.APIKey: 'APIKey'>
        >>> entry.interpolated
        False
        >>> entry.verify_connection_skip
        False
        >>> entry.xsoar_param_map
        {'credentials.password': 'key'}
    """

    type: AuthType
    name: str
    xsoar_param_map: dict[str, str]
    interpolated: bool = False
    verify_connection_skip: bool = False


@dataclass(frozen=True)
class AuthDetails:
    """Fully parsed Auth Details JSON object.

    Each entry in ``auth_types`` is one profile = one mutually-
    exclusive way to authenticate the integration. The relationship
    between profiles is implicit:

    - ``len(auth_types) == 0`` → integration requires no authentication.
    - ``len(auth_types) == 1`` → the single profile, always selected.
    - ``len(auth_types) >= 2`` → exclusive-OR; the user picks exactly
      one profile.

    There is no inter-profile AND, no OPTIONAL, no clause-joining.
    AND-ed secrets within a single auth flow live inside one profile's
    ``xsoar_param_map``. See ``connectus/column-schemas.md`` §
    "Auth Details" for the canonical schema.

    Attributes:
        auth_types: List of profile entries, sorted by (type, name).
        other_connection: Sorted list of YML param ids for
            connection-adjacent non-auth params (purely transport /
            network: URL, port, proxy, insecure, …). Required; may
            be an empty list when the integration has no such params.

    Examples:
        >>> details = AuthDetails(
        ...     auth_types=[
        ...         AuthEntry(type=AuthType.APIKey, name="api_key",
        ...                   xsoar_param_map={"api_key": "key"}),
        ...     ],
        ...     other_connection=["proxy", "url"],
        ... )
        >>> details.auth_type_names
        {'api_key'}
        >>> details.requires_choice
        False
    """

    auth_types: list[AuthEntry]
    other_connection: list[str]

    @property
    def auth_type_names(self) -> set[str]:
        """Set of all auth_types[].name values."""
        return {e.name for e in self.auth_types}

    @property
    def requires_choice(self) -> bool:
        """True when 2+ profiles exist and the user must pick one."""
        return len(self.auth_types) >= 2

    @property
    def is_none_required(self) -> bool:
        """True when no authentication is required at all."""
        return len(self.auth_types) == 0

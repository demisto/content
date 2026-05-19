"""Data model types for the auth_config_parser package.

All public types live here. Pure Python, no external dependencies.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class AuthType(str, enum.Enum):
    """The 7 valid auth-type enum values for Auth Details entries.

    Inherits from ``str`` so that ``AuthType("APIKey")`` construction
    from JSON values works naturally and ``entry.type.value`` returns
    the string for serialization.

    Examples:
        >>> AuthType("APIKey")
        <AuthType.APIKey: 'APIKey'>
        >>> AuthType.APIKey.value
        'APIKey'
        >>> AuthType("APIKey") == "APIKey"
        True
    """

    OAuth2AuthCode = "OAuth2AuthCode"
    OAuth2ClientCreds = "OAuth2ClientCreds"
    OAuth2JWT = "OAuth2JWT"
    APIKey = "APIKey"
    Plain = "Plain"
    Other = "Other"
    NoneRequired = "NoneRequired"


class ClauseOperator(str, enum.Enum):
    """Operators in the config expression mini-grammar.

    Examples:
        >>> ClauseOperator("REQUIRED")
        <ClauseOperator.REQUIRED: 'REQUIRED'>
        >>> ClauseOperator.CHOICE.value
        'CHOICE'
    """

    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    CHOICE = "CHOICE"


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
            - ``OAuth2ClientCreds`` / ``OAuth2AuthCode`` /
              ``OAuth2JWT`` / ``Other`` → any non-empty string
              (enum deliberately undefined for now).
            - ``NoneRequired`` → does not appear in ``auth_types[]``.

        interpolated: When True, the value is templated at runtime
            rather than supplied by the user. Defaults to False.

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
        >>> entry.xsoar_param_map
        {'credentials.password': 'key'}
    """

    type: AuthType
    name: str
    xsoar_param_map: dict[str, str]
    interpolated: bool = False


@dataclass(frozen=True)
class ConfigClause:
    """One clause in a config expression.

    Attributes:
        operator: REQUIRED, OPTIONAL, or CHOICE.
        names: The connection-type names referenced by this clause.

    Examples:
        >>> clause = ConfigClause(
        ...     operator=ClauseOperator.REQUIRED,
        ...     names=["api_key"],
        ... )
        >>> clause.operator
        <ClauseOperator.REQUIRED: 'REQUIRED'>
    """

    operator: ClauseOperator
    names: list[str]


@dataclass(frozen=True)
class ConfigExpression:
    """Parsed config expression.

    Attributes:
        none_required: True when the expression is the literal
            'NoneRequired'. When True, clauses is empty.
        clauses: Ordered list of parsed clauses. Empty when
            none_required is True.

    Examples:
        >>> expr = ConfigExpression(none_required=True)
        >>> expr.referenced_names
        []

        >>> expr = ConfigExpression(clauses=[
        ...     ConfigClause(operator=ClauseOperator.REQUIRED, names=["a"]),
        ...     ConfigClause(operator=ClauseOperator.OPTIONAL, names=["b"]),
        ... ])
        >>> expr.referenced_names
        ['a', 'b']
    """

    none_required: bool = False
    clauses: list[ConfigClause] = field(default_factory=list)

    @property
    def referenced_names(self) -> list[str]:
        """All connection-type names referenced across all clauses,
        in order, possibly with duplicates."""
        names: list[str] = []
        for clause in self.clauses:
            names.extend(clause.names)
        return names


@dataclass(frozen=True)
class AuthDetails:
    """Fully parsed Auth Details JSON object.

    Attributes:
        auth_types: List of auth entries, sorted by (type, name).
        config: Parsed config expression.
        other_connection: Sorted list of YML param ids for
            connection-adjacent non-auth params. None when the key
            is absent (legacy rows).

    Examples:
        >>> details = AuthDetails(
        ...     auth_types=[
        ...         AuthEntry(type=AuthType.APIKey, name="api_key",
        ...                   xsoar_param_map={"api_key": "key"}),
        ...     ],
        ...     config=ConfigExpression(clauses=[
        ...         ConfigClause(operator=ClauseOperator.REQUIRED,
        ...                      names=["api_key"]),
        ...     ]),
        ...     other_connection=["proxy", "url"],
        ... )
        >>> details.auth_type_names
        {'api_key'}
    """

    auth_types: list[AuthEntry]
    config: ConfigExpression
    other_connection: list[str] | None = None

    @property
    def auth_type_names(self) -> set[str]:
        """Set of all auth_types[].name values."""
        return {e.name for e in self.auth_types}

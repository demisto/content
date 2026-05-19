"""Utility functions for the auth_config_parser package.

Pure functions that extract derived information from parsed
:class:`~auth_config_parser.types.AuthDetails` objects. No
CSV/filesystem dependencies.
"""
from __future__ import annotations

from auth_config_parser.types import AuthDetails


def project_xsoar_param_to_yml_id(xsoar_param: str) -> str:
    """Collapse a dotted XSOAR param path to its base YML param id.

    Bare ids pass through unchanged. Dotted forms like
    ``'credentials.identifier'`` collapse to the segment before the
    first ``'.'`` (``'credentials'``).

    Args:
        xsoar_param: An XSOAR field path string.

    Returns:
        The base YML param id.

    Examples:
        >>> project_xsoar_param_to_yml_id("api_key")
        'api_key'
        >>> project_xsoar_param_to_yml_id("credentials.identifier")
        'credentials'
        >>> project_xsoar_param_to_yml_id("credentials.password")
        'credentials'
        >>> project_xsoar_param_to_yml_id("")
        ''
    """
    if not isinstance(xsoar_param, str):
        return ""
    return xsoar_param.split(".", 1)[0]


def auth_param_ids(details: AuthDetails) -> set[str]:
    """Extract the set of YML param ids from an AuthDetails object.

    Returns the deduplicated set of bare YML ``configuration[].name``
    values composed from:

    - Every key in every ``auth_types[].xsoar_param_map``, projected
      via :func:`project_xsoar_param_to_yml_id`.
    - Every entry in ``other_connection`` (already bare YML ids).

    Args:
        details: A parsed :class:`~auth_config_parser.types.AuthDetails`
            object.

    Returns:
        Set of YML param id strings.

    Examples:
        >>> from auth_config_parser.parser import parse_auth_details
        >>> details = parse_auth_details({
        ...     "auth_types": [{"type": "Plain", "name": "creds",
        ...         "xsoar_param_map": {
        ...             "credentials.identifier": "username",
        ...             "credentials.password": "password"}}],
        ...     "config": "REQUIRED(creds)",
        ...     "other_connection": ["url", "proxy"],
        ... })
        >>> sorted(auth_param_ids(details))
        ['credentials', 'proxy', 'url']
    """
    result: set[str] = set()

    for entry in details.auth_types:
        for xp in entry.xsoar_param_map:
            yml_id = project_xsoar_param_to_yml_id(xp)
            if yml_id:
                result.add(yml_id)

    if details.other_connection is not None:
        for item in details.other_connection:
            if isinstance(item, str) and item:
                result.add(item)

    return result


def auth_param_ids_with_sources(
    details: AuthDetails,
) -> dict[str, list[str]]:
    """Extract YML param ids with source attribution.

    Returns a dict mapping each YML param id to a list of
    human-readable source descriptions indicating where the param
    was declared. The descriptor for entries derived from
    ``auth_types[]`` quotes the full ``xsoar_param_map`` (keys and
    values) verbatim so downstream consumers (e.g. the cross-check
    overlap rejection messages) can show the operator both the
    XSOAR-side paths and the ConnectUs-side roles.

    Args:
        details: A parsed :class:`~auth_config_parser.types.AuthDetails`
            object.

    Returns:
        Dict of ``{yml_param_id: [source_description, ...]}``.

    Examples:
        >>> from auth_config_parser.parser import parse_auth_details
        >>> details = parse_auth_details({
        ...     "auth_types": [{"type": "Plain", "name": "creds",
        ...         "xsoar_param_map": {
        ...             "credentials.identifier": "username",
        ...             "credentials.password": "password"}}],
        ...     "config": "REQUIRED(creds)",
        ...     "other_connection": ["url"],
        ... })
        >>> sources = auth_param_ids_with_sources(details)
        >>> sources["url"]
        ['other_connection']
    """
    sources: dict[str, list[str]] = {}

    for entry in details.auth_types:
        # Collect projected ids for this entry.
        projected_for_entry: list[str] = []
        for xp in entry.xsoar_param_map:
            yml_id = project_xsoar_param_to_yml_id(xp)
            if yml_id:
                projected_for_entry.append(yml_id)

        # Group source description by entry — every projected id
        # cites the same entry-level (name, xsoar_param_map) pair so
        # the overlap message can quote the dotted forms (and their
        # roles) verbatim. Dedupe per-yml_id so dotted forms
        # collapsing to the same bare id (credentials.identifier +
        # credentials.password → credentials) don't repeat the same
        # descriptor twice.
        descriptor = (
            f"auth_types[].name={entry.name!r} "
            f"(xsoar_param_map={dict(entry.xsoar_param_map)!r})"
        )
        seen_for_entry: set[str] = set()
        for yml_id in projected_for_entry:
            if yml_id in seen_for_entry:
                continue
            seen_for_entry.add(yml_id)
            sources.setdefault(yml_id, []).append(descriptor)

    if details.other_connection is not None:
        for item in details.other_connection:
            if isinstance(item, str) and item:
                sources.setdefault(item, []).append("other_connection")

    return sources

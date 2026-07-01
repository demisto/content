"""Auth Parity Test analyzer.

Verifies that for each non-interpolated connection declared in an
integration's ``Auth Details``, secret values land in the **same
wire location** whether they are supplied the non-UCP way (via
``demisto.params()`` → integration code → ``BaseClient``) or the
UCP way (credential injection through
``demisto.getUCPCredentials()`` — and the
``CommonServerPython.get_ucp_credentials()`` wrapper that delegates
to it).

See :doc:`connectus/auth_parity_test_design.md` for the full design.

The analyzer is intentionally orchestration-light: parsing of Auth
Details delegates to :mod:`auth_config_parser`, integration loading
& child process execution reuse the helpers in
:mod:`check_command_params`, and HTTP capture reuses
:class:`capture_proxy.CaptureProxy`.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit

# auth_config_parser + capture_proxy + check_command_params are local
# siblings; make them importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth_config_parser import (  # noqa: E402
    AuthDetails,
    AuthEntry,
    AuthType,
    parse_auth_details,
    validate_auth_details,
)
from capture_proxy import CaptureProxy  # noqa: E402

# REUSED FROM check_command_params.py — these are stable public-ish
# helpers (file discovery, YML interrogation, content-prep pipeline,
# docker child runtime). Importing avoids ~600 lines of copy-paste.
# A future refactor should hoist them into a shared module.
import check_command_params as _ccp  # noqa: E402


# Content repo root = parent of the connectus/ dir this file lives in.
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolve_integration_path(raw_path: str) -> Path | None:
    """Resolve an integration directory path tolerantly.

    Sweep finding F1 (2026-06-03): the skill's §1.12 playbook and the
    ``files`` command both surface integration paths as repo-root-relative
    ``Packs/<Pack>/Integrations/<Name>`` strings. But ``Path(p).resolve()``
    is **cwd-relative**, so copy-pasting that path and running this script
    from ``connectus/`` (or anywhere but the repo root) produced a
    confusing ``ERROR_BAD_PATH``. Try, in order:

    1. absolute / cwd-relative (the historical behavior), then
    2. repo-root-relative (``<repo>/<raw_path>``).

    Returns the first candidate that is an existing directory, else
    ``None``.
    """
    cwd_candidate = Path(raw_path).resolve()
    if cwd_candidate.is_dir():
        return cwd_candidate
    if not Path(raw_path).is_absolute():
        repo_candidate = (_REPO_ROOT / raw_path).resolve()
        if repo_candidate.is_dir():
            return repo_candidate
    return None


# --------------------------------------------------------------------------
# Constants — error codes (§5.5) and exit codes
# --------------------------------------------------------------------------

ERROR_NON_PYTHON = "ERROR_NON_PYTHON"
ERROR_NO_BASECLIENT = "ERROR_NO_BASECLIENT"
# FIXES-TODO #12 (LOCKED 2026-05-31): refined short-circuit for
# integrations whose ``Client`` subclasses a class defined in a shared
# ``*ApiModule`` (e.g. MicrosoftApiModule, OktaApiModule, ServiceNowApiModule).
# The textual ``BaseClient`` detection in :func:`detect_no_baseclient`
# never sees the literal token in such an integration's own .py because
# the inheritance is transitive through the ApiModule. This is a
# diagnostic refinement, not a detection widening — the right operator
# response is still to mark the auth ``interpolated: true`` (per
# cross-cutting decision #3, the documented fallback).
APIMODULE_INTEGRATION_CANNOT_VERIFY = "APIMODULE_INTEGRATION_CANNOT_VERIFY"
# FIXES-TODO #9 (LOCKED 2026-05-31): structural-skip code for the
# multi-secret/multi-flow Passthrough pattern (e.g. AbuseIPDB's
# primary + Hunting keys). Per cross-cutting decision #2 (XOR-only
# auth), these integrations are classified as Passthrough. The parity
# gate's coverage of such bundles is intentionally reduced — by design,
# not a failure.
MULTI_SECRET_PASSTHROUGH = "MULTI_SECRET_PASSTHROUGH"
ERROR_ALL_INTERPOLATED = "ERROR_ALL_INTERPOLATED"
ERROR_CONNECTION_INTERPOLATED = "ERROR_CONNECTION_INTERPOLATED"
ERROR_INTEGRATION_REJECTS_HTTP = "ERROR_INTEGRATION_REJECTS_HTTP"

EXIT_NON_PYTHON = 10
EXIT_NO_BASECLIENT = 11
EXIT_APIMODULE_INTEGRATION_CANNOT_VERIFY = 15
EXIT_MULTI_SECRET_PASSTHROUGH = 16
EXIT_ALL_INTERPOLATED = 12
EXIT_CONNECTION_INTERPOLATED = 13
EXIT_INTEGRATION_REJECTS_HTTP = 14

# Parseable substrings the migration skill greps for. Do NOT reword.
_LITERAL_MARK_AUTH = "Mark its auth as interpolated"
_LITERAL_PARITY_GATE_SKIPPED = (
    "Auth parity gate inside set-auth: structurally skipped — re-run "
    "set-auth to commit the Auth Details cell."
)

_SENTINEL_PREFIX = "__AUTHPARITY__"
_OAUTH_TOKEN_HINT = "oauth_token"

DEFAULT_TIMEOUT_S = 30

# Signed-auth detection — substrings in the .py source that indicate
# the integration computes a derived signature from the secret, which
# the sentinel-grep approach cannot follow (§6.3).
_SIGNED_AUTH_INDICATORS = (
    "import hmac",
    "from hmac",
    "import botocore",
    "from botocore",
    "AWSApiModule",
    "EdgeGridAuth",
    "edgegrid",
)

# YML param type 14 is the certificate / cert-key auth slot (§6.4).
_YML_TYPE_CERTIFICATE_AUTH = 14


# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Location:
    """One structured wire location where a sentinel was observed.

    ``method`` and ``path`` come from the captured request. ``locator``
    is the §4.1 location-type string (e.g. ``header:authorization:bearer``,
    ``body.json:auth.client_secret``, ``query:api_key``).
    """

    method: str
    path: str
    locator: str


@dataclass(frozen=True)
class Diff:
    """Per-sentinel parity difference (§4.5)."""

    sentinel: str
    failure_code: str
    old_locations: list[str]
    new_locations: list[str]


@dataclass(frozen=True)
class SentinelLeaf:
    """One sentinel record, keyed by ``(xsoar_path, role)``.

    The ``role`` is the UCP role from ``AuthEntry.xsoar_param_map``
    (e.g. ``"key"``, ``"username"``, ``"password"``, ``"client_secret"``).
    Carrying it here is what lets the UCP-shape selectors (§2.5) route
    each sentinel into the right slot **by role** rather than by
    leaf-name heuristic — the bug Commit 4 of the
    ``xsoar_param_map`` migration plan fixes.

    The ``value`` string itself ALSO encodes the role (see §2.3 of
    ``connectus/auth_parity_test_design.md``) so a downstream grep on a
    captured request can recover both the XSOAR path and the role from
    the matched sentinel alone.
    """

    path: str
    role: str
    value: str


@dataclass
class SentinelMap:
    """Mapping ``connection_name → list[SentinelLeaf]``.

    A single :class:`SentinelMap` is shared across the old and new runs
    of one connection so both runs seed identical secret bytes; only
    their wire placement is compared.

    The list preserves the (key, value) iteration order of
    ``AuthEntry.xsoar_param_map`` at sentinel-generation time. Lookups
    by ``path`` use :meth:`leaves_by_path`; lookups by ``role`` use
    :meth:`leaves_by_role`.
    """

    by_connection: dict[str, list[SentinelLeaf]] = field(default_factory=dict)

    def for_connection(self, name: str) -> list[SentinelLeaf]:
        """Return the list of :class:`SentinelLeaf` for one connection."""
        return self.by_connection.get(name, [])

    def path_to_value(self, name: str) -> dict[str, str]:
        """``{xsoar_path: sentinel_value}`` view — for diff reporting.

        The user-visible identifier in diff reports is the XSOAR path
        (§4.6 of the design), so the diff comparator keys by path. When
        multiple leaves share a path (legal for OAuth where role is
        free-form), later entries overwrite earlier ones, which is fine:
        their sentinel values differ but the diff label is the same.
        """
        return {leaf.path: leaf.value for leaf in self.for_connection(name)}


@dataclass
class RequestSetDiff:
    """Symmetric (method, url_path) difference between two captured runs."""

    only_in_old: list[dict[str, str]] = field(default_factory=list)
    only_in_new: list[dict[str, str]] = field(default_factory=list)


# --------------------------------------------------------------------------
# §2.3 — sentinel generation
# --------------------------------------------------------------------------


def _make_sentinel(
    connection_name: str, xsoar_param_path: str, role: str
) -> str:
    """Build a single sentinel value per §2.3.

    Format: ``__AUTHPARITY__<conn>__<param_path>__<role>__<uuid8>``.
    ASCII-safe, ≥ 40 chars in practice for any non-trivial inputs.
    The uuid8 suffix is regenerated per call to keep sentinels unique
    across runs. The role substring makes the sentinel
    grep-attributable to its intended UCP slot — see §2.3's
    "Why this changed (2026-05)" note for the rationale.
    """
    suffix = uuid.uuid4().hex[:8]
    return (
        f"{_SENTINEL_PREFIX}{connection_name}__"
        f"{xsoar_param_path}__{role}__{suffix}"
    )


def generate_sentinels(details: AuthDetails) -> SentinelMap:
    """Build a :class:`SentinelMap` from parsed Auth Details.

    Entries with ``interpolated is True`` are skipped — they have no
    user-supplied secret to seed (§Scope). The returned mapping uses
    ``entry.name`` as the connection key and one :class:`SentinelLeaf`
    per ``(xsoar_path, role)`` pair from
    :attr:`AuthEntry.xsoar_param_map` (§2.3).
    """
    out = SentinelMap()
    for entry in details.auth_types:
        if entry.interpolated:
            continue
        leaves: list[SentinelLeaf] = []
        for xsoar_path, role in entry.xsoar_param_map.items():
            leaves.append(
                SentinelLeaf(
                    path=xsoar_path,
                    role=role,
                    value=_make_sentinel(entry.name, xsoar_path, role),
                )
            )
        out.by_connection[entry.name] = leaves
    return out


# --------------------------------------------------------------------------
# §2.5 — UCP shape mapping + mock builder (role-driven)
# --------------------------------------------------------------------------


def map_auth_type_to_ucp_shape(
    entry: AuthEntry, sentinels: list[SentinelLeaf]
) -> dict[str, Any] | None:
    """Build the UCP credential dict for ``entry`` using its sentinels.

    Implements the §8.5 ``match`` table on :class:`AuthType`. Returns
    ``None`` for :data:`AuthType.Passthrough` and
    :data:`AuthType.NoneRequired` (no synthesizable shape — handled
    as skips by the caller).

    The slot-selection inside each per-type helper is **role-driven**:
    each helper looks up the :class:`SentinelLeaf` whose ``role``
    matches the slot it's filling. This replaces the pre-2026-05
    leaf-name heuristic that picked sentinels by inspecting the
    XSOAR path's suffix (``.identifier`` / ``.password``); the heuristic
    failed for flat-param Plain configs and for APIKey-with-hiddenusername
    where the secret sits at ``<id>.password`` but its role is ``"key"``.
    See §2.3 of ``connectus/auth_parity_test_design.md`` for the full
    "Why this changed" rationale.
    """
    match entry.type:
        case AuthType.APIKey:
            return _ucp_shape_api_key(entry, sentinels)
        case AuthType.Plain:
            return _ucp_shape_plain(entry, sentinels)
        case AuthType.OAuth2ClientCreds | AuthType.OAuth2JWT:
            return _ucp_shape_oauth2(entry, sentinels)
        case AuthType.Passthrough:
            return None
        case AuthType.NoneRequired:
            return None
    return None


def _leaves_with_role(
    sentinels: list[SentinelLeaf], role: str
) -> list[SentinelLeaf]:
    """Return all leaves whose ``role`` equals ``role``, lex-sorted by path.

    Sorting by path makes the per-slot pick deterministic when multiple
    paths legally share a role (e.g. an APIKey with two paths both
    mapped to ``"key"``).
    """
    return sorted(
        (leaf for leaf in sentinels if leaf.role == role),
        key=lambda leaf: leaf.path,
    )


def _ucp_shape_api_key(
    _: AuthEntry, sentinels: list[SentinelLeaf]
) -> dict[str, Any]:
    """APIKey UCP shape — fills ``api_key.key`` with the sentinel whose role
    is ``"key"``.

    When multiple paths map to ``"key"`` (legal but contrived), the
    first one lex-sorted by path wins. The validator
    (:func:`auth_config_parser.validate_auth_details`) guarantees that
    at least one path is mapped to ``"key"`` for every APIKey entry, so
    this lookup always finds something for well-formed input.
    """
    key_leaves = _leaves_with_role(sentinels, "key")
    key_value = key_leaves[0].value if key_leaves else ""
    return {"type": "api_key", "api_key": {"key": key_value}}


def _ucp_shape_plain(
    _: AuthEntry, sentinels: list[SentinelLeaf]
) -> dict[str, Any]:
    """Plain UCP shape — fills ``plain.username`` / ``plain.password`` by
    looking up the leaves whose roles are ``"username"`` / ``"password"``.

    This is the regression-proof replacement for the old leaf-name
    heuristic that inspected XSOAR-path suffixes (``.identifier`` /
    ``.password``); see §2.3 of ``auth_parity_test_design.md``. A
    Plain entry with flat params (e.g.
    ``xsoar_param_map={"server_user": "username",
    "server_password": "password"}``) now routes correctly because the
    role is the source of truth.

    If only one of the two roles is present in the map, the missing
    slot is filled with an empty string. The Auth Details validator is
    responsible for rejecting Plain entries that lack the expected
    roles entirely; this helper does not enforce that policy.
    """
    user_leaves = _leaves_with_role(sentinels, "username")
    pw_leaves = _leaves_with_role(sentinels, "password")
    username = user_leaves[0].value if user_leaves else ""
    password = pw_leaves[0].value if pw_leaves else ""
    return {"type": "plain", "plain": {"username": username, "password": password}}


def _ucp_shape_oauth2(
    _: AuthEntry, sentinels: list[SentinelLeaf]
) -> dict[str, Any]:
    """OAuth2* UCP shape — fills ``oauth2.access_token`` with the first
    sentinel by lex-sorted path.

    TODO: Revisit slot selection once the OAuth2* role enum is locked
    in ``connectus/column-schemas.md``. The role values for OAuth2*
    entries are currently free-form (any non-empty string), so we can
    not pick by a stable role name. Lex-sorting by path mimics the
    pre-2026-05 behaviour of taking "any" sentinel and is deterministic.
    """
    chosen = sorted(sentinels, key=lambda leaf: leaf.path)
    access_token = chosen[0].value if chosen else ""
    return {
        "type": "oauth2",
        "oauth2": {"access_token": access_token, "token_type": "Bearer"},
    }


def build_ucp_mock(
    sentinel_map: SentinelMap, connection_name: str, auth_entry: AuthEntry
) -> Callable[[str], dict[str, Any]] | None:
    """Return a callable matching the ``demisto.getUCPCredentials`` contract
    (and the equivalent ``CommonServerPython.get_ucp_credentials`` wrapper
    that delegates to it).

    Signature: ``(method_unique_id: str) -> dict``. The returned dict is
    the UCP credential envelope for ``auth_entry``, populated with the
    sentinels held in ``sentinel_map`` for ``connection_name``. The
    callable ignores ``method_unique_id`` — there is exactly one
    connection in scope per parity run.
    """
    shape = map_auth_type_to_ucp_shape(
        auth_entry, sentinel_map.for_connection(connection_name)
    )
    if shape is None:
        return None

    def _mock(method_unique_id: str) -> dict[str, Any]:  # noqa: ARG001
        return shape

    return _mock


# --------------------------------------------------------------------------
# Param-dict seeding for the old run (§2.4)
# --------------------------------------------------------------------------


def build_old_params(
    sentinel_map: SentinelMap,
    connection_name: str,
    base_params: dict[str, Any],
) -> dict[str, Any]:
    """Return a copy of ``base_params`` with sentinels seeded at the
    XSOAR-path keys of ``xsoar_param_map`` for ``connection_name``.

    Dotted paths are expanded into nested dicts (``credentials.password``
    becomes ``{"credentials": {"password": "<sentinel>"}}``). The base
    dict is not mutated.

    Semantics are unchanged from the pre-``xsoar_param_map`` shape:
    the key set is the same (``xsoar_param_map.keys()`` is what used
    to be ``xsoar_params``); we now read the leaves from the
    role-aware :class:`SentinelLeaf` records.
    """
    params = json.loads(json.dumps(base_params))  # deep copy via JSON
    for leaf in sentinel_map.for_connection(connection_name):
        _set_dotted(params, leaf.path, leaf.value)
    return params


def _set_dotted(target: dict[str, Any], dotted_path: str, value: Any) -> None:
    """Set ``target[a][b]…[z] = value`` from a dotted path string."""
    if not dotted_path:
        return
    parts = dotted_path.split(".")
    node: Any = target
    for part in parts[:-1]:
        existing = node.get(part)
        if not isinstance(existing, dict):
            existing = {}
            node[part] = existing
        node = existing
    node[parts[-1]] = value


# --------------------------------------------------------------------------
# §4.1 + §4.2 — sentinel location extraction
# --------------------------------------------------------------------------


def _sentinel_variants(sentinel: str) -> list[str]:
    """Return [raw, base64(raw), urlsafe_base64(raw)] — see §6.6."""
    raw = sentinel.encode("utf-8")
    return [
        sentinel,
        base64.b64encode(raw).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
    ]


def _contains(haystack: str, needle: str) -> bool:
    return bool(haystack) and bool(needle) and (needle in haystack)


def extract_sentinel_locations(
    captured_request: dict[str, Any], sentinel: str
) -> set[Location]:
    """Return the wire locations where ``sentinel`` appears in one request.

    Implements §4.1 location taxonomy with §4.2 canonicalization. The
    sentinel is searched both raw and base64-encoded (§6.6).
    """
    method = str(captured_request.get("method", ""))
    path = str(captured_request.get("path", ""))
    variants = _sentinel_variants(sentinel)
    found: set[str] = set()
    _scan_headers(captured_request.get("headers") or {}, variants, found)
    _scan_query(captured_request.get("query") or "", variants, found)
    _scan_body(captured_request.get("body") or "",
               captured_request.get("headers") or {}, variants, found)
    _scan_url(captured_request.get("url") or "", variants, found)
    return {Location(method=method, path=path, locator=loc) for loc in found}


def _scan_headers(
    headers: dict[str, str], variants: list[str], found: set[str]
) -> None:
    """Headers — raw, then auth-scheme canonicalization."""
    for name, raw_value in headers.items():
        lname = name.lower()
        value = str(raw_value)
        if lname == "cookie":
            _scan_cookie(value, variants, found)
            continue
        if lname == "authorization":
            _scan_authorization(value, variants, found)
            continue
        if any(_contains(value, v) for v in variants):
            found.add(f"header:{lname}")


def _scan_authorization(value: str, variants: list[str], found: set[str]) -> None:
    """Decompose Authorization header: Bearer, Basic, Token, SSWS, …"""
    parts = value.split(None, 1)
    if len(parts) == 2:
        scheme, payload = parts
        scheme_l = scheme.lower()
        if scheme_l == "basic":
            _scan_basic(payload, variants, found)
            return
        if any(_contains(payload, v) for v in variants):
            found.add(f"header:authorization:{scheme_l}")
            return
    if any(_contains(value, v) for v in variants):
        found.add("header:authorization")


def _scan_basic(payload: str, variants: list[str], found: set[str]) -> None:
    """Base64-decode a Basic blob and look for sentinels in user/pass slots."""
    try:
        decoded = base64.b64decode(payload + "==", validate=False).decode(
            "utf-8", errors="replace"
        )
    except (ValueError, OSError):
        return
    if ":" in decoded:
        user, _, pwd = decoded.partition(":")
    else:
        user, pwd = decoded, ""
    if any(_contains(user, v) for v in variants):
        found.add("header:authorization:basic:user")
    if any(_contains(pwd, v) for v in variants):
        found.add("header:authorization:basic:pass")


def _scan_cookie(value: str, variants: list[str], found: set[str]) -> None:
    """Cookies — semicolon-separated name=value pairs (RFC 6265)."""
    for item in value.split(";"):
        if "=" not in item:
            continue
        name, _, cval = item.strip().partition("=")
        if any(_contains(cval, v) for v in variants):
            found.add(f"cookie:{name}")


def _scan_query(query: str, variants: list[str], found: set[str]) -> None:
    """Query string — parse_qsl with URL-decoding on values."""
    if not query:
        return
    for name, value in parse_qsl(query, keep_blank_values=True):
        if any(_contains(value, v) for v in variants):
            found.add(f"query:{name}")
        # Also try the unquoted form, parse_qsl already unquotes but
        # we keep this defensive in case operators double-encode.
        if any(_contains(unquote(value), v) for v in variants):
            found.add(f"query:{name}")


def _scan_body(
    body: str,
    headers: dict[str, str],
    variants: list[str],
    found: set[str],
) -> None:
    """Body — JSON and form-urlencoded based on Content-Type."""
    if not body:
        return
    ctype = ""
    for name, value in headers.items():
        if name.lower() == "content-type":
            ctype = str(value).lower()
            break
    if "application/json" in ctype or _looks_like_json(body):
        _scan_json_body(body, variants, found)
        return
    if "application/x-www-form-urlencoded" in ctype:
        _scan_form_body(body, variants, found)
        return
    # Unknown content-type: best-effort raw scan only.
    if any(_contains(body, v) for v in variants):
        found.add("body.raw")


def _looks_like_json(body: str) -> bool:
    stripped = body.lstrip()
    return stripped.startswith(("{", "["))


def _scan_json_body(body: str, variants: list[str], found: set[str]) -> None:
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return
    _walk_json(parsed, "", variants, found)


def _walk_json(
    node: Any, dotted: str, variants: list[str], found: set[str]
) -> None:
    """Recursive JSON walk recording any leaf string that holds a sentinel."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{dotted}.{key}" if dotted else str(key)
            _walk_json(value, child, variants, found)
        return
    if isinstance(node, list):
        for idx, value in enumerate(node):
            child = f"{dotted}[{idx}]"
            _walk_json(value, child, variants, found)
        return
    if isinstance(node, str) and any(_contains(node, v) for v in variants):
        found.add(f"body.json:{dotted}")


def _scan_form_body(body: str, variants: list[str], found: set[str]) -> None:
    parsed = parse_qs(body, keep_blank_values=True)
    for name, values in parsed.items():
        for value in values:
            if any(_contains(value, v) for v in variants):
                found.add(f"body.form:{name}")


def _scan_url(url: str, variants: list[str], found: set[str]) -> None:
    """URL userinfo — ``user:pass@host`` slots only."""
    if not url:
        return
    try:
        split = urlsplit(url)
    except ValueError:
        return
    user = split.username or ""
    pwd = split.password or ""
    if user and any(_contains(user, v) for v in variants):
        found.add("url.userinfo:user")
    if pwd and any(_contains(pwd, v) for v in variants):
        found.add("url.userinfo:pass")


# --------------------------------------------------------------------------
# §4.5 — diff classification + §6.7 request-set diff
# --------------------------------------------------------------------------


def compare_locations(
    old_locs: set[Location], new_locs: set[Location]
) -> list[Diff]:
    """Classify the symmetric difference into §4.5 failure codes.

    Operates on the set of :class:`Location` triples for a single
    sentinel across one command's old + new runs. Returns one
    :class:`Diff` per sentinel-level outcome — empty list means parity
    holds at this sentinel.
    """
    if not old_locs and not new_locs:
        return [_diff_missing_both()]
    old_only = old_locs - new_locs
    new_only = new_locs - old_locs
    if not old_only and not new_only:
        return []
    if old_only and new_only:
        return [_diff_wrong_location(old_only, new_only)]
    if old_only:
        return [_diff_missing_in_new(old_only)]
    return [_diff_extra_in_new(new_only)]


def _diff_missing_both() -> Diff:
    return Diff(sentinel="", failure_code="MISSING_IN_BOTH",
                old_locations=[], new_locations=[])


def _diff_wrong_location(old_only: set[Location], new_only: set[Location]) -> Diff:
    return Diff(
        sentinel="",
        failure_code="WRONG_LOCATION",
        old_locations=sorted(_loc_to_string(loc) for loc in old_only),
        new_locations=sorted(_loc_to_string(loc) for loc in new_only),
    )


def _diff_missing_in_new(old_only: set[Location]) -> Diff:
    return Diff(
        sentinel="",
        failure_code="MISSING_IN_NEW",
        old_locations=sorted(_loc_to_string(loc) for loc in old_only),
        new_locations=[],
    )


def _diff_extra_in_new(new_only: set[Location]) -> Diff:
    return Diff(
        sentinel="",
        failure_code="EXTRA_IN_NEW",
        old_locations=[],
        new_locations=sorted(_loc_to_string(loc) for loc in new_only),
    )


def _loc_to_string(loc: Location) -> str:
    return f"{loc.method} {loc.path} {loc.locator}"


def compare_request_sets(
    old_reqs: list[dict[str, Any]], new_reqs: list[dict[str, Any]]
) -> RequestSetDiff:
    """Symmetric difference on ``(method, url_path)`` per §6.7."""
    old_set = {(_req_method(r), _req_path(r)) for r in old_reqs}
    new_set = {(_req_method(r), _req_path(r)) for r in new_reqs}
    only_old = sorted(old_set - new_set)
    only_new = sorted(new_set - old_set)
    return RequestSetDiff(
        only_in_old=[{"method": m, "path": p} for m, p in only_old],
        only_in_new=[{"method": m, "path": p} for m, p in only_new],
    )


def _req_method(req: dict[str, Any]) -> str:
    return str(req.get("method", ""))


def _req_path(req: dict[str, Any]) -> str:
    return str(req.get("path", ""))


# --------------------------------------------------------------------------
# Static hard-error detection (§5.5 — pre-flight)
# --------------------------------------------------------------------------


def detect_non_python(yml_data: dict[str, Any], py_path: Path | None) -> str | None:
    """Return the language string when this is NOT a Python integration.

    Triggers :data:`ERROR_NON_PYTHON`. Returns ``None`` for valid Python.
    """
    script = yml_data.get("script") or {}
    script_type = ""
    if isinstance(script, dict):
        script_type = str(script.get("type") or "").lower()
    if script_type and script_type not in {"python", "python3"}:
        return script_type
    if py_path is None:
        return "unknown (no .py file found)"
    return None


def detect_no_baseclient(py_source: str) -> bool:
    """True when the Python source shows no sign of ``BaseClient`` usage.

    Implements the §5.5 static heuristic: looks for the literal patterns
    ``class <Name>(BaseClient)``, ``BaseClient(`` (instantiation), and
    an ``import ... BaseClient`` line from CommonServerPython.
    """
    if re.search(r"class\s+\w+\s*\([^)]*BaseClient[^)]*\)", py_source):
        return False
    if "BaseClient(" in py_source:
        return False
    if re.search(
        r"from\s+CommonServerPython\s+import\s+[^\n]*\bBaseClient\b", py_source
    ):
        return False
    # ``import *`` from CommonServerPython is the dominant idiom and
    # implicitly brings BaseClient in. Treat that as "may use BaseClient"
    # only when something also references the name unqualified.
    return "BaseClient" not in py_source


def detect_apimodule_import(py_source: str) -> str | None:
    """Return the name of the imported ``*ApiModule`` if any.

    Implements the FIXES-TODO #12 (LOCKED 2026-05-31) diagnostic-clarity
    refinement: ApiModule-using integrations (e.g. ``from
    MicrosoftApiModule import *``) cannot be statically verified as
    BaseClient-using because the inheritance is transitive through the
    ApiModule. The right operator response is to mark the auth
    ``interpolated: true`` (per cross-cutting #3). Returns the ApiModule
    name on match (e.g. ``"MicrosoftApiModule"``) or None.
    """
    match = re.search(
        r"from\s+(\w+ApiModule)\s+import\b", py_source
    )
    return match.group(1) if match else None


# FIXES-TODO #9 — credential-field name substrings (case-insensitive).
# A Passthrough profile carrying multiple keys whose names match any of
# these patterns is classified as a multi-secret/multi-flow bundle (the
# AbuseIPDB-class case per cross-cutting decision #2).
_CREDENTIAL_FIELD_PATTERNS = (
    "password", "key", "secret", "token", "credential", "apikey", "api_key",
)


def detect_multi_secret_passthrough(details: AuthDetails) -> list[str] | None:
    """Return the list of credential-named keys when a Passthrough
    profile carries 2+ of them; otherwise None.

    Per the FIXES-TODO #9 resolution: this is a heuristic — we count
    keys in any Passthrough profile's ``xsoar_param_map`` whose names
    contain any of :data:`_CREDENTIAL_FIELD_PATTERNS` as a
    case-insensitive substring. 2+ matches → the bundle is classified
    as multi-secret.
    """
    for entry in details.auth_types or []:
        if entry.type != AuthType.Passthrough:
            continue
        matched: list[str] = []
        for path in (entry.xsoar_param_map or {}).keys():
            lowered = path.lower()
            if any(pattern in lowered for pattern in _CREDENTIAL_FIELD_PATTERNS):
                matched.append(path)
        if len(matched) >= 2:
            return matched
    return None


def detect_signed_auth(py_source: str) -> bool:
    """True when the source code looks like it computes a derived signature.

    Triggers ``status: skipped_signed`` (§6.3).
    """
    return any(indicator in py_source for indicator in _SIGNED_AUTH_INDICATORS)


def detect_mtls(yml_data: dict[str, Any]) -> bool:
    """True when the YML declares a certificate / cert-key auth param (type 14)."""
    config = yml_data.get("configuration") or []
    for param in config:
        if isinstance(param, dict) and param.get("type") == _YML_TYPE_CERTIFICATE_AUTH:
            return True
    return False


def detect_integration_rejects_http(stderr: str) -> bool:
    """Heuristic match for §6.4.2 — integration rejects http:// URLs."""
    lowered = stderr.lower()
    if "http://" not in lowered and "https" not in lowered:
        return False
    return any(token in lowered for token in ("scheme", "protocol", "must be https"))


# --------------------------------------------------------------------------
# Hard-error JSON emission
# --------------------------------------------------------------------------


def _emit_hard_error(
    display: str, code: str, message: str, exit_code: int
) -> dict[str, Any]:
    """Build the §5.5 hard-error JSON envelope."""
    return {
        "integration": display,
        "error": {"code": code, "message": message, "exit_code": exit_code},
    }


def _msg_non_python(language: str) -> str:
    return (
        f"Auth parity test only supports Python integrations. "
        f"This integration is {language}. {_LITERAL_MARK_AUTH} "
        f"if it cannot use BaseClient injection."
    )


def _msg_no_baseclient() -> str:
    return (
        f"Auth parity test requires BaseClient usage. This integration "
        f"does not use BaseClient. {_LITERAL_MARK_AUTH} if it cannot "
        f"use BaseClient injection."
    )


def _msg_multi_secret_passthrough(matched_keys: list[str]) -> str:
    """FIXES-TODO #9 diagnostic — by design, not a failure.

    Per the cross-cutting Hints policy: no prescription. The XOR-only
    auth design (decision #2) makes Passthrough the explicit bucket for
    multi-secret/multi-flow integrations; the gate's reduced coverage
    is the documented trade-off.
    """
    keys = ", ".join(repr(k) for k in matched_keys)
    return (
        f"Multi-secret Passthrough auth profile detected (carries "
        f"{len(matched_keys)} credential-named keys: {keys}). Per the "
        f"XOR-only auth model (skill §1.2.2), multi-secret/multi-flow "
        f"integrations classify as Passthrough by design and the parity "
        f"gate's coverage of them is intentionally reduced. "
        f"{_LITERAL_PARITY_GATE_SKIPPED}"
    )


def _msg_apimodule_cannot_verify(apimodule_name: str) -> str:
    """Construct the FIXES-TODO #12 diagnostic message.

    Per the cross-cutting Hints policy (decision #1): the prescription is
    unambiguous (mark interpolated), so we include a one-line hint
    pointing at cross-cutting #3 / skill §1.2.2 directly.
    """
    return (
        f"Auth parity test cannot verify this integration: its Client "
        f"subclasses a class defined in {apimodule_name} (transitive "
        f"BaseClient inheritance is invisible to the textual detector). "
        f"{_LITERAL_MARK_AUTH} — see skill §1.2.2 (cross-cutting "
        f"decision #3: `interpolated: true` is the documented fallback "
        f"on any auth profile type when parity verification cannot run)."
    )


def _msg_all_interpolated() -> str:
    return (
        f"All auth types are interpolated. Auth parity test is not "
        f"applicable — interpolated connections are handled by "
        f"infrastructure, not integration code. {_LITERAL_PARITY_GATE_SKIPPED}"
    )


def _msg_connection_interpolated(name: str) -> str:
    return (
        f"Connection '{name}' is interpolated. Auth parity test only "
        f"applies to non-interpolated connections. Remove the "
        f"interpolated flag or skip this connection."
    )


def _msg_integration_rejects_http() -> str:
    return (
        f"Integration rejects HTTP URLs. Auth parity test requires "
        f"BaseClient URL rewriting to http://. {_LITERAL_MARK_AUTH} "
        f"if it cannot use BaseClient injection."
    )


# --------------------------------------------------------------------------
# §6.4.3 — OAuth token-exchange canned-response wrapper around CaptureProxy
# --------------------------------------------------------------------------


def install_oauth_token_wrapper(
    proxy: CaptureProxy, connection_name: str
) -> str:
    """Patch ``proxy`` so OAuth token-exchange requests get a canned reply.

    The wrapper inspects each captured request's (method, path,
    content-type, body) before the proxy returns ``200 {}``. When the
    request looks like an OAuth token exchange (§6.4.3), the canned
    response — including a synthetic ``access_token`` sentinel — is
    emitted instead.

    Returns the OAuth-token sentinel string so callers can include it
    in the location grep.
    """
    token_sentinel = f"{_SENTINEL_PREFIX}{_OAUTH_TOKEN_HINT}__{connection_name}__{uuid.uuid4().hex[:8]}"
    canned = json.dumps(
        {
            "access_token": token_sentinel,
            "token_type": "bearer",
            "expires_in": 3600,
        }
    ).encode("utf-8")

    # The capture proxy's request handler is built once at start time
    # via _make_handler(); rather than re-binding the handler class, we
    # monkey-patch the proxy's internal ``_record`` to remember pending
    # token-exchange requests and patch the BaseHTTPRequestHandler's
    # ``_send_json`` indirectly by overriding the proxy's
    # ``_oauth_canned`` attribute the handler reads on each request.
    #
    # Practically: we monkey-patch the proxy by attaching the canned
    # bytes + matcher to it; the simplest implementation that works
    # without subclassing is to wrap the proxy's ``_record`` so it
    # logs whether the next response should be canned. The actual
    # response-emission patch lives in :func:`_patch_handler_for_oauth`.
    _patch_handler_for_oauth(proxy, canned)
    return token_sentinel


def _patch_handler_for_oauth(proxy: CaptureProxy, canned: bytes) -> None:
    """Wrap the proxy handler's ``_handle_capture`` to emit OAuth canned reply.

    The original ``_handle_capture`` writes ``200 {}``; the wrapper
    detects OAuth token-exchange shape and writes ``canned`` instead.
    Request recording stays unchanged so the parity comparison still
    sees the outgoing token request.
    """
    server = proxy._server  # type: ignore[attr-defined]
    if server is None:
        return
    handler_cls = server.RequestHandlerClass

    original = handler_cls._handle_capture  # type: ignore[attr-defined]

    def wrapped(self: Any, path: str, query: str) -> None:
        body_bytes = self._read_body()
        body_text = body_bytes.decode("utf-8", errors="replace")
        record = _record_for(self, path, query, body_text)
        proxy._record(record)  # type: ignore[attr-defined]
        if _is_oauth_token_request(self, path, body_text):
            _emit_canned(self, canned)
            return
        self._send_json(200, {})

    handler_cls._handle_capture = wrapped  # type: ignore[attr-defined]
    # Mark patch idempotent — keep a reference so successive patches don't stack.
    handler_cls._auth_parity_original_capture = original  # type: ignore[attr-defined]


def _record_for(handler: Any, path: str, query: str, body: str) -> dict[str, Any]:
    return {
        "method": handler.command,
        "path": path,
        "query": query,
        "url": handler.path,
        "headers": {k: v for k, v in handler.headers.items()},
        "body": body,
        "timestamp": time.time(),
    }


def _is_oauth_token_request(handler: Any, path: str, body: str) -> bool:
    if handler.command != "POST":
        return False
    if not any(hint in path for hint in ("/token", "/oauth", "/oauth2")):
        return False
    ctype = (handler.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" not in ctype:
        return False
    return "grant_type" in body


def _emit_canned(handler: Any, body: bytes) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# --------------------------------------------------------------------------
# §2.7 — run_old / run_new orchestration
# --------------------------------------------------------------------------


@dataclass
class RunResult:
    """One run's outcome (old or new) for one (connection, command)."""

    status: str  # "ok" | "crashed" | "no_requests"
    rc: int
    stdout: str
    stderr: str
    timed_out: bool
    requests: list[dict[str, Any]] = field(default_factory=list)


# YML param names commonly used by integrations to hold the API base
# endpoint. The capture proxy can only intercept HTTP if the
# integration's *actual* base-URL param is rewritten — hardcoding
# ``url`` silently no-op'd on the ~45 integrations that use one of the
# other aliases (e.g. JiraV3 uses ``server_url``), letting them call
# the real API during parity runs.
_URL_PARAM_ALIASES = (
    "url",
    "server_url",
    "serverUrl",
    "host",
    "base_url",
    "baseUrl",
    "endpoint",
    "server",
    "api_url",
    "instance_url",
)


def _seed_url_params(
    params: dict[str, Any],
    proxy_port: int,
    integration_id: str | None = None,
) -> None:
    """Apply §2.7.2 URL-rewrite + insecure flag in-place.

    Rewrites every key in :data:`_URL_PARAM_ALIASES` that is already
    present in ``params``. Does **not** add missing keys — that would
    inject an unknown param the integration's YML may not declare.

    If no alias is present, emits a loud stderr warning: the integration
    will bypass the capture proxy and may hit a real API. This is a tool
    bug — the alias list needs extending.
    """
    proxy = f"http://127.0.0.1:{proxy_port}"
    rewritten: list[str] = []
    for key in _URL_PARAM_ALIASES:
        if key in params:
            params[key] = proxy
            rewritten.append(key)
    params["insecure"] = True
    if not rewritten:
        sys.stderr.write(
            f"[auth_parity] WARNING: no URL-aliased param found in params for "
            f"integration {integration_id!r}; expected one of "
            f"{list(_URL_PARAM_ALIASES)}. The integration may bypass the "
            f"capture proxy and make real HTTP calls. This is a tool bug if "
            f"the integration has a YML config param holding its base "
            f"endpoint — extend _URL_PARAM_ALIASES.\n"
        )


def _seed_proxy_env(
    params: dict[str, Any],
    env: dict[str, str],
    proxy_port: int,
    *,
    integration_id: str | None = None,
) -> None:
    """Apply §2.7 HTTPS_PROXY env-var seeding + force proxy/insecure in-place.

    Companion to :func:`_seed_url_params` — runs unconditionally alongside
    it (the "both mechanisms, every run" decision from the MITM refactor
    plan). Together they form a belt-and-suspenders: either the
    integration's HTTP client honors the ``HTTPS_PROXY`` env var and
    routes CONNECT through the proxy's MITM path, or it ignores the env
    and uses the proxy URL injected by :func:`_seed_url_params` directly.
    Either way the request lands at the same capture proxy.

    Mutations:

    * ``params["proxy"] = True`` — CommonServerPython's :class:`BaseClient`
      gates env-var honoring on this flag.
    * ``params["insecure"] = True`` — the proxy presents a self-signed
      cert; verification must be off (the URL-rewrite seeder sets this
      too, but we set it unconditionally here as well).
    * ``env`` gets ``HTTPS_PROXY`` / ``HTTP_PROXY`` (and lowercase
      variants) pointing at ``http://127.0.0.1:<port>``.
    * ``env["NO_PROXY"] = ""`` / ``env["no_proxy"] = ""`` — override any
      localhost-bypass default that would let a request skip the proxy.

    ``integration_id`` is accepted for parity with :func:`_seed_url_params`
    but is currently unused; reserved for future per-integration diagnostics.
    """
    del integration_id  # reserved for future per-integration diagnostics
    params["proxy"] = True
    params["insecure"] = True
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    env["HTTPS_PROXY"] = proxy_url
    env["HTTP_PROXY"] = proxy_url
    env["https_proxy"] = proxy_url
    env["http_proxy"] = proxy_url
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""


def _build_base_params(
    yml_data: dict[str, Any],
    seed_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a baseline ``demisto.params()`` dict for the integration.

    Value precedence for a non-auth YML param is:

    1. A per-invocation ``--seed-param NAME=VALUE`` override (when
       supplied) — wins for the named param, taking effect inside the
       type-aware placeholder pass below. For YML ``type:9``
       (credentials) widgets, the dotted-leaf form
       ``NAME.identifier=<v>`` / ``NAME.password=<v>`` is supported.
    2. A type-aware placeholder from
       :func:`check_command_params.build_param_values` — sentinels for
       most params, plus cert/PEM/thumbprint coercion for the
       Microsoft cert-thumbprint slot.

    Auth params are overlaid by :func:`build_old_params` or omitted
    entirely in the new run. The proxy URL is a placeholder that
    :func:`_seed_url_params` overwrites once the proxy is up.

    ``seed_overrides`` keys that don't correspond to a visible YML
    param (or that target a wrong-type parent on the dotted-leaf form)
    surface as ``[seed] WARNING`` lines from the sibling analyzer's
    own validation. Flat ``NAME=VALUE`` on a ``type:9`` credentials
    parent raises ``ValueError`` from
    :func:`check_command_params.build_param_values` (the analyzer
    cannot produce a sensible runtime value for the param) — callers
    surface that as a CLI exit-2 error.
    """
    yml_params = _ccp.get_yml_params(yml_data)
    values, _, _ = _ccp.build_param_values(
        yml_params=yml_params,
        proxy_url="http://127.0.0.1:0",
        ignore=set(),
        coerce_certs=True,
        seed_overrides=seed_overrides,
    )
    return values


def _omit_paths(params: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    """Return ``params`` with each dotted ``paths`` key removed (deep copy)."""
    out = json.loads(json.dumps(params))
    for path in paths:
        _delete_dotted(out, path)
    return out


def _delete_dotted(target: dict[str, Any], dotted_path: str) -> None:
    if not dotted_path:
        return
    parts = dotted_path.split(".")
    node: Any = target
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return
        node = node[part]
    if isinstance(node, dict):
        node.pop(parts[-1], None)


def run_old(
    integration_path: Path,
    yml_data: dict[str, Any],
    command: str,
    sentinel_map: SentinelMap,
    connection_name: str,
    proxy: CaptureProxy,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    seed_overrides: dict[str, Any] | None = None,
    integration_id: str | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> RunResult:
    """Execute the integration with sentinels seeded into ``demisto.params()``.

    UCP is forced **off** via on-disk patches injected into the child
    process bootstrap (§2.7.3).
    """
    base = _build_base_params(yml_data, seed_overrides=seed_overrides)
    params = build_old_params(sentinel_map, connection_name, base)
    return _execute_run(
        integration_path=integration_path,
        yml_data=yml_data,
        command=command,
        params=params,
        proxy=proxy,
        timeout=timeout,
        docker_cfg=docker_cfg,
        ucp_enabled=False,
        ucp_credentials=None,
        integration_id=integration_id,
        seed_args=seed_args,
    )


def run_new(
    integration_path: Path,
    yml_data: dict[str, Any],
    command: str,
    sentinel_map: SentinelMap,
    connection_name: str,
    auth_entry: AuthEntry,
    proxy: CaptureProxy,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    seed_overrides: dict[str, Any] | None = None,
    integration_id: str | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> RunResult:
    """Execute the integration with ``xsoar_param_map`` keys omitted and UCP on.

    UCP is forced **on**: ``demisto.getUCPCredentials`` is patched in
    the child to feed the sentinels through the UCP injection seam
    (this is the seam ``CommonServerPython.get_ucp_credentials()``
    delegates to, and also what integrations call directly when they
    bypass the CSP wrapper). The CSP-level :func:`is_ucp_enabled` and
    :func:`should_use_ucp_auth` flags are also patched as the branch
    selectors that decide whether the integration takes the UCP code
    path at all.
    """
    base = _build_base_params(yml_data, seed_overrides=seed_overrides)
    # The new run omits every XSOAR path that the connection's
    # xsoar_param_map names — i.e. every key the old run seeded with a
    # sentinel — so the integration is forced down the UCP injection
    # path for those secrets. (Pre-Commit-4 this read auth_entry.xsoar_params.)
    params = _omit_paths(base, list(auth_entry.xsoar_param_map.keys()))
    ucp_shape = map_auth_type_to_ucp_shape(
        auth_entry, sentinel_map.for_connection(connection_name)
    )
    return _execute_run(
        integration_path=integration_path,
        yml_data=yml_data,
        command=command,
        params=params,
        proxy=proxy,
        timeout=timeout,
        docker_cfg=docker_cfg,
        ucp_enabled=True,
        ucp_credentials=ucp_shape,
        integration_id=integration_id,
        seed_args=seed_args,
    )


def _execute_run(
    integration_path: Path,
    yml_data: dict[str, Any],
    command: str,
    params: dict[str, Any],
    proxy: CaptureProxy,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    ucp_enabled: bool,
    ucp_credentials: dict[str, Any] | None,
    integration_id: str | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> RunResult:
    """Shared run pipeline for old + new: prep content, exec child, read proxy."""
    # Belt-and-suspenders: BOTH the URL-rewrite seeder AND the env-var
    # seeder run unconditionally every run (see plan
    # plans/auth-parity-proxy-mitm-refactor.md §1 "we don't care how it
    # got here"). Either path lands the request at the same capture proxy.
    _seed_url_params(params, proxy.port, integration_id=integration_id)
    extra_env: dict[str, str] = {}
    _seed_proxy_env(params, extra_env, proxy.port, integration_id=integration_id)
    # Mount the proxy's cert dir into the child (so the in-Docker side
    # of the child can pin its TLS trust at the MITM cert if it wants).
    cert_dir = proxy.cert_dir()
    if cert_dir is not None:
        extra_env["AUTH_PARITY_CERT_DIR"] = str(cert_dir)
    session_id = proxy.new_session()
    with tempfile.TemporaryDirectory(prefix="auth_parity_") as raw_tmp:
        tmp = Path(raw_tmp)
        try:
            unified, mock_dir = _ccp.prepare_unified_content(integration_path, tmp)
        except _ccp.DynamicPrepError as exc:
            return _crashed_run(rc=-1, stderr=f"prepare-content failed: {exc}")
        _write_ucp_patch(mock_dir, ucp_enabled, ucp_credentials)
        # Provide a real on-disk file for file-upload commands. Such
        # commands resolve a war-room entry id via demisto.getFilePath()
        # and open() the returned path before issuing any HTTP request;
        # with the default empty mock path they crash on open() (a
        # file-resolution failure unrelated to auth placement). The mock's
        # getFilePath honors CHECK_FILE_PATH when set.
        upload_stub = tmp / "auth_parity_upload_stub.bin"
        upload_stub.write_bytes(b"auth-parity-upload-stub")
        extra_env["CHECK_FILE_PATH"] = str(upload_stub)
        proxy_url = f"http://127.0.0.1:{proxy.port}"
        # Seed demisto.args() from the command's YML ``arguments`` so
        # handlers with REQUIRED arguments (file ids, site ids, etc.) run
        # far enough to issue their HTTP request instead of crashing on a
        # missing arg before any call is made. Reuses the same arg-value
        # builder as check_command_params (YML defaultValue → first
        # predefined → SENTINEL_ARG_<name>).
        #
        # Only REQUIRED args are seeded. Optional args are deliberately
        # left unset so the handler takes its natural "argument absent"
        # path: seeding an optional arg that carries a format validator
        # (e.g. a ``next_page_url`` the integration asserts is a real URL)
        # with a sentinel string makes the command crash on arg
        # validation before any HTTP call — a false negative unrelated to
        # auth placement. Required args have no such "absent" path, so
        # they must be seeded for the handler to run at all.
        # Operator --seed-arg overrides (scoped to this command) are always
        # honored, even for optional args, so conditionally-required args
        # (e.g. a command that needs EITHER site_id OR next_page_url) can be
        # supplied to reach the HTTP call.
        cmd_seed_args = (seed_args or {}).get(command, {})
        all_command_args = _ccp.get_command_args(yml_data, command)
        args_to_seed = [
            a for a in all_command_args
            if a.get("required") or a.get("name") in cmd_seed_args
        ]
        command_args = _ccp.build_arg_values(
            args_to_seed, seed_args=cmd_seed_args
        )
        try:
            rc, stdout, stderr, timed_out = _ccp.run_integration(
                unified_path=unified,
                mock_dir=mock_dir,
                command=command,
                params=params,
                proxy_url=proxy_url,
                timeout=timeout,
                docker_cfg=docker_cfg,
                image=(docker_cfg.resolve_image_for(yml_data) if docker_cfg else None),
                args=command_args,
                extra_env=extra_env,
                extra_mounts=([(str(cert_dir), str(cert_dir), "ro")] if cert_dir else None),
            )
        except _ccp.DynamicAnalysisError as exc:
            return _crashed_run(rc=-1, stderr=f"docker error: {exc}")
    requests = proxy.get_requests(session_id)
    status = _classify_run(rc, timed_out, requests)
    return RunResult(
        status=status, rc=rc, stdout=stdout, stderr=stderr,
        timed_out=timed_out, requests=requests,
    )


def _crashed_run(rc: int, stderr: str) -> RunResult:
    return RunResult(
        status="crashed", rc=rc, stdout="", stderr=stderr,
        timed_out=False, requests=[],
    )


def _classify_run(rc: int, timed_out: bool, requests: list[dict[str, Any]]) -> str:
    if timed_out:
        return "crashed"
    # Non-zero RC means something went wrong, but if we still captured
    # requests the run is "ok" for parity purposes (the integration
    # made calls before whatever failed).
    if rc != 0 and not requests:
        return "crashed"
    if not requests:
        return "no_requests"
    return "ok"


# --------------------------------------------------------------------------
# UCP patching — extra bootstrap file written next to ``demistomock.py``
# --------------------------------------------------------------------------


_UCP_PATCH_TEMPLATE = textwrap.dedent(
    '''
    """Post-import UCP patch for the auth-parity test harness.

    The child bootstrap (in check_command_params._BOOTSTRAP_TEMPLATE)
    exec_modules the integration and then patches return_error. We
    extend it via a sitecustomize.py-style import side effect: this
    file is imported BEFORE the integration via PYTHONSTARTUP-like
    trickery — specifically, it is auto-imported by the integration's
    import chain because we put it on sys.path under a stable name.

    But because the auth-parity test does NOT control the bootstrap
    template (it lives in check_command_params), we instead rely on
    a thin shim: the harness writes ``ucp_patch.py`` next to
    ``demistomock.py`` and arranges for it to be imported once
    CommonServerPython is loaded, by replacing the ``DemistoClassApiModule``
    stub with one that imports ucp_patch.

    Patch strategy
    --------------
    We patch ``demisto.getUCPCredentials`` (the camel-case method on
    the ``demisto`` object exposed by ``demistomock``) because (a) it
    is what ``CommonServerPython.get_ucp_credentials()`` ultimately
    delegates to, and (b) it catches integrations that bypass the CSP
    wrapper and call ``demisto.getUCPCredentials(...)`` directly. A
    single low-level patch covers both call patterns.

    The CSP-level ``is_ucp_enabled`` / ``should_use_ucp_auth`` flags
    are NOT patched directly. They derive their value from the demisto
    object:

      * ``is_ucp_enabled()`` returns truthy iff
        ``demisto.unifiedConnectorMetadata()`` returns a truthy value
        — and we mock that below to return a non-empty profile dict,
        so ``is_ucp_enabled()`` naturally returns True.
      * ``should_use_ucp_auth()`` is ``is_ucp_enabled() and not
        _UCP_AUTH_PARAMS_INJECTED``. The module-level
        ``_UCP_AUTH_PARAMS_INJECTED`` flag defaults to False and
        nothing in production CSP flips it, so
        ``should_use_ucp_auth()`` is naturally True as well.

    The defensive loop below resets ``_UCP_AUTH_PARAMS_INJECTED`` to
    False on any module that happens to expose it — cheap insurance
    against a hypothetical future where some integration's
    import-time code flips that flag.

    When ``AUTH_PARITY_UCP_ENABLED`` is "0" (non-UCP run), we do
    NOT install ``demisto.getUCPCredentials`` at all — it stays
    whatever ``demistomock`` provides natively (or raises
    AttributeError), so non-UCP-path code that accidentally tries UCP
    fails the same way it would in real non-UCP execution.
    """
    import os as _os
    import json as _json
    import sys as _sys

    _UCP_ENABLED = _os.environ.get("AUTH_PARITY_UCP_ENABLED") == "1"
    _UCP_CREDS_JSON = _os.environ.get("AUTH_PARITY_UCP_CREDS", "")
    _UCP_CREDS = _json.loads(_UCP_CREDS_JSON) if _UCP_CREDS_JSON else None


    def apply_patches():
        # Defensive: ensure should_use_ucp_auth() isn't gated off by a
        # stray writer flipping _UCP_AUTH_PARAMS_INJECTED to True at
        # import time. In production CSP nothing flips it, but this is
        # cheap insurance and stays narrowly scoped to one flag.
        for _mod in list(_sys.modules.values()):
            if _mod is None:
                continue
            if hasattr(_mod, "_UCP_AUTH_PARAMS_INJECTED"):
                try:
                    _mod._UCP_AUTH_PARAMS_INJECTED = False
                except Exception:
                    pass

        # Credential fetcher on the demisto object. Only installed for
        # the new run (UCP enabled + creds provided). This is the
        # catch-all seam: CSP.get_ucp_credentials() delegates here, and
        # integrations that call demisto.getUCPCredentials directly
        # also hit this mock.
        if not _UCP_ENABLED or _UCP_CREDS is None:
            return
        import demistomock as demisto  # noqa: F401

        def _mock_get_ucp_credentials(method_unique_id, *args, **kwargs):  # noqa: ARG001
            return _UCP_CREDS

        demisto.getUCPCredentials = _mock_get_ucp_credentials  # type: ignore[attr-defined]

        # BOTH UCP seams need mocking, not just the credential fetcher.
        # CSP's _inject_ucp_credentials calls the chain
        #   _resolve_ucp_capability -> get_ucp_method_unique_id
        #     -> _get_ucp_profiles -> demisto.unifiedConnectorMetadata()
        # BEFORE it ever calls demisto.getUCPCredentials. The default
        # demistomock.unifiedConnectorMetadata() returns {}, which trips
        # the empty-check in CSP._get_ucp_profiles and raises
        # UcpException — short-circuiting the chain so getUCPCredentials
        # is never reached and the integration's _apply_ucp_* override
        # never fires. A single generic profile carrying a
        # method_unique_id satisfies all three resolution paths
        # (sub_capability / capability / fallback-first) in
        # CSP.get_ucp_method_unique_id, because none of them inspect the
        # method_unique_id itself — they only forward it to the (already
        # mocked) demisto.getUCPCredentials.
        #
        # As a bonus, this same mock is what makes CSP's
        # ``is_ucp_enabled()`` return True naturally (it's defined as
        # ``bool(demisto.unifiedConnectorMetadata())``), so we don't
        # need to patch that function directly.
        demisto.unifiedConnectorMetadata = lambda: {  # type: ignore[attr-defined]
            "connectionProfiles": [{"method_unique_id": "auth-parity-mock"}]
        }


    apply_patches()
    '''
).lstrip()


# Augmented DemistoClassApiModule that ALSO imports ucp_patch after
# preserving the seeded demisto. The unified .py file does
# ``from DemistoClassApiModule import *`` near the end of
# CommonServerPython; that import triggers our patch.
_DEMISTO_CLASS_API_MODULE_WITH_UCP = textwrap.dedent(
    '''
    """No-op DemistoClassApiModule that also installs the UCP patch."""
    import demistomock as demisto  # noqa: F401
    class Demisto:  # noqa: D401
        pass
    try:
        import ucp_patch  # noqa: F401
    except Exception:  # pragma: no cover — defensive
        pass
    '''
).lstrip()


def _write_ucp_patch(
    mock_dir: Path, ucp_enabled: bool, ucp_credentials: dict[str, Any] | None
) -> None:
    """Drop the UCP-patch sidecar and override DemistoClassApiModule.

    Sets two env vars consumed by ``ucp_patch.py`` at import time:
    ``AUTH_PARITY_UCP_ENABLED`` (``"1"`` or ``"0"``) and
    ``AUTH_PARITY_UCP_CREDS`` (JSON-encoded credential dict, empty when
    UCP is off).
    """
    (mock_dir / "ucp_patch.py").write_text(_UCP_PATCH_TEMPLATE, encoding="utf-8")
    (mock_dir / "DemistoClassApiModule.py").write_text(
        _DEMISTO_CLASS_API_MODULE_WITH_UCP, encoding="utf-8"
    )
    os.environ["AUTH_PARITY_UCP_ENABLED"] = "1" if ucp_enabled else "0"
    if ucp_enabled and ucp_credentials is not None:
        os.environ["AUTH_PARITY_UCP_CREDS"] = json.dumps(ucp_credentials)
    else:
        os.environ["AUTH_PARITY_UCP_CREDS"] = ""


# --------------------------------------------------------------------------
# §7 — orchestration
# --------------------------------------------------------------------------


def _connection_skip_status(
    entry: AuthEntry, py_source: str, yml_data: dict[str, Any],
    force_run: bool = False,
) -> str | None:
    """Return a ``skipped_*`` status for this entry, or ``None`` to run it.

    The ``interpolated`` and ``Passthrough``/``NoneRequired`` skips are
    intrinsic to the profile (there is genuinely nothing testable) and
    are honored even under ``force_run``. The ``skipped_signed`` /
    ``skipped_mtls`` heuristics, however, are static detections that
    fire on the *presence* of a signing import or a type:14 cert param
    anywhere in the integration — they wrongly suppress a perfectly
    testable non-cert/non-signed profile (e.g. an API-token profile on
    a Microsoft integration that also declares a cert-thumbprint slot).
    ``force_run`` overrides those two so the live run proceeds.
    """
    if entry.interpolated:
        return "skipped_interpolated"
    if entry.type in (AuthType.Passthrough, AuthType.NoneRequired):
        return "skipped_passthrough"
    if force_run:
        return None
    if detect_signed_auth(py_source):
        return "skipped_signed"
    if detect_mtls(yml_data):
        return "skipped_mtls"
    return None


def _per_command_result(
    run_old_result: RunResult,
    run_new_result: RunResult,
    sentinel_map: SentinelMap,
    connection_name: str,
    extra_sentinels: list[str],
    auth_entry: AuthEntry | None = None,
) -> dict[str, Any]:
    """Build the per-command result block (§5.2 diagnostics + status).

    Per §4.6 of the design, the user-visible identifier in each diff
    entry is still the **XSOAR path** (``"sentinel"`` field in the
    diff JSON), not the new role-encoded sentinel value — so the
    sentinels dict here is keyed by path. The role lives inside the
    sentinel string itself, available for grep but not the primary
    diff label.

    When ``auth_entry`` is supplied, the diffs are post-classified for
    the FIXES-TODO #13 UCP-strip-crash pattern: when the new run
    crashed with a ``KeyError`` on a key from the connection's
    ``xsoar_param_map``, or with a ``TypeError: 'NoneType' object is
    not subscriptable`` from a ``.get("credentials").get(...)`` chain,
    the generic ``RUN_FAILED_NEW`` code is replaced with the more
    specific ``UCP_STRIP_CRASHED_UNCONDITIONAL_READ``.
    """
    sentinels = dict(sentinel_map.path_to_value(connection_name))
    for extra in extra_sentinels:
        sentinels[f"__oauth_token__::{extra[-8:]}"] = extra

    old_locs = _per_sentinel_locations(run_old_result.requests, sentinels)
    new_locs = _per_sentinel_locations(run_new_result.requests, sentinels)
    diffs = _classify_command_diffs(sentinels, old_locs, new_locs)
    diffs.extend(_run_status_diffs(run_old_result, run_new_result))

    # FIXES-TODO #13 (LOCKED 2026-05-31): post-classify RUN_FAILED_NEW
    # for the UCP-strip-crash pattern. Detection only — no embedded
    # prescription (two valid fix paths exist per skill §1.12), only a
    # location pointer to the skill section.
    if auth_entry is not None:
        diffs = _reclassify_ucp_strip_crash(diffs, run_new_result, auth_entry)

    status = _command_status(run_old_result, run_new_result, diffs)
    return {
        "status": status,
        "diffs": [_diff_to_json(d) for d in diffs],
        "old_run": _run_to_json(run_old_result, old_locs),
        "new_run": _run_to_json(run_new_result, new_locs),
        "request_set_diff": _request_set_diff_to_json(
            compare_request_sets(run_old_result.requests, run_new_result.requests)
        ),
    }


# ---------------------------------------------------------------------------
# FIXES-TODO #13 — UCP-strip-crash post-classification
# ---------------------------------------------------------------------------

# Both crash signatures we recognize. Per the resolution's open-question
# answer, BOTH patterns are detected: the explicit KeyError and the
# TypeError-from-NoneType chain.
_UCP_KEYERROR_RE = re.compile(r"KeyError:\s*['\"]?(?P<key>[\w.\-]+)['\"]?")
_UCP_NONETYPE_RE = re.compile(
    r"TypeError:\s*['\"]?NoneType['\"]?\s+object\s+is\s+not\s+subscriptable",
    re.IGNORECASE,
)
_UCP_DOTGET_CRED_RE = re.compile(
    r"\.get\(\s*['\"]credentials['\"]\s*[,)]"
)


def _reclassify_ucp_strip_crash(
    diffs: list[Diff],
    new_run: RunResult,
    auth_entry: AuthEntry,
) -> list[Diff]:
    """Replace generic ``RUN_FAILED_NEW`` with the UCP-strip-specific code.

    Returns a (possibly modified) list of diffs. The original list is not
    mutated. The reclassification fires only when the new run crashed
    AND the stderr signature matches one of the recognized patterns AND
    the implicated key/chain is plausibly UCP-stripped (i.e. it appears
    in the connection's ``xsoar_param_map``).
    """
    if new_run.status != "crashed":
        return diffs
    if not any(d.failure_code == "RUN_FAILED_NEW" for d in diffs):
        return diffs

    stderr = new_run.stderr or ""
    matched = _detect_ucp_strip_crash_signature(stderr, auth_entry)
    if not matched:
        return diffs

    rewritten: list[Diff] = []
    for d in diffs:
        if d.failure_code == "RUN_FAILED_NEW":
            rewritten.append(
                Diff(
                    sentinel=d.sentinel,
                    failure_code="UCP_STRIP_CRASHED_UNCONDITIONAL_READ",
                    old_locations=d.old_locations,
                    new_locations=d.new_locations,
                )
            )
        else:
            rewritten.append(d)
    return rewritten


def _detect_ucp_strip_crash_signature(
    stderr: str, auth_entry: AuthEntry
) -> bool:
    """True when the new-run stderr matches the UCP-strip-crash pattern.

    Two recognized signatures:

    * **KeyError**: ``KeyError: 'identifier'`` (or any other XSOAR-path
      leaf) where the named key appears in the connection's
      ``xsoar_param_map``. Captures the AMPv2 case from the original
      finding.
    * **TypeError-from-NoneType chain**: ``TypeError: 'NoneType' object
      is not subscriptable`` paired with a ``.get("credentials")`` call
      in the same stderr block. Captures integrations that defensively
      use ``.get(...).get(...)`` chains but still crash when UCP strips
      the parent.
    """
    # Build the set of "interesting" keys: every leaf name appearing in
    # the connection's xsoar_param_map. For dotted paths
    # (``credentials.identifier``) we include both the full path and
    # each segment as candidates — different integrations crash at
    # different layers of the chain.
    candidates: set[str] = set()
    for path in (auth_entry.xsoar_param_map or {}).keys():
        if not path:
            continue
        candidates.add(path)
        for segment in path.split("."):
            if segment:
                candidates.add(segment)

    for m in _UCP_KEYERROR_RE.finditer(stderr):
        key = m.group("key")
        if key in candidates:
            return True

    if _UCP_NONETYPE_RE.search(stderr) and _UCP_DOTGET_CRED_RE.search(stderr):
        # The NoneType chain often unwinds without naming the
        # credentials key in the KeyError style, but the .get("credentials")
        # call appears in the traceback. That's the AMPv2-class shape.
        # Conservative trigger: only fire when xsoar_param_map mentions
        # 'credentials' so we don't surface this on unrelated NoneType
        # crashes.
        if any("credentials" in k for k in (auth_entry.xsoar_param_map or {})):
            return True
    return False


def _per_sentinel_locations(
    requests: list[dict[str, Any]], sentinels: dict[str, str]
) -> dict[str, set[Location]]:
    out: dict[str, set[Location]] = {key: set() for key in sentinels}
    for req in requests:
        for key, sentinel in sentinels.items():
            out[key].update(extract_sentinel_locations(req, sentinel))
    return out


def _classify_command_diffs(
    sentinels: dict[str, str],
    old_locs: dict[str, set[Location]],
    new_locs: dict[str, set[Location]],
) -> list[Diff]:
    diffs: list[Diff] = []
    for key in sentinels:
        for diff in compare_locations(old_locs.get(key, set()), new_locs.get(key, set())):
            diffs.append(
                Diff(
                    sentinel=key,
                    failure_code=diff.failure_code,
                    old_locations=diff.old_locations,
                    new_locations=diff.new_locations,
                )
            )
    return diffs


def _run_status_diffs(old: RunResult, new: RunResult) -> list[Diff]:
    diffs: list[Diff] = []
    if old.status == "crashed":
        diffs.append(Diff(sentinel="", failure_code="RUN_FAILED_OLD",
                          old_locations=[], new_locations=[]))
    if new.status == "crashed":
        diffs.append(Diff(sentinel="", failure_code="RUN_FAILED_NEW",
                          old_locations=[], new_locations=[]))
    if (old.status == "no_requests" and new.status == "no_requests"):
        diffs.append(Diff(sentinel="", failure_code="NO_REQUESTS_CAPTURED",
                          old_locations=[], new_locations=[]))
    return diffs


_INCONCLUSIVE_CODES = {
    "MISSING_IN_BOTH",
    "RUN_FAILED_OLD",
    "RUN_FAILED_NEW",
    "NO_REQUESTS_CAPTURED",
}
_FAIL_CODES = {"MISSING_IN_NEW", "EXTRA_IN_NEW", "WRONG_LOCATION"}


def _command_status(
    old: RunResult, new: RunResult, diffs: list[Diff]
) -> str:
    if any(d.failure_code in _FAIL_CODES for d in diffs):
        return "fail"
    if old.status == "crashed" or new.status == "crashed":
        return "inconclusive"
    if all(d.failure_code in _INCONCLUSIVE_CODES for d in diffs) and diffs:
        return "inconclusive"
    return "pass"


def _diff_to_json(diff: Diff) -> dict[str, Any]:
    return {
        "sentinel": diff.sentinel,
        "failure_code": diff.failure_code,
        "old_locations": diff.old_locations,
        "new_locations": diff.new_locations,
    }


def _run_to_json(
    run: RunResult, locations: dict[str, set[Location]]
) -> dict[str, Any]:
    return {
        "status": run.status,
        "captured_request_count": len(run.requests),
        "locations": {
            key: sorted(_loc_to_string(loc) for loc in locs)
            for key, locs in locations.items()
        },
        "stderr_excerpt": run.stderr[-500:],
    }


def _request_set_diff_to_json(diff: RequestSetDiff) -> dict[str, Any]:
    return {"only_in_old": diff.only_in_old, "only_in_new": diff.only_in_new}


def _connection_status(commands: dict[str, dict[str, Any]]) -> str:
    """Collapse per-command statuses into the connection-level status."""
    if not commands:
        return "inconclusive"
    statuses = {result["status"] for result in commands.values()}
    if "fail" in statuses:
        return "fail"
    if statuses == {"pass"}:
        return "pass"
    if "pass" in statuses and "inconclusive" in statuses:
        return "pass"
    return "inconclusive"


def check_connection_parity(
    integration_path: Path,
    yml_data: dict[str, Any],
    py_source: str,
    entry: AuthEntry,
    commands: list[str],
    sentinel_map: SentinelMap,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    seed_overrides: dict[str, Any] | None = None,
    integration_id: str | None = None,
    force_run: bool = False,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Run old + new for each command, collect diffs, classify status."""
    skip = _connection_skip_status(entry, py_source, yml_data, force_run=force_run)
    if skip is not None:
        return {"status": skip, "commands": {}, "diagnostics": {}}

    commands_block: dict[str, dict[str, Any]] = {}
    diagnostics_commands: dict[str, dict[str, Any]] = {}
    for command in commands:
        cmd_block, cmd_diag = _run_one_command(
            integration_path=integration_path,
            yml_data=yml_data,
            entry=entry,
            command=command,
            sentinel_map=sentinel_map,
            timeout=timeout,
            docker_cfg=docker_cfg,
            seed_overrides=seed_overrides,
            integration_id=integration_id,
            seed_args=seed_args,
        )
        commands_block[command] = {"status": cmd_block["status"]}
        diagnostics_commands[command] = cmd_diag

    return {
        "status": _connection_status(commands_block),
        "commands": commands_block,
        "diagnostics": {
            # Per §4.6 — diagnostics expose the XSOAR-path → sentinel
            # view (the user-facing identifier). The role lives inside
            # the sentinel value itself for grep-time attribution.
            "sentinels": dict(sentinel_map.path_to_value(entry.name)),
            "commands": diagnostics_commands,
        },
    }


def _run_one_command(
    integration_path: Path,
    yml_data: dict[str, Any],
    entry: AuthEntry,
    command: str,
    sentinel_map: SentinelMap,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    seed_overrides: dict[str, Any] | None = None,
    integration_id: str | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run old + new for one command — isolated per-command exception handling."""
    proxy = CaptureProxy(port=0)
    proxy.start()
    try:
        oauth_extra = _install_oauth_if_relevant(proxy, entry)
        try:
            old = run_old(
                integration_path, yml_data, command, sentinel_map,
                entry.name, proxy, timeout, docker_cfg,
                seed_overrides=seed_overrides,
                integration_id=integration_id,
                seed_args=seed_args,
            )
        except Exception as exc:  # noqa: BLE001 — per-command isolation
            old = _crashed_run(rc=-1, stderr=f"run_old exception: {exc}")
        try:
            new = run_new(
                integration_path, yml_data, command, sentinel_map,
                entry.name, entry, proxy, timeout, docker_cfg,
                seed_overrides=seed_overrides,
                integration_id=integration_id,
                seed_args=seed_args,
            )
        except Exception as exc:  # noqa: BLE001 — per-command isolation
            new = _crashed_run(rc=-1, stderr=f"run_new exception: {exc}")
        result = _per_command_result(
            old, new, sentinel_map, entry.name, oauth_extra,
            auth_entry=entry,
        )
        # ERROR_INTEGRATION_REJECTS_HTTP detection (§5.5) is raised by
        # the caller, not here — we just surface the stderr.
        return {"status": result["status"]}, result
    finally:
        proxy.stop()


def _install_oauth_if_relevant(proxy: CaptureProxy, entry: AuthEntry) -> list[str]:
    """When ``entry`` is OAuth2, install the canned token-exchange reply."""
    oauth_types = (
        AuthType.OAuth2ClientCreds,
        AuthType.OAuth2JWT,
    )
    if entry.type not in oauth_types:
        return []
    sentinel = install_oauth_token_wrapper(proxy, entry.name)
    return [sentinel]


# --------------------------------------------------------------------------
# Top-level orchestration
# --------------------------------------------------------------------------


# NOTE: This analyzer is intentionally stateless w.r.t. workflow_state.
# The orchestrator (the connectus-migration skill) reads the relevant
# pipeline cells once via ``workflow_state.py show-step --raw`` and
# passes their values in as CLI flags (``--auth-details`` /
# ``--auth-details-file``). Per-param value seeding for params the
# automatic placeholder generator misses (cert-thumbprint format
# validators, JWT secrets with format validation, OIDC issuer URLs,
# etc.) is supplied via repeatable ``--seed-param NAME=VALUE`` flags
# at the CLI; the analyzer does NOT consult the workflow_state
# ``Params for test with default in code`` cell. There is no
# ``show-step`` shell-out and no import of ``workflow_state`` anywhere
# in this file — the analyzer does not know about
# ``connectus-migration-pipeline.csv``.


def _select_commands(
    yml_data: dict[str, Any], cli_commands: list[str] | None
) -> list[str]:
    """Pick the command list per §1: start with ``test-module``, allow override."""
    if cli_commands:
        return list(cli_commands)
    discovered = _ccp.discover_commands(yml_data)
    if "test-module" in discovered:
        return ["test-module"]
    return discovered[:1] if discovered else []


def check_auth_parity(  # noqa: PLR0911 — many early-return hard-error gates
    integration_path: Path,
    integration_id: str,
    auth_details: Any,
    commands_filter: list[str] | None,
    connection_filter: str | None,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    display_name_override: str | None = None,
    seed_overrides: dict[str, Any] | None = None,
    force_run: bool = False,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """End-to-end orchestrator for one integration. Returns the §5.2 JSON.

    Inputs are injected by the caller (the migration skill / CLI); this
    function never consults ``workflow_state.py`` or the pipeline CSV.

    Args:
        integration_path: Filesystem directory of the integration.
        integration_id: Logical id, used for log/diagnostic messages and
            as a fallback for the ``integration`` field in stdout JSON.
        auth_details: Parsed ``Auth Details`` cell — either a dict
            matching the column schema, ``None`` (treated as
            "no auth"), or anything that
            :func:`validate_auth_details` will reject if malformed.
        commands_filter: Optional explicit command list (else the
            analyzer picks one per §1).
        connection_filter: Optional ``auth_types[].name`` to restrict
            the test to.
        timeout: Per-command wall-clock timeout (seconds).
        docker_cfg: Docker config.
        display_name_override: Optional human-readable name for the
            ``integration`` field. Falls back to ``yml['display']`` and
            then to ``integration_id``.
        seed_overrides: Optional per-param seed-value overrides
            (``{name: value}``), forwarded to
            :func:`check_command_params.build_param_values` for the
            type-aware placeholder pass. Use for params whose
            auto-generated placeholder trips a format validator the
            analyzer cannot sentinel itself (cert thumbprints, JWT
            secrets with format validation, OIDC issuer URLs, etc.).
            For YML ``type:9`` credentials widgets, the dotted-leaf
            form ``NAME.identifier`` / ``NAME.password`` is supported.
        force_run: When True, bypass the "cannot verify" structural
            gates (``ERROR_NO_BASECLIENT`` /
            ``APIMODULE_INTEGRATION_CANNOT_VERIFY`` /
            ``MULTI_SECRET_PASSTHROUGH``) and proceed with the live
            parity run anyway. This is the operator escape hatch for
            integrations the static detector wrongly flags as
            unverifiable — most notably ``*ApiModule``-based
            integrations (MicrosoftApiModule, OktaApiModule, …) whose
            ``Client`` subclasses ``BaseClient`` transitively and so
            never shows a literal ``BaseClient`` token in their own
            ``.py``. The ``ERROR_NON_PYTHON`` gate is NOT bypassed (a
            non-Python integration genuinely cannot be run by this
            harness).
    """
    yml_path, py_path = _ccp.find_integration_files(integration_path)
    yml_data = _ccp.load_yml(yml_path)
    display = display_name_override or _ccp.display_name(yml_data, integration_id)

    # Parse + validate Auth Details up front so the interpolation gate can
    # run before ANY "cannot verify" structural gate (non-python,
    # no-baseclient, apimodule, multi-secret-passthrough).
    errors = validate_auth_details(auth_details) if auth_details is not None else []
    if errors:
        raise ValueError(f"Invalid Auth Details for {integration_id}: {errors}")
    details = (
        parse_auth_details(auth_details) if auth_details is not None
        else _empty_details()
    )

    # ORDERING FIX (SplunkPy v2, 2026-06-03; extended to NON_PYTHON,
    # 2026-06-03): the all-interpolated short-circuit MUST run before EVERY
    # "cannot verify" structural gate — including the non-python gate below.
    # When EVERY auth type is interpolated there is genuinely nothing to
    # parity-test, so the integration takes the clean all-interpolated pass
    # path regardless of language or whether it uses BaseClient.
    #
    # Previously the no-baseclient gate fired first and pre-empted this, so a
    # fully-interpolated non-BaseClient integration (SplunkPy v2, which uses
    # splunklib) wrongly errored with ERROR_NO_BASECLIENT and the
    # ``interpolated: true`` flag was never evaluated. The original SplunkPy
    # fix moved this check above no-baseclient/apimodule/multi-secret but
    # left it BELOW the non-python check, so non-python (.js/.ps1)
    # integrations could never reach the all-interpolated path: marking them
    # ``interpolated: true`` (as the tool's own diagnostic instructs) had no
    # effect and they were un-committable. Hoisting the check above the
    # non-python gate restores the documented "mark interpolated -> clean
    # ALL_INTERPOLATED path" behavior for every language.
    #
    # The connection-filter interpolation check stays AFTER the structural
    # gates (see below) — it only matters once we know we have a
    # mixed/non-interpolated profile worth testing.
    if details.auth_types and all(e.interpolated for e in details.auth_types):
        return _emit_hard_error(
            display, ERROR_ALL_INTERPOLATED,
            _msg_all_interpolated(), EXIT_ALL_INTERPOLATED,
        )

    lang = detect_non_python(yml_data, py_path)
    if lang is not None:
        return _emit_hard_error(
            display, ERROR_NON_PYTHON, _msg_non_python(lang), EXIT_NON_PYTHON
        )
    assert py_path is not None  # narrowed by detect_non_python
    py_source = py_path.read_text(encoding="utf-8", errors="replace")

    # --force-run bypasses the no-baseclient / apimodule "cannot verify"
    # structural gate. The static detector textually scans the integration's
    # OWN .py for a ``BaseClient`` token; ``*ApiModule``-based integrations
    # (MicrosoftApiModule, OktaApiModule, …) inherit BaseClient transitively
    # through the ApiModule's Client class and so legitimately have no such
    # token, producing a false "cannot verify". When the operator knows the
    # integration is in fact BaseClient-backed, force_run lets the live run
    # proceed instead of short-circuiting.
    if not force_run and detect_no_baseclient(py_source):
        # FIXES-TODO #12 (LOCKED 2026-05-31): refine the diagnostic for
        # integrations whose ``Client`` subclasses a class defined in a
        # shared ``*ApiModule`` (MicrosoftApiModule, OktaApiModule, …).
        # The textual ``detect_no_baseclient`` triggers because the
        # ApiModule's class is imported under its own name, but the
        # integration IS using BaseClient transitively. Emit the more
        # specific code so the operator's path forward (mark
        # ``interpolated: true``) is unambiguous.
        apimodule = detect_apimodule_import(py_source)
        if apimodule:
            return _emit_hard_error(
                display,
                APIMODULE_INTEGRATION_CANNOT_VERIFY,
                _msg_apimodule_cannot_verify(apimodule),
                EXIT_APIMODULE_INTEGRATION_CANNOT_VERIFY,
            )
        return _emit_hard_error(
            display, ERROR_NO_BASECLIENT, _msg_no_baseclient(), EXIT_NO_BASECLIENT,
        )

    # FIXES-TODO #9 (LOCKED 2026-05-31): multi-secret Passthrough
    # structural skip. Per cross-cutting decision #2 (XOR-only auth),
    # multi-secret/multi-flow integrations like AbuseIPDB classify as
    # Passthrough; the gate explicitly says "by design, not a failure."
    # Runs AFTER the all-interpolated check (a fully-interpolated bundle is
    # the clean path and wins) but is otherwise a more specific diagnostic
    # than the per-connection interpolation gate below.
    multi_secret_keys = detect_multi_secret_passthrough(details)
    if not force_run and multi_secret_keys is not None:
        return _emit_hard_error(
            display, MULTI_SECRET_PASSTHROUGH,
            _msg_multi_secret_passthrough(multi_secret_keys),
            EXIT_MULTI_SECRET_PASSTHROUGH,
        )

    interp_check = _check_interpolation_hard_errors(
        display, details, connection_filter
    )
    if interp_check is not None:
        return interp_check

    sentinels = generate_sentinels(details)
    commands = _select_commands(yml_data, commands_filter)
    return _run_all_connections(
        display=display,
        integration_path=integration_path,
        yml_data=yml_data,
        py_source=py_source,
        details=details,
        sentinels=sentinels,
        commands=commands,
        connection_filter=connection_filter,
        timeout=timeout,
        docker_cfg=docker_cfg,
        seed_overrides=seed_overrides,
        force_run=force_run,
        seed_args=seed_args,
    )


def _empty_details() -> AuthDetails:
    """Return an empty ``AuthDetails`` for integrations with no Auth Details cell."""
    return AuthDetails(auth_types=[], other_connection=[])


def _check_interpolation_hard_errors(
    display: str, details: AuthDetails, connection_filter: str | None
) -> dict[str, Any] | None:
    """Apply the ERROR_ALL_INTERPOLATED + ERROR_CONNECTION_INTERPOLATED gates."""
    if details.auth_types and all(e.interpolated for e in details.auth_types):
        return _emit_hard_error(
            display, ERROR_ALL_INTERPOLATED,
            _msg_all_interpolated(), EXIT_ALL_INTERPOLATED,
        )
    if connection_filter is not None:
        for entry in details.auth_types:
            if entry.name == connection_filter and entry.interpolated:
                return _emit_hard_error(
                    display, ERROR_CONNECTION_INTERPOLATED,
                    _msg_connection_interpolated(connection_filter),
                    EXIT_CONNECTION_INTERPOLATED,
                )
    return None


def _run_all_connections(
    display: str,
    integration_path: Path,
    yml_data: dict[str, Any],
    py_source: str,
    details: AuthDetails,
    sentinels: SentinelMap,
    commands: list[str],
    connection_filter: str | None,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    seed_overrides: dict[str, Any] | None = None,
    force_run: bool = False,
    seed_args: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Iterate over auth entries, collect per-connection results."""
    auth_parity: dict[str, Any] = {}
    diagnostics: dict[str, Any] = {}
    rejected_http = False
    for entry in details.auth_types:
        if connection_filter is not None and entry.name != connection_filter:
            continue
        per_conn = check_connection_parity(
            integration_path=integration_path,
            yml_data=yml_data,
            py_source=py_source,
            entry=entry,
            commands=commands,
            sentinel_map=sentinels,
            timeout=timeout,
            docker_cfg=docker_cfg,
            seed_overrides=seed_overrides,
            integration_id=display,
            force_run=force_run,
            seed_args=seed_args,
        )
        auth_parity[entry.name] = {
            "status": per_conn["status"], "commands": per_conn["commands"],
        }
        diagnostics[entry.name] = per_conn["diagnostics"]
        if _connection_rejects_http(per_conn["diagnostics"]):
            rejected_http = True
    if rejected_http:
        return _emit_hard_error(
            display, ERROR_INTEGRATION_REJECTS_HTTP,
            _msg_integration_rejects_http(), EXIT_INTEGRATION_REJECTS_HTTP,
        )
    return {
        "integration": display,
        "auth_parity": auth_parity,
        "diagnostics": diagnostics,
    }


def _connection_rejects_http(diagnostics: dict[str, Any]) -> bool:
    """Inspect per-command stderr for the §6.4.2 HTTP-rejection signature."""
    for cmd_diag in diagnostics.get("commands", {}).values():
        old = cmd_diag.get("old_run") or {}
        if detect_integration_rejects_http(str(old.get("stderr_excerpt", ""))):
            return True
    return False


# --------------------------------------------------------------------------
# CLI surface (§5.1)
# --------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auth Parity Test — verify non-UCP vs UCP secret placement parity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("integration_path", help="Path to the integration directory.")
    parser.add_argument(
        "--integration-id", required=True,
        help=(
            "Integration ID. Used as an identifier in the output JSON and "
            "in log messages. NOT used to look up workflow state — the "
            "orchestrator passes the Auth Details cell in via "
            "--auth-details / --auth-details-file below."
        ),
    )

    # Auth Details cell — mandatory; either inline JSON or a file. Use
    # '-' to read inline JSON from stdin. The analyzer hard-rejects
    # both being missing (no silent default).
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        "--auth-details", default=None,
        help=(
            "Raw JSON of the 'Auth Details' cell, as a single string. "
            "Pass '-' to read from stdin. Mutually exclusive with "
            "--auth-details-file. Empty input is a hard error."
        ),
    )
    auth_group.add_argument(
        "--auth-details-file", default=None,
        help=(
            "Path to a file whose contents are the raw JSON of the "
            "'Auth Details' cell. Mutually exclusive with --auth-details. "
            "Empty file is a hard error."
        ),
    )

    # Per-param seed-value overrides — repeatable escape hatch for
    # params whose auto-generated placeholder trips a format validator
    # the analyzer's own coercion (cert/key/thumbprint) cannot
    # anticipate (e.g. JWT secrets with format validation, OIDC issuer
    # URLs, custom hex/regex-validated tokens).
    parser.add_argument(
        "--seed-param",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "Explicitly seed YML param NAME with VALUE for the parity "
            "run's baseline params, overriding the YML defaultvalue, "
            "the cert/key/thumbprint auto-coercion, and the generic "
            "SENTINEL_PARAM_<name> string. Repeatable: pass once per "
            "param. Use this when the analyzer's automatic seeding "
            "still trips a format validator at module load (cert "
            "thumbprints, JWT secrets with format validation, OIDC "
            "issuer URLs, etc.). For YML type:9 (credentials) widgets, "
            "use the dotted-leaf form NAME.identifier=<v> / "
            "NAME.password=<v> (either leaf may be omitted; omitted "
            "leaves keep their default sentinel). Flat NAME=VALUE on a "
            "credentials widget is rejected with exit code 2. Stray "
            "dotted-leaf overrides (unknown parent, wrong-type parent, "
            "leaf not in {identifier, password}) surface as "
            "[seed] WARNING lines on stderr and do NOT abort the run. "
            "The skill (connectus/connectus-migration-SKILL.md §1.12) "
            "documents the recovery loop. Mirrors the same flag on "
            "check_command_params.py verbatim."
        ),
    )

    parser.add_argument(
        "--display-name", default=None,
        help=(
            "Human-readable integration name for the top-level "
            "'integration' field in the output JSON. Falls back to the "
            "YML 'display' field, then to --integration-id."
        ),
    )

    parser.add_argument("--commands", nargs="+", default=None)
    parser.add_argument("--connection", default=None,
                        help="Restrict the test to one auth_types[].name.")
    parser.add_argument(
        "--force-run", action="store_true",
        help=(
            "Bypass the 'cannot verify' structural gates "
            "(ERROR_NO_BASECLIENT / APIMODULE_INTEGRATION_CANNOT_VERIFY / "
            "MULTI_SECRET_PASSTHROUGH) and run the live parity test anyway. "
            "Use for integrations the static detector wrongly flags as "
            "unverifiable, e.g. *ApiModule-based integrations "
            "(MicrosoftApiModule, OktaApiModule, ...) whose Client "
            "subclasses BaseClient transitively. The ERROR_NON_PYTHON gate "
            "is never bypassed."
        ),
    )
    parser.add_argument(
        "--seed-arg",
        action="append",
        default=None,
        metavar="CMD:NAME=VALUE",
        help=(
            "Seed a single command argument value for the parity run, "
            "scoped to one command. Repeatable. Required YML arguments are "
            "auto-seeded already; use this for conditionally-required "
            "arguments (e.g. a command that needs EITHER site_id OR "
            "next_page_url) or to override an auto-seeded value so the "
            "handler runs far enough to issue its HTTP request. Mirrors the "
            "same flag on check_command_params.py. Example: "
            "--seed-arg msgraph-list-drives-in-site:site_id=test-site-id"
        ),
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--docker", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--docker-image", default=_ccp.DEFAULT_DOCKER_IMAGE)
    parser.add_argument("--use-integration-docker", action="store_true")
    return parser.parse_args(argv)


def _read_cell_input(
    inline: str | None,
    file_path: str | None,
    *,
    cell_name: str,
    required: bool,
) -> str:
    """Read a workflow-state cell value from one of the CLI sources.

    Returns the raw text (post-strip). Reads stdin when ``inline == '-'``.

    Args:
        inline: The ``--X`` flag value (or ``None``).
        file_path: The ``--X-file`` flag value (or ``None``).
        cell_name: Human-readable name for error messages.
        required: When True, an empty post-strip result is a SystemExit.

    Raises:
        SystemExit(2): If both args are None and ``required`` is True,
            if the file does not exist, or if the result is empty and
            ``required`` is True.
    """
    if inline is None and file_path is None:
        if required:
            sys.stderr.write(
                f"error: {cell_name} input is required "
                f"(pass --{cell_name.replace(' ', '-')} or "
                f"--{cell_name.replace(' ', '-')}-file)\n"
            )
            sys.exit(2)
        return ""

    if inline is not None:
        text = sys.stdin.read() if inline == "-" else inline
    else:
        assert file_path is not None  # mutex group guarantees this
        path = Path(file_path)
        if not path.is_file():
            sys.stderr.write(f"error: {cell_name} file not found: {file_path}\n")
            sys.exit(2)
        text = path.read_text(encoding="utf-8")

    text = text.strip()
    if required and not text:
        sys.stderr.write(
            f"error: {cell_name} input is empty; expected raw JSON\n"
        )
        sys.exit(2)
    return text


def _parse_auth_details_input(args: argparse.Namespace) -> Any:
    """Read + JSON-parse the Auth Details input from the CLI."""
    text = _read_cell_input(
        args.auth_details, args.auth_details_file,
        cell_name="auth-details", required=True,
    )
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: --auth-details is not valid JSON: {exc}\n")
        sys.exit(2)


def _exit_code_for(result: dict[str, Any]) -> int:
    """Pick the process exit code from the result envelope.

    AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): the all-interpolated
    envelope is the ONLY clean fallback for the workflow_state gate — when
    every auth is interpolated there is genuinely nothing to parity-test and
    the standalone CLI must exit 0 so the gate's "all-interpolated clean path"
    is observable from the process exit code as well as the envelope.

    This is intentionally a special-case here rather than a change to the
    ``EXIT_ALL_INTERPOLATED`` constant: other callers (and the
    ``error.exit_code`` field carried in the envelope) may still depend on the
    distinct ``12`` value, so the constant is preserved. Every "cannot verify"
    code (APIMODULE_INTEGRATION_CANNOT_VERIFY, ERROR_NO_BASECLIENT,
    ERROR_NON_PYTHON, ERROR_INTEGRATION_REJECTS_HTTP, MULTI_SECRET_PASSTHROUGH,
    ERROR_CONNECTION_INTERPOLATED) keeps its non-zero exit code.
    """
    error = result.get("error")
    if isinstance(error, dict):
        if str(error.get("code") or "") == ERROR_ALL_INTERPOLATED:
            return 0
        return int(error.get("exit_code") or 1)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point — emits a single JSON object on stdout.

    Per-param seed-value overrides may be supplied via repeatable
    ``--seed-param NAME=VALUE``; see :func:`check_auth_parity` for the
    semantics and the dotted-leaf rules for ``type:9`` credentials.
    """
    # Auto-apply the DEMISTO_SDK_LOG_FILE_PATH workaround at the earliest
    # possible point (FIXES-TODO #2). Belt-and-suspenders: the same call
    # also fires inside ``_ccp.prepare_unified_content``; calling here
    # first ensures the env var is present even for code paths that read
    # ``os.environ['DEMISTO_SDK_LOG_FILE_PATH']`` before they spawn the
    # ``demisto-sdk`` subprocess.
    _ccp._ensure_demisto_sdk_log_path()
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    integration_path = _resolve_integration_path(args.integration_path)
    if integration_path is None or not integration_path.is_dir():
        # Show the cwd-relative resolution in the error (the most likely
        # user expectation) plus the repo-root candidate we also tried.
        tried_cwd = Path(args.integration_path).resolve()
        result = {
            "integration": args.display_name or args.integration_id,
            "error": {
                "code": "ERROR_BAD_PATH",
                "message": (
                    f"Not a directory: {tried_cwd} "
                    f"(also tried repo-root-relative). Pass a path that "
                    f"exists relative to the current directory OR relative "
                    f"to the content repo root (e.g. "
                    f"'Packs/<Pack>/Integrations/<Name>')."
                ),
                "exit_code": 2,
            },
        }
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 2

    # Parse the injected Auth Details cell. Calls sys.exit(2) on bad
    # input — by design, since the orchestrator should pass valid cell
    # values (the workflow_state validators already vetted them at
    # write time).
    auth_details = _parse_auth_details_input(args)

    # Parse repeatable --seed-param NAME=VALUE flags (mirrors the same
    # parser/validation in check_command_params.py).
    try:
        seed_overrides = _ccp.parse_seed_overrides(args.seed_param)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    # Parse repeatable --seed-arg CMD:NAME=VALUE flags (mirrors the same
    # parser in check_command_params.py).
    try:
        seed_args = _ccp.parse_seed_args(args.seed_arg)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    docker_cfg = _ccp.DockerConfig(
        mode=args.docker, default_image=args.docker_image,
        use_integration_docker=args.use_integration_docker,
    )
    try:
        result = check_auth_parity(
            integration_path=integration_path,
            integration_id=args.integration_id,
            auth_details=auth_details,
            commands_filter=args.commands,
            connection_filter=args.connection,
            timeout=args.timeout,
            docker_cfg=docker_cfg,
            display_name_override=args.display_name,
            seed_overrides=seed_overrides,
            force_run=args.force_run,
            seed_args=seed_args,
        )
    except ValueError as exc:
        # build_param_values raises ValueError for operator-input
        # misuse (specifically: flat NAME=VALUE on a type=9 credentials
        # widget). Surface as a CLI-arg error (rc=2).
        sys.stderr.write(f"error: {exc}\n")
        result = {
            "integration": args.display_name or args.integration_id,
            "error": {
                "code": "ERROR_SEED_PARAM_INVALID",
                "message": f"{exc}",
                "exit_code": 2,
            },
        }
        json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
        sys.stdout.write("\n")
        return 2
    except Exception as exc:  # noqa: BLE001 — top-level guard
        import traceback
        traceback.print_exc(file=sys.stderr)
        result = {
            "integration": args.display_name or args.integration_id,
            "error": {
                "code": "ERROR_UNHANDLED",
                "message": f"{type(exc).__name__}: {exc}",
                "exit_code": 3,
            },
        }
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return _exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())

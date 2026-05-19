"""Auth Parity Test analyzer.

Verifies that for each non-interpolated connection declared in an
integration's ``Auth Details``, secret values land in the **same
wire location** whether they are supplied the legacy way (via
``demisto.params()`` → integration code → ``BaseClient``) or the
new way (UCP credential injection through
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


# --------------------------------------------------------------------------
# Constants — error codes (§5.5) and exit codes
# --------------------------------------------------------------------------

ERROR_NON_PYTHON = "ERROR_NON_PYTHON"
ERROR_NO_BASECLIENT = "ERROR_NO_BASECLIENT"
ERROR_ALL_INTERPOLATED = "ERROR_ALL_INTERPOLATED"
ERROR_CONNECTION_INTERPOLATED = "ERROR_CONNECTION_INTERPOLATED"
ERROR_INTEGRATION_REJECTS_HTTP = "ERROR_INTEGRATION_REJECTS_HTTP"

EXIT_NON_PYTHON = 10
EXIT_NO_BASECLIENT = 11
EXIT_ALL_INTERPOLATED = 12
EXIT_CONNECTION_INTERPOLATED = 13
EXIT_INTEGRATION_REJECTS_HTTP = 14

# Parseable substrings the migration skill greps for. Do NOT reword.
_LITERAL_MARK_AUTH = "Mark its auth as interpolated"
_LITERAL_MARKPASS_STEP_11 = (
    "Step #11 (auth parity test passes) is effectively migrated — markpass."
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
    ``None`` for :data:`AuthType.Other` and :data:`AuthType.NoneRequired`
    (no synthesizable shape — handled as skips by the caller).

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
        case AuthType.OAuth2ClientCreds | AuthType.OAuth2AuthCode | AuthType.OAuth2JWT:
            return _ucp_shape_oauth2(entry, sentinels)
        case AuthType.Other:
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


def _msg_all_interpolated() -> str:
    return (
        f"All auth types are interpolated. Auth parity test is not "
        f"applicable — interpolated connections are handled by "
        f"infrastructure, not integration code. {_LITERAL_MARKPASS_STEP_11}"
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


def _seed_url_params(params: dict[str, Any], proxy_port: int) -> None:
    """Apply §2.7.2 URL-rewrite + insecure flag in-place."""
    params["url"] = f"http://127.0.0.1:{proxy_port}"
    params["insecure"] = True


def _build_base_params(
    yml_data: dict[str, Any],
    param_defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a baseline ``demisto.params()`` dict for the integration.

    Per design §2.4 the value precedence for a non-auth required YML
    param is:

    1. The ``Params for test with default in code`` cell — values are
       used **verbatim** (any JSON type the cell allows).
    2. A type-aware placeholder from
       :func:`check_command_params.build_param_values` — fallback only
       for params not covered by the cell.

    Auth params are overlaid by :func:`build_old_params` or omitted
    entirely in the new run. The proxy URL is a placeholder that
    :func:`_seed_url_params` overwrites once the proxy is up.

    ``param_defaults`` keys that do not correspond to a visible YML
    param are ignored (the cell is treated as a hint set, not a strict
    schema — stray keys must not crash the analyzer).
    """
    yml_params = _ccp.get_yml_params(yml_data)
    values, _, _ = _ccp.build_param_values(
        yml_params=yml_params,
        proxy_url="http://127.0.0.1:0",
        ignore=set(),
        coerce_certs=True,
        seed_overrides=None,
    )
    if param_defaults:
        for name, override in param_defaults.items():
            if name in values:
                values[name] = override
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
    param_defaults: dict[str, Any] | None = None,
) -> RunResult:
    """Execute the integration with sentinels seeded into ``demisto.params()``.

    UCP is forced **off** via on-disk patches injected into the child
    process bootstrap (§2.7.3).
    """
    base = _build_base_params(yml_data, param_defaults=param_defaults)
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
    param_defaults: dict[str, Any] | None = None,
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
    base = _build_base_params(yml_data, param_defaults=param_defaults)
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
) -> RunResult:
    """Shared run pipeline for old + new: prep content, exec child, read proxy."""
    _seed_url_params(params, proxy.port)
    session_id = proxy.new_session()
    with tempfile.TemporaryDirectory(prefix="auth_parity_") as raw_tmp:
        tmp = Path(raw_tmp)
        try:
            unified, mock_dir = _ccp.prepare_unified_content(integration_path, tmp)
        except _ccp.DynamicPrepError as exc:
            return _crashed_run(rc=-1, stderr=f"prepare-content failed: {exc}")
        _write_ucp_patch(mock_dir, ucp_enabled, ucp_credentials)
        proxy_url = f"http://127.0.0.1:{proxy.port}"
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
    remain patched here because they are the **branch selectors** the
    integration code uses to decide whether to take the UCP path at
    all — they are NOT credential fetchers. Only the demisto-object
    mock fetches credentials in this harness.

    When ``AUTH_PARITY_UCP_ENABLED`` is "0" (old / legacy run), we do
    NOT install ``demisto.getUCPCredentials`` at all — it stays
    whatever ``demistomock`` provides natively (or raises
    AttributeError), so legacy-path code that accidentally tries UCP
    fails the same way it would in real legacy execution.
    """
    import os as _os
    import json as _json
    import sys as _sys

    _UCP_ENABLED = _os.environ.get("AUTH_PARITY_UCP_ENABLED") == "1"
    _UCP_CREDS_JSON = _os.environ.get("AUTH_PARITY_UCP_CREDS", "")
    _UCP_CREDS = _json.loads(_UCP_CREDS_JSON) if _UCP_CREDS_JSON else None


    def apply_patches():
        # Branch selectors — these decide whether the integration's code
        # takes the UCP code path at all. They are NOT credential fetchers;
        # the credential fetcher is the demisto.getUCPCredentials mock
        # installed below.
        #
        # In production the integration imports CommonServerPython as a
        # separate module, but the parity harness concatenates CSP into the
        # unified file and loads it under the module name
        # "integration_under_test" (see check_command_params._BOOTSTRAP_TEMPLATE
        # and prepare_unified_content). So sys.modules["CommonServerPython"]
        # is None in the child, and a CSP-only lookup would silently no-op.
        #
        # Patch every loaded module that exposes BOTH flags. In the child
        # that's exactly the unified module; in production it's CSP. Either
        # way, the namespace where BaseClient._http_request resolves these
        # functions gets overridden.
        patched_modules = 0
        for _mod in list(_sys.modules.values()):
            if _mod is None:
                continue
            if hasattr(_mod, "is_ucp_enabled") and hasattr(_mod, "should_use_ucp_auth"):
                _mod.is_ucp_enabled = lambda *a, **k: _UCP_ENABLED
                _mod.should_use_ucp_auth = lambda *a, **k: _UCP_ENABLED
                patched_modules += 1
        if patched_modules == 0:
            # Be loud — silent no-op here is exactly the regression that
            # caused the post-Commit-6 APIVoid parity failure.
            import sys as _sys_err
            print(
                "[ucp_patch] WARNING: no module exposed both is_ucp_enabled "
                "and should_use_ucp_auth; UCP branch will stay disabled.",
                file=_sys_err.stderr,
            )

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

        # H8c fix: BOTH UCP seams need mocking, not just the credential
        # fetcher. CSP's _inject_ucp_credentials calls the chain
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
    entry: AuthEntry, py_source: str, yml_data: dict[str, Any]
) -> str | None:
    """Return a ``skipped_*`` status for this entry, or ``None`` to run it."""
    if entry.interpolated:
        return "skipped_interpolated"
    if entry.type in (AuthType.Other, AuthType.NoneRequired):
        return "skipped_other_type"
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
) -> dict[str, Any]:
    """Build the per-command result block (§5.2 diagnostics + status).

    Per §4.6 of the design, the user-visible identifier in each diff
    entry is still the **XSOAR path** (``"sentinel"`` field in the
    diff JSON), not the new role-encoded sentinel value — so the
    sentinels dict here is keyed by path. The role lives inside the
    sentinel string itself, available for grep but not the primary
    diff label.
    """
    sentinels = dict(sentinel_map.path_to_value(connection_name))
    for extra in extra_sentinels:
        sentinels[f"__oauth_token__::{extra[-8:]}"] = extra

    old_locs = _per_sentinel_locations(run_old_result.requests, sentinels)
    new_locs = _per_sentinel_locations(run_new_result.requests, sentinels)
    diffs = _classify_command_diffs(sentinels, old_locs, new_locs)
    diffs.extend(_run_status_diffs(run_old_result, run_new_result))

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
    param_defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run old + new for each command, collect diffs, classify status."""
    skip = _connection_skip_status(entry, py_source, yml_data)
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
            param_defaults=param_defaults,
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
    param_defaults: dict[str, Any] | None = None,
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
                param_defaults=param_defaults,
            )
        except Exception as exc:  # noqa: BLE001 — per-command isolation
            old = _crashed_run(rc=-1, stderr=f"run_old exception: {exc}")
        try:
            new = run_new(
                integration_path, yml_data, command, sentinel_map,
                entry.name, entry, proxy, timeout, docker_cfg,
                param_defaults=param_defaults,
            )
        except Exception as exc:  # noqa: BLE001 — per-command isolation
            new = _crashed_run(rc=-1, stderr=f"run_new exception: {exc}")
        result = _per_command_result(
            old, new, sentinel_map, entry.name, oauth_extra,
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
        AuthType.OAuth2AuthCode,
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
# ``--auth-details-file`` and ``--param-defaults`` /
# ``--param-defaults-file``). There is no ``show-step`` shell-out and
# no import of ``workflow_state`` anywhere in this file — the analyzer
# does not know about ``connectus-migration-pipeline.csv``.


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
    param_defaults: dict[str, Any],
    commands_filter: list[str] | None,
    connection_filter: str | None,
    timeout: int,
    docker_cfg: _ccp.DockerConfig | None,
    display_name_override: str | None = None,
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
        param_defaults: Parsed ``Params for test with default in code``
            cell — a dict of ``param_id -> default_value``. Empty dict
            for integrations with no overrides.
        commands_filter: Optional explicit command list (else the
            analyzer picks one per §1).
        connection_filter: Optional ``auth_types[].name`` to restrict
            the test to.
        timeout: Per-command wall-clock timeout (seconds).
        docker_cfg: Docker config.
        display_name_override: Optional human-readable name for the
            ``integration`` field. Falls back to ``yml['display']`` and
            then to ``integration_id``.
    """
    yml_path, py_path = _ccp.find_integration_files(integration_path)
    yml_data = _ccp.load_yml(yml_path)
    display = display_name_override or _ccp.display_name(yml_data, integration_id)

    lang = detect_non_python(yml_data, py_path)
    if lang is not None:
        return _emit_hard_error(
            display, ERROR_NON_PYTHON, _msg_non_python(lang), EXIT_NON_PYTHON
        )
    assert py_path is not None  # narrowed by detect_non_python
    py_source = py_path.read_text(encoding="utf-8", errors="replace")
    if detect_no_baseclient(py_source):
        return _emit_hard_error(
            display, ERROR_NO_BASECLIENT, _msg_no_baseclient(), EXIT_NO_BASECLIENT,
        )

    errors = validate_auth_details(auth_details) if auth_details is not None else []
    if errors:
        raise ValueError(f"Invalid Auth Details for {integration_id}: {errors}")
    details = (
        parse_auth_details(auth_details) if auth_details is not None
        else _empty_details()
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
        param_defaults=param_defaults,
    )


def _empty_details() -> AuthDetails:
    """Return an empty ``AuthDetails`` for integrations with no Auth Details cell."""
    from auth_config_parser.types import ConfigExpression
    return AuthDetails(auth_types=[], config=ConfigExpression(none_required=True))


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
    param_defaults: dict[str, Any] | None = None,
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
            param_defaults=param_defaults,
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
        description="Auth Parity Test — verify legacy vs UCP secret placement parity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("integration_path", help="Path to the integration directory.")
    parser.add_argument(
        "--integration-id", required=True,
        help=(
            "Integration ID. Used as an identifier in the output JSON and "
            "in log messages. NOT used to look up workflow state — the "
            "orchestrator passes the cells in via --auth-details / "
            "--param-defaults below."
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

    # Params for test with default in code cell — optional; defaults
    # to {} when neither flag is supplied.
    defaults_group = parser.add_mutually_exclusive_group()
    defaults_group.add_argument(
        "--param-defaults", default=None,
        help=(
            "Raw JSON of the 'Params for test with default in code' cell. "
            "Pass '-' to read from stdin. Mutually exclusive with "
            "--param-defaults-file. Empty input is treated as '{}'."
        ),
    )
    defaults_group.add_argument(
        "--param-defaults-file", default=None,
        help=(
            "Path to a file whose contents are the raw JSON of the "
            "'Params for test with default in code' cell. Mutually "
            "exclusive with --param-defaults. Empty file is treated as '{}'."
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


def _parse_param_defaults_input(args: argparse.Namespace) -> dict[str, Any]:
    """Read + JSON-parse the Param Defaults input; '{}' if empty/missing."""
    text = _read_cell_input(
        args.param_defaults, args.param_defaults_file,
        cell_name="param-defaults", required=False,
    )
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: --param-defaults is not valid JSON: {exc}\n")
        sys.exit(2)
    if not isinstance(parsed, dict):
        sys.stderr.write(
            f"error: --param-defaults must be a JSON object, got "
            f"{type(parsed).__name__}\n"
        )
        sys.exit(2)
    return parsed


def _exit_code_for(result: dict[str, Any]) -> int:
    """Pick the process exit code from the result envelope."""
    error = result.get("error")
    if isinstance(error, dict):
        return int(error.get("exit_code") or 1)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point — emits a single JSON object on stdout."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    integration_path = Path(args.integration_path).resolve()
    if not integration_path.is_dir():
        result = {
            "integration": args.display_name or args.integration_id,
            "error": {
                "code": "ERROR_BAD_PATH",
                "message": f"Not a directory: {integration_path}",
                "exit_code": 2,
            },
        }
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 2

    # Parse injected cells from the CLI. These call sys.exit(2) on
    # bad input — by design, since the orchestrator should pass valid
    # cell values (the workflow_state validators already vetted them
    # at write time).
    auth_details = _parse_auth_details_input(args)
    param_defaults = _parse_param_defaults_input(args)

    docker_cfg = _ccp.DockerConfig(
        mode=args.docker, default_image=args.docker_image,
        use_integration_docker=args.use_integration_docker,
    )
    try:
        result = check_auth_parity(
            integration_path=integration_path,
            integration_id=args.integration_id,
            auth_details=auth_details,
            param_defaults=param_defaults,
            commands_filter=args.commands,
            connection_filter=args.connection,
            timeout=args.timeout,
            docker_cfg=docker_cfg,
            display_name_override=args.display_name,
        )
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

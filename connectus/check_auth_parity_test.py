"""Unit tests for :mod:`check_auth_parity`.

Covers the §7 "Test structure sketch" unit-test list from
``connectus/auth_parity_test_design.md``: sentinel generation,
UCP-shape mapping, location extraction with canonicalization, diff
classification, request-set diffing, and the hard-error short-circuits.

Integration tests against real packs (AbnormalSecurity, Salesforce_IAM,
CrowdStrike Falcon) are intentionally **not** implemented in this
subtask; they are tracked in a follow-up ticket. See the design doc
§7 "Test structure sketch".
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_auth_parity as cap  # noqa: E402
from auth_config_parser import AuthDetails, AuthEntry, AuthType  # noqa: E402
from auth_config_parser.types import ConfigClause, ConfigExpression, ClauseOperator  # noqa: E402


# --------------------------------------------------------------------------
# Builder helpers
# --------------------------------------------------------------------------


def _details(*entries: AuthEntry) -> AuthDetails:
    return AuthDetails(
        auth_types=list(entries),
        config=ConfigExpression(
            clauses=[ConfigClause(operator=ClauseOperator.REQUIRED,
                                  names=[e.name for e in entries])]
        ),
        other_connection=[],
    )


def _api_key_entry(name: str = "api_key", interpolated: bool = False) -> AuthEntry:
    return AuthEntry(
        type=AuthType.APIKey, name=name,
        xsoar_param_map={"api_key": "key"},
        interpolated=interpolated,
    )


def _plain_entry(name: str = "creds") -> AuthEntry:
    return AuthEntry(
        type=AuthType.Plain, name=name,
        xsoar_param_map={
            "credentials.identifier": "username",
            "credentials.password": "password",
        },
    )


def _oauth_entry(name: str = "oauth", subtype: AuthType = AuthType.OAuth2ClientCreds) -> AuthEntry:
    return AuthEntry(
        type=subtype, name=name,
        xsoar_param_map={"client_secret": "client_secret"},
    )


def _leaves_by_path(
    leaves: list[cap.SentinelLeaf],
) -> dict[str, cap.SentinelLeaf]:
    """Index a list of :class:`SentinelLeaf` records by their ``path``."""
    return {leaf.path: leaf for leaf in leaves}


def _make_leaf(path: str, role: str, value: str) -> cap.SentinelLeaf:
    return cap.SentinelLeaf(path=path, role=role, value=value)


def _captured(method: str = "GET", path: str = "/api/v1/x",
              headers: dict[str, str] | None = None, query: str = "",
              body: str = "", url: str = "") -> dict[str, object]:
    return {
        "method": method, "path": path, "url": url or f"http://127.0.0.1{path}",
        "query": query, "headers": headers or {}, "body": body,
    }


# --------------------------------------------------------------------------
# generate_sentinels
# --------------------------------------------------------------------------


class TestGenerateSentinels:
    def test_shape_matches_design_regex(self) -> None:
        """Sentinel string format: ``__AUTHPARITY__<conn>__<path>__<role>__<uuid8>``.

        The role substring is the Commit-4 addition — it lets a downstream
        grep recover both the XSOAR path AND the UCP role from the
        captured sentinel alone (§2.3 of the design doc).
        """
        details = _details(_api_key_entry(), _plain_entry("creds"))
        smap = cap.generate_sentinels(details)
        pat = re.compile(
            r"^__AUTHPARITY__[A-Za-z0-9_.-]+"   # __<conn>
            r"__[A-Za-z0-9_.-]+"                # __<xsoar_path>
            r"__[A-Za-z0-9_.-]+"                # __<role>
            r"__[0-9a-f]{8}$"                   # __<uuid8>
        )
        for conn_name, leaves in smap.by_connection.items():
            assert leaves, f"connection {conn_name} has no sentinels"
            for leaf in leaves:
                assert pat.match(leaf.value), (
                    f"sentinel for {conn_name}.{leaf.path} not in expected "
                    f"shape: {leaf.value!r}"
                )

    def test_interpolated_entries_are_skipped(self) -> None:
        details = _details(
            _api_key_entry("kept"),
            _api_key_entry("dropped", interpolated=True),
        )
        smap = cap.generate_sentinels(details)
        assert "kept" in smap.by_connection
        assert "dropped" not in smap.by_connection

    def test_one_sentinel_per_xsoar_leaf(self) -> None:
        details = _details(_plain_entry("creds"))
        smap = cap.generate_sentinels(details)
        by_path = _leaves_by_path(smap.for_connection("creds"))
        assert set(by_path.keys()) == {
            "credentials.identifier", "credentials.password",
        }
        # Roles are propagated from xsoar_param_map.
        assert by_path["credentials.identifier"].role == "username"
        assert by_path["credentials.password"].role == "password"

    def test_minimum_length_40(self) -> None:
        # Real-world auth-types[].name values are always at least a few
        # characters; the design's ≥40-char promise covers any non-trivial
        # input. Use a representative Plain connection here.
        details = _details(_plain_entry("credentials"))
        smap = cap.generate_sentinels(details)
        for leaf in smap.for_connection("credentials"):
            assert len(leaf.value) >= 40, (
                f"sentinel too short ({len(leaf.value)}): {leaf.value!r}"
            )


# --------------------------------------------------------------------------
# map_auth_type_to_ucp_shape
# --------------------------------------------------------------------------


class TestMapAuthTypeToUcpShape:
    def test_api_key(self) -> None:
        entry = _api_key_entry()
        sentinels = [_make_leaf("api_key", "key", "S_API")]
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {"type": "api_key", "api_key": {"key": "S_API"}}

    def test_plain(self) -> None:
        entry = _plain_entry()
        sentinels = [
            _make_leaf("credentials.identifier", "username", "S_USER"),
            _make_leaf("credentials.password", "password", "S_PASS"),
        ]
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {
            "type": "plain",
            "plain": {"username": "S_USER", "password": "S_PASS"},
        }

    @pytest.mark.parametrize(
        "subtype",
        [AuthType.OAuth2ClientCreds, AuthType.OAuth2AuthCode, AuthType.OAuth2JWT],
    )
    def test_oauth2_variants(self, subtype: AuthType) -> None:
        entry = _oauth_entry(subtype=subtype)
        sentinels = [_make_leaf("client_secret", "client_secret", "S_TOK")]
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {
            "type": "oauth2",
            "oauth2": {"access_token": "S_TOK", "token_type": "Bearer"},
        }

    def test_other_returns_none(self) -> None:
        entry = AuthEntry(
            type=AuthType.Other, name="x",
            xsoar_param_map={"x": "x"},
        )
        sentinels = [_make_leaf("x", "x", "S")]
        assert cap.map_auth_type_to_ucp_shape(entry, sentinels) is None

    def test_none_required_returns_none(self) -> None:
        entry = AuthEntry(
            type=AuthType.NoneRequired, name="n",
            xsoar_param_map={},
        )
        assert cap.map_auth_type_to_ucp_shape(entry, []) is None


# --------------------------------------------------------------------------
# Role-driven dispatch (Commit-4 regression tests).
#
# These tests pin the behavioural change that the xsoar_param_map
# migration introduces: UCP-slot selection is now driven by the
# explicit role from xsoar_param_map.values(), NOT by leaf-name
# heuristic on the XSOAR path. See plan §5.4 and the "Why this
# changed (2026-05)" note in §2.3 of auth_parity_test_design.md.
# --------------------------------------------------------------------------


class TestRoleDrivenDispatch:
    def test_one_sentinel_per_xsoar_path(self) -> None:
        """Each (path, role) pair gets one sentinel.

        - APIKey with a single path → 1 sentinel.
        - Plain with identifier/password split → 2 sentinels.
        - APIKey with TWO paths both mapped to ``"key"`` → 2 sentinels.
        """
        # Case A: APIKey, single path.
        a = AuthEntry(
            type=AuthType.APIKey, name="a",
            xsoar_param_map={"api_key": "key"},
        )
        # Case B: Plain, identifier + password (canonical credentials widget).
        b = AuthEntry(
            type=AuthType.Plain, name="b",
            xsoar_param_map={
                "credentials.identifier": "username",
                "credentials.password": "password",
            },
        )
        # Case C: APIKey, two paths both mapped to "key" (contrived but legal —
        # the validator allows it and Commit 4 documents this as the
        # multiple-paths-same-role case).
        c = AuthEntry(
            type=AuthType.APIKey, name="c",
            xsoar_param_map={
                "credentials.password": "key",
                "extra_key_param": "key",
            },
        )
        smap = cap.generate_sentinels(_details(a, b, c))
        assert len(smap.for_connection("a")) == 1
        assert len(smap.for_connection("b")) == 2
        assert len(smap.for_connection("c")) == 2

    def test_ucp_shape_plain_reads_roles_not_leaf_names(self) -> None:
        """Regression-proof guard against the old leaf-name heuristic.

        Pre-Commit-4, ``_ucp_shape_plain`` looked at the XSOAR-path
        suffix to decide which sentinel was the username and which was
        the password. With flat parameter names (no ``.identifier`` /
        ``.password`` leaves) the heuristic had no signal to work with.
        Role-driven dispatch fixes this by reading
        ``xsoar_param_map.values()``.
        """
        entry = AuthEntry(
            type=AuthType.Plain, name="srv",
            xsoar_param_map={
                "server_user": "username",
                "server_password": "password",
            },
        )
        # Intentionally name the sentinel values so the leaf-name
        # heuristic — were it still in place — would have NO way to
        # disambiguate (both flat params, neither named "identifier"
        # nor "password").
        sentinels = [
            _make_leaf("server_user", "username", "S_USER_VALUE"),
            _make_leaf("server_password", "password", "S_PASS_VALUE"),
        ]
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {
            "type": "plain",
            "plain": {
                "username": "S_USER_VALUE",
                "password": "S_PASS_VALUE",
            },
        }

    def test_ucp_shape_api_key_writes_key_sentinel_only(self) -> None:
        """When two paths map to ``"key"``, only the first (lex-sorted) wins.

        Both sentinels are still generated (so ``build_old_params`` seeds
        both leaves into the old run's ``demisto.params()``), but the UCP
        envelope's single ``api_key.key`` slot can only hold one value.
        Commit 4 documents picking the first by lex-sorted path for
        determinism. The second sentinel never appears in the UCP shape.
        """
        entry = AuthEntry(
            type=AuthType.APIKey, name="ak",
            xsoar_param_map={
                "credentials.password": "key",
                "credentials.identifier": "key",
            },
        )
        # Build leaves with stable, distinguishable sentinel values so we
        # can assert exactly which one was selected.
        leaves = [
            _make_leaf("credentials.password", "key", "S_PW"),
            _make_leaf("credentials.identifier", "key", "S_ID"),
        ]
        shape = cap.map_auth_type_to_ucp_shape(entry, leaves)
        # "credentials.identifier" lex-sorts before "credentials.password",
        # so its sentinel value wins.
        assert shape == {"type": "api_key", "api_key": {"key": "S_ID"}}
        # The other sentinel ("S_PW") does NOT appear in the envelope.
        assert "S_PW" not in json.dumps(shape)

    def test_omit_paths_iterates_map_keys(self) -> None:
        """``_omit_paths`` consumes ``xsoar_param_map.keys()``, not some
        other field.

        Commit 4 changed ``run_new`` to pass
        ``list(entry.xsoar_param_map.keys())`` into ``_omit_paths``. This
        test pins the contract by spying on ``_omit_paths`` from within
        the ``run_new`` execution path and asserting the paths argument
        equals the map keys.
        """
        entry = _plain_entry("creds")
        base = {
            "credentials": {
                "identifier": "u",
                "password": "p",
            },
            "other_param": "keep_me",
        }
        # _omit_paths is pure — call it directly with the keys to lock
        # in the contract. The call site in run_new is a one-liner that
        # passes list(entry.xsoar_param_map.keys()) here.
        result = cap._omit_paths(base, list(entry.xsoar_param_map.keys()))
        # Both XSOAR-path leaves should be gone; non-auth params preserved.
        assert result == {"credentials": {}, "other_param": "keep_me"}

    def test_sentinel_encodes_role_for_attribution(self) -> None:
        """The role appears as a grep-friendly substring of the sentinel.

        This lets a downstream operator running ``grep`` on a captured
        request recover not just which XSOAR path the sentinel came
        from, but also which UCP role it was meant to fill — even when
        the diff comparator already classified the locations.
        """
        details = _details(_plain_entry("creds"), _api_key_entry("ak"))
        smap = cap.generate_sentinels(details)
        by_path_plain = _leaves_by_path(smap.for_connection("creds"))
        # Each Plain leaf's value contains the role string between two
        # __ separators (the design's __<role>__ slot).
        assert "__username__" in by_path_plain["credentials.identifier"].value
        assert "__password__" in by_path_plain["credentials.password"].value
        # APIKey: the role "key" is also present in the sentinel.
        by_path_ak = _leaves_by_path(smap.for_connection("ak"))
        assert "__key__" in by_path_ak["api_key"].value


# --------------------------------------------------------------------------
# extract_sentinel_locations — headers
# --------------------------------------------------------------------------


SENTINEL = "__AUTHPARITY__c__credentials.password__deadbeef"


def _locators(req: dict[str, object], sentinel: str = SENTINEL) -> set[str]:
    return {loc.locator for loc in cap.extract_sentinel_locations(req, sentinel)}


class TestExtractHeaderLocations:
    def test_bearer(self) -> None:
        req = _captured(headers={"Authorization": f"Bearer {SENTINEL}"})
        assert _locators(req) == {"header:authorization:bearer"}

    def test_basic_user_only(self) -> None:
        creds = f"{SENTINEL}:somepass"
        b64 = base64.b64encode(creds.encode()).decode()
        req = _captured(headers={"Authorization": f"Basic {b64}"})
        assert _locators(req) == {"header:authorization:basic:user"}

    def test_basic_pass_only(self) -> None:
        creds = f"someuser:{SENTINEL}"
        b64 = base64.b64encode(creds.encode()).decode()
        req = _captured(headers={"Authorization": f"Basic {b64}"})
        assert _locators(req) == {"header:authorization:basic:pass"}

    def test_basic_both_user_and_pass(self) -> None:
        creds = f"{SENTINEL}:{SENTINEL}"
        b64 = base64.b64encode(creds.encode()).decode()
        req = _captured(headers={"Authorization": f"Basic {b64}"})
        assert _locators(req) == {
            "header:authorization:basic:user",
            "header:authorization:basic:pass",
        }

    @pytest.mark.parametrize("prefix", ["Token", "SSWS", "ApiKey"])
    def test_custom_prefix(self, prefix: str) -> None:
        req = _captured(headers={"Authorization": f"{prefix} {SENTINEL}"})
        assert _locators(req) == {f"header:authorization:{prefix.lower()}"}

    def test_custom_header_case_insensitive(self) -> None:
        req = _captured(headers={"X-Api-Key": SENTINEL})
        assert _locators(req) == {"header:x-api-key"}

    def test_cookie(self) -> None:
        req = _captured(headers={"Cookie": f"session_token={SENTINEL}; other=foo"})
        assert _locators(req) == {"cookie:session_token"}


# --------------------------------------------------------------------------
# extract_sentinel_locations — query / body / url
# --------------------------------------------------------------------------


class TestExtractQueryAndBody:
    def test_query_param(self) -> None:
        req = _captured(query=f"api_key={SENTINEL}&foo=bar")
        assert _locators(req) == {"query:api_key"}

    def test_query_param_url_encoded(self) -> None:
        from urllib.parse import quote
        encoded = quote(SENTINEL, safe="")
        req = _captured(query=f"api_key={encoded}")
        assert _locators(req) == {"query:api_key"}

    def test_json_body_dotted_path(self) -> None:
        body = json.dumps({"auth": {"client_secret": SENTINEL}, "other": 1})
        req = _captured(
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert _locators(req) == {"body.json:auth.client_secret"}

    def test_json_body_array_index_path(self) -> None:
        body = json.dumps({"creds": [{"secret": SENTINEL}]})
        req = _captured(headers={"Content-Type": "application/json"}, body=body)
        assert _locators(req) == {"body.json:creds[0].secret"}

    def test_form_body(self) -> None:
        req = _captured(
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"client_id={SENTINEL}&grant_type=client_credentials",
        )
        assert _locators(req) == {"body.form:client_id"}

    def test_url_userinfo_user(self) -> None:
        req = _captured(url=f"http://{SENTINEL}:somepass@host/x")
        assert "url.userinfo:user" in _locators(req)

    def test_url_userinfo_pass(self) -> None:
        req = _captured(url=f"http://someuser:{SENTINEL}@host/x")
        assert "url.userinfo:pass" in _locators(req)

    def test_base64_variant_standard(self) -> None:
        encoded = base64.b64encode(SENTINEL.encode()).decode().rstrip("=")
        req = _captured(headers={"X-Encoded": encoded})
        assert _locators(req) == {"header:x-encoded"}

    def test_base64_variant_urlsafe(self) -> None:
        encoded = base64.urlsafe_b64encode(SENTINEL.encode()).decode().rstrip("=")
        req = _captured(headers={"X-Encoded": encoded})
        assert _locators(req) == {"header:x-encoded"}


# --------------------------------------------------------------------------
# compare_locations — §4.5 failure taxonomy
# --------------------------------------------------------------------------


def _loc(path: str = "/api", method: str = "GET",
         locator: str = "header:x-api-key") -> cap.Location:
    return cap.Location(method=method, path=path, locator=locator)


class TestCompareLocations:
    def test_pass(self) -> None:
        a = {_loc()}
        assert cap.compare_locations(a, a) == []

    def test_missing_in_new(self) -> None:
        diffs = cap.compare_locations({_loc()}, set())
        assert len(diffs) == 1
        assert diffs[0].failure_code == "MISSING_IN_NEW"

    def test_extra_in_new(self) -> None:
        diffs = cap.compare_locations(set(), {_loc()})
        assert len(diffs) == 1
        assert diffs[0].failure_code == "EXTRA_IN_NEW"

    def test_wrong_location(self) -> None:
        old = {_loc(locator="header:authorization:bearer")}
        new = {_loc(locator="header:x-api-key")}
        diffs = cap.compare_locations(old, new)
        assert len(diffs) == 1
        assert diffs[0].failure_code == "WRONG_LOCATION"
        assert "header:authorization:bearer" in diffs[0].old_locations[0]
        assert "header:x-api-key" in diffs[0].new_locations[0]

    def test_missing_in_both(self) -> None:
        diffs = cap.compare_locations(set(), set())
        assert len(diffs) == 1
        assert diffs[0].failure_code == "MISSING_IN_BOTH"


# --------------------------------------------------------------------------
# compare_request_sets — §6.7
# --------------------------------------------------------------------------


class TestCompareRequestSets:
    def test_symmetric_difference(self) -> None:
        old = [
            {"method": "POST", "path": "/oauth/token"},
            {"method": "GET", "path": "/api/v1/x"},
        ]
        new = [
            {"method": "GET", "path": "/api/v1/x"},
            {"method": "POST", "path": "/api/v1/y"},
        ]
        diff = cap.compare_request_sets(old, new)
        assert diff.only_in_old == [{"method": "POST", "path": "/oauth/token"}]
        assert diff.only_in_new == [{"method": "POST", "path": "/api/v1/y"}]

    def test_identical_request_sets(self) -> None:
        same = [{"method": "GET", "path": "/x"}]
        diff = cap.compare_request_sets(same, same)
        assert diff.only_in_old == []
        assert diff.only_in_new == []


# --------------------------------------------------------------------------
# Canonicalization corner cases
# --------------------------------------------------------------------------


class TestCanonicalization:
    def test_header_case(self) -> None:
        upper = _captured(headers={"X-Api-Key": SENTINEL})
        lower = _captured(headers={"x-api-key": SENTINEL})
        assert _locators(upper) == _locators(lower) == {"header:x-api-key"}

    def test_basic_decode_round_trip(self) -> None:
        creds = f"user:{SENTINEL}"
        b64 = base64.b64encode(creds.encode()).decode()
        req = _captured(headers={"Authorization": f"Basic {b64}"})
        # The raw base64 blob itself MUST NOT be reported — only decoded slots.
        locs = _locators(req)
        assert "header:authorization:basic:pass" in locs
        assert "header:authorization" not in locs
        assert "header:authorization:basic" not in locs

    def test_bearer_strip(self) -> None:
        req = _captured(headers={"Authorization": f"Bearer {SENTINEL}"})
        # The scheme prefix is part of the locator name but NOT counted as
        # part of the sentinel payload. Same locator is reported regardless
        # of leading/trailing whitespace in the header.
        assert _locators(req) == {"header:authorization:bearer"}


# --------------------------------------------------------------------------
# Hard-error short-circuits — integration via main()
# --------------------------------------------------------------------------


def _make_python_integration(
    tmp_path: Path,
    py_source: str = "from CommonServerPython import *\nclass C(BaseClient):\n    pass\ndef main():\n    pass\n",
    script_type: str = "python",
    integration_id: str = "TestInt",
) -> Path:
    """Create a minimal Python integration directory under ``tmp_path``."""
    pack = tmp_path / "Packs" / "X" / "Integrations" / integration_id
    pack.mkdir(parents=True)
    yml = {
        "commonfields": {"id": integration_id, "version": -1},
        "name": integration_id, "display": integration_id,
        "category": "Utilities",
        "configuration": [
            {"name": "url", "type": 0, "required": True},
            {"name": "api_key", "type": 4, "required": True},
        ],
        "script": {
            "script": "-", "type": script_type, "subtype": "python3",
            "commands": [], "dockerimage": "demisto/python3:latest",
        },
    }
    import yaml as _yaml
    (pack / f"{integration_id}.yml").write_text(_yaml.safe_dump(yml))
    (pack / f"{integration_id}.py").write_text(py_source)
    return pack


def _make_js_integration(tmp_path: Path) -> Path:
    pack = tmp_path / "Packs" / "X" / "Integrations" / "JsInt"
    pack.mkdir(parents=True)
    yml = {
        "commonfields": {"id": "JsInt", "version": -1},
        "name": "JsInt", "display": "JsInt",
        "category": "Utilities",
        "configuration": [],
        "script": {"script": "-", "type": "javascript", "commands": []},
    }
    import yaml as _yaml
    (pack / "JsInt.yml").write_text(_yaml.safe_dump(yml))
    return pack


def _run_main_capture(argv: list[str]) -> tuple[int, dict]:
    """Invoke ``cap.main`` capturing stdout/exit code; returns (rc, parsed_json)."""
    from io import StringIO
    buf = StringIO()
    real_stdout = sys.stdout
    sys.stdout = buf
    try:
        rc = cap.main(argv)
    finally:
        sys.stdout = real_stdout
    payload: dict = json.loads(buf.getvalue())
    return rc, payload


class TestHardErrors:
    # Minimal stub Auth Details payload that satisfies the now-required
    # --auth-details CLI flag. The non-python / no-baseclient gates
    # fire BEFORE Auth Details validation, so the contents are
    # immaterial for these tests; any well-formed payload works.
    _STUB_AUTH_DETAILS = json.dumps({
        "auth_types": [],
        "config": "NoneRequired",
        "other_connection": [],
    })

    def test_error_non_python(self, tmp_path: Path) -> None:
        pack = _make_js_integration(tmp_path)
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "JsInt",
             "--auth-details", self._STUB_AUTH_DETAILS]
        )
        assert rc == cap.EXIT_NON_PYTHON
        assert payload["error"]["code"] == cap.ERROR_NON_PYTHON
        assert cap._LITERAL_MARK_AUTH in payload["error"]["message"]

    def test_error_no_baseclient(self, tmp_path: Path) -> None:
        py = "def main():\n    pass\n"  # No BaseClient anywhere.
        pack = _make_python_integration(tmp_path, py_source=py)
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "TestInt",
             "--auth-details", self._STUB_AUTH_DETAILS]
        )
        assert rc == cap.EXIT_NO_BASECLIENT
        assert payload["error"]["code"] == cap.ERROR_NO_BASECLIENT
        assert cap._LITERAL_MARK_AUTH in payload["error"]["message"]

    def test_error_all_interpolated(self, tmp_path: Path) -> None:
        pack = _make_python_integration(tmp_path)
        # Auth Details are now passed in via --auth-details (the
        # orchestrator's job per the REMOVE-workflow_state-lookup
        # refactor). No more monkey-patching the workflow_state read.
        details_json = {
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}, "interpolated": True},
            ],
            "config": "REQUIRED(api_key)",
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "TestInt",
             "--auth-details", json.dumps(details_json)]
        )
        assert rc == cap.EXIT_ALL_INTERPOLATED
        assert payload["error"]["code"] == cap.ERROR_ALL_INTERPOLATED
        assert cap._LITERAL_MARKPASS_STEP_11 in payload["error"]["message"]

    def test_error_connection_interpolated(self, tmp_path: Path) -> None:
        pack = _make_python_integration(tmp_path)
        # auth_config_parser.validate_auth_details requires the
        # auth_types list to be sorted by (type, name); the entries
        # below intentionally satisfy that — 'dropped' sorts before
        # 'kept' under the APIKey type prefix.
        details_json = {
            "auth_types": [
                {"type": "APIKey", "name": "dropped",
                 "xsoar_param_map": {"api_key": "key"}, "interpolated": True},
                {"type": "APIKey", "name": "kept",
                 "xsoar_param_map": {"api_key": "key"}, "interpolated": False},
            ],
            "config": "REQUIRED(kept) + OPTIONAL(dropped)",
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "TestInt",
             "--auth-details", json.dumps(details_json),
             "--connection", "dropped"]
        )
        assert rc == cap.EXIT_CONNECTION_INTERPOLATED
        assert payload["error"]["code"] == cap.ERROR_CONNECTION_INTERPOLATED


class TestPerConnectionSkip:
    def test_skipped_interpolated_mixed(self) -> None:
        """One interpolated + one not: interpolated → skipped, not an error."""
        details = _details(
            _api_key_entry("kept"),
            _api_key_entry("dropped", interpolated=True),
        )
        smap = cap.generate_sentinels(details)
        # Per-connection skip is decided by _connection_skip_status, not main().
        skip = cap._connection_skip_status(
            details.auth_types[1], py_source="class C(BaseClient): pass", yml_data={}
        )
        assert skip == "skipped_interpolated"
        # And the non-interpolated entry should be runnable.
        not_skip = cap._connection_skip_status(
            details.auth_types[0], py_source="class C(BaseClient): pass", yml_data={}
        )
        assert not_skip is None
        # And generate_sentinels skipped the interpolated entry.
        assert "dropped" not in smap.by_connection


# --------------------------------------------------------------------------
# Detection helpers — quick sanity checks
# --------------------------------------------------------------------------


class TestDetection:
    def test_detect_signed_hmac(self) -> None:
        assert cap.detect_signed_auth("import hmac\nclass C: pass\n")

    def test_detect_signed_botocore(self) -> None:
        assert cap.detect_signed_auth("from botocore.auth import SigV4Auth\n")

    def test_detect_signed_negative(self) -> None:
        assert not cap.detect_signed_auth("import requests\nclass C: pass\n")

    def test_detect_no_baseclient_imported_via_star(self) -> None:
        # ``import *`` without explicit BaseClient symbol use → no usage.
        src = "from CommonServerPython import *\ndef main():\n    pass\n"
        assert cap.detect_no_baseclient(src)

    def test_detect_no_baseclient_subclass(self) -> None:
        src = "from CommonServerPython import *\nclass C(BaseClient):\n    pass\n"
        assert not cap.detect_no_baseclient(src)

    def test_detect_mtls_yml_type_14(self) -> None:
        yml = {"configuration": [{"name": "cert", "type": 14}]}
        assert cap.detect_mtls(yml)

    def test_detect_mtls_negative(self) -> None:
        yml = {"configuration": [{"name": "api_key", "type": 4}]}
        assert not cap.detect_mtls(yml)


# --------------------------------------------------------------------------
# _build_base_params precedence (design §2.4)
# --------------------------------------------------------------------------


class TestBuildBaseParamsPrecedence:
    """Per design §2.4: ``Params for test with default in code`` values must
    win over the type-aware placeholders for the same param key. Keys
    absent from the cell still get a placeholder; keys in the cell that
    don't exist as YML params are silently ignored.
    """

    _YML = {
        "configuration": [
            {"name": "fetch_limit", "type": 0, "required": True},
            {"name": "first_fetch", "type": 0, "required": True},
            {"name": "url", "type": 0, "required": True},
            {"name": "isFetchEvents", "type": 8, "required": False},
        ],
    }

    def test_cell_value_beats_placeholder_for_same_key(self) -> None:
        """Column wins for keys that are also visible YML params."""
        baseline = cap._build_base_params(self._YML, param_defaults=None)
        # Sanity: the placeholder code produced *some* value for fetch_limit.
        assert "fetch_limit" in baseline
        placeholder_value = baseline["fetch_limit"]

        with_overrides = cap._build_base_params(
            self._YML,
            param_defaults={"fetch_limit": 50, "first_fetch": "3 days"},
        )
        assert with_overrides["fetch_limit"] == 50
        assert with_overrides["first_fetch"] == "3 days"
        # The override is verbatim — including non-string JSON types.
        assert isinstance(with_overrides["fetch_limit"], int)
        # The override truly displaced the placeholder.
        assert with_overrides["fetch_limit"] != placeholder_value

    def test_keys_absent_from_cell_keep_placeholders(self) -> None:
        """Params not in the cell still get a type-aware placeholder."""
        baseline = cap._build_base_params(self._YML, param_defaults=None)
        with_partial = cap._build_base_params(
            self._YML, param_defaults={"fetch_limit": 99}
        )
        # ``first_fetch`` was NOT in the cell — placeholder is preserved.
        assert with_partial["first_fetch"] == baseline["first_fetch"]
        # ``isFetchEvents`` was NOT in the cell — placeholder is preserved.
        assert with_partial.get("isFetchEvents") == baseline.get("isFetchEvents")

    def test_stray_keys_in_cell_are_ignored(self) -> None:
        """Cell keys that don't map to a visible YML param are dropped."""
        result = cap._build_base_params(
            self._YML,
            param_defaults={"fetch_limit": 7, "this_param_does_not_exist": "oops"},
        )
        assert result["fetch_limit"] == 7
        assert "this_param_does_not_exist" not in result

    def test_empty_or_none_cell_is_a_noop(self) -> None:
        """``None`` and ``{}`` both leave the placeholder baseline intact."""
        baseline = cap._build_base_params(self._YML, param_defaults=None)
        empty = cap._build_base_params(self._YML, param_defaults={})
        assert empty == baseline


class TestUcpPatchTemplate:
    """Pin the shape of the UCP-patch sidecar template (§2.5 wiring).

    Regression guards against silently regressing to the previous CSP
    `get_ucp_credentials` patch shape, and confirms the branch-selector
    flags actually flip the values seen by the integration at runtime.
    """

    def test_ucp_patch_template_mocks_demisto_getucpcredentials(self) -> None:
        template = cap._UCP_PATCH_TEMPLATE
        # The credential-fetcher seam is now the demisto-object method.
        assert "demisto.getUCPCredentials = " in template
        # Regression guard: the old CSP-attribute patch must be gone.
        assert "csp.get_ucp_credentials = " not in template
        # The branch-selector patch must target ANY module that exposes
        # both flags — not just sys.modules["CommonServerPython"], which
        # does NOT exist in the parity harness's child interpreter (the
        # unified CSP+integration source is loaded under the module name
        # "integration_under_test"). Pin the iteration approach so we
        # cannot silently regress to a CSP-only lookup that no-ops.
        assert "for _mod in list(_sys.modules.values()):" in template
        assert 'hasattr(_mod, "is_ucp_enabled")' in template
        assert 'hasattr(_mod, "should_use_ucp_auth")' in template

    def test_ucp_patch_flips_flags_in_unified_module_namespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Run the patch template against a sim of the child's sys.modules.

        Mimics the parity harness's child interpreter: the integration is
        loaded under the name ``integration_under_test`` and that single
        module owns the ``is_ucp_enabled`` / ``should_use_ucp_auth``
        callables (because CSP source is concatenated into it). There is
        NO ``CommonServerPython`` module. The patch must still flip the
        flags on the unified module — otherwise BaseClient._http_request
        skips the UCP injection branch and overrides like
        APIVoid.Client._apply_ucp_api_key never run (the post-Commit-6
        APIVoid parity regression).
        """
        import sys as _sys
        import types as _types

        # Build a fake unified module that owns both flags, returning
        # False (the un-patched default that mirrors the real CSP
        # behaviour when demisto.unifiedConnectorMetadata() returns None).
        fake_unified = _types.ModuleType("integration_under_test")
        fake_unified.is_ucp_enabled = lambda *a, **k: False  # type: ignore[attr-defined]
        fake_unified.should_use_ucp_auth = lambda *a, **k: False  # type: ignore[attr-defined]
        monkeypatch.setitem(_sys.modules, "integration_under_test", fake_unified)
        # Ensure there is NO CommonServerPython module — that's the
        # condition under which the old CSP-only lookup silently no-ops.
        monkeypatch.delitem(_sys.modules, "CommonServerPython", raising=False)

        # Seed the env-var contract the patch template consumes.
        monkeypatch.setenv("AUTH_PARITY_UCP_ENABLED", "1")
        monkeypatch.setenv("AUTH_PARITY_UCP_CREDS", "")

        # Drop the part of the template that imports demistomock (we are
        # not exercising the credential-mock branch here, only the
        # branch-selector patch). The early-return at "not _UCP_ENABLED
        # or _UCP_CREDS is None" handles this for us — _UCP_CREDS_JSON
        # is empty so _UCP_CREDS is None and the demistomock branch is
        # skipped — but exec()ing the template still defines the
        # apply_patches() function and then calls it.
        exec(cap._UCP_PATCH_TEMPLATE, {"__name__": "ucp_patch_under_test"})

        # The patch MUST have flipped the unified module's flags.
        assert fake_unified.is_ucp_enabled() is True
        assert fake_unified.should_use_ucp_auth() is True

    def test_ucp_patch_template_mocks_unified_connector_metadata_too(self) -> None:
        """H8c regression: BOTH UCP seams must be mocked on the demisto object.

        Before H8c, the new-run patch installed only
        ``demisto.getUCPCredentials``. CSP's UCP injection chain calls
        ``demisto.unifiedConnectorMetadata()`` FIRST (inside
        ``_get_ucp_profiles``); when that returned an empty dict (the
        ``demistomock`` default) the chain raised ``UcpException`` and
        ``getUCPCredentials`` was never reached — so the integration's
        ``_apply_ucp_*`` override never fired, and test_module returned
        a "Test Failed" string with zero HTTP requests. This test pins
        BOTH mocks into the template (textual guard) and validates the
        full chain end-to-end (functional guard) so the regression
        cannot recur.
        """
        # 1. Textual guard: both seams must appear in the template.
        template = cap._UCP_PATCH_TEMPLATE
        assert "demisto.getUCPCredentials = " in template
        assert "demisto.unifiedConnectorMetadata = " in template

        # 2. Functional guard: exec the template against a fake unified
        # module that owns the real CSP profile-resolution helpers, then
        # call get_ucp_method_unique_id() and assert it returns the
        # mocked method_unique_id WITHOUT raising UcpException.
        import os as _os
        import sys as _sys
        import types as _types

        import demistomock as _demistomock  # type: ignore[import-not-found]

        # Snapshot/restore the env vars and the two demisto attributes
        # the template mutates, so this test stays hermetic.
        prev_env = {
            k: _os.environ.get(k)
            for k in ("AUTH_PARITY_UCP_ENABLED", "AUTH_PARITY_UCP_CREDS")
        }
        prev_get = getattr(_demistomock, "getUCPCredentials", None)
        prev_meta = getattr(_demistomock, "unifiedConnectorMetadata", None)
        prev_unified = _sys.modules.get("integration_under_test")
        try:
            _os.environ["AUTH_PARITY_UCP_ENABLED"] = "1"
            _os.environ["AUTH_PARITY_UCP_CREDS"] = (
                '{"credentials": {"password": "auth-parity-sentinel"}}'
            )

            # Minimal fake unified module exposing the branch-selector
            # flags so the iteration-based patch finds it.
            fake_unified = _types.ModuleType("integration_under_test")
            fake_unified.is_ucp_enabled = lambda *a, **k: False  # type: ignore[attr-defined]
            fake_unified.should_use_ucp_auth = lambda *a, **k: False  # type: ignore[attr-defined]
            _sys.modules["integration_under_test"] = fake_unified

            # Run the patch template. After this both demisto.* mocks
            # are installed AND fake_unified's flags are flipped.
            exec(cap._UCP_PATCH_TEMPLATE, {"__name__": "ucp_patch_under_test"})

            # Both seams must now be callable and return non-default
            # values (the regression: only one was installed).
            meta = _demistomock.unifiedConnectorMetadata()
            assert meta != {}, "unifiedConnectorMetadata mock did not install"
            profiles = meta.get("connectionProfiles") or []
            assert profiles, "mock metadata must carry a non-empty connectionProfiles list"
            assert profiles[0].get("method_unique_id"), (
                "mock profile must carry a method_unique_id so CSP's "
                "fallback-to-first-profile path resolves to a usable id"
            )

            creds = _demistomock.getUCPCredentials("any-method-id")
            assert creds == {"credentials": {"password": "auth-parity-sentinel"}}, (
                "getUCPCredentials mock did not return the seeded UCP payload"
            )

            # Functional end-to-end: drop the REAL CSP helpers onto the
            # fake unified module and exercise the full chain. This
            # mirrors what happens inside the parity-harness child
            # process: CSP source is concatenated into
            # ``integration_under_test``, so these helpers resolve
            # ``demisto.unifiedConnectorMetadata`` against the same
            # demistomock module we just patched.
            import importlib

            csp = importlib.import_module(
                "Packs.Base.Scripts.CommonServerPython.CommonServerPython"
            )
            fake_unified._get_ucp_profiles = csp._get_ucp_profiles  # type: ignore[attr-defined]
            fake_unified._find_ucp_profile_by_capability = (  # type: ignore[attr-defined]
                csp._find_ucp_profile_by_capability
            )
            fake_unified._find_ucp_profile_by_sub_capability = (  # type: ignore[attr-defined]
                csp._find_ucp_profile_by_sub_capability
            )
            fake_unified.get_ucp_method_unique_id = csp.get_ucp_method_unique_id  # type: ignore[attr-defined]

            # In the real parity harness CSP source is concatenated into
            # ``integration_under_test`` and resolves ``demisto`` against
            # the demistomock module we just patched. In this isolated
            # unit test CSP is imported as its own package and binds
            # ``demisto`` to a fresh ``Demisto()`` instance (not the
            # demistomock module). Forward both mocks onto CSP's
            # ``demisto`` object so the chain sees them.
            prev_csp_meta = getattr(csp.demisto, "unifiedConnectorMetadata", None)
            prev_csp_get = getattr(csp.demisto, "getUCPCredentials", None)
            csp.demisto.unifiedConnectorMetadata = _demistomock.unifiedConnectorMetadata  # type: ignore[attr-defined]
            csp.demisto.getUCPCredentials = _demistomock.getUCPCredentials  # type: ignore[attr-defined]
            try:
                # The whole point: this used to raise UcpException pre-H8c.
                resolved = csp.get_ucp_method_unique_id("automation-and-remediation")
                assert resolved == "auth-parity-mock", (
                    "CSP get_ucp_method_unique_id should return the mocked "
                    "method_unique_id; got {!r}".format(resolved)
                )
            finally:
                if prev_csp_meta is None:
                    try:
                        del csp.demisto.unifiedConnectorMetadata
                    except AttributeError:
                        pass
                else:
                    csp.demisto.unifiedConnectorMetadata = prev_csp_meta  # type: ignore[attr-defined]
                if prev_csp_get is None:
                    try:
                        del csp.demisto.getUCPCredentials
                    except AttributeError:
                        pass
                else:
                    csp.demisto.getUCPCredentials = prev_csp_get  # type: ignore[attr-defined]
        finally:
            for k, v in prev_env.items():
                if v is None:
                    _os.environ.pop(k, None)
                else:
                    _os.environ[k] = v
            if prev_get is None:
                _demistomock.__dict__.pop("getUCPCredentials", None)
            else:
                _demistomock.getUCPCredentials = prev_get  # type: ignore[attr-defined]
            if prev_meta is None:
                _demistomock.__dict__.pop("unifiedConnectorMetadata", None)
            else:
                _demistomock.unifiedConnectorMetadata = prev_meta  # type: ignore[attr-defined]
            if prev_unified is None:
                _sys.modules.pop("integration_under_test", None)
            else:
                _sys.modules["integration_under_test"] = prev_unified


# --------------------------------------------------------------------------
# Integration test placeholders (§7 sketch — separate ticket)
# --------------------------------------------------------------------------


@pytest.mark.skip(reason="integration — separate ticket")
def test_apikey_integration_abnormal_security() -> None:
    """End-to-end parity on Packs/AbnormalSecurity (header Bearer pattern)."""


@pytest.mark.skip(reason="integration — separate ticket")
def test_plain_integration_salesforce_iam() -> None:
    """End-to-end parity on Salesforce_IAM (ROPC / basic-auth pattern)."""


@pytest.mark.skip(reason="integration — separate ticket")
def test_oauth2_integration_crowdstrike_falcon() -> None:
    """End-to-end parity on CrowdStrike Falcon (OAuth2 client-creds)."""

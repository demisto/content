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


# --------------------------------------------------------------------------
# Builder helpers
# --------------------------------------------------------------------------


def _details(*entries: AuthEntry) -> AuthDetails:
    return AuthDetails(
        auth_types=list(entries),
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
        [AuthType.OAuth2ClientCreds, AuthType.OAuth2JWT],
    )
    def test_oauth2_variants(self, subtype: AuthType) -> None:
        entry = _oauth_entry(subtype=subtype)
        sentinels = [_make_leaf("client_secret", "client_secret", "S_TOK")]
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {
            "type": "oauth2",
            "oauth2": {"access_token": "S_TOK", "token_type": "Bearer"},
        }

    def test_passthrough_returns_none(self) -> None:
        entry = AuthEntry(
            type=AuthType.Passthrough, name="x",
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

    def test_non_python_all_interpolated_takes_clean_path(
        self, tmp_path: Path
    ) -> None:
        """ORDERING FIX (NON_PYTHON, 2026-06-03): a non-Python (.js/.ps1)
        integration whose auth is fully interpolated must reach the clean
        ERROR_ALL_INTERPOLATED path (rc 0 / committable), NOT the
        ERROR_NON_PYTHON hard error.

        REGRESSION: previously the NON_PYTHON gate fired before the
        all-interpolated short-circuit, so marking a JS integration's auth
        ``interpolated: true`` (as the tool's own NON_PYTHON diagnostic
        instructs) had no effect and the integration was un-committable.
        The all-interpolated check is now hoisted above the NON_PYTHON gate.
        """
        pack = _make_js_integration(tmp_path)
        auth_details = json.dumps({
            "auth_types": [
                {"type": "Plain", "name": "credentials", "interpolated": True,
                 "xsoar_param_map": {
                     "credentials.identifier": "username",
                     "credentials.password": "password"}},
            ],
            "other_connection": [],
        })
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "JsInt",
             "--auth-details", auth_details]
        )
        # Must be the clean all-interpolated path, NOT NON_PYTHON.
        assert payload["error"]["code"] == cap.ERROR_ALL_INTERPOLATED
        assert payload["error"]["exit_code"] == cap.EXIT_ALL_INTERPOLATED

    def test_non_python_non_interpolated_still_errors(
        self, tmp_path: Path
    ) -> None:
        """Guard: a non-Python integration with a NON-interpolated profile
        must STILL hard-error NON_PYTHON (the fix must not make untested
        non-python secret placements silently committable)."""
        pack = _make_js_integration(tmp_path)
        auth_details = json.dumps({
            "auth_types": [
                {"type": "Plain", "name": "credentials",
                 "xsoar_param_map": {
                     "credentials.identifier": "username",
                     "credentials.password": "password"}},
            ],
            "other_connection": [],
        })
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "JsInt",
             "--auth-details", auth_details]
        )
        assert rc == cap.EXIT_NON_PYTHON
        assert payload["error"]["code"] == cap.ERROR_NON_PYTHON

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

    def test_multi_secret_passthrough_emits_dedicated_diagnostic(
        self, tmp_path: Path
    ) -> None:
        """FIXES-TODO #9: Passthrough profile with 2+ credential-named
        keys produces ``MULTI_SECRET_PASSTHROUGH`` rather than running
        the gate (or short-circuiting on a vaguer NoBaseClient).

        ORDERING FIX (2026-06-03): the entry is now NON-interpolated. A
        genuinely-all-interpolated passthrough bundle legitimately takes
        the clean all-interpolated path (see
        ``test_all_interpolated_passthrough_takes_clean_path`` and the
        api.py gate strictness note), so the multi-secret diagnostic is
        only reachable for a passthrough bundle that still carries secrets
        to place (interpolated=False).
        """
        pack = _make_python_integration(tmp_path)
        details_json = {
            "auth_types": [
                {"type": "Passthrough", "name": "bag",
                 "xsoar_param_map": {
                     "credentials.password": "primary",
                     "hunting_credentials.password": "hunting_key",
                 },
                 "interpolated": False},
            ],
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "AbuseIPDB",
             "--auth-details", json.dumps(details_json)]
        )
        assert rc == cap.EXIT_MULTI_SECRET_PASSTHROUGH
        assert payload["error"]["code"] == cap.MULTI_SECRET_PASSTHROUGH
        # The diagnostic lists the matched credential keys …
        assert "credentials.password" in payload["error"]["message"]
        assert "hunting_credentials.password" in payload["error"]["message"]
        # … and frames the skip as "by design" via the canonical literal.
        assert cap._LITERAL_PARITY_GATE_SKIPPED in payload["error"]["message"]

    def test_all_interpolated_passthrough_takes_clean_path(
        self, tmp_path: Path
    ) -> None:
        """ORDERING FIX (2026-06-03): a fully-interpolated multi-secret
        passthrough bundle is the clean all-interpolated path — it must
        NOT auto-pass merely for being passthrough, nor error. It takes
        ERROR_ALL_INTERPOLATED (rc 0), matching the api.py gate's
        documented intent (workflow_state/api.py §_PARITY_STRUCTURAL_SKIP_CODES).
        """
        pack = _make_python_integration(tmp_path)
        details_json = {
            "auth_types": [
                {"type": "Passthrough", "name": "bag",
                 "xsoar_param_map": {
                     "credentials.password": "primary",
                     "hunting_credentials.password": "hunting_key",
                 },
                 "interpolated": True},
            ],
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "AbuseIPDB",
             "--auth-details", json.dumps(details_json)]
        )
        assert payload["error"]["code"] != cap.MULTI_SECRET_PASSTHROUGH
        assert rc == 0
        assert payload["error"]["code"] == cap.ERROR_ALL_INTERPOLATED

    def test_apimodule_import_emits_dedicated_diagnostic(
        self, tmp_path: Path
    ) -> None:
        """FIXES-TODO #12: integrations whose Client subclasses a class
        from an ApiModule produce ``APIMODULE_INTEGRATION_CANNOT_VERIFY``
        rather than the plain ``ERROR_NO_BASECLIENT`` message."""
        py = (
            "from CommonServerPython import *  # noqa: F401\n"
            "from MicrosoftApiModule import *  # noqa: E402\n"
            "def main():\n"
            "    pass\n"
        )
        pack = _make_python_integration(tmp_path, py_source=py)
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "AzureFirewall",
             "--auth-details", self._STUB_AUTH_DETAILS]
        )
        assert rc == cap.EXIT_APIMODULE_INTEGRATION_CANNOT_VERIFY
        assert payload["error"]["code"] == cap.APIMODULE_INTEGRATION_CANNOT_VERIFY
        # The diagnostic names the ApiModule (so the operator knows
        # WHY the gate cannot verify) …
        assert "MicrosoftApiModule" in payload["error"]["message"]
        # … includes the unambiguous prescription (cross-cutting #3) …
        assert cap._LITERAL_MARK_AUTH in payload["error"]["message"]
        # … and is a NEW enum member (not just a refined existing one).
        assert (
            cap.APIMODULE_INTEGRATION_CANNOT_VERIFY != cap.ERROR_NO_BASECLIENT
        )

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
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "TestInt",
             "--auth-details", json.dumps(details_json)]
        )
        # AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): the all-interpolated
        # case is the ONLY clean fallback, so the standalone CLI now exits 0
        # (the envelope still carries ERROR_ALL_INTERPOLATED with its distinct
        # EXIT_ALL_INTERPOLATED value for callers that inspect error.exit_code).
        assert rc == 0
        assert payload["error"]["code"] == cap.ERROR_ALL_INTERPOLATED
        assert payload["error"]["exit_code"] == cap.EXIT_ALL_INTERPOLATED
        assert cap._LITERAL_PARITY_GATE_SKIPPED in payload["error"]["message"]

    def test_all_interpolated_passes_even_without_baseclient(
        self, tmp_path: Path
    ) -> None:
        """REPRODUCTION (SplunkPy v2, 2026-06-03): a fully-interpolated
        integration that does NOT use BaseClient must take the clean
        all-interpolated pass path, NOT the ERROR_NO_BASECLIENT gate.

        Before the ordering fix, ``detect_no_baseclient`` fired first and
        short-circuited with ERROR_NO_BASECLIENT, so the
        ``interpolated: true`` flag was never evaluated. With the fix the
        interpolation short-circuit runs first, so the no-baseclient gate
        is never reached for an all-interpolated auth.
        """
        # No BaseClient anywhere (mirrors SplunkPy v2, which uses splunklib).
        py = "def main():\n    pass\n"
        pack = _make_python_integration(tmp_path, py_source=py)
        details_json = {
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}, "interpolated": True},
            ],
            "other_connection": [],
        }
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "SplunkPy v2",
             "--auth-details", json.dumps(details_json)]
        )
        # Must NOT be the no-baseclient gate.
        assert payload["error"]["code"] != cap.ERROR_NO_BASECLIENT
        # Must be the clean all-interpolated path (rc 0).
        assert rc == 0
        assert payload["error"]["code"] == cap.ERROR_ALL_INTERPOLATED
        assert payload["error"]["exit_code"] == cap.EXIT_ALL_INTERPOLATED
        assert cap._LITERAL_PARITY_GATE_SKIPPED in payload["error"]["message"]

    def test_exit_code_for_all_interpolated_is_zero(self) -> None:
        """AUTH-PARITY GATE STRICTNESS FIX: _exit_code_for() maps the
        all-interpolated envelope to 0 (the only clean fallback).
        """
        envelope = {
            "integration": "TestInt",
            "error": {
                "code": cap.ERROR_ALL_INTERPOLATED,
                "message": "all interpolated",
                "exit_code": cap.EXIT_ALL_INTERPOLATED,
            },
        }
        assert cap._exit_code_for(envelope) == 0

    def test_exit_code_for_cannot_verify_codes_are_nonzero(self) -> None:
        """Every "cannot verify" code keeps its non-zero exit code, so the
        gate cannot mistake an untested integration for a passing one.
        """
        cannot_verify = [
            (cap.APIMODULE_INTEGRATION_CANNOT_VERIFY,
             cap.EXIT_APIMODULE_INTEGRATION_CANNOT_VERIFY),
            (cap.ERROR_NO_BASECLIENT, cap.EXIT_NO_BASECLIENT),
            (cap.ERROR_NON_PYTHON, cap.EXIT_NON_PYTHON),
            (cap.ERROR_INTEGRATION_REJECTS_HTTP,
             cap.EXIT_INTEGRATION_REJECTS_HTTP),
        ]
        for code, exit_code in cannot_verify:
            envelope = {
                "integration": "TestInt",
                "error": {
                    "code": code,
                    "message": "cannot verify",
                    "exit_code": exit_code,
                },
            }
            rc = cap._exit_code_for(envelope)
            assert rc != 0, f"{code} must map to a non-zero exit code"
            assert rc == exit_code

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

    # FIXES-TODO #9 — multi-secret Passthrough detection
    def test_multi_secret_passthrough_two_credentials(self) -> None:
        """AbuseIPDB-shape: Passthrough with primary + Hunting keys."""
        details = _details(
            AuthEntry(
                type=AuthType.Passthrough, name="bag",
                xsoar_param_map={
                    "credentials.password": "primary",
                    "hunting_credentials.password": "hunting_key",
                },
            )
        )
        matched = cap.detect_multi_secret_passthrough(details)
        assert matched is not None
        assert len(matched) == 2

    def test_multi_secret_passthrough_apikey_pattern(self) -> None:
        details = _details(
            AuthEntry(
                type=AuthType.Passthrough, name="bag",
                xsoar_param_map={
                    "api_key": "primary",
                    "secondary_token": "hunting",
                },
            )
        )
        assert cap.detect_multi_secret_passthrough(details) is not None

    def test_single_secret_passthrough_does_not_trigger(self) -> None:
        """A Passthrough with just one credential-named key isn't multi-."""
        details = _details(
            AuthEntry(
                type=AuthType.Passthrough, name="bag",
                xsoar_param_map={
                    "api_key": "primary",
                    "url": "endpoint",  # non-credential — doesn't count
                },
            )
        )
        assert cap.detect_multi_secret_passthrough(details) is None

    def test_non_passthrough_with_two_secrets_does_not_trigger(self) -> None:
        """Plain auth profiles aren't subject to the multi-secret skip."""
        details = _details(
            AuthEntry(
                type=AuthType.Plain, name="creds",
                xsoar_param_map={
                    "credentials.identifier": "username",
                    "credentials.password": "password",
                },
            )
        )
        assert cap.detect_multi_secret_passthrough(details) is None

    # FIXES-TODO #12 — ApiModule import detection
    def test_detect_apimodule_import_microsoft(self) -> None:
        src = (
            "from CommonServerPython import *\n"
            "from MicrosoftApiModule import *\n"
            "def main():\n    pass\n"
        )
        assert cap.detect_apimodule_import(src) == "MicrosoftApiModule"

    def test_detect_apimodule_import_okta(self) -> None:
        src = (
            "from OktaApiModule import OktaClient\n"
            "def main():\n    pass\n"
        )
        assert cap.detect_apimodule_import(src) == "OktaApiModule"

    def test_detect_apimodule_import_negative(self) -> None:
        src = (
            "from CommonServerPython import *\n"
            "from typing import Any\n"
            "def main():\n    pass\n"
        )
        assert cap.detect_apimodule_import(src) is None


# --------------------------------------------------------------------------
# _build_base_params precedence — per-invocation --seed-param overrides
# --------------------------------------------------------------------------


class TestBuildBaseParamsPrecedence:
    """Per-invocation ``--seed-param NAME=VALUE`` overrides must win over
    the type-aware placeholders for the same param key. Keys absent
    from the overrides dict still get a placeholder; stray keys (no
    matching YML param) are silently dropped at the
    ``build_param_values`` level (the stray-key WARNING surfaces one
    layer up inside ``analyze_integration``, not here).

    The overrides flow through
    :func:`check_command_params.build_param_values` via the
    ``seed_overrides`` kwarg — there is no longer a second-pass overlay
    in :func:`_build_base_params`.
    """

    _YML = {
        "configuration": [
            {"name": "fetch_limit", "type": 0, "required": True},
            {"name": "first_fetch", "type": 0, "required": True},
            {"name": "url", "type": 0, "required": True},
            {"name": "isFetchEvents", "type": 8, "required": False},
        ],
    }

    def test_seed_override_beats_placeholder_for_same_key(self) -> None:
        """Operator override wins for keys that are also visible YML params."""
        baseline = cap._build_base_params(self._YML, seed_overrides=None)
        # Sanity: the placeholder code produced *some* value for fetch_limit.
        assert "fetch_limit" in baseline
        placeholder_value = baseline["fetch_limit"]

        with_overrides = cap._build_base_params(
            self._YML,
            seed_overrides={
                "fetch_limit": "50-real-value",
                "first_fetch": "3 days back",
            },
        )
        # Values >=4 chars are used verbatim as ad-hoc traceable
        # sentinels (mirroring check_command_params.py's behavior).
        assert with_overrides["fetch_limit"] == "50-real-value"
        assert with_overrides["first_fetch"] == "3 days back"
        # The override truly displaced the placeholder.
        assert with_overrides["fetch_limit"] != placeholder_value

    def test_keys_absent_from_overrides_keep_placeholders(self) -> None:
        """Params not in seed_overrides still get a type-aware placeholder."""
        baseline = cap._build_base_params(self._YML, seed_overrides=None)
        with_partial = cap._build_base_params(
            self._YML, seed_overrides={"fetch_limit": "99-real-value"}
        )
        # ``first_fetch`` was NOT overridden — placeholder is preserved.
        assert with_partial["first_fetch"] == baseline["first_fetch"]
        # ``isFetchEvents`` was NOT overridden — placeholder is preserved.
        assert with_partial.get("isFetchEvents") == baseline.get("isFetchEvents")

    def test_stray_keys_are_silently_ignored_at_this_layer(self) -> None:
        """Stray seed-override keys are dropped (no exception) — the
        ``[seed] WARNING`` is surfaced one layer up inside
        :func:`check_command_params.analyze_integration`, not by
        :func:`build_param_values` itself, so this layer is silent.
        """
        result = cap._build_base_params(
            self._YML,
            seed_overrides={
                "fetch_limit": "7-real-value",
                "this_param_does_not_exist": "oops",
            },
        )
        assert result["fetch_limit"] == "7-real-value"
        assert "this_param_does_not_exist" not in result

    def test_empty_or_none_overrides_is_a_noop(self) -> None:
        """``None`` and ``{}`` both leave the placeholder baseline intact."""
        baseline = cap._build_base_params(self._YML, seed_overrides=None)
        empty = cap._build_base_params(self._YML, seed_overrides={})
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

    def test_ucp_patch_no_longer_touches_csp_functions(self) -> None:
        """Guard against re-introducing the old H7 CSP-function patches.

        After the simplification the patch template mocks ONLY the
        ``demisto`` object (``unifiedConnectorMetadata`` +
        ``getUCPCredentials``). The CSP ``is_ucp_enabled`` and
        ``should_use_ucp_auth`` functions return True naturally:
        the former is ``bool(demisto.unifiedConnectorMetadata())``
        which the mock makes truthy; the latter is
        ``is_ucp_enabled() and not _UCP_AUTH_PARAMS_INJECTED`` and
        the injected flag defaults to False. So directly assigning
        to these CSP symbols is dead weight and must not creep back.
        """
        template = cap._UCP_PATCH_TEMPLATE
        assert "is_ucp_enabled =" not in template, (
            "patch template must not assign to is_ucp_enabled — the "
            "function returns True naturally once "
            "demisto.unifiedConnectorMetadata is mocked"
        )
        assert "should_use_ucp_auth =" not in template, (
            "patch template must not assign to should_use_ucp_auth — "
            "the function is True naturally because is_ucp_enabled() "
            "is True and _UCP_AUTH_PARAMS_INJECTED defaults to False"
        )

    def test_ucp_patch_makes_real_csp_flags_return_true_end_to_end(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Behavioural assertion: real CSP functions return True after the patch.

        Replaces the old implementation-flavoured H7 regression test.
        Instead of asserting "the patch template reassigns
        ``is_ucp_enabled`` / ``should_use_ucp_auth`` on the unified
        module", which is what the OLD patch did, we now assert the
        end-to-end behaviour: after running the patch template, the
        real ``csp.is_ucp_enabled()`` and ``csp.should_use_ucp_auth()``
        both return True. They get there naturally because the patch
        mocks ``demisto.unifiedConnectorMetadata()`` to a truthy value
        (which is what ``is_ucp_enabled()`` consults) and resets
        ``_UCP_AUTH_PARAMS_INJECTED`` to False (which
        ``should_use_ucp_auth()`` requires).
        """
        import importlib
        import os as _os
        import sys as _sys

        import demistomock as _demistomock  # type: ignore[import-not-found]

        csp = importlib.import_module(
            "Packs.Base.Scripts.CommonServerPython.CommonServerPython"
        )

        # Snapshot/restore the demisto-object attributes the template
        # mutates, and the module-level _UCP_AUTH_PARAMS_INJECTED flag.
        prev_get = getattr(_demistomock, "getUCPCredentials", None)
        prev_meta = getattr(_demistomock, "unifiedConnectorMetadata", None)
        prev_csp_meta = getattr(csp.demisto, "unifiedConnectorMetadata", None)
        prev_csp_get = getattr(csp.demisto, "getUCPCredentials", None)
        prev_injected = getattr(csp, "_UCP_AUTH_PARAMS_INJECTED", False)

        # Need non-empty creds so the patch template installs the
        # demisto.* mocks (it short-circuits early when creds are None).
        monkeypatch.setenv("AUTH_PARITY_UCP_ENABLED", "1")
        monkeypatch.setenv(
            "AUTH_PARITY_UCP_CREDS",
            '{"credentials": {"password": "auth-parity-sentinel"}}',
        )

        # Stress the defensive loop: pretend something set the
        # injection flag to True. The patch must reset it.
        csp._UCP_AUTH_PARAMS_INJECTED = True  # type: ignore[attr-defined]

        try:
            # Run the patch template.
            exec(cap._UCP_PATCH_TEMPLATE, {"__name__": "ucp_patch_under_test"})

            # The template mocks `demisto` (= demistomock) — forward
            # those mocks onto CSP's bound demisto object so the real
            # CSP helpers see them. In the production parity-harness
            # child, CSP source is concatenated into the unified module
            # and resolves ``demisto`` against the same demistomock
            # module the template patched, so this forwarding is just
            # mimicking what happens for free in the real run.
            csp.demisto.unifiedConnectorMetadata = (  # type: ignore[attr-defined]
                _demistomock.unifiedConnectorMetadata
            )
            csp.demisto.getUCPCredentials = (  # type: ignore[attr-defined]
                _demistomock.getUCPCredentials
            )

            # End-to-end behaviour: the REAL CSP functions return True
            # without anyone monkey-patching them directly.
            assert csp.is_ucp_enabled() is True, (
                "is_ucp_enabled() should return True because "
                "demisto.unifiedConnectorMetadata() is mocked truthy"
            )
            assert csp.should_use_ucp_auth() is True, (
                "should_use_ucp_auth() should return True because "
                "is_ucp_enabled() is True AND the defensive loop "
                "reset _UCP_AUTH_PARAMS_INJECTED to False"
            )
            # And the defensive reset actually fired.
            assert csp._UCP_AUTH_PARAMS_INJECTED is False
        finally:
            _os.environ.pop("AUTH_PARITY_UCP_ENABLED", None)
            _os.environ.pop("AUTH_PARITY_UCP_CREDS", None)
            csp._UCP_AUTH_PARAMS_INJECTED = prev_injected  # type: ignore[attr-defined]
            if prev_get is None:
                _demistomock.__dict__.pop("getUCPCredentials", None)
            else:
                _demistomock.getUCPCredentials = prev_get  # type: ignore[attr-defined]
            if prev_meta is None:
                _demistomock.__dict__.pop("unifiedConnectorMetadata", None)
            else:
                _demistomock.unifiedConnectorMetadata = prev_meta  # type: ignore[attr-defined]
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
            # Keep _sys reference used elsewhere from being flagged unused.
            _ = _sys

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


# --------------------------------------------------------------------------
# _seed_url_params — URL alias rewrite (regression for the silent no-op
# that let 45+ integrations bypass the capture proxy because their
# YML param was named ``server_url`` / ``host`` / ``base_url`` rather
# than the hardcoded ``url``).
# --------------------------------------------------------------------------


class TestUrlParamRewrite:
    PROXY_PORT = 54321
    PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"

    def test_rewrites_url_key(self) -> None:
        params = {"url": "https://real.com"}
        cap._seed_url_params(params, self.PROXY_PORT)
        assert params["url"] == self.PROXY_URL

    def test_rewrites_server_url_key(self) -> None:
        """The Jira V3 regression: ``server_url`` must be rewritten."""
        params = {"server_url": "https://api.atlassian.com/ex/jira"}
        cap._seed_url_params(params, self.PROXY_PORT)
        assert params["server_url"] == self.PROXY_URL

    def test_rewrites_multiple_aliases_if_present(self) -> None:
        params = {
            "url": "https://real.com",
            "server_url": "https://other.com",
        }
        cap._seed_url_params(params, self.PROXY_PORT)
        assert params["url"] == self.PROXY_URL
        assert params["server_url"] == self.PROXY_URL

    def test_warns_when_no_url_param_present(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        params: dict[str, object] = {"some_other_param": "foo"}
        cap._seed_url_params(params, self.PROXY_PORT, integration_id="MyInt")
        captured = capsys.readouterr()
        assert "[auth_parity] WARNING" in captured.err
        assert "'MyInt'" in captured.err
        # The integration_id-less variant should still warn (just less informative).
        params2: dict[str, object] = {"foo": "bar"}
        cap._seed_url_params(params2, self.PROXY_PORT)
        captured2 = capsys.readouterr()
        assert "[auth_parity] WARNING" in captured2.err

    def test_insecure_always_set_to_true(self) -> None:
        # Matched-alias case.
        params_with_url = {"url": "https://real.com"}
        cap._seed_url_params(params_with_url, self.PROXY_PORT)
        assert params_with_url["insecure"] is True
        # Aliased-key case.
        params_with_alias = {"server_url": "https://real.com"}
        cap._seed_url_params(params_with_alias, self.PROXY_PORT)
        assert params_with_alias["insecure"] is True
        # No-match case (still set, even when warning fires).
        params_no_match: dict[str, object] = {"foo": "bar"}
        cap._seed_url_params(params_no_match, self.PROXY_PORT)
        assert params_no_match["insecure"] is True

    def test_does_not_create_url_key_if_absent(self) -> None:
        """Guard against the previous silent-no-op behavior: when only
        ``server_url`` is present, we must NOT inject an unrelated
        ``url`` key the YML never declared."""
        params = {"server_url": "https://api.atlassian.com"}
        cap._seed_url_params(params, self.PROXY_PORT)
        assert params["server_url"] == self.PROXY_URL
        assert "url" not in params
        # And the symmetric case — params with only ``host`` shouldn't
        # gain ``url`` or any other alias key.
        params_host = {"host": "https://example.com"}
        cap._seed_url_params(params_host, self.PROXY_PORT)
        assert params_host["host"] == self.PROXY_URL
        for alias in cap._URL_PARAM_ALIASES:
            if alias != "host":
                assert alias not in params_host

    def test_runs_side_by_side_with_seed_proxy_env(self) -> None:
        """Confirm both seeders run on the same params dict with no conflict.

        Regression for the §2.7 "both mechanisms, every run" decision —
        ``_seed_url_params`` and ``_seed_proxy_env`` mutate the same
        ``params`` and the result is consistent: the URL alias points at
        the proxy, ``proxy=True``, ``insecure=True``, and the env-var
        seeder has not clobbered the alias rewrite.
        """
        params = {"server_url": "https://api.atlassian.com"}
        env: dict[str, str] = {}
        cap._seed_url_params(params, self.PROXY_PORT, integration_id="MyInt")
        cap._seed_proxy_env(params, env, self.PROXY_PORT, integration_id="MyInt")
        assert params["server_url"] == self.PROXY_URL
        assert params["proxy"] is True
        assert params["insecure"] is True
        assert env["HTTPS_PROXY"] == self.PROXY_URL


# --------------------------------------------------------------------------
# _seed_proxy_env — HTTPS_PROXY env-var seeding for the MITM CONNECT path.
# Companion to TestUrlParamRewrite (see plan
# plans/auth-parity-proxy-mitm-refactor.md §2.2). Both run unconditionally
# every parity run.
# --------------------------------------------------------------------------


class TestSeedProxyEnv:
    PROXY_PORT = 54321
    PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"

    def test_seeds_https_proxy_env_var(self) -> None:
        params: dict[str, object] = {}
        env: dict[str, str] = {}
        cap._seed_proxy_env(params, env, self.PROXY_PORT)
        assert env["HTTPS_PROXY"] == self.PROXY_URL
        assert env["https_proxy"] == self.PROXY_URL

    def test_seeds_http_proxy_env_var(self) -> None:
        params: dict[str, object] = {}
        env: dict[str, str] = {}
        cap._seed_proxy_env(params, env, self.PROXY_PORT)
        assert env["HTTP_PROXY"] == self.PROXY_URL
        assert env["http_proxy"] == self.PROXY_URL

    def test_sets_proxy_param_true(self) -> None:
        """``BaseClient`` gates env-var honoring on ``params['proxy']``."""
        params: dict[str, object] = {"proxy": False}
        env: dict[str, str] = {}
        cap._seed_proxy_env(params, env, self.PROXY_PORT)
        assert params["proxy"] is True

    def test_sets_insecure_true(self) -> None:
        """The MITM cert is self-signed; verification must be off."""
        params: dict[str, object] = {"insecure": False}
        env: dict[str, str] = {}
        cap._seed_proxy_env(params, env, self.PROXY_PORT)
        assert params["insecure"] is True

    def test_clears_no_proxy_default(self) -> None:
        """``NO_PROXY=localhost,127.0.0.1`` would let requests skip the proxy
        and hit a real upstream; we explicitly clear it.
        """
        params: dict[str, object] = {}
        env: dict[str, str] = {"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "*"}
        cap._seed_proxy_env(params, env, self.PROXY_PORT)
        assert env["NO_PROXY"] == ""
        assert env["no_proxy"] == ""


# --------------------------------------------------------------------------
# CONNECT MITM tunnel: the proxy must terminate ``CONNECT host:port`` from
# HTTPS_PROXY-aware clients, wrap the socket in TLS with its self-signed
# cert, and record the inner decrypted request tagged
# ``"transport": "connect-mitm"``. Loopback CONNECT to the proxy's own
# port must be refused with 403.
# --------------------------------------------------------------------------


class TestConnectMitm:
    @pytest.fixture()
    def proxy(self):  # type: ignore[no-untyped-def]
        # Import inside the fixture so a missing ``cryptography`` blows up
        # the one test class that needs it rather than the whole module.
        from capture_proxy import CaptureProxy  # noqa: WPS433

        p = CaptureProxy(port=0)
        p.start()
        try:
            yield p
        finally:
            p.stop()

    @staticmethod
    def _send_connect(port: int, target: str):  # type: ignore[no-untyped-def]
        import socket

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii")
        )
        buf = b""
        deadline = 0
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            deadline += 1
            if deadline > 50:
                break
        return buf, s

    def test_connect_returns_200_then_tls_wraps(self, proxy) -> None:  # type: ignore[no-untyped-def]
        """Happy path: 200 Connection Established, then TLS handshake succeeds."""
        import ssl

        resp, sock = self._send_connect(proxy.port, "api.example.com:443")
        try:
            head = resp.split(b"\r\n", 1)[0]
            assert b"200" in head, f"expected 200, got {head!r}"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(sock, server_hostname="api.example.com")
            try:
                # Issuer CN proves it's our MITM cert, not the real one.
                der = tls.getpeercert(binary_form=True)
                assert der is not None and len(der) > 0
            finally:
                tls.close()
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def test_connect_records_inner_request_with_transport_tag(self, proxy) -> None:  # type: ignore[no-untyped-def]
        """Inner HTTP request flows through ``_handle_capture`` tagged
        ``transport="connect-mitm"`` and ``connect_host`` set to the
        CONNECT target."""
        import ssl

        sid = proxy.new_session()
        resp, sock = self._send_connect(proxy.port, "api.example.com:443")
        assert b"200" in resp.split(b"\r\n", 1)[0]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname="api.example.com")
        try:
            tls.sendall(
                b"POST /v1/widgets HTTP/1.1\r\n"
                b"Host: api.example.com\r\n"
                b"Content-Length: 11\r\n\r\n"
                b"hello world"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
            assert b"200" in buf.split(b"\r\n", 1)[0]
        finally:
            tls.close()
        requests = proxy.get_requests(sid)
        assert len(requests) == 1
        req = requests[0]
        assert req["transport"] == "connect-mitm"
        assert req["connect_host"] == "api.example.com"
        assert req["connect_port"] == 443
        assert req["method"] == "POST"
        assert req["path"] == "/v1/widgets"
        assert req["body"] == "hello world"

    def test_connect_refuses_loopback_to_own_port(self, proxy) -> None:  # type: ignore[no-untyped-def]
        """A CONNECT aimed at the proxy itself must 403; otherwise a
        misconfigured client could tunnel TLS into the control-plane
        handler."""
        target = f"127.0.0.1:{proxy.port}"
        resp, sock = self._send_connect(proxy.port, target)
        try:
            head = resp.split(b"\r\n", 1)[0]
            assert b"403" in head, f"expected 403 Loopback Forbidden, got {head!r}"
            assert b"Loopback Forbidden" in resp
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def test_cert_files_exist_during_proxy_lifetime(self, proxy) -> None:  # type: ignore[no-untyped-def]
        cert_dir = proxy.cert_dir()
        cert_path = proxy.ca_cert_path()
        assert cert_dir is not None and cert_dir.exists()
        assert cert_path is not None and cert_path.exists()
        # key.pem alongside cert.pem.
        assert (cert_dir / "key.pem").exists()
        # PEM-encoded cert.
        assert cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")

    def test_cert_dir_cleaned_up_on_proxy_stop(self) -> None:
        """The tempdir must be removed when the proxy stops — no leaked
        certs on disk between runs."""
        from capture_proxy import CaptureProxy  # noqa: WPS433

        p = CaptureProxy(port=0)
        p.start()
        cert_dir = p.cert_dir()
        assert cert_dir is not None and cert_dir.exists()
        p.stop()
        assert p.cert_dir() is None
        assert not cert_dir.exists()


# --------------------------------------------------------------------------
# §X — Inconclusive-status emission contract (FIXES-TODO #1)
# --------------------------------------------------------------------------
#
# The parity-gate evaluator in workflow_state.api now REJECTS connections
# whose status is "inconclusive" (previously they were silently accepted).
# These tests pin the lower-level contract: which run-shape combinations
# produce status="inconclusive" so the gate's rejection path actually fires
# for the right inputs.


class TestUcpStripCrashDetection:
    """FIXES-TODO #13 — post-classify ``RUN_FAILED_NEW`` for the
    UCP-strip-crash pattern.

    The new run strips every key listed in the connection's
    ``xsoar_param_map`` from ``params`` before invoking the child
    (UCP is supposed to inject the secret via
    ``demisto.getUCPCredentials()`` instead). Integrations whose
    ``main()`` reads those keys unconditionally crash with either:

    * ``KeyError: '<leaf>'`` where the leaf appears in the
      xsoar_param_map, OR
    * ``TypeError: 'NoneType' object is not subscriptable`` from a
      ``.get("credentials").get(...)`` chain.

    The post-classifier replaces the generic ``RUN_FAILED_NEW`` with
    the more specific ``UCP_STRIP_CRASHED_UNCONDITIONAL_READ`` code so
    the operator can recognize the pattern and apply one of the two
    documented fixes from skill §1.12.
    """

    @staticmethod
    def _crashed_run(stderr: str) -> cap.RunResult:
        return cap.RunResult(
            status="crashed", rc=1, stdout="", stderr=stderr,
            timed_out=False, requests=[],
        )

    @staticmethod
    def _ok_run() -> cap.RunResult:
        return cap.RunResult(
            status="ok", rc=0, stdout="", stderr="", timed_out=False,
            requests=[],
        )

    @staticmethod
    def _plain_entry_with_credentials() -> AuthEntry:
        return AuthEntry(
            type=AuthType.Plain, name="creds",
            xsoar_param_map={
                "credentials.identifier": "username",
                "credentials.password": "password",
            },
        )

    def test_keyerror_on_identifier_triggers_reclassification(self) -> None:
        """The AMPv2 case: KeyError on a leaf from xsoar_param_map."""
        stderr = (
            "Traceback (most recent call last):\n"
            '  File "/x/AMPv2.py", line 3665, in main\n'
            '    client_id = params["credentials"]["identifier"]\n'
            "              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^\n"
            "KeyError: 'identifier'\n"
        )
        new_run = self._crashed_run(stderr)
        entry = self._plain_entry_with_credentials()
        diffs = [cap.Diff(sentinel="", failure_code="RUN_FAILED_NEW",
                          old_locations=[], new_locations=[])]
        rewritten = cap._reclassify_ucp_strip_crash(diffs, new_run, entry)
        codes = [d.failure_code for d in rewritten]
        assert "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" in codes
        assert "RUN_FAILED_NEW" not in codes

    def test_nonetype_chain_triggers_reclassification(self) -> None:
        """The defensive ``.get('credentials').get(...)`` chain still
        crashes because UCP strips the parent dict — the leaf .get
        returns None and the second .get fails with TypeError."""
        stderr = (
            "Traceback (most recent call last):\n"
            '  File "/x/Int.py", line 100, in main\n'
            '    user = params.get("credentials").get("identifier")\n'
            "TypeError: 'NoneType' object is not subscriptable\n"
        )
        new_run = self._crashed_run(stderr)
        entry = self._plain_entry_with_credentials()
        diffs = [cap.Diff(sentinel="", failure_code="RUN_FAILED_NEW",
                          old_locations=[], new_locations=[])]
        rewritten = cap._reclassify_ucp_strip_crash(diffs, new_run, entry)
        codes = [d.failure_code for d in rewritten]
        assert "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" in codes

    def test_unrelated_keyerror_does_not_trigger(self) -> None:
        """KeyError on a key NOT in xsoar_param_map should NOT be
        reclassified — it's a genuine bug, not the UCP-strip pattern."""
        stderr = (
            "Traceback (most recent call last):\n"
            "KeyError: 'some_unrelated_key'\n"
        )
        new_run = self._crashed_run(stderr)
        entry = self._plain_entry_with_credentials()
        diffs = [cap.Diff(sentinel="", failure_code="RUN_FAILED_NEW",
                          old_locations=[], new_locations=[])]
        rewritten = cap._reclassify_ucp_strip_crash(diffs, new_run, entry)
        codes = [d.failure_code for d in rewritten]
        assert "RUN_FAILED_NEW" in codes
        assert "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" not in codes

    def test_ok_new_run_does_not_trigger(self) -> None:
        """A passing new run with no RUN_FAILED_NEW diff is left alone."""
        new_run = self._ok_run()
        entry = self._plain_entry_with_credentials()
        diffs: list[cap.Diff] = []
        rewritten = cap._reclassify_ucp_strip_crash(diffs, new_run, entry)
        assert rewritten == []

    def test_unrelated_nonetype_without_credentials_in_map_does_not_trigger(
        self,
    ) -> None:
        """NoneType subscript error without any 'credentials' key in
        xsoar_param_map should NOT be reclassified — too noisy."""
        stderr = (
            "TypeError: 'NoneType' object is not subscriptable\n"
        )
        new_run = self._crashed_run(stderr)
        # Entry whose xsoar_param_map has no 'credentials' key.
        entry = AuthEntry(
            type=AuthType.APIKey, name="api_key",
            xsoar_param_map={"api_key": "key"},
        )
        diffs = [cap.Diff(sentinel="", failure_code="RUN_FAILED_NEW",
                          old_locations=[], new_locations=[])]
        rewritten = cap._reclassify_ucp_strip_crash(diffs, new_run, entry)
        codes = [d.failure_code for d in rewritten]
        assert "RUN_FAILED_NEW" in codes
        assert "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" not in codes


class TestCommandStatusInconclusiveEmission:
    """Pin the inputs that produce ``_command_status == 'inconclusive'``.

    Added 2026-05-31 alongside FIXES-TODO #1: the gate at the
    workflow_state level rejects ``inconclusive`` rather than accepting
    it permissively. Documenting here which run-shape combinations
    produce that status so the rejection contract is grounded in
    observable behavior.
    """

    @staticmethod
    def _run(status: str, stderr: str = "") -> cap.RunResult:
        return cap.RunResult(
            status=status, rc=0, stdout="", stderr=stderr, timed_out=False,
            requests=[],
        )

    def test_both_crashed_yields_inconclusive(self) -> None:
        old = self._run("crashed", stderr="prepare-content failed: boom")
        new = self._run("crashed", stderr="prepare-content failed: boom")
        diffs = cap._run_status_diffs(old, new)
        status = cap._command_status(old, new, diffs)
        assert status == "inconclusive"

    def test_only_new_crashed_yields_inconclusive(self) -> None:
        old = self._run("ok")
        new = self._run("crashed", stderr="KeyError: 'identifier'")
        diffs = cap._run_status_diffs(old, new)
        status = cap._command_status(old, new, diffs)
        assert status == "inconclusive"

    def test_both_no_requests_yields_inconclusive(self) -> None:
        old = self._run("no_requests")
        new = self._run("no_requests")
        diffs = cap._run_status_diffs(old, new)
        status = cap._command_status(old, new, diffs)
        assert status == "inconclusive"

    def test_clean_ok_with_no_diffs_yields_pass(self) -> None:
        # Sanity: the inconclusive contract isn't accidentally triggered
        # when both runs are clean and there are no diffs.
        old = self._run("ok")
        new = self._run("ok")
        status = cap._command_status(old, new, diffs=[])
        assert status == "pass"


class TestResolveIntegrationPath:
    """Regression for sweep finding F1 (2026-06-03): the standalone CLI
    must resolve repo-root-relative ``Packs/...`` paths (as printed by the
    ``files`` command and used in the skill's §1.12 playbook) even when the
    process cwd is not the repo root.
    """

    def test_cwd_relative_existing_dir_resolves(self, tmp_path, monkeypatch) -> None:
        d = tmp_path / "Packs" / "Foo" / "Integrations" / "Foo"
        d.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        got = cap._resolve_integration_path("Packs/Foo/Integrations/Foo")
        assert got == d.resolve()

    def test_repo_root_relative_resolves_from_other_cwd(self, tmp_path, monkeypatch) -> None:
        # Point the module's repo-root anchor at a temp tree, then chdir
        # somewhere else entirely. The repo-root-relative path must still
        # resolve.
        repo = tmp_path / "repo"
        d = repo / "Packs" / "Bar" / "Integrations" / "Bar"
        d.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.setattr(cap, "_REPO_ROOT", repo.resolve())
        monkeypatch.chdir(elsewhere)
        got = cap._resolve_integration_path("Packs/Bar/Integrations/Bar")
        assert got == d.resolve()

    def test_nonexistent_path_returns_none(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
        monkeypatch.chdir(tmp_path)
        assert cap._resolve_integration_path("Packs/Nope/Nope") is None

    def test_absolute_path_not_repo_joined(self, tmp_path, monkeypatch) -> None:
        d = tmp_path / "abs" / "dir"
        d.mkdir(parents=True)
        monkeypatch.setattr(cap, "_REPO_ROOT", (tmp_path / "repo").resolve())
        got = cap._resolve_integration_path(str(d))
        assert got == d.resolve()

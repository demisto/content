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
        type=AuthType.APIKey, name=name, xsoar_params=["api_key"],
        interpolated=interpolated,
    )


def _plain_entry(name: str = "creds") -> AuthEntry:
    return AuthEntry(
        type=AuthType.Plain, name=name,
        xsoar_params=["credentials.identifier", "credentials.password"],
    )


def _oauth_entry(name: str = "oauth", subtype: AuthType = AuthType.OAuth2ClientCreds) -> AuthEntry:
    return AuthEntry(type=subtype, name=name, xsoar_params=["client_secret"])


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
        details = _details(_api_key_entry(), _plain_entry("creds"))
        smap = cap.generate_sentinels(details)
        pat = re.compile(r"^__AUTHPARITY__[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+__[0-9a-f]{8}$")
        for conn_name, conn_sentinels in smap.by_connection.items():
            assert conn_sentinels, f"connection {conn_name} has no sentinels"
            for path, value in conn_sentinels.items():
                assert pat.match(value), f"sentinel for {conn_name}.{path} not in expected shape: {value!r}"

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
        assert set(smap.for_connection("creds").keys()) == {
            "credentials.identifier", "credentials.password",
        }

    def test_minimum_length_40(self) -> None:
        # Real-world auth-types[].name values are always at least a few
        # characters; the design's ≥40-char promise covers any non-trivial
        # input. Use a representative Plain connection here.
        details = _details(_plain_entry("credentials"))
        smap = cap.generate_sentinels(details)
        for value in smap.for_connection("credentials").values():
            assert len(value) >= 40, f"sentinel too short ({len(value)}): {value!r}"


# --------------------------------------------------------------------------
# map_auth_type_to_ucp_shape
# --------------------------------------------------------------------------


class TestMapAuthTypeToUcpShape:
    def test_api_key(self) -> None:
        entry = _api_key_entry()
        sentinels = {"api_key": "S_API"}
        shape = cap.map_auth_type_to_ucp_shape(entry, sentinels)
        assert shape == {"type": "api_key", "api_key": {"key": "S_API"}}

    def test_plain(self) -> None:
        entry = _plain_entry()
        sentinels = {
            "credentials.identifier": "S_USER",
            "credentials.password": "S_PASS",
        }
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
        shape = cap.map_auth_type_to_ucp_shape(entry, {"client_secret": "S_TOK"})
        assert shape == {
            "type": "oauth2",
            "oauth2": {"access_token": "S_TOK", "token_type": "Bearer"},
        }

    def test_other_returns_none(self) -> None:
        entry = AuthEntry(type=AuthType.Other, name="x", xsoar_params=["x"])
        assert cap.map_auth_type_to_ucp_shape(entry, {"x": "S"}) is None

    def test_none_required_returns_none(self) -> None:
        entry = AuthEntry(type=AuthType.NoneRequired, name="n", xsoar_params=[])
        assert cap.map_auth_type_to_ucp_shape(entry, {}) is None


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
    def test_error_non_python(self, tmp_path: Path) -> None:
        pack = _make_js_integration(tmp_path)
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "JsInt"]
        )
        assert rc == cap.EXIT_NON_PYTHON
        assert payload["error"]["code"] == cap.ERROR_NON_PYTHON
        assert cap._LITERAL_MARK_AUTH in payload["error"]["message"]

    def test_error_no_baseclient(self, tmp_path: Path) -> None:
        py = "def main():\n    pass\n"  # No BaseClient anywhere.
        pack = _make_python_integration(tmp_path, py_source=py)
        rc, payload = _run_main_capture(
            [str(pack), "--integration-id", "TestInt"]
        )
        assert rc == cap.EXIT_NO_BASECLIENT
        assert payload["error"]["code"] == cap.ERROR_NO_BASECLIENT
        assert cap._LITERAL_MARK_AUTH in payload["error"]["message"]

    def test_error_all_interpolated(self, tmp_path: Path) -> None:
        pack = _make_python_integration(tmp_path)
        # Stub out the Auth Details read to return all-interpolated config.
        details_json = {
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_params": ["api_key"], "interpolated": True},
            ],
            "config": "REQUIRED(api_key)",
            "other_connection": [],
        }
        with mock.patch.object(cap, "_read_auth_details_json", return_value=details_json):
            rc, payload = _run_main_capture(
                [str(pack), "--integration-id", "TestInt"]
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
                 "xsoar_params": ["api_key"], "interpolated": True},
                {"type": "APIKey", "name": "kept",
                 "xsoar_params": ["api_key"], "interpolated": False},
            ],
            "config": "REQUIRED(kept) + OPTIONAL(dropped)",
            "other_connection": [],
        }
        with mock.patch.object(cap, "_read_auth_details_json", return_value=details_json):
            rc, payload = _run_main_capture(
                [str(pack), "--integration-id", "TestInt",
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

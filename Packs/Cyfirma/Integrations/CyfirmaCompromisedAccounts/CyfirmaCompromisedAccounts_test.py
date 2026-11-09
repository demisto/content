"""Unit tests for the CYFIRMA Compromised Accounts integration."""

import json
import re
from datetime import datetime, UTC
from unittest.mock import ANY, MagicMock

import CyfirmaCompromisedAccounts as mod  # <-- change to your module name
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, IncidentSeverity

BASE_URL = "https://api.test/api/ex/v3/da"

EVENT = {
    "uid": "U1",
    "title": "Leaked credentials",
    "category": "COMPROMISED",
    "categoryLabel": "Compromised Accounts",
    "subCategory": "CUSTOMER",
    "subCategoryLabel": "Customer Accounts",
    "lastModifiedDate": "2026-10-02T10:00:00Z",
    "createdDate": "2026-10-01T10:00:00Z",
    "email": "a@b.com",
    "user": "should-be-skipped",
    "compromisedDetails": {"password": "x", "source": "leak"},
}


@pytest.fixture
def client():
    return mod.Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "k"})


def _rows(custom_fields: dict) -> dict:
    return {r["fields"]: r["values"] for r in custom_fields["cyfirmacompromisedaccountdetails"]}


# ------------------------------------------------------------------ helpers
class TestHelpers:
    def test_kv_fields_capitalizes_and_skips(self):
        res = mod._kv_fields({"abc": 1, "skipme": 2, "xYz": 3}, skip={"skipme"})
        assert res == [{"fields": "Abc", "values": 1}, {"fields": "Xyz", "values": 3}]

    def test_kv_fields_empty(self):
        assert mod._kv_fields({}) == []

    def test_parse_date_utc_aware(self):
        res = mod._parse_date("2026-10-01T10:00:00Z")
        assert res is not None
        assert res.utcoffset().total_seconds() == 0

    def test_parse_date_relative(self):
        assert mod._parse_date("90 days") is not None

    @pytest.mark.parametrize("value", [None, "", "this is not a date at all"])
    def test_parse_date_invalid(self, value):
        assert mod._parse_date(value) is None


# ------------------------------------------------------------------ call_api
class TestCallApi:
    def test_returns_json(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/foo/ping", json={"isOrgActive": True})
        assert client.call_api("/foo/ping") == {"isOrgActive": True}

    def test_empty_body_returns_empty_dict(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/foo/ping", status_code=200, content=b"")
        assert client.call_api("/foo/ping") == {}

    def test_http_error_raises(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/foo/ping", status_code=403, text="Forbidden")
        with pytest.raises(DemistoException):
            client.call_api("/foo/ping")

    def test_sends_params_and_api_key(self, client, requests_mock):
        m = requests_mock.get(f"{BASE_URL}/x", json={})
        client.call_api("/x", params={"page": 3})
        assert m.last_request.qs == {"page": ["3"]}
        assert m.last_request.headers["X-Api-Key"] == "k"


# ------------------------------------------------------------------ custom fields
class TestPopulateCustomFields:
    def test_full_event(self, client):
        cf = client._populate_custom_fields(EVENT)
        assert list(cf) == ["cyfirmacompromisedaccountdetails"]
        rows = _rows(cf)
        assert rows["Subcategory"] == "Customer Accounts"
        assert rows["Category"] == "Compromised Accounts"
        assert rows["Title"] == "Leaked credentials"
        assert rows["Uid"] == "U1"
        assert rows["Email"] == "a@b.com"
        assert rows["Password"] == "x"
        assert rows["Source"] == "leak"

    def test_skipped_fields_not_present(self, client):
        rows = _rows(client._populate_custom_fields(EVENT))
        for skipped in ("User", "Compromiseddetails", "Subcategorylabel", "Categorylabel"):
            assert skipped not in rows
        # "Category"/"Subcategory" come from the label rows, not from the raw keys
        assert rows["Category"] != "COMPROMISED"

    @pytest.mark.parametrize("details", [None, {}])
    def test_empty_or_null_compromised_details(self, client, details):
        """Regression: explicit null used to raise AttributeError."""
        cf = client._populate_custom_fields({"uid": "U", "compromisedDetails": details})
        rows = _rows(cf)
        assert rows["Uid"] == "U"

    def test_missing_labels_default_to_empty(self, client):
        rows = _rows(client._populate_custom_fields({}))
        assert rows == {"Subcategory": "", "Category": ""}


# ------------------------------------------------------------------ incident building
class TestBuildIncident:
    def test_full_event(self, client):
        inc = client._build_incident_json(EVENT)
        assert inc["type"] == "Compromised Accounts"
        assert inc["name"] == "Leaked credentials"
        assert inc["occurred"] == "2026-10-02T10:00:00Z"
        assert inc["severity"] == IncidentSeverity.CRITICAL
        assert inc["category"] == "COMPROMISED"
        assert inc["subcategory"] == "CUSTOMER"
        assert inc["dbotMirrorId"] == "U1"
        assert inc["sourceBrand"] == "CYFIRMA"
        assert json.loads(inc["rawJSON"]) == EVENT
        assert "cyfirmacompromisedaccountdetails" in inc["CustomFields"]

    def test_occurred_falls_back_to_created_date(self, client):
        """Regression: the default used to be the literal string 'createdDate'."""
        inc = client._build_incident_json({"createdDate": "2026-09-01T00:00:00Z"})
        assert inc["occurred"] == "2026-09-01T00:00:00Z"

    def test_last_modified_preferred_over_created(self, client):
        inc = client._build_incident_json({"lastModifiedDate": "2026-09-02T00:00:00Z", "createdDate": "2026-09-01T00:00:00Z"})
        assert inc["occurred"] == "2026-09-02T00:00:00Z"

    def test_occurred_none_without_dates(self, client):
        assert client._build_incident_json({"title": "t"})["occurred"] is None

    def test_empty_event_defaults(self, client):
        inc = client._build_incident_json({})
        assert inc["type"] == ""
        assert inc["name"] == ""
        assert inc["dbotMirrorId"] == ""
        assert inc["severity"] == IncidentSeverity.CRITICAL


# ------------------------------------------------------------------ get_incidents
class TestGetIncidents:
    def test_queries_all_three_endpoints(self, client, mocker):
        paths = []

        def fake(end_point, params=None):
            paths.append(end_point)
            return {"data": [EVENT], "metaData": {"isLast": True}}

        mocker.patch.object(client, "call_api", side_effect=fake)
        incidents = client.get_incidents({"size": 2})

        assert paths == list(mod._API_PATHS.values())
        assert len(paths) == 3
        assert len(incidents) == 3
        assert "X-Request-Id" in client._headers

    def test_pagination(self, client, mocker):
        calls = []
        pages = iter(
            [
                {"data": [EVENT], "metaData": {"isLast": False}},
                {"data": [EVENT], "metaData": {"isLast": False}},
                {"data": [EVENT], "metaData": {"isLast": True}},
            ]
        )

        def fake(end_point, params=None):
            calls.append((end_point, params["page"]))
            if end_point == mod._API_PATHS["CUS"]:
                return next(pages)
            return {"data": [], "metaData": {"isLast": True}}

        mocker.patch.object(client, "call_api", side_effect=fake)
        incidents = client.get_incidents({})

        assert len(incidents) == 3
        assert calls[:3] == [(mod._API_PATHS["CUS"], 0), (mod._API_PATHS["CUS"], 1), (mod._API_PATHS["CUS"], 2)]
        # page resets for the next endpoint
        assert calls[3] == (mod._API_PATHS["EMP"], 0)
        assert calls[4] == (mod._API_PATHS["PUB"], 0)

    def test_caller_params_not_mutated(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"data": [], "metaData": {"isLast": True}})
        params = {"size": 5}
        client.get_incidents(params)
        assert params == {"size": 5}

    def test_params_forwarded(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"data": [], "metaData": {"isLast": True}})
        client.get_incidents({"size": 7, "after": 123, "includeThirdParty": True})
        sent = m.call_args.kwargs["params"]
        assert sent["size"] == 7
        assert sent["after"] == 123
        assert sent["includeThirdParty"] is True
        assert sent["page"] == 0

    @pytest.mark.parametrize("response", [{}, {"data": []}, {"metaData": {}}])
    def test_empty_responses(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        assert client.get_incidents({}) == []

    def test_unique_request_id_per_endpoint(self, client, mocker):
        ids = []

        def fake(end_point, params=None):
            ids.append(client._headers["X-Request-Id"])
            return {"data": [], "metaData": {"isLast": True}}

        mocker.patch.object(client, "call_api", side_effect=fake)
        client.get_incidents({})
        assert len(set(ids)) == 3


# ------------------------------------------------------------------ test_module
class TestTestModule:
    def test_ok(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"isOrgActive": True})
        assert mod.test_module(client) == "ok"

    def test_ok_with_company_active(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"isOrgActive": True, "isCompanyActive": True})
        assert mod.test_module(client) == "ok"

    @pytest.mark.parametrize(
        "response",
        [
            {},
            None,
            {"isOrgActive": False},
            {"isOrgActive": True, "isCompanyActive": False},
        ],
    )
    def test_not_authorized(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        assert mod.test_module(client) == "Not Authorized"

    @pytest.mark.parametrize("msg", ["Forbidden", "Unauthorized"])
    def test_auth_error(self, client, mocker, msg):
        mocker.patch.object(client, "call_api", side_effect=DemistoException(msg))
        assert "Authorization Error" in mod.test_module(client)

    def test_other_error_reraised(self, client, mocker):
        mocker.patch.object(client, "call_api", side_effect=DemistoException("boom"))
        with pytest.raises(DemistoException, match="boom"):
            mod.test_module(client)


# ------------------------------------------------------------------ fetch_incidents
class TestFetchIncidents:
    @pytest.fixture
    def fake_client(self):
        c = MagicMock()
        c.get_incidents.return_value = [{"name": "x"}]
        return c

    def test_first_run(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={"includeThirdPartyCompromisedAccounts": "true"})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        inc_mock = mocker.patch.object(demisto, "incidents")
        last_run_mock = mocker.patch.object(demisto, "setLastRun")

        mod.fetch_incidents(fake_client, "90 days", 5)

        sent = fake_client.get_incidents.call_args.kwargs["params"]
        assert sent["size"] == 5
        assert sent["page"] == 0
        assert sent["includeThirdParty"] is True
        assert isinstance(sent["after"], int)

        inc_mock.assert_called_once_with([{"name": "x"}])
        last_fetch = last_run_mock.call_args.args[0]["last_fetch"]
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", last_fetch)

    def test_include_third_party_defaults_false(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")
        mod.fetch_incidents(fake_client, "1 day", 5)
        assert fake_client.get_incidents.call_args.kwargs["params"]["includeThirdParty"] is False

    def test_uses_last_run(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2026-10-01T00:00:00Z"})
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")

        mod.fetch_incidents(fake_client, "90 days", 5)

        expected = int(datetime(2026, 10, 1, tzinfo=UTC).timestamp() * 1000)
        assert fake_client.get_incidents.call_args.kwargs["params"]["after"] == expected

    def test_last_run_without_last_fetch_uses_first_fetch(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={"unrelated": 1})
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")
        mod.fetch_incidents(fake_client, "7 days", 5)  # must not crash
        assert fake_client.get_incidents.called

    def test_none_last_run(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value=None)
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")
        mod.fetch_incidents(fake_client, "7 days", 5)
        assert fake_client.get_incidents.called

    def test_no_incidents_still_updates_last_run(self, fake_client, mocker):
        fake_client.get_incidents.return_value = []
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        inc_mock = mocker.patch.object(demisto, "incidents")
        set_mock = mocker.patch.object(demisto, "setLastRun")
        mod.fetch_incidents(fake_client, "1 day", 5)
        inc_mock.assert_called_once_with([])
        set_mock.assert_called_once()

    def test_invalid_first_fetch(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        with pytest.raises(DemistoException, match="Invalid 'First fetch'"):
            mod.fetch_incidents(fake_client, "not a valid date at all", 5)

    def test_api_error_does_not_update_last_run(self, fake_client, mocker):
        """Regression: Forbidden errors used to be swallowed (returned as a string)."""
        fake_client.get_incidents.side_effect = DemistoException("Forbidden")
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        set_mock = mocker.patch.object(demisto, "setLastRun")
        inc_mock = mocker.patch.object(demisto, "incidents")
        with pytest.raises(DemistoException):
            mod.fetch_incidents(fake_client, "1 day", 5)
        set_mock.assert_not_called()
        inc_mock.assert_not_called()

    def test_last_run_timestamp_taken_before_api_call(self, fake_client, mocker):
        """Alerts created while the fetch runs must not be skipped next time."""
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "incidents")
        set_mock = mocker.patch.object(demisto, "setLastRun")

        frozen = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
        dt_mock = mocker.patch.object(mod, "datetime")
        dt_mock.now.return_value = frozen
        mod.fetch_incidents(fake_client, "1 day", 5)

        dt_mock.now.assert_called_once_with(UTC)
        assert set_mock.call_args.args[0] == {"last_fetch": "2026-10-05T12:00:00Z"}


# ------------------------------------------------------------------ main
class TestMain:
    BASE_PARAMS = {
        "url": "https://api.test/",
        "api_key": {"password": "k"},
        "max_fetch": "5",
        "first_fetch": " 10 days ",
    }

    def _setup(self, mocker, command, params=None):
        mocker.patch.object(demisto, "params", return_value=params or self.BASE_PARAMS)
        mocker.patch.object(demisto, "command", return_value=command)
        mocker.patch.object(demisto, "info")
        rr = mocker.patch.object(mod, "return_results")
        err = mocker.patch.object(mod, "return_error", side_effect=SystemExit)
        return rr, err

    def test_test_module(self, mocker):
        rr, _ = self._setup(mocker, "test-module")
        mocker.patch.object(mod, "test_module", return_value="ok")
        mod.main()
        rr.assert_called_once_with("ok")

    def test_fetch_incidents(self, mocker):
        self._setup(mocker, "fetch-incidents")
        m = mocker.patch.object(mod, "fetch_incidents")
        mod.main()
        m.assert_called_once_with(ANY, "10 days", 5)

    def test_defaults(self, mocker):
        self._setup(mocker, "fetch-incidents", {"url": "https://x.com", "api_key": {"password": "k"}})
        m = mocker.patch.object(mod, "fetch_incidents")
        mod.main()
        m.assert_called_once_with(ANY, mod.DEFAULT_FIRST_FETCH, mod.DEFAULT_MAX_FETCH)

    def test_invalid_max_fetch_raises(self, mocker):
        self._setup(
            mocker,
            "fetch-incidents",
            {"url": "https://x.com", "api_key": {"password": "k"}, "max_fetch": "abc"},
        )
        with pytest.raises(ValueError):
            mod.main()

    def test_unknown_command(self, mocker):
        _, err = self._setup(mocker, "nope")
        with pytest.raises(SystemExit):
            mod.main()
        assert "not implemented" in err.call_args.args[0]

    @pytest.mark.parametrize(
        "params",
        [
            {"api_key": {"password": "k"}},
            {"url": "https://x.com"},
            {"url": "https://x.com", "api_key": None},
        ],
    )
    def test_missing_credentials(self, mocker, params):
        _, err = self._setup(mocker, "test-module", params)
        with pytest.raises(SystemExit):
            mod.main()
        assert "required" in err.call_args.args[0]

    def test_forbidden_gives_auth_message(self, mocker):
        _, err = self._setup(mocker, "test-module")
        mocker.patch.object(mod, "test_module", side_effect=Exception("403 Forbidden"))
        with pytest.raises(SystemExit):
            mod.main()
        err.assert_called_once_with("Authorization Error: make sure API Key is correctly set")

    def test_generic_error_message(self, mocker):
        _, err = self._setup(mocker, "test-module")
        mocker.patch.object(mod, "test_module", side_effect=Exception("kaboom"))
        with pytest.raises(SystemExit):
            mod.main()
        msg = err.call_args.args[0]
        assert "Failed to execute test-module command" in msg
        assert "kaboom" in msg

    def test_client_built_with_expected_config(self, mocker):
        self._setup(mocker, "test-module", {**self.BASE_PARAMS, "insecure": True, "proxy": True})
        mocker.patch.object(mod, "test_module", return_value="ok")
        client_cls = mocker.patch.object(mod, "Client")
        mod.main()
        kwargs = client_cls.call_args.kwargs
        assert kwargs["base_url"] == "https://api.test/api/ex/v3/da"
        assert kwargs["verify"] is False
        assert kwargs["proxy"] is True
        assert kwargs["headers"] == {"X-Api-Key": "k", "X-App-Name": "PALO_ALTO_XSOAR_V2_CA"}

"""Unit tests for the CYFIRMA integration."""

import json
import re
from datetime import datetime, UTC
from unittest.mock import ANY, MagicMock

import Cyfirma as mod
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, IncidentSeverity

BASE_URL = "https://api.test/api/ex/v3/da"

ALERT = {
    "alertId": "A1",
    "title": "Open port found",
    "category": "ATTACK_SURFACE",
    "categoryLabel": "Attack Surface",
    "subCategory": "OPEN_PORTS",
    "subCategoryLabel": "Open Ports",
    "alertCreatedDate": "2026-10-01T10:00:00Z",
    "alertDetails": {
        "uid": "U1",
        "exposureScore": 6.5,
        "host": "a.com",
        "networkAttributes": {"ip": "1.1.1.1"},
        "portDetails": [{"port": 80}, {"port": 443}, {"foo": 1}],
    },
}


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client():
    return mod.Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "k"})


def _rows(custom_fields: dict, key: str) -> dict:
    """Convert grid rows to {field: value} for easy assertions."""
    return {r["fields"]: r["values"] for r in custom_fields[key]}


# ------------------------------------------------------------------ helpers
class TestHelpers:
    def test_kv_fields_capitalizes_and_skips(self):
        res = mod._kv_fields({"abc": 1, "skipme": 2, "xYz": 3}, skip={"skipme"})
        assert res == [
            {"fields": "Abc", "values": 1},
            {"fields": "Xyz", "values": 3},
        ]

    def test_kv_fields_empty(self):
        assert mod._kv_fields({}) == []

    @pytest.mark.parametrize(
        "value, sep, expected",
        [
            (["a", "b"], ",", "a,b"),
            ([1, 2], "-", "1-2"),
            (("x", "y"), ", ", "x, y"),
            ({"only"}, ",", "only"),
            (None, ",", ""),
            ("text", ",", "text"),
            (5, ",", "5"),
            ([], ",", ""),
        ],
    )
    def test_safe_join(self, value, sep, expected):
        assert mod._safe_join(value, sep) == expected

    def test_parse_date_valid_and_utc_aware(self):
        res = mod._parse_date("2026-10-01T10:00:00Z")
        assert res is not None
        assert res.tzinfo is not None
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


# ------------------------------------------------------------------ take down API methods
class TestTakeDownClientMethods:
    def test_initiate_take_down_with_comment(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"ok": 1})
        assert client.initiate_take_down("A1", "please") == {"ok": 1}
        m.assert_called_once_with(mod._TAKE_DOWN_CREATE_API_PATH, {"alertId": "A1", "comment": "please"})

    def test_initiate_take_down_without_comment(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={})
        client.initiate_take_down("A1")
        m.assert_called_once_with(mod._TAKE_DOWN_CREATE_API_PATH, {"alertId": "A1"})

    def test_take_down_list_data_with_sub_category(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"data": [{"a": 1}]})
        assert client.take_down_list_data("PHISHING", "1", "10") == [{"a": 1}]
        m.assert_called_once_with(
            mod._TAKE_DOWN_LIST_API_PATH,
            {"page": "1", "size": "10", "subCategory": "PHISHING"},
        )

    def test_take_down_list_data_without_sub_category(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"data": []})
        assert client.take_down_list_data("", "0", "50") == []
        m.assert_called_once_with(mod._TAKE_DOWN_LIST_API_PATH, {"page": "0", "size": "50"})

    @pytest.mark.parametrize("response", [{}, None, []])
    def test_take_down_list_data_unexpected_response(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        assert client.take_down_list_data("", "0", "50") == []


# ------------------------------------------------------------------ severity
@pytest.mark.parametrize(
    "score, expected",
    [
        (9, IncidentSeverity.CRITICAL),
        (8.1, IncidentSeverity.CRITICAL),
        (8, IncidentSeverity.HIGH),
        (5.5, IncidentSeverity.HIGH),
        (5, IncidentSeverity.MEDIUM),
        (3, IncidentSeverity.MEDIUM),
        (2.9, IncidentSeverity.LOW),
        (1, IncidentSeverity.LOW),
        (0.5, IncidentSeverity.UNKNOWN),
        (0, IncidentSeverity.UNKNOWN),
        (-1, IncidentSeverity.UNKNOWN),
        (None, IncidentSeverity.UNKNOWN),
        ("abc", IncidentSeverity.UNKNOWN),
        ("7", IncidentSeverity.HIGH),
    ],
)
def test_get_severity(score, expected):
    assert mod._get_severity(score) == expected


# ------------------------------------------------------------------ custom fields
class TestPopulateCustomFields:
    def test_standard_alert(self, client):
        cf = client._populate_custom_fields(ALERT)

        details = _rows(cf, "cyfirmaalertdetails")
        assert details["Subcategory"] == "Open Ports"
        assert details["Category"] == "Attack Surface"
        assert details["Alertid"] == "A1"
        assert details["Objectid"] == "U1"
        assert details["Host"] == "a.com"
        assert "Portdetails" not in details  # skipped
        assert "Networkattributes" not in details  # skipped

        assert cf["cyfirmanetworkattributes"] == [{"fields": "Ip", "values": "1.1.1.1"}]
        assert cf["cyfirmadigitalfootprints"] == [{"fields": "Open Ports", "values": "80,443"}]
        assert "cyfirmadeepfakedetails" not in cf
        assert "cyfirmavulnerabilities" not in cf

    def test_deep_fake_details(self, client):
        alert = {"alertDetails": {"deepFakeDetails": {"score": 5}}}
        cf = client._populate_custom_fields(alert)
        assert cf["cyfirmadeepfakedetails"] == [{"fields": "Score", "values": 5}]

    def test_vulnerabilities(self, client):
        alert = {
            "subCategory": "DOMAIN_IP_VULNERABILITY",
            "alertDetails": {"vulnerabilities": [{"cveNo": "CVE-1", "cvssScore": 9, "isKev": True, "products": ["a", "b"]}]},
        }
        cf = client._populate_custom_fields(alert)
        assert cf["cyfirmavulnerabilities"] == [{"cve": "CVE-1", "cvssscore": 9, "kev": "True", "products": "a, b"}]

    def test_flat_event_without_alert_details(self, client):
        alert = {"alertId": "A9", "uid": "U9", "subCategory": "X", "host": "h"}
        cf = client._populate_custom_fields(alert)
        details = _rows(cf, "cyfirmaalertdetails")
        assert details["Objectid"] == "U9"
        assert details["Host"] == "h"


class TestSubCategoryFields:
    def test_open_ports(self, client):
        res = client._build_sub_category_data_fields({"portDetails": [{"port": 22}, {"port": 8080}, {}]}, "OPEN_PORTS")
        assert res == [{"fields": "Open Ports", "values": "22,8080"}]

    def test_open_ports_empty(self, client):
        res = client._build_sub_category_data_fields({}, "OPEN_PORTS")
        assert res == [{"fields": "Open Ports", "values": ""}]

    def test_certificates(self, client):
        res = client._build_sub_category_data_fields(
            {"certificateDetails": {"issuer": ["x", "y"], "serial": "1"}}, "CERTIFICATES"
        )
        assert res == [
            {"fields": "issuer", "values": "x,y"},
            {"fields": "serial", "values": "1"},
        ]

    def test_configuration(self, client):
        res = client._build_sub_category_data_fields(
            {"configurationDetails": {"missingEppCodes": ["a", "b"], "name": "n"}},
            "CONFIGURATION",
        )
        assert {"fields": "missingEppCodes", "values": "a,b"} in res
        assert {"fields": "name", "values": "n"} in res

    def test_ip_domain_reputation_only_reported_categories(self, client):
        res = client._build_sub_category_data_fields(
            {"ipDomainReputationDetails": {"reportedCategories": ["spam"], "other": "x"}},
            "IP_DOMAIN_REPUTATION",
        )
        assert res == [{"fields": "reportedCategories", "values": "spam"}]

    def test_default_asset_details(self, client):
        res = client._build_sub_category_data_fields({"assetDetails": {"os": "linux"}}, "OTHER")
        assert res == [{"fields": "Os", "values": "linux"}]


class TestStaticFieldHelpers:
    def test_vulnerability_fields_defaults(self):
        assert mod.Client._vulnerability_fields([{}]) == [{"cve": "", "cvssscore": "", "kev": "False", "products": ""}]

    def test_vulnerability_fields_empty(self):
        assert mod.Client._vulnerability_fields([]) == []

    def test_details_fields_non_list_join_value(self):
        res = mod.Client._details_fields({"issuer": None, "n": 1}, join_keys={"issuer"})
        assert res == [{"fields": "issuer", "values": ""}, {"fields": "n", "values": 1}]

    def test_details_fields_only_keys(self):
        res = mod.Client._details_fields({"a": 1, "b": 2}, join_keys=set(), only_keys={"b"})
        assert res == [{"fields": "b", "values": 2}]


# ------------------------------------------------------------------ incident building
class TestBuildIncident:
    def test_full_alert(self, client):
        inc = client._build_incident_json(ALERT)
        assert inc["type"] == "Attack Surface"
        assert inc["name"] == "Open port found"
        assert inc["occurred"] == "2026-10-01T10:00:00Z"
        assert inc["severity"] == IncidentSeverity.HIGH
        assert inc["category"] == "ATTACK_SURFACE"
        assert inc["subcategory"] == "OPEN_PORTS"
        assert inc["dbotMirrorId"] == "A1"
        assert inc["sourceBrand"] == "CYFIRMA"
        assert json.loads(inc["rawJSON"]) == ALERT
        assert "cyfirmaalertdetails" in inc["CustomFields"]

    def test_occurred_falls_back_to_last_modified(self, client):
        inc = client._build_incident_json({"lastModifiedDate": "2026-09-01T00:00:00Z"})
        assert inc["occurred"] == "2026-09-01T00:00:00Z"

    def test_occurred_none_without_dates(self, client):
        assert client._build_incident_json({"title": "t"})["occurred"] is None

    def test_mirror_id_falls_back_to_uid(self, client):
        inc = client._build_incident_json({"alertDetails": {"uid": "U7"}})
        assert inc["dbotMirrorId"] == "U7"

    def test_mirror_id_empty_when_nothing(self, client):
        assert client._build_incident_json({})["dbotMirrorId"] == ""

    def test_missing_exposure_score_is_unknown(self, client):
        inc = client._build_incident_json({"alertDetails": {}})
        assert inc["severity"] == IncidentSeverity.UNKNOWN


# ------------------------------------------------------------------ get_incidents
class TestGetIncidents:
    def test_pagination_and_disabled_types(self, client, mocker):
        calls = []
        pages = iter(
            [
                {"data": [ALERT], "metaData": {"isLast": False}},
                {"data": [ALERT], "metaData": {"isLast": True}},
            ]
        )

        def fake(end_point, params=None):
            calls.append((end_point, dict(params)))
            return next(pages)

        mocker.patch.object(client, "call_api", side_effect=fake)
        incidents = client.get_incidents({"size": 2}, {"AS": True, "BI": False})

        assert len(incidents) == 2
        assert [c[0] for c in calls] == [mod._API_PATHS["AS"]] * 2
        assert [c[1]["page"] for c in calls] == [0, 1]
        assert all(c[1]["size"] == 2 for c in calls)
        assert "X-Request-Id" in client._headers

    def test_caller_params_not_mutated(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"data": [], "metaData": {"isLast": True}})
        params = {"size": 5}
        client.get_incidents(params, {"AS": True})
        assert params == {"size": 5}

    def test_page_resets_per_alert_type(self, client, mocker):
        seen = []

        def fake(end_point, params=None):
            seen.append((end_point, params["page"]))
            return {"data": [], "metaData": {"isLast": end_point != mod._API_PATHS["AS"] or params["page"] == 1}}

        mocker.patch.object(client, "call_api", side_effect=fake)
        client.get_incidents({}, {"AS": True, "BI": True})
        assert seen == [
            (mod._API_PATHS["AS"], 0),
            (mod._API_PATHS["AS"], 1),
            (mod._API_PATHS["BI"], 0),
        ]

    def test_all_disabled_makes_no_calls(self, client, mocker):
        m = mocker.patch.object(client, "call_api")
        assert client.get_incidents({}, {"AS": False, "BI": False}) == []
        m.assert_not_called()

    def test_empty_response_stops(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={})
        assert client.get_incidents({}, {"AS": True}) == []


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


# ------------------------------------------------------------------ take down commands
TAKE_DOWN_ROW = {
    "ticket_name": "T-1",
    "sub_category": "PHISHING",
    "created_date": "2026-10-01",
    "modified_date": "2026-10-02",
    "status": "OPEN",
    "domain": "evil.com",
    "created_by": "u1",
    "modified_by": "u2",
    "url_status": "UP",
    "url_status_updated_by": "u3",
    "category": "BRAND",
}


class TestTakeDownListResults:
    def test_empty(self):
        res = mod.take_down_list_command_results([], "t")
        assert res.readable_output == "No data found for current request."
        assert res.outputs is None

    def test_unexpected_format(self):
        res = mod.take_down_list_command_results({"a": 1}, "t")  # type: ignore[arg-type]
        assert res.readable_output == "Unexpected response format."

    def test_success(self):
        res = mod.take_down_list_command_results([TAKE_DOWN_ROW], "My Title")
        assert res.outputs_prefix == "Cyfirma.TakeDownList"
        assert res.outputs_key_field == "ticket_id"
        assert res.outputs[0]["ticket_id"] == "T-1"
        assert res.outputs[0]["domain"] == "evil.com"
        assert "My Title" in res.readable_output
        assert "T-1" in res.readable_output
        assert res.raw_response == [TAKE_DOWN_ROW]

    def test_missing_keys_do_not_crash(self):
        res = mod.take_down_list_command_results([{}], "t")
        assert res.outputs[0]["ticket_id"] == ""


class TestInitiateTakeDown:
    def test_missing_alert_id(self, client, mocker):
        mocker.patch.object(demisto, "args", return_value={})
        with pytest.raises(DemistoException, match="alert_id is required"):
            mod.initiate_take_down_request(client)

    def test_success(self, client, mocker):
        mocker.patch.object(demisto, "args", return_value={"alert_id": "A1", "comment": "c"})
        m = mocker.patch.object(client, "initiate_take_down", return_value={"response": {"ticketName": "T-9"}})
        res = mod.initiate_take_down_request(client)
        m.assert_called_once_with("A1", "c")
        assert "T-9" in res.readable_output
        assert res.outputs["ticket_id"] == "T-9"
        assert res.outputs_prefix == "Cyfirma.InitiateTakeDown"

    @pytest.mark.parametrize(
        "api_response, expected",
        [
            ({}, "No data found"),
            ({"error": True}, "Error in creating"),
            ({"error": False, "response": {}}, "Error in creating"),
            ({"foo": "bar"}, "Error in creating"),
        ],
    )
    def test_failures(self, client, mocker, api_response, expected):
        mocker.patch.object(demisto, "args", return_value={"alert_id": "A1"})
        mocker.patch.object(client, "initiate_take_down", return_value=api_response)
        res = mod.initiate_take_down_request(client)
        assert expected in res.readable_output
        assert res.outputs["ticket_id"] == ""


class TestGetTakeDownList:
    def test_defaults(self, client, mocker):
        mocker.patch.object(demisto, "args", return_value={})
        m = mocker.patch.object(client, "take_down_list_data", return_value=[TAKE_DOWN_ROW])
        res = mod.get_take_down_list(client)
        m.assert_called_once_with("", "0", "50")
        assert "Sub Category: All" in res.readable_output
        assert "Page: 0" in res.readable_output

    def test_custom_args(self, client, mocker):
        mocker.patch.object(demisto, "args", return_value={"sub_category": "PHISH", "size": "5", "page": "2"})
        m = mocker.patch.object(client, "take_down_list_data", return_value=[TAKE_DOWN_ROW])
        res = mod.get_take_down_list(client)
        m.assert_called_once_with("PHISH", "2", "5")
        assert "Sub Category: PHISH" in res.readable_output

    def test_no_data(self, client, mocker):
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(client, "take_down_list_data", return_value=[])
        assert "No data found" in mod.get_take_down_list(client).readable_output


# ------------------------------------------------------------------ fetch_incidents
class TestFetchIncidents:
    @pytest.fixture
    def fake_client(self):
        c = MagicMock()
        c.get_incidents.return_value = [{"name": "x"}]
        return c

    def test_first_run(self, fake_client, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={"fetchAttackSurface": True, "includeThirdParty": "true"},
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        inc_mock = mocker.patch.object(demisto, "incidents")
        last_run_mock = mocker.patch.object(demisto, "setLastRun")

        mod.fetch_incidents(fake_client, "90 days", 5)

        kwargs = fake_client.get_incidents.call_args.kwargs
        assert kwargs["params"]["size"] == 5
        assert kwargs["params"]["page"] == 0
        assert kwargs["params"]["includeThirdParty"] is True
        assert isinstance(kwargs["params"]["after"], int)
        assert kwargs["alerts_to_fetch"]["AS"] is True
        for k in ("BI", "DW", "SP"):
            assert kwargs["alerts_to_fetch"][k] is False

        inc_mock.assert_called_once_with([{"name": "x"}])
        last_fetch = last_run_mock.call_args.args[0]["last_fetch"]
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", last_fetch)

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

    def test_invalid_first_fetch(self, fake_client, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        with pytest.raises(DemistoException, match="Invalid 'First fetch'"):
            mod.fetch_incidents(fake_client, "not a valid date at all", 5)

    def test_api_error_does_not_update_last_run(self, fake_client, mocker):
        fake_client.get_incidents.side_effect = DemistoException("Forbidden")
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        set_mock = mocker.patch.object(demisto, "setLastRun")
        inc_mock = mocker.patch.object(demisto, "incidents")
        with pytest.raises(DemistoException):
            mod.fetch_incidents(fake_client, "1 day", 5)
        set_mock.assert_not_called()
        inc_mock.assert_not_called()


# ------------------------------------------------------------------ alert parser
class TestAlertParser:
    def test_success(self, mocker):
        mocker.patch.object(
            demisto,
            "incident",
            return_value={
                "CustomFields": {
                    "cyfirmaalertdetails": [
                        {"fields": "Host", "values": "a.com"},
                        {"fields": "", "values": "ignored"},
                        {"values": "no name"},
                    ]
                }
            },
        )
        rr = mocker.patch.object(mod, "return_results")
        mod.command_alertdetailextraction()
        res = rr.call_args.args[0]
        assert res.outputs_prefix == "Cyfirma.Alert"
        assert res.outputs == {"Host": "a.com"}

    @pytest.mark.parametrize(
        "incident",
        [{}, {"CustomFields": None}, {"CustomFields": {}}, {"CustomFields": {"cyfirmaalertdetails": []}}],
    )
    def test_empty(self, mocker, incident):
        mocker.patch.object(demisto, "incident", return_value=incident)
        err = mocker.patch.object(mod, "return_error", side_effect=SystemExit)
        with pytest.raises(SystemExit):
            mod.command_alertdetailextraction()
        err.assert_called_once()
        assert "empty" in err.call_args.args[0]


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

    def test_default_max_fetch_and_first_fetch(self, mocker):
        self._setup(mocker, "fetch-incidents", {"url": "https://x.com", "api_key": {"password": "k"}})
        m = mocker.patch.object(mod, "fetch_incidents")
        mod.main()
        m.assert_called_once_with(ANY, mod.DEFAULT_FIRST_FETCH, mod.DEFAULT_MAX_FETCH)

    @pytest.mark.parametrize(
        "command, target",
        [
            ("cyfirma-takedown-initiate", "initiate_take_down_request"),
            ("cyfirma-takedown-list", "get_take_down_list"),
        ],
    )
    def test_command_results_are_returned(self, mocker, command, target):
        rr, _ = self._setup(mocker, command)
        m = mocker.patch.object(mod, target, return_value="RESULT")
        mod.main()
        m.assert_called_once()
        rr.assert_called_once_with("RESULT")

    def test_alert_parser(self, mocker):
        self._setup(mocker, "cyfirma-alert-parser")
        m = mocker.patch.object(mod, "command_alertdetailextraction")
        mod.main()
        m.assert_called_once()

    def test_unknown_command(self, mocker):
        _, err = self._setup(mocker, "nope")
        with pytest.raises(SystemExit):
            mod.main()
        assert "not implemented" in err.call_args.args[0]

    def test_missing_url(self, mocker):
        _, err = self._setup(mocker, "test-module", {"api_key": {"password": "k"}})
        with pytest.raises(SystemExit):
            mod.main()
        assert "required" in err.call_args.args[0]

    def test_missing_api_key(self, mocker):
        _, err = self._setup(mocker, "test-module", {"url": "https://x.com", "api_key": None})
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
        self._setup(
            mocker,
            "test-module",
            {**self.BASE_PARAMS, "insecure": True, "proxy": True},
        )
        mocker.patch.object(mod, "test_module", return_value="ok")
        client_cls = mocker.patch.object(mod, "Client")
        mod.main()
        kwargs = client_cls.call_args.kwargs
        assert kwargs["base_url"] == "https://api.test/api/ex/v3/da"
        assert kwargs["verify"] is False
        assert kwargs["proxy"] is True
        assert kwargs["headers"]["X-Api-Key"] == "k"
        assert kwargs["headers"]["X-App-Name"] == "PALO_ALTO_XSOAR_V2_AL"

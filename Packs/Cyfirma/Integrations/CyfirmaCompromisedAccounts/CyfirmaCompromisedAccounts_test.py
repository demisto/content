"""Unit tests for the CYFIRMA Compromised Accounts integration."""

import json
import re
from datetime import UTC, datetime

import CyfirmaCompromisedAccounts as cf
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, IncidentSeverity

BASE_URL = "https://api.cyfirma.test/api/ex/v3/da"
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


@pytest.fixture
def client():
    return cf.Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "key"})


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------


def test_kv_fields_no_skip():
    assert cf.kv_fields({"abc": 1, "lastModifiedDate": "x"}) == [
        {"fields": "Abc", "values": 1},
        {"fields": "Lastmodifieddate", "values": "x"},
    ]


def test_kv_fields_with_skip():
    assert cf.kv_fields({"a": 1, "b": 2}, frozenset({"a"})) == [{"fields": "B", "values": 2}]


def test_kv_fields_empty():
    assert cf.kv_fields({}) == []


@pytest.mark.parametrize("value", [None, ""])
def test_parse_date_empty(value):
    assert cf.parse_date(value) is None


def test_parse_date_absolute():
    assert cf.parse_date("2024-01-01T00:00:00Z") == datetime(2024, 1, 1, tzinfo=UTC)


def test_parse_date_relative():
    result = cf.parse_date("2 days")
    assert result is not None
    assert result < datetime.now()


def test_parse_date_unparsable():
    assert cf.parse_date("this is not a date at all") is None


# ----------------------------------------------------------------------------------------------
# Client.call_api
# ----------------------------------------------------------------------------------------------


def test_call_api_ok(client, mocker):
    resp = mocker.Mock(status_code=200, content=b"{}")
    resp.json.return_value = {"data": [1]}
    http = mocker.patch.object(client, "_http_request", return_value=resp)

    assert client.call_api("/x", params={"a": 1}) == {"data": [1]}
    kwargs = http.call_args.kwargs
    assert kwargs["url_suffix"] == "/x"
    assert kwargs["params"] == {"a": 1}
    assert kwargs["method"] == "GET"
    assert kwargs["resp_type"] == "response"
    assert kwargs["retries"] == 3
    assert kwargs["status_list_to_retry"] == (502, 503, 504)
    assert kwargs["raise_on_status"] is True


def test_call_api_empty_content(client, mocker):
    mocker.patch.object(client, "_http_request", return_value=mocker.Mock(status_code=200, content=b""))
    assert client.call_api("/x") == {}


def test_call_api_non_200(client, mocker):
    mocker.patch.object(client, "_http_request", return_value=mocker.Mock(status_code=204, content=b"x"))
    assert client.call_api("/x") == {}


# ----------------------------------------------------------------------------------------------
# Client.populate_custom_fields / build_incident_json
# ----------------------------------------------------------------------------------------------

EVENT = {
    "uid": "u-1",
    "title": "Leaked creds",
    "category": "CA",
    "categoryLabel": "Compromised Accounts",
    "subCategory": "CUS",
    "subCategoryLabel": "Customer Accounts",
    "createdDate": "2024-03-01T00:00:00Z",
    "lastModifiedDate": "2024-03-05T10:20:30Z",
    "hasActive": True,
    "isSafe": False,
    "user": "bob",
    "domain": "example.com",
    "compromisedDetails": {"password": "x", "ip": "1.1.1.1"},
}


def test_populate_custom_fields(client):
    rows = client.populate_custom_fields(EVENT)["cyfirmacompromisedaccountdetails"]
    assert rows[0] == {"fields": "Subcategory", "values": "Customer Accounts"}
    assert rows[1] == {"fields": "Category", "values": "Compromised Accounts"}
    labels = [r["fields"] for r in rows]
    assert "Uid" in labels
    assert "Domain" in labels
    assert "Password" in labels
    assert "Ip" in labels
    assert "Hasactive" not in labels
    assert "User" not in labels
    assert "Compromiseddetails" not in labels


@pytest.mark.parametrize("details", [None, {}])
def test_populate_custom_fields_null_or_empty_details(client, details):
    rows = client.populate_custom_fields({"compromisedDetails": details})["cyfirmacompromisedaccountdetails"]
    assert rows == [
        {"fields": "Subcategory", "values": ""},
        {"fields": "Category", "values": ""},
    ]


def test_build_incident_json(client):
    incident = client.build_incident_json(EVENT)
    assert incident["type"] == "Compromised Accounts"
    assert incident["name"] == "Leaked creds"
    assert incident["occurred"] == "2024-03-05T10:20:30Z"
    assert incident["severity"] == IncidentSeverity.CRITICAL
    assert json.loads(incident["rawJSON"]) == EVENT
    assert incident["category"] == "CA"
    assert incident["subcategory"] == "CUS"
    assert incident["dbotMirrorId"] == "u-1"
    assert incident["sourceBrand"] == "CYFIRMA"
    assert incident["labels"] == []
    assert "cyfirmacompromisedaccountdetails" in incident["CustomFields"]


def test_build_incident_json_falls_back_to_created_date(client):
    incident = client.build_incident_json({"createdDate": "2024-03-01T00:00:00Z"})
    assert incident["occurred"] == "2024-03-01T00:00:00Z"


def test_build_incident_json_no_dates_and_defaults(client):
    incident = client.build_incident_json({})
    assert incident["occurred"] is None
    assert incident["type"] == ""
    assert incident["name"] == ""
    assert incident["category"] == ""
    assert incident["subcategory"] == ""
    assert incident["dbotMirrorId"] == ""


# ----------------------------------------------------------------------------------------------
# Client.get_incidents
# ----------------------------------------------------------------------------------------------


def test_get_incidents_paginates_all_endpoints(client, mocker):
    cus, emp, pub = cf._API_PATHS["CUS"], cf._API_PATHS["EMP"], cf._API_PATHS["PUB"]
    responses = {
        (cus, 0): {"data": [{"uid": "1"}, {"uid": "2"}], "metaData": {"isLast": False}},
        (cus, 1): {"data": [{"uid": "3"}], "metaData": {"isLast": True}},
        (emp, 0): {},  # no data, no metaData -> loop stops
        (pub, 0): {"data": [{"uid": "4"}], "metaData": {}},  # isLast missing -> treated as last
    }
    calls: list = []

    def fake_call_api(end_point, params=None):
        page = params.get("page") if params else None
        calls.append((end_point, page))
        if page is None:
            return {}
        return responses.get((end_point, page), {})

    mocker.patch.object(client, "call_api", side_effect=fake_call_api)

    base_params = {"size": 10}
    incidents = client.get_incidents(base_params)

    assert [i["dbotMirrorId"] for i in incidents] == ["1", "2", "3", "4"]
    assert calls == [(cus, 0), (cus, 1), (emp, 0), (pub, 0)]
    assert base_params == {"size": 10}  # caller's dict untouched
    assert "X-Request-Id" in client._headers


# ----------------------------------------------------------------------------------------------
# test_module
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("exc_msg", ["Forbidden", "Unauthorized"])
def test_test_module_auth_error(client, mocker, exc_msg):
    mocker.patch.object(client, "call_api", side_effect=DemistoException(exc_msg))
    assert cf.test_module(client).startswith("Authorization Error")


def test_test_module_other_error_reraised(client, mocker):
    mocker.patch.object(client, "call_api", side_effect=DemistoException("Server exploded"))
    with pytest.raises(DemistoException):
        cf.test_module(client)


@pytest.mark.parametrize(
    "response, expected",
    [
        ({}, "Not Authorized"),
        ({"isOrgActive": False}, "Not Authorized"),
        ({"isOrgActive": True, "isCompanyActive": False}, "Not Authorized"),
        ({"isOrgActive": True, "isCompanyActive": True}, "ok"),
        ({"isOrgActive": True}, "ok"),
    ],
)
def test_test_module_responses(client, mocker, response, expected):
    mocker.patch.object(client, "call_api", return_value=response)
    assert cf.test_module(client) == expected


# ----------------------------------------------------------------------------------------------
# fetch_incidents
# ----------------------------------------------------------------------------------------------


@pytest.fixture
def fetch_env(mocker):
    return {
        "params": mocker.patch.object(demisto, "params", return_value={}),
        "get_last_run": mocker.patch.object(demisto, "getLastRun", return_value={}),
        "incidents": mocker.patch.object(demisto, "incidents"),
        "set_last_run": mocker.patch.object(demisto, "setLastRun"),
    }


def test_fetch_incidents_first_run(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents", return_value=[{"name": "a"}])

    cf.fetch_incidents(client, "60 days", 25)

    request_params = get_inc.call_args.kwargs["params"]
    assert request_params["page"] == 0
    assert request_params["size"] == 25
    assert request_params["includeThirdParty"] is False
    assert isinstance(request_params["after"], int)
    fetch_env["incidents"].assert_called_once_with([{"name": "a"}])
    saved = fetch_env["set_last_run"].call_args.args[0]["last_fetch"]
    assert DATE_RE.fullmatch(saved)


def test_fetch_incidents_uses_last_run_and_third_party(client, mocker, fetch_env):
    fetch_env["params"].return_value = {"includeThirdPartyCompromisedAccounts": True}
    fetch_env["get_last_run"].return_value = {"last_fetch": "2024-01-01T00:00:00Z"}
    get_inc = mocker.patch.object(client, "get_incidents", return_value=[])

    cf.fetch_incidents(client, "60 days", 10)

    request_params = get_inc.call_args.kwargs["params"]
    assert request_params["after"] == 1704067200000
    assert request_params["includeThirdParty"] is True
    fetch_env["incidents"].assert_called_once_with([])


def test_fetch_incidents_last_run_none(client, mocker, fetch_env):
    fetch_env["get_last_run"].return_value = None
    mocker.patch.object(client, "get_incidents", return_value=[])
    cf.fetch_incidents(client, "7 days", 10)
    fetch_env["set_last_run"].assert_called_once()


def test_fetch_incidents_invalid_first_fetch(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents")
    with pytest.raises(DemistoException, match="Invalid 'First fetch'"):
        cf.fetch_incidents(client, "this is not a date at all", 10)
    get_inc.assert_not_called()
    fetch_env["set_last_run"].assert_not_called()


# ----------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------

BASE_PARAMS = {"url": "https://api.cyfirma.test/", "api_key": {"password": "k"}}


def _setup(mocker, params, command):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "info")


@pytest.mark.parametrize(
    "params",
    [{}, {"url": "https://x"}, {"api_key": {"password": "k"}}, {"url": "https://x", "api_key": {}}],
)
def test_main_missing_credentials(mocker, params):
    _setup(mocker, params, "test-module")
    err = mocker.patch.object(cf, "return_error", side_effect=SystemExit)
    with pytest.raises(SystemExit):
        cf.main()
    err.assert_called_once_with("Server URL and API Key are required.")


def test_main_test_module(mocker):
    _setup(mocker, BASE_PARAMS, "test-module")
    tm = mocker.patch.object(cf, "test_module", return_value="ok")
    results = mocker.patch.object(cf, "return_results")
    cf.main()
    tm.assert_called_once()
    results.assert_called_once_with("ok")


def test_main_fetch_incidents_defaults(mocker):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    fetch = mocker.patch.object(cf, "fetch_incidents")
    cf.main()
    fetch.assert_called_once_with(mocker.ANY, cf.DEFAULT_FIRST_FETCH, cf.DEFAULT_MAX_FETCH)


def test_main_fetch_incidents_custom_params(mocker):
    params = {
        **BASE_PARAMS,
        "max_fetch": "50",
        "first_fetch": "  7 days  ",
        "insecure": True,
        "proxy": True,
    }
    _setup(mocker, params, "fetch-incidents")
    fetch = mocker.patch.object(cf, "fetch_incidents")
    cf.main()
    fetch.assert_called_once_with(mocker.ANY, "7 days", 50)


def test_main_invalid_max_fetch_raises(mocker):
    _setup(mocker, {**BASE_PARAMS, "max_fetch": "abc"}, "fetch-incidents")
    with pytest.raises(ValueError):
        cf.main()


def test_main_unknown_command(mocker):
    _setup(mocker, BASE_PARAMS, "bogus-command")
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    err.assert_called_once()
    message = err.call_args.args[0]
    assert "bogus-command" in message
    assert "not implemented" in message


def test_main_forbidden_error(mocker):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    mocker.patch.object(cf, "fetch_incidents", side_effect=DemistoException("403 Forbidden"))
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    assert err.call_count == 2
    assert err.call_args_list[0].args[0].startswith("Authorization Error")
    assert "Failed to execute fetch-incidents command" in err.call_args_list[1].args[0]


def test_main_generic_error(mocker):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    mocker.patch.object(cf, "fetch_incidents", side_effect=RuntimeError("boom"))
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    err.assert_called_once()
    assert "boom" in err.call_args.args[0]

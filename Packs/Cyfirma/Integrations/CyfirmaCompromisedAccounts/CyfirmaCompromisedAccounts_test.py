"""Unit tests for the CYFIRMA Compromised Accounts integration."""

import json
import re
from datetime import datetime, UTC

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
    result = cf.parse_date("2 days ago")
    assert result is not None
    # compare timestamps: dateparser may return a naive or an aware datetime for relative dates
    assert result.timestamp() < datetime.now().timestamp()


def test_parse_date_unparsable():
    assert cf.parse_date("this is not a date at all") is None


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
    assert incident["datetimeofthebreach"] is None
    assert incident["severity"] == IncidentSeverity.CRITICAL
    assert json.loads(incident["rawJSON"]) == EVENT
    assert incident["category"] == "CA"
    assert incident["subCategory"] == "CUS"
    assert incident["dbotMirrorId"] == "u-1"
    assert incident["sourceBrand"] == "CYFIRMA"
    assert incident["labels"] == []
    assert "cyfirmacompromisedaccountdetails" in incident["CustomFields"]


def test_build_incident_json_breach_date(client):
    event = {**EVENT, "compromisedDetails": {"breachDate": "2024-02-01T00:00:00Z"}}
    incident = client.build_incident_json(event)
    assert incident["datetimeofthebreach"] == "2024-02-01T00:00:00Z"


def test_build_incident_json_falls_back_to_created_date(client):
    incident = client.build_incident_json({"createdDate": "2024-03-01T00:00:00Z"})
    assert incident["occurred"] == "2024-03-01T00:00:00Z"


def test_build_incident_json_no_dates_and_defaults(client):
    incident = client.build_incident_json({})
    assert incident["occurred"] is None
    assert incident["datetimeofthebreach"] is None
    assert incident["type"] == ""
    assert incident["name"] == ""
    assert incident["category"] == ""
    assert incident["subCategory"] == ""
    assert incident["dbotMirrorId"] == ""


# ----------------------------------------------------------------------------------------------
# Client.get_incidents (requests go through ``Client.get``)
# ----------------------------------------------------------------------------------------------


def test_get_incidents_paginates_all_endpoints(client, mocker):
    cus, emp, pub = cf._API_PATHS["CUS"], cf._API_PATHS["EMP"], cf._API_PATHS["PUB"]
    responses = {
        (cus, 0): {"data": [{"uid": "1"}, {"uid": "2"}], "metaData": {"isLast": False}},
        (cus, 1): {"data": [{"uid": "3"}], "metaData": {"isLast": True}},
        (emp, 1): {},  # no data, no metaData -> loop stops
        (pub, 1): {"data": [{"uid": "4"}], "metaData": {}},  # isLast missing -> treated as last
    }
    calls: list = []
    headers_seen: list = []

    def fake_get(path, params=None, headers=None, **kwargs):
        page = int((params or {}).get("page", 0))
        calls.append((path, page))
        headers_seen.append(headers)
        return responses.get((path, page), {})

    mocker.patch.object(client, "call_get_request", side_effect=fake_get)

    base_params = {"size": 10}
    incidents = client.get_incidents(base_params)

    assert [i["dbotMirrorId"] for i in incidents] == ["1", "2", "3", "4"]
    # the current page is retained across endpoints
    assert calls == [(cus, 0), (cus, 1), (emp, 1), (pub, 1)]
    assert all("X-Request-ID" in h for h in headers_seen)
    assert base_params == {"size": 10, "page": 1}


def test_get_incidents_stops_at_size_cap(client, mocker):
    get = mocker.patch.object(
        client,
        "call_get_request",
        return_value={"data": [{"uid": "1"}, {"uid": "2"}, {"uid": "3"}], "metaData": {"isLast": False}},
    )
    incidents = client.get_incidents({"size": 2})
    assert len(incidents) == 2
    assert get.call_count == 1


def test_get_incidents_zero_size(client, mocker):
    get = mocker.patch.object(client, "call_get_request")
    assert client.get_incidents({"size": 0}) == []
    get.assert_not_called()


# ----------------------------------------------------------------------------------------------
# test_module
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("exc_msg", ["Forbidden", "Unauthorized"])
def test_test_module_auth_error(client, mocker, exc_msg):
    mocker.patch.object(client, "call_get_request", side_effect=DemistoException(exc_msg))
    assert cf.test_module(client).startswith("Authorization Error")


def test_test_module_other_error_reraised(client, mocker):
    mocker.patch.object(client, "call_get_request", side_effect=DemistoException("Server exploded"))
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
    mocker.patch.object(client, "call_get_request", return_value=response)
    assert cf.test_module(client) == expected


def test_test_module_pings_test_path(client, mocker):
    get = mocker.patch.object(client, "call_get_request", return_value={"isOrgActive": True})
    cf.test_module(client)
    get.assert_called_once_with(cf._TEST_PATH)


# ----------------------------------------------------------------------------------------------
# fetch_incidents (params and last_run are passed in by ``main``)
# ----------------------------------------------------------------------------------------------


@pytest.fixture
def fetch_env(mocker):
    return {
        "incidents": mocker.patch.object(demisto, "incidents"),
        "set_last_run": mocker.patch.object(demisto, "setLastRun"),
    }


def test_fetch_incidents_first_run(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents", return_value=[{"name": "a"}])

    cf.fetch_incidents(client, "60 days ago", 25, {}, {})

    # fetch_incidents passes the query parameters as ``req_params``; the page is added by get_incidents
    request_params = get_inc.call_args.kwargs["req_params"]
    assert request_params["size"] == 25
    assert request_params["includeThirdParty"] is False
    assert isinstance(request_params["after"], int)
    fetch_env["incidents"].assert_called_once_with([{"name": "a"}])
    saved = fetch_env["set_last_run"].call_args.args[0]["last_fetch"]
    assert DATE_RE.fullmatch(saved)


def test_fetch_incidents_uses_last_run_and_third_party(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents", return_value=[])

    cf.fetch_incidents(
        client,
        "60 days ago",
        10,
        {"includeThirdPartyCompromisedAccounts": True},
        {"last_fetch": "2024-01-01T00:00:00Z"},
    )

    request_params = get_inc.call_args.kwargs["req_params"]
    assert request_params["after"] == 1704067200000
    assert request_params["includeThirdParty"] is True
    fetch_env["incidents"].assert_called_once_with([])


def test_fetch_incidents_empty_last_fetch_falls_back_to_first_fetch(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents", return_value=[])
    cf.fetch_incidents(client, "7 days ago", 10, {}, {"last_fetch": ""})
    assert isinstance(get_inc.call_args.kwargs["req_params"]["after"], int)
    fetch_env["set_last_run"].assert_called_once()


def test_fetch_incidents_invalid_first_fetch(client, mocker, fetch_env):
    get_inc = mocker.patch.object(client, "get_incidents")
    with pytest.raises(DemistoException, match="Invalid 'First fetch'"):
        cf.fetch_incidents(client, "this is not a date at all", 10, {}, {})
    get_inc.assert_not_called()
    fetch_env["set_last_run"].assert_not_called()


# ----------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------

BASE_PARAMS = {"url": "https://api.cyfirma.test/", "api_key": {"password": "k"}}


@pytest.fixture
def main_env(mocker):
    """Patch the client and auth handler so main() never builds a real HTTP client."""
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    return {
        "client_cls": mocker.patch.object(cf, "Client"),
        "auth_handler": mocker.patch.object(cf, "APIKeyAuthHandler"),
    }


def _setup(mocker, params, command, last_run=None):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run if last_run is not None else {})


@pytest.mark.parametrize(
    "params",
    [{}, {"url": "https://x"}, {"api_key": {"password": "k"}}, {"url": "https://x", "api_key": {}}],
)
def test_main_missing_credentials(mocker, main_env, params):
    _setup(mocker, params, "test-module")
    err = mocker.patch.object(cf, "return_error", side_effect=SystemExit)
    with pytest.raises(SystemExit):
        cf.main()
    err.assert_called_once_with("Server URL and API Key are required.")


def test_main_builds_client(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "test-module")
    mocker.patch.object(cf, "test_module", return_value="ok")
    mocker.patch.object(cf, "return_results")
    cf.main()
    main_env["auth_handler"].assert_called_once_with(key="k", header_name="X-Api-Key")
    kwargs = main_env["client_cls"].call_args.kwargs
    assert kwargs["base_url"].rstrip("/") == BASE_URL
    assert kwargs["verify"] is True
    assert kwargs["proxy"] is False
    assert kwargs["auth_handler"] is main_env["auth_handler"].return_value


def test_main_test_module(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "test-module")
    tm = mocker.patch.object(cf, "test_module", return_value="ok")
    results = mocker.patch.object(cf, "return_results")
    cf.main()
    tm.assert_called_once_with(main_env["client_cls"].return_value)
    results.assert_called_once_with("ok")


def test_main_fetch_incidents_defaults(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    fetch = mocker.patch.object(cf, "fetch_incidents")
    cf.main()
    fetch.assert_called_once_with(
        main_env["client_cls"].return_value,
        cf.DEFAULT_FIRST_FETCH,
        cf.DEFAULT_MAX_FETCH,
        BASE_PARAMS,
        {},
    )


def test_main_fetch_incidents_custom_params(mocker, main_env):
    params = {
        **BASE_PARAMS,
        "max_fetch": "50",
        "first_fetch": "  7 days  ",
        "insecure": True,
        "proxy": True,
    }
    last_run = {"last_fetch": "2024-01-01T00:00:00Z"}
    _setup(mocker, params, "fetch-incidents", last_run=last_run)
    fetch = mocker.patch.object(cf, "fetch_incidents")
    cf.main()
    fetch.assert_called_once_with(main_env["client_cls"].return_value, "7 days", 50, params, last_run)
    client_kwargs = main_env["client_cls"].call_args.kwargs
    assert client_kwargs["verify"] is False
    assert client_kwargs["proxy"] is True


def test_main_last_run_none_becomes_empty_dict(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    mocker.patch.object(demisto, "getLastRun", return_value=None)
    fetch = mocker.patch.object(cf, "fetch_incidents")
    cf.main()
    assert fetch.call_args.args[4] == {}


def test_main_invalid_max_fetch_raises(mocker, main_env):
    _setup(mocker, {**BASE_PARAMS, "max_fetch": "abc"}, "fetch-incidents")
    with pytest.raises(ValueError):
        cf.main()


def test_main_unknown_command(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "bogus-command")
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    err.assert_called_once()
    message = err.call_args.args[0]
    assert "bogus-command" in message
    assert "not implemented" in message


def test_main_forbidden_error(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    mocker.patch.object(cf, "fetch_incidents", side_effect=DemistoException("403 Forbidden"))
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    assert err.call_args_list[0].args[0].startswith("Authorization Error")
    assert "Failed to execute fetch-incidents command" in err.call_args_list[1].args[0]


def test_main_generic_error(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "fetch-incidents")
    mocker.patch.object(cf, "fetch_incidents", side_effect=RuntimeError("boom"))
    err = mocker.patch.object(cf, "return_error")
    cf.main()
    err.assert_called_once()
    assert "boom" in err.call_args.args[0]

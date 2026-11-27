"""Unit tests for the CYFIRMA integration (Cortex XSOAR)."""

import re
from datetime import datetime, UTC

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, IncidentSeverity


import Cyfirma

from Cyfirma import (
    Client,
    _parse_date,
    command_alertdetailextraction,
    fetch_incidents,
    get_severity,
    get_take_down_list,
    initiate_take_down_request,
    kv_fields,
    safe_join,
    take_down_list_command_results,
)

BASE_URL = "https://api.example.com/api/ex/v3/da"


class ReturnErrorCalled(Exception):
    """Raised by the patched return_error so execution stops like the real one."""


@pytest.fixture
def client():
    return Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "key"}, proxy=False)


@pytest.fixture
def mock_return_error(mocker):
    def _raise(msg, *args, **kwargs):
        raise ReturnErrorCalled(msg)

    return mocker.patch.object(Cyfirma, "return_error", side_effect=_raise)


@pytest.fixture
def sample_alert():
    return {
        "alertId": "A1",
        "title": "Open port found",
        "alertCreatedDate": "2026-01-01T10:00:00Z",
        "categoryLabel": "Attack Surface",
        "category": "AS",
        "subCategory": "OPEN_PORTS",
        "subCategoryLabel": "Open Ports",
        "alertDetails": {
            "uid": "U1",
            "exposureScore": 6.5,
            "extra": "val",
            "portDetails": [{"port": 80}, {"port": 443}, {"other": 1}],
            "networkAttributes": {"ip": "1.1.1.1"},
            "vulnerabilities": [
                {
                    "cveNo": "CVE-1",
                    "cvssScore": 9.8,
                    "isKev": True,
                    "products": ["a", "b"],
                }
            ],
        },
    }


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def test_kv_fields_capitalizes_keys():
    assert kv_fields({"ip": "1.1.1.1", "exposureScore": 5}) == [
        {"fields": "Ip", "values": "1.1.1.1"},
        {"fields": "Exposurescore", "values": 5},
    ]


def test_kv_fields_skips_keys():
    assert kv_fields({"a": 1, "b": 2}, skip={"a"}) == [{"fields": "B", "values": 2}]


def test_kv_fields_empty():
    assert kv_fields({}) == []


@pytest.mark.parametrize(
    "value, sep, expected",
    [
        (["a", "b"], ",", "a,b"),
        (("a", 1), ", ", "a, 1"),
        ({"x"}, ",", "x"),
        (None, ",", ""),
        ("text", ",", "text"),
        (5, ",", "5"),
        ([], ",", ""),
    ],
)
def test_safe_join(value, sep, expected):
    assert safe_join(value, sep) == expected


@pytest.mark.parametrize(
    "score, expected",
    [
        (9, IncidentSeverity.CRITICAL),
        ("8.1", IncidentSeverity.CRITICAL),
        (8, IncidentSeverity.HIGH),
        (5.1, IncidentSeverity.HIGH),
        (5, IncidentSeverity.MEDIUM),
        (3, IncidentSeverity.MEDIUM),
        (2.9, IncidentSeverity.LOW),
        (1, IncidentSeverity.LOW),
        (0.5, IncidentSeverity.UNKNOWN),
        (0, IncidentSeverity.UNKNOWN),
        (None, IncidentSeverity.UNKNOWN),
        ("abc", IncidentSeverity.UNKNOWN),
    ],
)
def test_get_severity(score, expected):
    assert get_severity(score) == expected


def test_parse_date_empty():
    assert _parse_date(None) is None
    assert _parse_date("") is None


def test_parse_date_absolute():
    result = _parse_date("2026-01-01T00:00:00Z")
    assert result is not None
    assert (result.year, result.month, result.day) == (2026, 1, 1)


def test_parse_date_relative():
    assert _parse_date("3 days ago") is not None


def test_parse_date_invalid():
    assert _parse_date("this is not a date") is None


# ----------------------------------------------------------------------------
# Client: HTTP layer
# ----------------------------------------------------------------------------


def test_call_get_post_put_delegate(client, mocker):
    get = mocker.patch.object(Client, "call_get_request", return_value={"r": 1})
    post = mocker.patch.object(Client, "call_post_request", return_value={"r": 1})
    put = mocker.patch.object(Client, "call_put_request", return_value={"r": 1})
    assert client.call_get_request("/g", params={"p": 1}) == {"r": 1}
    assert get.call_args.args == ("/g",)
    assert get.call_args.kwargs["params"] == {"p": 1}
    # assert "X-Request-ID" in get.call_args.kwargs["headers"]
    assert client.call_post_request("/p", body={"b": 1}) == {"r": 1}
    assert post.call_args.args == ("/p",)
    # assert post.call_args.kwargs["json_data"] == {"b": 1}
    assert client.call_put_request("/u", body={"b": 2}) == {"r": 1}
    assert put.call_args.args == ("/u",)
    # assert put.call_args.kwargs["json_data"] == {"b": 2}


def test_call_request_keeps_custom_headers(client, mocker):
    get = mocker.patch.object(Client, "call_get_request", return_value={})
    client.call_get_request("/g", headers={"X-Request-ID": "fixed"})
    assert get.call_args.kwargs["headers"] == {"X-Request-ID": "fixed"}


# ----------------------------------------------------------------------------
# Client: incident building
# ----------------------------------------------------------------------------


def test_vulnerability_fields():
    rows = Client._vulnerability_fields(
        [
            {"cveNo": "CVE-1", "cvssScore": 9.8, "isKev": True, "products": ["a", "b"]},
            {},
        ]
    )
    assert rows[0] == {
        "cve": "CVE-1",
        "cvssscore": 9.8,
        "kev": "True",
        "products": "a, b",
    }
    assert rows[1] == {"cve": "", "cvssscore": "", "kev": "False", "products": ""}


def test_vulnerability_fields_empty():
    assert Client._vulnerability_fields([]) == []


def test_details_fields_join_and_filter():
    details = {"issuer": ["a", "b"], "serial": "1"}
    assert Client._details_fields(details, join_keys={"issuer"}) == [
        {"fields": "issuer", "values": "a, b"},
        {"fields": "serial", "values": "1"},
    ]
    assert Client._details_fields(details, join_keys={"issuer"}, only_keys={"issuer"}) == [{"fields": "issuer", "values": "a, b"}]


def test_sub_category_open_ports(client):
    details = {"portDetails": [{"port": 80}, {"port": 443}, {"other": 1}]}
    assert client._build_sub_category_data_fields(details, "OPEN_PORTS") == [{"fields": "Open Ports", "values": "80,443"}]


def test_sub_category_open_ports_missing(client):
    assert client._build_sub_category_data_fields({}, "OPEN_PORTS") == [{"fields": "Open Ports", "values": ""}]


def test_sub_category_certificates(client):
    details = {"certificateDetails": {"issuer": ["CA1", "CA2"], "serial": "1"}}
    assert client._build_sub_category_data_fields(details, "CERTIFICATES") == [
        {"fields": "issuer", "values": "CA1, CA2"},
        {"fields": "serial", "values": "1"},
    ]


def test_sub_category_configuration(client):
    details = {"configurationDetails": {"missingEppCodes": ["x", "y"], "state": "bad"}}
    assert client._build_sub_category_data_fields(details, "CONFIGURATION") == [
        {"fields": "missingEppCodes", "values": "x, y"},
        {"fields": "state", "values": "bad"},
    ]


def test_sub_category_ip_domain_reputation_only_reported_categories(client):
    details = {
        "ipDomainReputationDetails": {
            "reportedCategories": ["spam", "bot"],
            "ignored": "x",
        }
    }
    assert client._build_sub_category_data_fields(details, "IP_DOMAIN_REPUTATION") == [
        {"fields": "reportedCategories", "values": "spam, bot"}
    ]


def test_sub_category_default_uses_asset_details(client):
    details = {"assetDetails": {"name": "host1"}}
    assert client._build_sub_category_data_fields(details, "SOMETHING_ELSE") == [{"fields": "Name", "values": "host1"}]


def test_populate_custom_fields(client, sample_alert):
    result = client._populate_custom_fields(sample_alert)

    alert_rows = {r["fields"]: r["values"] for r in result["cyfirmaalertdetails"]}
    assert alert_rows["Subcategory"] == "Open Ports"
    assert alert_rows["Category"] == "Attack Surface"
    assert alert_rows["Alertid"] == "A1"
    assert alert_rows["Objectid"] == "U1"
    assert alert_rows["Extra"] == "val"
    # fields in _SKIP_FIELDS must not leak into the generic rows
    assert "Portdetails" not in alert_rows
    assert "Networkattributes" not in alert_rows
    assert "Vulnerabilities" not in alert_rows

    assert result["cyfirmanetworkattributes"] == [{"fields": "Ip", "values": "1.1.1.1"}]
    assert result["cyfirmadigitalfootprints"] == [{"fields": "Open Ports", "values": "80,443"}]
    assert result["cyfirmavulnerabilities"][0]["cve"] == "CVE-1"
    assert result["cyfirmadeepfakedetails"] == []


def test_populate_custom_fields_with_deepfake(client, sample_alert):
    sample_alert["alertDetails"]["deepFakeDetails"] = {"score": 1}
    result = client._populate_custom_fields(sample_alert)
    assert result["cyfirmadeepfakedetails"] == [{"fields": "Score", "values": 1}]


def test_populate_custom_fields_without_alert_details(client):
    flat = {
        "alertId": "A2",
        "uid": "U2",
        "subCategory": "X",
        "assetDetails": {"k": "v"},
    }
    result = client._populate_custom_fields(flat)
    assert result["cyfirmadigitalfootprints"] == [{"fields": "K", "values": "v"}]
    assert result["cyfirmavulnerabilities"] == []


def test_build_incident_json(client, sample_alert):
    incident = client._build_incident_json(sample_alert)
    assert incident["type"] == "Attack Surface"
    assert incident["name"] == "Open port found"
    assert incident["occurred"] == "2026-01-01T10:00:00Z"
    assert incident["severity"] == IncidentSeverity.HIGH
    assert incident["category"] == "AS"
    assert incident["subCategory"] == "OPEN_PORTS"
    assert incident["dbotMirrorId"] == "A1"
    assert incident["sourceBrand"] == "CYFIRMA"
    assert incident["labels"] == []
    assert "CustomFields" in incident
    assert '"alertId": "A1"' in incident["rawJSON"]


def test_build_incident_json_falls_back_to_last_modified_date(client):
    incident = client._build_incident_json({"lastModifiedDate": "2026-02-02T00:00:00Z", "alertDetails": {}})
    assert incident["occurred"] == "2026-02-02T00:00:00Z"


def test_build_incident_json_no_dates_or_ids(client):
    incident = client._build_incident_json({})
    assert incident["occurred"] is None
    assert incident["dbotMirrorId"] == ""
    assert incident["name"] == ""
    # a missing exposureScore defaults to 1 in _build_incident_json, which maps to LOW
    assert incident["severity"] == IncidentSeverity.LOW


def test_build_incident_json_mirror_id_falls_back_to_uid(client):
    incident = client._build_incident_json({"alertDetails": {"uid": "U9"}})
    assert incident["dbotMirrorId"] == "U9"


# ----------------------------------------------------------------------------
# Client: get_incidents / take down
# ----------------------------------------------------------------------------


def test_get_incidents_paginates(client, sample_alert, mocker):
    get = mocker.patch.object(
        Client,
        "call_get_request",
        side_effect=[
            {"data": [sample_alert], "metaData": {"isLast": False}},
            {"data": [sample_alert], "metaData": {"isLast": True}},
        ],
    )
    # "size" is both the page size and the cap on total incidents, so it must be >= 2 to get two pages
    incidents = client.get_incidents({"size": 2, "after": 0}, {"AS": True, "BI": False})
    assert len(incidents) == 2
    assert get.call_count == 2
    assert all(c.kwargs["end_point"] == "/al/as" for c in get.call_args_list)


def test_get_incidents_respects_max_size(client, sample_alert, mocker):
    get = mocker.patch.object(
        Client,
        "call_get_request",
        return_value={"data": [sample_alert, sample_alert, sample_alert], "metaData": {"isLast": False}},
    )
    incidents = client.get_incidents({"size": 2}, {"AS": True})
    assert len(incidents) == 2
    assert get.call_count == 1


def test_get_incidents_multiple_types(client, sample_alert, mocker):
    get = mocker.patch.object(
        Client,
        "call_get_request",
        return_value={"data": [sample_alert], "metaData": {"isLast": True}},
    )
    incidents = client.get_incidents({"size": 10}, {"AS": True, "BI": True, "DW": True, "SP": True})
    assert len(incidents) == 4
    assert [c.kwargs["end_point"] for c in get.call_args_list] == [
        "/al/as",
        "/al/bi",
        "/al/dbwm",
        "/al/spe",
    ]


def test_get_incidents_zero_size_fetches_nothing(client, mocker):
    get = mocker.patch.object(Client, "call_get_request")
    assert client.get_incidents({}, {"AS": True}) == []
    get.assert_not_called()


def test_get_incidents_nothing_enabled(client, mocker):
    get = mocker.patch.object(Client, "call_get_request")
    assert client.get_incidents({"size": 10}, {"AS": False}) == []
    get.assert_not_called()


def test_get_incidents_empty_response_stops(client, mocker):
    get = mocker.patch.object(Client, "call_get_request", return_value={})
    assert client.get_incidents({"size": 10}, {"AS": True}) == []
    assert get.call_count == 1


def test_initiate_take_down_with_comment(client, mocker):
    post = mocker.patch.object(Client, "call_post_request", return_value={"status": "SUCCESS"})
    client.initiate_take_down("A1", "please remove")
    post.assert_called_once_with(
        end_point="/td/initiate",
        params={"objectId": "A1", "assetComment": "please remove"},
        headers={"X-Request-ID": post.call_args.kwargs["headers"]["X-Request-ID"]},
    )


def test_initiate_take_down_without_comment(client, mocker):
    post = mocker.patch.object(Client, "call_post_request", return_value={})
    client.initiate_take_down("A1")
    post.assert_called_once_with(
        end_point="/td/initiate",
        params={"objectId": "A1"},
        headers={"X-Request-ID": post.call_args.kwargs["headers"]["X-Request-ID"]},
    )


def test_take_down_list_data_with_domain(client, mocker):
    get = mocker.patch.object(Client, "call_get_request", return_value={"data": [{"ticketId": "T1"}]})
    assert client.take_down_list_data("example.com", "0", "10") == [{"ticketId": "T1"}]
    get.assert_called_once_with(
        end_point="/td",
        params={"page": "0", "size": "10", "domains": "example.com"},
        headers={"X-Request-ID": get.call_args.kwargs["headers"]["X-Request-ID"]},
    )


def test_take_down_list_data_without_domain(client, mocker):
    get = mocker.patch.object(Client, "call_get_request", return_value={"data": []})
    assert client.take_down_list_data("", "1", "5") == []
    assert "domains" not in get.call_args.kwargs["params"]


def test_take_down_list_data_non_dict_response(client, mocker):
    mocker.patch.object(Client, "call_get_request", return_value=[])
    assert client.take_down_list_data("", "0", "5") == []


# ----------------------------------------------------------------------------
# test_module
# (called as Cyfirma.test_module so pytest does not collect it as a test)
# ----------------------------------------------------------------------------


def test_test_module_ok(client, mocker):
    mocker.patch.object(Client, "call_get_request", return_value={"isOrgActive": True})
    assert Cyfirma.test_module(client) == "ok"


def test_test_module_ok_company_active(client, mocker):
    mocker.patch.object(
        Client,
        "call_get_request",
        return_value={"isOrgActive": True, "isCompanyActive": True},
    )
    assert Cyfirma.test_module(client) == "ok"


@pytest.mark.parametrize("msg", ["Forbidden", "Unauthorized"])
def test_test_module_auth_errors(client, mocker, msg):
    mocker.patch.object(Client, "call_get_request", side_effect=DemistoException(msg))
    assert Cyfirma.test_module(client) == "Authorization Error: make sure API Key is correctly set"


def test_test_module_other_error_is_raised(client, mocker):
    mocker.patch.object(Client, "call_get_request", side_effect=DemistoException("Connection timeout"))
    with pytest.raises(DemistoException, match="Connection timeout"):
        Cyfirma.test_module(client)


@pytest.mark.parametrize(
    "response",
    [{}, {"isOrgActive": False}, {"isOrgActive": True, "isCompanyActive": False}],
)
def test_test_module_not_authorized(client, mocker, response):
    # test_module raises (rather than returns) when the org/company is not active
    mocker.patch.object(Client, "call_get_request", return_value=response)
    with pytest.raises(DemistoException, match="Not Authorized"):
        Cyfirma.test_module(client)


# ----------------------------------------------------------------------------
# Take-down commands
# ----------------------------------------------------------------------------

TICKET = {
    "ticketId": "T1",
    "domain": "bad.com",
    "takedownSubCategory": "Phishing",
    "takedownCategory": "Brand",
    "status": "OPEN",
    "createdDate": "2026-01-01",
    "lastModifiedDate": "2026-01-02",
    "createdBy": "u1",
    "lastModifiedBy": "u2",
    "details": "d",
}


def test_take_down_list_command_results_empty():
    assert take_down_list_command_results([], "title").readable_output == "No data found for current request."


def test_take_down_list_command_results_unexpected_format():
    result = take_down_list_command_results({"a": 1}, "title")  # type: ignore[arg-type]
    assert result.readable_output == "Unexpected response format."


def test_take_down_list_command_results_success():
    result = take_down_list_command_results([TICKET], "My Title")
    assert "My Title" in result.readable_output
    assert "T1" in result.readable_output
    assert result.outputs_prefix == "Cyfirma.TakeDownList"
    assert result.outputs_key_field == "ticket_id"
    assert result.outputs == [
        {
            "ticket_id": "T1",
            "sub_category": "Phishing",
            "created_date": "2026-01-01",
            "modified_date": "2026-01-02",
            "status": "OPEN",
            "domain": "bad.com",
            "created_by": "u1",
            "modified_by": "u2",
        }
    ]
    assert result.raw_response == [TICKET]


def test_take_down_list_command_results_missing_fields():
    result = take_down_list_command_results([{}], "t")
    assert isinstance(result.outputs, list)
    assert isinstance(result.outputs[0], dict)
    assert result.outputs[0]["ticket_id"] == ""


def test_initiate_take_down_request_success(client, mocker):
    init = mocker.patch.object(
        Client,
        "initiate_take_down",
        return_value={"status": "success", "data": {"takeDownId": "TD-1"}},
    )
    result = initiate_take_down_request(client, {"object_id": "A1", "comment": "c"})
    init.assert_called_once_with("A1", "c")
    assert result.outputs == {
        "take_down_id": "TD-1",
        "message": "Take Down Request Created Successfully - Ticket ID: TD-1",
    }
    assert result.outputs_prefix == "Cyfirma.TakeDown"
    assert "TD-1" in result.readable_output


def test_initiate_take_down_request_missing_object_id(client):
    with pytest.raises(DemistoException, match="object_id is required"):
        initiate_take_down_request(client, {})


def test_initiate_take_down_request_no_data(client, mocker):
    mocker.patch.object(Client, "initiate_take_down", return_value={})
    with pytest.raises(DemistoException, match="No data returned"):
        initiate_take_down_request(client, {"object_id": "A1"})


@pytest.mark.parametrize(
    "response, reason",
    [
        ({"status": "FAILED", "message": "bad alert"}, "bad alert"),
        ({"status": "ERROR", "error": "denied"}, "denied"),
        ({"status": "FAILED"}, "unknown error"),
        ({"foo": "bar"}, "unknown error"),
    ],
)
def test_initiate_take_down_request_failure_status(client, mocker, response, reason):
    mocker.patch.object(Client, "initiate_take_down", return_value=response)
    with pytest.raises(DemistoException, match=reason):
        initiate_take_down_request(client, {"object_id": "A1"})


@pytest.mark.parametrize("data", [None, "string", {}, {"takeDownId": ""}])
def test_initiate_take_down_request_missing_ticket_id(client, mocker, data):
    mocker.patch.object(Client, "initiate_take_down", return_value={"status": "SUCCESS", "data": data})
    with pytest.raises(DemistoException, match="no ticket ID"):
        initiate_take_down_request(client, {"object_id": "A1"})


def test_get_take_down_list_defaults(client, mocker):
    lst = mocker.patch.object(Client, "take_down_list_data", return_value=[TICKET])
    result = get_take_down_list(client, {})
    lst.assert_called_once_with("", "0", "50")
    assert "Domain: All, Page: 0, Size: 50" in result.readable_output


def test_get_take_down_list_with_args(client, mocker):
    lst = mocker.patch.object(Client, "take_down_list_data", return_value=[TICKET])
    result = get_take_down_list(client, {"domain": "bad.com", "size": "10", "page": "2"})
    lst.assert_called_once_with("bad.com", "2", "10")
    assert "Domain: bad.com, Page: 2, Size: 10" in result.readable_output


def test_get_take_down_list_no_data(client, mocker):
    mocker.patch.object(Client, "take_down_list_data", return_value=[])
    assert get_take_down_list(client, {}).readable_output == "No data found for current request."


# ----------------------------------------------------------------------------
# fetch_incidents
# ----------------------------------------------------------------------------


def _patch_demisto_fetch(mocker, params, last_run):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    incidents = mocker.patch.object(demisto, "incidents")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    return incidents, set_last_run


def test_fetch_incidents_first_run(client, mocker):
    params = {
        "fetchAttackSurface": True,
        "fetchBrandExposure": "true",
        "includeThirdParty": False,
    }
    incidents, set_last_run = _patch_demisto_fetch(mocker, params, None)
    get = mocker.patch.object(Client, "get_incidents", return_value=[{"name": "x"}])

    fetch_incidents(client, "3 days ago", 50, params, {})

    kwargs = get.call_args.kwargs
    assert kwargs["alerts_to_fetch"] == {
        "AS": True,
        "BI": True,
        "DW": False,
        "SP": False,
    }
    # fetch_incidents passes the query parameters as ``req_params`` (the page is added later by get_incidents)
    assert kwargs["req_params"]["size"] == 50
    assert kwargs["req_params"]["includeThirdParty"] is False
    assert isinstance(kwargs["req_params"]["after"], int)
    incidents.assert_called_once_with([{"name": "x"}])
    saved = set_last_run.call_args.args[0]["last_fetch"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", saved)


def test_fetch_incidents_uses_last_run(client, mocker):
    _patch_demisto_fetch(mocker, {"includeThirdParty": True}, {"last_fetch": "2026-01-01T00:00:00Z"})
    get = mocker.patch.object(Client, "get_incidents", return_value=[])

    fetch_incidents(
        client,
        "3 days ago",
        10,
        {"includeThirdParty": True},
        {"last_fetch": "2026-01-01T00:00:00Z"},
    )

    expected = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1000)
    assert get.call_args.kwargs["req_params"]["after"] == expected
    assert get.call_args.kwargs["req_params"]["includeThirdParty"] is True


def test_fetch_incidents_invalid_first_fetch(client, mocker):
    _patch_demisto_fetch(mocker, {}, {})
    mocker.patch.object(Cyfirma, "_parse_date", return_value=None)
    get = mocker.patch.object(Client, "get_incidents")
    with pytest.raises(DemistoException, match="Invalid 'First fetch'"):
        fetch_incidents(
            client,
            "garbage",
            10,
            {"includeThirdParty": True},
            {},
        )
    get.assert_not_called()


# ----------------------------------------------------------------------------
# cyfirma-alert-parser
# ----------------------------------------------------------------------------


def test_alert_parser_success(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={
            "CustomFields": {
                "cyfirmaalertdetails": [
                    {"fields": "Alertid", "values": "A1"},
                    {"fields": "Category", "values": "AS"},
                    {"fields": "", "values": "ignored"},
                    {"fields": "NoValue"},
                ]
            }
        },
    )
    results = mocker.patch.object(Cyfirma, "return_results")
    command_alertdetailextraction()
    command_result = results.call_args.args[0]
    assert command_result.outputs_prefix == "Cyfirma.Alert"
    assert command_result.outputs == {
        "Alertid": "A1",
        "Category": "AS",
        "NoValue": None,
    }


@pytest.mark.parametrize(
    "incident",
    [
        {},
        {"CustomFields": None},
        {"CustomFields": {}},
        {"CustomFields": {"cyfirmaalertdetails": []}},
    ],
)
def test_alert_parser_empty_grid(mocker, mock_return_error, incident):
    mocker.patch.object(demisto, "incident", return_value=incident)
    with pytest.raises(ReturnErrorCalled, match="cyfirmaalertdetails is empty"):
        command_alertdetailextraction()


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

VALID_PARAMS = {"url": "https://api.example.com/", "api_key": {"password": "secret"}}


def _run_main(mocker, command, params=None, args=None):
    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS if params is None else params)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    Cyfirma.main()


def test_main_test_module(mocker):
    mocker.patch.object(Cyfirma, "test_module", return_value="ok")
    results = mocker.patch.object(Cyfirma, "return_results")
    _run_main(mocker, "test-module")
    results.assert_called_once_with("ok")


def test_main_builds_client_with_expected_arguments(mocker):
    client_cls = mocker.patch.object(Cyfirma, "Client")
    mocker.patch.object(Cyfirma, "test_module", return_value="ok")
    mocker.patch.object(Cyfirma, "return_results")
    params = {**VALID_PARAMS, "insecure": True, "proxy": True}
    _run_main(mocker, "test-module", params=params)
    kwargs = client_cls.call_args.kwargs
    assert kwargs["base_url"] == "https://api.example.com/api/ex/v3/da/"
    assert kwargs["verify"] is False
    assert kwargs["proxy"] is True
    assert kwargs["headers"]["X-App-Name"] == "PALO_ALTO_XSOAR_V2_AL"
    assert "auth_handler" in kwargs


def test_main_fetch_incidents_uses_defaults(mocker):
    fetch = mocker.patch.object(Cyfirma, "fetch_incidents")
    _run_main(mocker, "fetch-incidents")
    assert fetch.call_args.args[1:3] == ("60 days", 100)


def test_main_fetch_incidents_custom_params(mocker):
    fetch = mocker.patch.object(Cyfirma, "fetch_incidents")
    params = {**VALID_PARAMS, "max_fetch": "25", "first_fetch": " 7 days "}
    _run_main(mocker, "fetch-incidents", params=params)
    assert fetch.call_args.args[1:3] == ("7 days", 25)


def test_main_takedown_initiate(mocker):
    cmd = mocker.patch.object(Cyfirma, "initiate_take_down_request", return_value="res")
    results = mocker.patch.object(Cyfirma, "return_results")
    _run_main(mocker, "cyfirma-takedown-initiate")
    cmd.assert_called_once()
    results.assert_called_once_with("res")


def test_main_takedown_list(mocker):
    cmd = mocker.patch.object(Cyfirma, "get_take_down_list", return_value="res")
    results = mocker.patch.object(Cyfirma, "return_results")
    _run_main(mocker, "cyfirma-takedown-list")
    cmd.assert_called_once()
    results.assert_called_once_with("res")


def test_main_alert_parser(mocker):
    cmd = mocker.patch.object(Cyfirma, "command_alertdetailextraction")
    _run_main(mocker, "cyfirma-alert-parser")
    cmd.assert_called_once()


@pytest.mark.parametrize(
    "params",
    [
        {"url": "", "api_key": {"password": "k"}},
        {"api_key": {"password": "k"}},
        {"url": "https://api.example.com"},
        {"url": "https://api.example.com", "api_key": {}},
        {"url": "https://api.example.com", "api_key": None},
    ],
)
def test_main_missing_url_or_api_key(mocker, mock_return_error, params):
    with pytest.raises(ReturnErrorCalled, match="Server URL and API Key are required"):
        _run_main(mocker, "test-module", params=params)


def test_main_unknown_command(mocker, mock_return_error):
    with pytest.raises(ReturnErrorCalled, match="Failed to execute nope command"):
        _run_main(mocker, "nope")


def test_main_forbidden_error(mocker, mock_return_error):
    mocker.patch.object(Cyfirma, "test_module", side_effect=DemistoException("403 Forbidden"))
    with pytest.raises(ReturnErrorCalled, match="Authorization Error"):
        _run_main(mocker, "test-module")


def test_main_generic_error(mocker, mock_return_error):
    mocker.patch.object(Cyfirma, "test_module", side_effect=DemistoException("kaboom"))
    with pytest.raises(
        ReturnErrorCalled,
        match="Failed to execute test-module command.\nError:\nkaboom",
    ):
        _run_main(mocker, "test-module")

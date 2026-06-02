import json

import pytest

from CommonServerPython import (
    arg_to_datetime,
    DemistoException,
    IncidentSeverity,
    CommandResults,
)

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests the test_module validation command."""
    from SOCRadarIncidents import Client, test_module

    mock_socradar_api_key = "APIKey"
    mock_socradar_company_id = "0"
    suffix = f"company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}"
    mock_response = util_load_json("test_data/check_auth_response.json")
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    response = test_module(client)

    assert response == "ok"


def test_test_module_handles_authorization_error(requests_mock):
    """Tests the test_module validation command authorization error."""
    from SOCRadarIncidents import Client, test_module, MESSAGES

    mock_socradar_api_key = "WrongAPIKey"
    mock_socradar_company_id = "0"
    suffix = f"company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}"
    mock_response = util_load_json("test_data/check_auth_response_auth_error.json")
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response, status_code=401)
    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )
    with pytest.raises(DemistoException, match=MESSAGES["AUTHORIZATION_ERROR"]):
        test_module(client)


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents function.

    Configures requests_mock instance to generate the appropriate
    SOCRadar Incidents API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/fetch_incidents_response.json")
    suffix = (
        f"company/{mock_socradar_company_id}/incidents/v2?key={mock_socradar_api_key}"
        f"&severity=Medium%2CHigh"
        f"&limit=2"
        f"&start_date=1594512000"
    )
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    last_run = {"last_fetch": 1594512000}  # Jul 12, 2020

    mock_first_fetch_time = arg_to_datetime(arg="30 days", arg_name="First fetch time")

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=2,
        last_run=last_run,
        first_fetch_time=mock_first_fetch_time,
        resolution_status="all",
        fp_status="all",
        severity=["Medium", "High"],
        incident_main_type=None,
        incident_sub_type=None,
    )

    expected_output = util_load_json("test_data/fetch_incidents_expected_output.json")

    assert new_incidents == expected_output
    assert len(new_incidents) <= 2


def test_fetch_incidents_handles_incorrect_severity():
    """Tests the fetch-incidents function incorrect severity error."""
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    last_run = {"last_fetch": 1594512000}  # Jul 12, 2020

    mock_first_fetch_time = arg_to_datetime(arg="30 days", arg_name="First fetch time")

    incorrect_severity_levels = ["Incorrect", "Severity", "Levels"]

    with pytest.raises(ValueError):
        fetch_incidents(
            client=client,
            max_results=2,
            last_run=last_run,
            first_fetch_time=mock_first_fetch_time,
            resolution_status="all",
            fp_status="all",
            severity=incorrect_severity_levels,
            incident_main_type=None,
            incident_sub_type=None,
        )


def test_mark_incident_as_fp(requests_mock):
    """Tests the mark_incident_as_fp_command function.

    Configures requests_mock instance to generate the appropriate
    SOCRadar mark incident as fp API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from SOCRadarIncidents import Client, mark_incident_as_fp_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/mark_incident_fp_response.json")
    suffix = f"company/{mock_socradar_company_id}/incidents/fp?key={mock_socradar_api_key}"
    requests_mock.post(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    mock_args = {"socradar_incident_id": mock_incident_id, "comments": mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    response = mark_incident_as_fp_command(client=client, args=mock_args)

    expected_output = util_load_json("test_data/mark_incident_fp_expected_output.json")

    assert isinstance(response, CommandResults)
    assert response.raw_response == expected_output


def test_mark_incident_as_fp_handles_error(requests_mock):
    """Tests the mark_incident_as_fp_command function.

    Configures requests_mock instance to generate the appropriate
    SOCRadar mark incident as fp API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from SOCRadarIncidents import Client, mark_incident_as_fp_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/mark_incident_fp_response_error.json")
    suffix = f"company/{mock_socradar_company_id}/incidents/fp?key={mock_socradar_api_key}"
    requests_mock.post(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    mock_args = {"socradar_incident_id": mock_incident_id, "comments": mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    with pytest.raises(DemistoException):
        mark_incident_as_fp_command(client=client, args=mock_args)


def test_mark_incident_as_resolved(requests_mock):
    """Tests the mark_incident_as_resolved_command function.

    Configures requests_mock instance to generate the appropriate
    SOCRadar mark incident as resolved API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from SOCRadarIncidents import Client, mark_incident_as_resolved_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/mark_incident_resolved_response.json")
    suffix = f"company/{mock_socradar_company_id}/incidents/resolve?key={mock_socradar_api_key}"
    requests_mock.post(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    mock_args = {"socradar_incident_id": mock_incident_id, "comments": mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    response = mark_incident_as_resolved_command(client=client, args=mock_args)

    expected_output = util_load_json("test_data/mark_incident_resolved_expected_output.json")

    assert isinstance(response, CommandResults)
    assert response.raw_response == expected_output


def test_mark_incident_as_resolved_handles_error(requests_mock):
    """Tests the mark_incident_as_resolved_command function response error."""
    from SOCRadarIncidents import Client, mark_incident_as_resolved_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/mark_incident_resolved_response_error.json")
    suffix = f"company/{mock_socradar_company_id}/incidents/resolve?key={mock_socradar_api_key}"
    requests_mock.post(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    mock_args = {"socradar_incident_id": mock_incident_id, "comments": mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    with pytest.raises(DemistoException):
        mark_incident_as_resolved_command(client=client, args=mock_args)


CONVERT_DEMISTO_SEVERITY_INPUTS = [
    ("INFO", IncidentSeverity.INFO),
    ("LOW", IncidentSeverity.LOW),
    ("MEDIUM", IncidentSeverity.MEDIUM),
    ("HIGH", IncidentSeverity.HIGH),
    ("CRITICAL", IncidentSeverity.CRITICAL),
    ("UNKNOWN", IncidentSeverity.UNKNOWN),
]


@pytest.mark.parametrize("incident_severity, demisto_severity", CONVERT_DEMISTO_SEVERITY_INPUTS)
def test_convert_to_demisto_severity(incident_severity, demisto_severity):
    from SOCRadarIncidents import convert_to_demisto_severity

    assert convert_to_demisto_severity(incident_severity) == demisto_severity


def test_fetch_incidents_with_include_company_id(requests_mock):
    """Tests fetch_incidents with include_company_id=True adds company_id to incidents."""
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json("test_data/fetch_incidents_response.json")
    suffix = (
        f"company/{mock_socradar_company_id}/incidents/v2?key={mock_socradar_api_key}"
        f"&severity=High"
        f"&limit=2"
        f"&start_date=1594512000"
    )
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    last_run = {"last_fetch": 1594512000}

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=2,
        last_run=last_run,
        first_fetch_time=None,
        resolution_status="all",
        fp_status="all",
        severity=["High"],
        incident_main_type=None,
        incident_sub_type=None,
        include_company_id=True,
    )

    for incident in new_incidents:
        raw = json.loads(incident["rawJSON"])
        assert raw.get("company_id") == "0"
        assert incident["CustomFields"]["socradarcompanyid"] == "0"


def test_fetch_incidents_alarm_title_fallback(requests_mock):
    """Tests that alarm_title falls back to alarm_generic_title when alarm_notification_texts is missing."""
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = {
        "data": [
            {
                "id": 999,
                "insert_date": "2021-07-01T12:00:00.000000",
                "alarm_risk_level": "HIGH",
                "alarm_notification_texts": None,
                "alarm_type_details": {"alarm_generic_title": "Fallback Title"},
                "alarm_assets": [],
                "alarm_related_assets": [],
                "alarm_related_entities": [],
            }
        ],
        "is_success": True,
        "message": "Success",
        "response_code": 200,
    }
    suffix = (
        f"company/{mock_socradar_company_id}/incidents/v2?key={mock_socradar_api_key}"
        f"&limit=10"
        f"&start_date=1594512000"
    )
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=10,
        last_run={"last_fetch": 1594512000},
        first_fetch_time=None,
        resolution_status=None,
        fp_status=None,
        severity=[],
        incident_main_type=None,
        incident_sub_type=None,
    )

    assert len(new_incidents) == 1
    assert "Fallback Title" in new_incidents[0]["name"]


def test_fetch_incidents_none_related_assets_and_entities(requests_mock):
    """Tests None-safety for alarm_related_assets and alarm_related_entities."""
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = {
        "data": [
            {
                "id": 888,
                "insert_date": "2021-07-01T12:00:00.000000",
                "alarm_risk_level": "MEDIUM",
                "alarm_notification_texts": {"alarm_title": "Test", "alarm_text": "content"},
                "alarm_type_details": {},
                "alarm_assets": None,
                "alarm_related_assets": None,
                "alarm_related_entities": None,
            }
        ],
        "is_success": True,
        "message": "Success",
        "response_code": 200,
    }
    suffix = (
        f"company/{mock_socradar_company_id}/incidents/v2?key={mock_socradar_api_key}"
        f"&limit=10"
        f"&start_date=1594512000"
    )
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/{suffix}", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=10,
        last_run={"last_fetch": 1594512000},
        first_fetch_time=None,
        resolution_status=None,
        fp_status=None,
        severity=[],
        incident_main_type=None,
        incident_sub_type=None,
    )

    assert len(new_incidents) == 1
    assert new_incidents[0]["CustomFields"]["socradarincidentassets"] == ""
    assert new_incidents[0]["CustomFields"]["socradarrelatedassets"] == ""
    assert new_incidents[0]["CustomFields"]["socradarrelatedentities"] == ""


def test_fetch_incidents_first_fetch_no_last_run(requests_mock):
    """Tests fetch_incidents when last_run is empty (first fetch)."""
    from SOCRadarIncidents import Client, fetch_incidents
    from CommonServerPython import arg_to_datetime

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = {"data": [], "is_success": True, "message": "Success", "response_code": 200}
    requests_mock.get(f"{SOCRADAR_API_ENDPOINT}/company/{mock_socradar_company_id}/incidents/v2", json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    first_fetch_time = int(arg_to_datetime("30 days", arg_name="First fetch time").timestamp())

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=10,
        last_run={},
        first_fetch_time=first_fetch_time,
        resolution_status=None,
        fp_status=None,
        severity=[],
        incident_main_type=None,
        incident_sub_type=None,
    )

    assert next_run["last_fetch"] == first_fetch_time
    assert incidents == []


def test_parse_int_or_raise_success():
    from SOCRadarIncidents import parse_int_or_raise

    assert parse_int_or_raise("42") == 42
    assert parse_int_or_raise(100) == 100


def test_parse_int_or_raise_failure():
    from SOCRadarIncidents import parse_int_or_raise

    with pytest.raises(ValueError):
        parse_int_or_raise("not_a_number")


def test_parse_int_or_raise_custom_error():
    from SOCRadarIncidents import parse_int_or_raise

    with pytest.raises(ValueError, match="custom error"):
        parse_int_or_raise("bad", error_msg="custom error")


def test_handle_error_response_400(requests_mock):
    """Tests handle_error_response with 400 status code."""
    from SOCRadarIncidents import Client

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    suffix = f"company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}"
    requests_mock.get(
        f"{SOCRADAR_API_ENDPOINT}/{suffix}",
        json={"error": "bad request reason"},
        status_code=400,
    )

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    with pytest.raises(DemistoException, match="bad request reason"):
        client.check_auth()


def test_handle_error_response_429(requests_mock):
    """Tests handle_error_response with 429 rate limit status."""
    from SOCRadarIncidents import Client, MESSAGES

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    suffix = f"company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}"
    requests_mock.get(
        f"{SOCRADAR_API_ENDPOINT}/{suffix}",
        json={"message": "rate limited"},
        status_code=429,
    )

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    with pytest.raises(DemistoException, match=MESSAGES["RATE_LIMIT_EXCEED_ERROR"]):
        client.check_auth()


def test_search_incidents_not_success(requests_mock):
    """Tests search_incidents raises DemistoException when is_success is False."""
    from SOCRadarIncidents import Client

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = {"is_success": False, "message": "Something went wrong", "data": []}
    requests_mock.get(
        f"{SOCRADAR_API_ENDPOINT}/company/{mock_socradar_company_id}/incidents/v2",
        json=mock_response,
    )

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False,
    )

    with pytest.raises(DemistoException, match="Something went wrong"):
        client.search_incidents(
            resolution_status=None,
            fp_status=None,
            severity=None,
            incident_main_type=None,
            incident_sub_type=None,
            max_results=10,
            start_date=None,
        )


def test_main_dict_api_key(mocker):
    """Tests main() when api_key param is a dict (credential type 9)."""
    from SOCRadarIncidents import main

    mocker.patch("SOCRadarIncidents.demisto.params", return_value={
        "apikey": {"password": "test-api-key-from-dict"},
        "socradar_company_id": "0",
        "first_fetch": "30 days",
        "insecure": False,
        "proxy": False,
    })
    mocker.patch("SOCRadarIncidents.demisto.command", return_value="test-module")
    mocker.patch("SOCRadarIncidents.demisto.debug")
    mock_return = mocker.patch("SOCRadarIncidents.return_results")

    mock_client_class = mocker.patch("SOCRadarIncidents.Client")
    mock_client_instance = mock_client_class.return_value
    mock_client_instance.check_auth.return_value = {"is_success": True}

    main()

    mock_client_class.assert_called_once()
    call_kwargs = mock_client_class.call_args
    assert call_kwargs[1]["api_key"] == "test-api-key-from-dict"
    mock_return.assert_called_once_with("ok")

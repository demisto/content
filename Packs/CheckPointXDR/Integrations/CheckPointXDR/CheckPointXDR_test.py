import datetime
import json
from unittest.mock import MagicMock
from CheckPointXDR import (
    Client,
    update_remote_system_command,
    fetch_incidents,
    get_instances_id,
    map_severity,
    parse_incidents,
    test_module as check_module,
    get_mapping_fields_command,
    main,
    OUTGOING_MIRRORED_FIELDS,
)
from CommonServerPython import IncidentStatus, DemistoException, GetMappingFieldsResponse


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module(mocker):
    client = Client(
        base_url="https://cloudinfra-gw.portal.checkpoint.com", client_id="****", access_key="****", verify=False, proxy=False
    )

    mocker.patch.object(
        Client,
        "_login",
        return_value=None,
    )
    mock_response = util_load_json("./test_data/checkpointxdr-get_incidents.json")
    query_events = mocker.patch.object(
        Client,
        "get_incidents",
        return_value=mock_response.get("objects"),
    )

    result = check_module(client, {}, datetime.datetime(2024, 1, 1))
    query_events.assert_called()
    assert result == "ok"


def test_parse_incidents():
    mock_incidents = util_load_json("./test_data/checkpointxdr-get_incidents.json").get("objects")

    mock_result = util_load_json("./test_data/checkpointxdr-parse_incident-output.json")
    result = parse_incidents(mock_incidents, {}, 10, 0)
    assert result[0][0].get("dbotMirrorId") == mock_result[0].get("dbotMirrorId")
    assert result[0][0].get("severity") == mock_result[0].get("severity")


def test_fetch_incidents(mocker):
    client = Client(
        base_url="https://cloudinfra-gw.portal.checkpoint.com", client_id="****", access_key="****", verify=False, proxy=False
    )

    mocker.patch.object(
        Client,
        "_login",
        return_value=None,
    )
    mock_insights_response = util_load_json("./test_data/checkpointxdr-get_incidents.json")
    query_insights = mocker.patch.object(
        Client,
        "get_incidents",
        return_value=mock_insights_response.get("objects"),
    )

    fetch_incidents(client, {}, {}, datetime.datetime(2024, 1, 1), 1000)
    query_insights.assert_called()


def test_update_remote_system_command_close_true(mocker):
    client = Client("dummyurl", "id", "key", False, False)

    mock_update_incident = mocker.patch.object(Client, "update_incident", return_value={})
    mocker.patch("CheckPointXDR.demisto.params", return_value={"close_out": True})
    mocker.patch("CheckPointXDR.demisto.debug")
    mocker.patch("CheckPointXDR.demisto.error")
    mocker.patch("CheckPointXDR.argToBoolean", return_value=True)

    args = {
        "remoteId": "123",
        "delta": {"closeReason": "False Positive"},
        "incidentChanged": True,
        "status": IncidentStatus.DONE,
        "data": {},
    }

    result = update_remote_system_command(client, args)
    assert result == "123"
    mock_update_incident.assert_called_once_with(status=IncidentStatus.DONE, close_reason="False Positive", incident_id="123")


def test_update_remote_system_command_close_false(mocker):
    client = Client("dummyurl", "id", "key", False, False)

    mock_update_incident = mocker.patch.object(Client, "update_incident")
    mocker.patch("CheckPointXDR.demisto.params", return_value={"close_out": False})
    mocker.patch("CheckPointXDR.demisto.debug")
    mocker.patch("CheckPointXDR.argToBoolean", return_value=False)

    args = {
        "remoteId": "321",
        "delta": {"closeReason": "Duplicate"},
        "incidentChanged": True,
        "status": IncidentStatus.DONE,
        "data": {},
    }

    result = update_remote_system_command(client, args)
    assert result == "321"
    mock_update_incident.assert_not_called()


def test_map_severity_levels():
    assert map_severity("Low") == 1
    assert map_severity("medium") == 2
    assert map_severity("HIGH") == 3
    assert map_severity("critical") == 4
    assert map_severity("unknown") == 1  # default fallback


def test_get_instances_id_found(mocker):
    mocker.patch("CheckPointXDR.demisto.getIntegrationContext", return_value={"instances_id": "abc123"})

    result = get_instances_id()
    assert result == "abc123"


def test_get_instances_id_cached(mocker):
    mocker.patch("CheckPointXDR.demisto.getIntegrationContext", return_value={"instances_id": "cached123"})
    result = get_instances_id()
    assert result == "cached123"


def test_client_login(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)

    # Mock the HTTP request response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = util_load_json("./test_data/checkpointxdr-login-response.json")

    # Apply the mock to the _http_request method
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("CheckPointXDR.demisto.debug")

    # Test successful login
    client._login()

    # Verify token was set
    assert client.token == "dummy-token-123456"


def test_client_login_failure(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)

    # Mock the HTTP request response for failure
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"

    # Apply the mock to the _http_request method
    mocker.patch.object(Client, "_http_request", return_value=mock_response)

    # Test failed login
    try:
        client._login()
    except DemistoException as e:
        # Verify exception message
        assert "Log-in failed: 401: Unauthorized" in str(e)


def test_client_update_incident(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)
    client.token = "dummy-token"

    # Mock the HTTP request response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = util_load_json("./test_data/checkpointxdr-update-incident-response.json")

    # Apply the mocks
    mocker.patch.object(Client, "_login")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("CheckPointXDR.demisto.debug")

    # Test update incident
    result = client.update_incident(status=1, close_reason="Resolved", incident_id="12345")

    # Verify result
    assert result == {"incident_id": "12345", "status": "close - handled"}


def test_client_update_incident_no_id(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)
    mocker.patch("CheckPointXDR.demisto.debug")

    # Test update incident with no ID
    try:
        client.update_incident(status=1, close_reason="Resolved")
    except DemistoException as e:
        # Verify exception message
        assert "No incident ID provided" in str(e)


def test_client_update_incident_failure(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)
    client.token = "dummy-token"

    # Mock the login
    mocker.patch.object(Client, "_login")

    # Mock the HTTP request response for failure
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Incident not found"

    # Apply the mock to the _http_request method
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("CheckPointXDR.demisto.debug")
    mocker.patch("CheckPointXDR.demisto.error")

    # Test failed update
    try:
        client.update_incident(status=1, close_reason="Resolved", incident_id="invalid-id")
    except DemistoException as e:
        # Verify exception message
        assert "Failed to update XDR incident: 404: Incident not found" in str(e)


def test_get_mapping_fields_command():
    result = get_mapping_fields_command()

    # Check that the result contains the mapping response
    assert isinstance(result, GetMappingFieldsResponse)

    # Verify that the result has scheme types
    assert len(result.scheme_types_mappings) > 0

    # Verify the fields exist to be mapped
    assert OUTGOING_MIRRORED_FIELDS


def test_main_test_module(mocker):
    # Mock all the necessary functions
    mocker.patch(
        "CheckPointXDR.demisto.params",
        return_value={
            "url": "https://test.url",
            "credentials": {"identifier": "client-id", "password": "access-key"},
            "insecure": True,
            "proxy": False,
            "max_fetch": 100,
            "first_fetch": "3 days",
            "mirror_direction": "Outgoing",
        },
    )
    mocker.patch("CheckPointXDR.demisto.command", return_value="test-module")
    mocker.patch("CheckPointXDR.demisto.args", return_value={})
    mocker.patch("CheckPointXDR.demisto.getLastRun", return_value={})

    # Mock test_module to return 'ok'
    mocker.patch("CheckPointXDR.test_module", return_value="ok")

    # Mock return_results
    mock_return_results = mocker.patch("CheckPointXDR.return_results")

    # Run main
    main()

    # Verify return_results was called with 'ok'
    mock_return_results.assert_called_once_with("ok")


def test_main_fetch_incidents(mocker):
    # Mock all the necessary functions
    mocker.patch(
        "CheckPointXDR.demisto.params",
        return_value={
            "url": "https://test.url",
            "credentials": {"identifier": "client-id", "password": "access-key"},
            "insecure": True,
            "proxy": False,
            "max_fetch": 100,
            "first_fetch": "3 days",
            "mirror_direction": "Outgoing",
        },
    )
    mocker.patch("CheckPointXDR.demisto.command", return_value="fetch-incidents")
    mocker.patch("CheckPointXDR.demisto.args", return_value={})
    mocker.patch("CheckPointXDR.demisto.getLastRun", return_value={})
    mocker.patch("CheckPointXDR.get_instances_id", return_value="instance-123")

    # Mock fetch_incidents
    mock_incidents = [{"id": "123", "name": "Test Incident"}]
    mock_next_run = {"last_fetch": "2023-12-24T12:30:04.364"}
    mocker.patch("CheckPointXDR.fetch_incidents", return_value=(mock_next_run, mock_incidents))

    # Mock the demisto functions that will be called
    mock_incidents_func = mocker.patch("CheckPointXDR.demisto.incidents")
    mock_set_last_run = mocker.patch("CheckPointXDR.demisto.setLastRun")
    mocker.patch("CheckPointXDR.demisto.debug")

    # Run main
    main()

    # Verify the demisto functions were called correctly
    mock_incidents_func.assert_called_once_with(mock_incidents)
    mock_set_last_run.assert_called_once_with(mock_next_run)


def test_main_update_remote_system(mocker):
    # Mock all the necessary functions
    mocker.patch(
        "CheckPointXDR.demisto.params",
        return_value={
            "url": "https://test.url",
            "credentials": {"identifier": "client-id", "password": "access-key"},
            "insecure": True,
            "proxy": False,
            "max_fetch": 100,
            "first_fetch": "3 days",
            "mirror_direction": "Outgoing",
        },
    )
    mocker.patch("CheckPointXDR.demisto.command", return_value="update-remote-system")
    mocker.patch("CheckPointXDR.demisto.args", return_value={"remote_incident_id": "123"})
    mocker.patch("CheckPointXDR.demisto.getLastRun", return_value={})

    # Mock update_remote_system_command
    mocker.patch("CheckPointXDR.update_remote_system_command", return_value="123")

    # Mock return_results
    mock_return_results = mocker.patch("CheckPointXDR.return_results")
    mocker.patch("CheckPointXDR.demisto.debug")

    # Run main
    main()

    # Verify return_results was called with the incident ID
    mock_return_results.assert_called_once_with("123")


def test_main_get_mapping_fields(mocker):
    # Mock all the necessary functions
    mocker.patch(
        "CheckPointXDR.demisto.params",
        return_value={
            "url": "https://test.url",
            "credentials": {"identifier": "client-id", "password": "access-key"},
            "insecure": True,
            "proxy": False,
            "max_fetch": 100,
            "first_fetch": "3 days",
            "mirror_direction": "Outgoing",
        },
    )
    mocker.patch("CheckPointXDR.demisto.command", return_value="get-mapping-fields")
    mocker.patch("CheckPointXDR.demisto.args", return_value={})
    mocker.patch("CheckPointXDR.demisto.getLastRun", return_value={})

    # Mock the mapping fields response
    mapping_response = MagicMock()
    mocker.patch("CheckPointXDR.get_mapping_fields_command", return_value=mapping_response)

    # Mock return_results
    mock_return_results = mocker.patch("CheckPointXDR.return_results")
    mocker.patch("CheckPointXDR.demisto.debug")

    # Run main
    main()

    # Verify return_results was called with the mapping response
    mock_return_results.assert_called_once_with(mapping_response)


def test_main_exception_handling(mocker):
    # Mock all the necessary functions
    mocker.patch(
        "CheckPointXDR.demisto.params",
        return_value={
            "url": "https://test.url",
            "credentials": {"identifier": "client-id", "password": "access-key"},
            "insecure": True,
            "proxy": False,
            "max_fetch": 100,
            "first_fetch": "3 days",
            "mirror_direction": "Outgoing",
        },
    )
    mocker.patch("CheckPointXDR.demisto.command", return_value="test-module")
    mocker.patch("CheckPointXDR.demisto.args", return_value={})
    mocker.patch("CheckPointXDR.demisto.getLastRun", return_value={})

    # Mock test_module to raise an exception
    mocker.patch("CheckPointXDR.test_module", side_effect=Exception("Test error"))

    # Mock return_error
    mock_return_error = mocker.patch("CheckPointXDR.return_error")
    mocker.patch("CheckPointXDR.demisto.debug")

    # Run main
    main()

    # Verify return_error was called with the error message
    mock_return_error.assert_called_once()
    assert "Failed to execute test-module command" in mock_return_error.call_args[0][0]
    assert "Test error" in mock_return_error.call_args[0][0]


def test_client_get_incidents(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)
    client.token = "dummy-token"

    # Mock the login
    mocker.patch.object(Client, "_login")

    # Mock the HTTP request response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"incidents": util_load_json("./test_data/checkpointxdr-get_incidents.json").get("objects")}
    }

    # Apply the mock to the _http_request method
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("CheckPointXDR.demisto.debug")
    # Test get_incidents
    result = client.get_incidents("2023-12-01", 1000)
    # Verify result
    assert len(result) == 1
    assert result[0]["id"] == 636750


def test_client_get_incidents_error(mocker):
    client = Client("https://test.url", "client-id", "access-key", False, False)
    client.token = "dummy-token"

    # Mock the login
    mocker.patch.object(Client, "_login")

    # Mock the HTTP request to raise an exception
    mocker.patch.object(Client, "_http_request", side_effect=Exception("API Error"))
    mocker.patch("CheckPointXDR.demisto.debug")
    mocker.patch("CheckPointXDR.demisto.error")

    # Test get_incidents with error
    try:
        client.get_incidents("2023-12-01", 1000)
    except DemistoException as e:
        # Verify exception message
        assert "Failed to fetch XDR incidents: API Error" in str(e)

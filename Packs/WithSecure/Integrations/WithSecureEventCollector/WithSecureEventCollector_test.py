import json
import pytest
import demistomock as demisto
from WithSecureEventCollector import (
    Client,
    fetch_events_command,
    fetch_incidents_command,
    get_devices_command,
    get_events_command,
    get_incidents_command,
    isolate_endpoint_command,
    release_endpoint_command,
    update_incident_status_command,
)


def mock_client():
    return Client(base_url="https://test.com", verify=False, proxy=False, client_id="client_id", client_secret="client_secret")


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


TOKEN_TEST = [
    ({"access_token": "integration_context_token", "valid_until": 1000}, "integration_context_token"),
    ({}, "new_access_token"),
    ({"access_token": "integration_context_token", "valid_until": -1}, "new_access_token"),
]


@pytest.mark.parametrize("integration_context, expected_token", TOKEN_TEST)
def test_get_access_token(mocker, requests_mock, integration_context, expected_token):
    client = mock_client()
    import WithSecureEventCollector

    mocker.patch.object(WithSecureEventCollector, "get_integration_context", return_value=integration_context)
    mocker.patch.object(WithSecureEventCollector, "time", return_value=0)
    requests_mock.post("https://test.com/as/token.oauth2", json={"access_token": "new_access_token", "expires_in": 1})
    result = client.get_access_token()
    assert result == expected_token


def test_get_events_command(requests_mock, mocker):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.
    """
    client = mock_client()
    mock_response = util_load_json("test_data/get_events.json")
    args = {"fetch_from": "2022-12-26T00:00:00Z", "limit": 2}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.post(
        "https://test.com/security-events/v1/security-events",
        json=mock_response,
    )
    events, response = get_events_command(client, args, "3 days")

    assert len(events) == 2
    assert events == mock_response.get("items")


def test_fetch_events_command(requests_mock, mocker):
    """Tests fetch-events command function.
    Given: and already fetched event id, and a latested fetched event timestamp
    When: running fetch-event command
    Check: the already fetched event does not get fetched again
    """

    client = mock_client()
    mock_response = util_load_json("test_data/fetch_events.json")
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    mocker.patch.object(demisto, "getLastRun", return_value={"fetch_from": "2023-03-15T14:39:13Z", "event_id": "test_id"})
    requests_mock.post(
        "https://test.com/security-events/v1/security-events",
        json=mock_response,
    )
    events, _ = fetch_events_command(client, first_fetch="1 day", limit=100)
    for ev in mock_response.get("items"):
        ev["_time"] = ev.get("clientTimestamp")
    expected = [mock_response.get("items")[0]]
    assert len(events) == 1
    assert events == expected


def test_fetch_incidents_command(mocker):
    """Tests fetch-incidents command logic."""
    client = mock_client()
    mock_response = {
        "items": [
            {
                "incidentId": "2c902c73-e2a6-40fd-9532-257ee102e1c2",
                "incidentPublicId": "3599-654321",
                "createdTimestamp": "2024-03-20T08:00:00Z",
                "severity": "high",
                "riskLevel": "high",
                "name": "Test incident",
            }
        ]
    }

    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"incidents": {"fetch_from": "2024-03-19T00:00:00Z", "incident_id": "prev"}},
    )
    mocker.patch.object(
        Client,
        "get_incidents",
        side_effect=[mock_response, {"items": []}],
    )

    incidents, next_run = fetch_incidents_command(
        client,
        "2024-03-19T00:00:00Z",
        10,
        ["new"],
        [],
        [],
        "WithSecure Incident",
    )

    assert len(incidents) == 1
    assert incidents[0]["type"] == "WithSecure Incident"
    assert incidents[0]["severity"] == 3
    assert next_run["incident_id"] == "2c902c73-e2a6-40fd-9532-257ee102e1c2"


def test_get_incidents_command(requests_mock, mocker):
    """Tests get-incidents command function."""
    client = mock_client()
    mock_response = {
        "items": [
            {
                "incidentId": "2c902c73-e2a6-40fd-9532-257ee102e1c1",
                "incidentPublicId": "3599-123456",
                "status": "new",
                "severity": "high",
                "riskLevel": "high",
                "riskScore": 85.5,
                "categories": ["MALWARE", "LATERAL_MOVEMENT"],
                "name": "Incident on DESKTOP-1"
            }
        ]
    }
    args = {"status": "new", "risk_level": "high", "limit": "20"}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.get(
        "https://test.com/incidents/v1/incidents?limit=20&archived=false&status=new&riskLevel=high",
        json=mock_response,
    )
    result = get_incidents_command(client, args)
    assert result.outputs == mock_response.get("items")
    assert len(result.outputs) == 1


def test_get_incidents_command_no_results(requests_mock, mocker):
    """Ensures a readable message is returned when no incidents are available."""
    client = mock_client()
    args = {}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.get(
        "https://test.com/incidents/v1/incidents?limit=20&archived=false",
        json={"items": []},
    )
    result = get_incidents_command(client, args)
    assert result.outputs == []
    assert result.readable_output == "No incidents were found for the given filters."


def test_update_incident_status_command(requests_mock, mocker):
    """Tests update-incident-status command function."""
    client = mock_client()
    mock_response = {
        "multistatus": [
            {"target": "2c902c73-e2a6-40fd-9532-257ee102e1c1", "status": 204}
        ]
    }
    args = {"incident_id": "2c902c73-e2a6-40fd-9532-257ee102e1c1", "status": "acknowledged"}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.patch(
        "https://test.com/incidents/v1/incidents",
        json=mock_response,
    )
    result = update_incident_status_command(client, args)
    assert result.outputs[0]["status"] == 204


def test_get_devices_command(requests_mock, mocker):
    """Tests get-devices command function."""
    client = mock_client()
    mock_response = {
        "items": [
            {
                "id": "ec8a0100-d313-4896-b3cb-02188e060bf3",
                "name": "DESKTOP-ABC123",
                "type": "computer",
                "state": "active",
                "online": True,
                "protectionStatusOverview": "allOk"
            }
        ]
    }
    args = {"state": "active", "limit": "50"}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.get(
        "https://test.com/devices/v1/devices?limit=50&state=active",
        json=mock_response,
    )
    result = get_devices_command(client, args)
    assert result.outputs == mock_response.get("items")
    assert len(result.outputs) == 1


def test_get_devices_command_no_results(requests_mock, mocker):
    """Ensures a readable message is returned when device list is empty."""
    client = mock_client()
    args = {}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.get(
        "https://test.com/devices/v1/devices?limit=50",
        json={"items": []},
    )
    result = get_devices_command(client, args)
    assert result.outputs == []
    assert result.readable_output == "No devices were found for the given filters."


def test_isolate_endpoint_command(requests_mock, mocker):
    """Tests isolate-endpoint command function."""
    client = mock_client()
    mock_response = {
        "multistatus": [
            {
                "target": "ec8a0100-d313-4896-b3cb-02188e060bf3",
                "status": 202,
                "operationId": "7243413413490181"
            }
        ],
        "transactionId": "0000-abcdef-1234"
    }
    args = {"device_ids": "ec8a0100-d313-4896-b3cb-02188e060bf3", "message": "Isolation test"}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.post(
        "https://test.com/devices/v1/operations",
        json=mock_response,
    )
    result = isolate_endpoint_command(client, args)
    assert result.outputs[0]["deviceId"] == "ec8a0100-d313-4896-b3cb-02188e060bf3"
    assert result.outputs[0]["status"] == 202


def test_release_endpoint_command(requests_mock, mocker):
    """Tests release-endpoint command function."""
    client = mock_client()
    mock_response = {
        "multistatus": [
            {
                "target": "ec8a0100-d313-4896-b3cb-02188e060bf3",
                "status": 202,
                "operationId": "7243413413490182"
            }
        ],
        "transactionId": "0000-abcdef-1234"
    }
    args = {"device_ids": "ec8a0100-d313-4896-b3cb-02188e060bf3"}
    mocker.patch.object(Client, "get_access_token", return_value="access_token")
    requests_mock.post(
        "https://test.com/devices/v1/operations",
        json=mock_response,
    )
    result = release_endpoint_command(client, args)
    assert result.outputs[0]["deviceId"] == "ec8a0100-d313-4896-b3cb-02188e060bf3"
    assert result.outputs[0]["status"] == 202

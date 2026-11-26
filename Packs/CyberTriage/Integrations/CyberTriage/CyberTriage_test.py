import pytest
from CommonServerPython import DemistoException
import CyberTriage
from CyberTriage import CyberTriageClient, triage_endpoint_command

BASE_URL = "https://ct-server:9443/api/"
HOST = {
    "hostId": 12,
    "incidentId": 1,
    "incidentName": "Incident 001",
    "hostDisplayName": "finance1-win-10",
    "createdDate": "2022-03-03T22:48:20.000Z",
    "state": "CREATED",
}


@pytest.fixture()
def client():
    return CyberTriageClient(
        server="ct-server",
        rest_port="9443",
        api_auth_token="token",
        user="admin-user",
        password="secret",
        verify_server_cert=True,
    )


def test_test_module(client, requests_mock):
    """
    Given:
        - a server that answers the incident listing
    Then:
        - ensure test-module returns ok and sends the bearer token
    """
    requests_mock.get(f"{BASE_URL}incidents", json=[])
    assert CyberTriage.test_module(client) == "ok"
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token"


def test_test_module_public_api_disabled(client, requests_mock):
    """
    Given:
        - a Team server with the public API turned off (403)
    Then:
        - ensure the error explains how to enable the public API
    """
    requests_mock.get(f"{BASE_URL}incidents", status_code=403, json={"status": 403, "message": "The public API is disabled."})
    with pytest.raises(DemistoException, match="public API is enabled"):
        CyberTriage.test_module(client)


def test_triage_endpoint_existing_incident(client, requests_mock):
    """
    Given:
        - an incident whose name differs only in case, plus a partial-name match
    When:
        - running ct-triage-endpoint with only the required args
    Then:
        - ensure the case-insensitive match is reused, only given fields plus credentials are sent,
          and the host ID is returned as the legacy SessionId
    """
    requests_mock.get(
        f"{BASE_URL}incidents",
        json=[
            {"incidentId": 7, "name": "Incident 001 old"},
            {"incidentId": 1, "name": "incident 001"},
        ],
    )
    create = requests_mock.post(f"{BASE_URL}incidents", json={"incidentId": 99})
    psexec = requests_mock.post(f"{BASE_URL}incidents/1/hosts/live-psexec", status_code=202, json=HOST)

    result = triage_endpoint_command(client, {"host_name": "finance1-win-10", "incident_name": "Incident 001"})

    assert not create.called
    assert psexec.last_request.json() == {"userId": "admin-user", "password": "secret", "hostName": "finance1-win-10"}
    assert result.outputs == {"CyberTriage": {"SessionId": "12"}, "Endpoint": {"Hostname": "finance1-win-10"}}


def test_triage_endpoint_creates_incident(client, requests_mock):
    """
    Given:
        - no incident with the requested name
    When:
        - running ct-triage-endpoint against an IP with all options set
    Then:
        - ensure the incident is created and the options are mapped to the request body
    """
    requests_mock.get(f"{BASE_URL}incidents", json=[])
    create = requests_mock.post(f"{BASE_URL}incidents", status_code=201, json={"incidentId": 3, "name": "MADEUP"})
    psexec = requests_mock.post(f"{BASE_URL}incidents/3/hosts/live-psexec", status_code=202, json=HOST)

    result = triage_endpoint_command(
        client,
        {
            "host_name": "192.0.2.50",
            "incident_name": "MADEUP",
            "scan_options": "pr,nw",
            "malware_scan_requested": "yes",
            "send_content": "no",
        },
    )

    assert create.last_request.json() == {"name": "MADEUP"}
    assert psexec.last_request.json() == {
        "userId": "admin-user",
        "password": "secret",
        "hostName": "192.0.2.50",
        "scanOptions": "pr,nw",
        "malwareScanRequested": True,
        "sendContent": False,
    }
    assert result.outputs["Endpoint"] == {"IPAddress": "192.0.2.50"}


def test_triage_endpoint_server_error(client, requests_mock):
    """
    Given:
        - the server rejects the collection (target unreachable)
    Then:
        - ensure the server's message is surfaced
    """
    requests_mock.get(f"{BASE_URL}incidents", json=[{"incidentId": 1, "name": "Default"}])
    requests_mock.post(
        f"{BASE_URL}incidents/1/hosts/live-psexec", status_code=422, json={"status": 422, "message": "The host is unreachable."}
    )
    with pytest.raises(DemistoException, match="unreachable"):
        triage_endpoint_command(client, {"host_name": "ct-win10-01"})

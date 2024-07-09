import json
from JizoM import (
    Client,
    get_query_records_command,
    get_protocols_command,
    get_peers_command,
    get_alert_rules_command,
    get_device_records_command,
    get_device_alerts_command,
)

MOCK_URL = "http://123-fake-api.com"
client = Client(
    base_url=MOCK_URL,
    auth=("user_role", "fake_password"),
    verify=False,
    proxy=False,
)


def load_mock_response(file_name: str) -> dict:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        dict: Mock file content.

    """
    with open(f"test_data/{file_name}") as f:
        return json.load(f)


def test_test_module(requests_mock):
    """
    To test test_module command when success response come.
    Given
        - A valid response
    When
        - The status code returned is 200
    Then
        - Ensure test module should return success
    """

    from JizoM import test_module
    requests_mock.get(f"{MOCK_URL}/ping", status_code=200)
    assert test_module(client) == 'ok'


def test_get_token(requests_mock):
    """
    To test get_token command when success response come.
    Given
        - A valid response
    Then
        - Ensure get_token returns the token that will be required
        to get responses from other endpoints
    """

    from JizoM import get_token
    requests_mock.post(f"{MOCK_URL}/login", json=load_mock_response("connect.json"), status_code=200)
    result = get_token(client)
    assert "token" in result
    assert type(result['token']) == str


def test_get_protocols_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_protocols",
        json=load_mock_response("protocols.json"),
    )
    response = get_protocols_command(client, {})
    assert len(response.outputs) == 3
    assert response.outputs_prefix == "JizoM.Protocols"
    assert response.outputs["alerts_files"]["total"]["total"] == 200000


def test_get_peers_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_peers",
        json=load_mock_response("peers.json"),
    )

    response = get_peers_command(client, {})
    assert list(response.outputs.keys()) == [
        "alerts_flows",
        "alerts_files",
        "alerts_usecase",
    ]
    assert response.outputs_prefix == "JizoM.Peers"
    assert "Probe_02" in response.outputs["alerts_usecase"]["data"]


def test_get_query_records_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_query_records",
        json=load_mock_response("query_records.json"),
    )

    response = get_query_records_command(client, {})
    assert (
        len(response.outputs["alerts_flows"]["data"])
        == response.outputs["alerts_flows"]["count"]
    )
    assert response.outputs_prefix == "JizoM.QueryRecords"
    assert "data" in response.outputs["alerts_flows"]


def test_get_alert_rules_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_alert_rules",
        json=load_mock_response("alert_rules.json"),
    )

    response = get_alert_rules_command(client, {})
    assert len(response.outputs) == 1
    assert response.outputs_prefix == "JizoM.AlertRules"
    assert response.outputs["alerts_flows"]["data"][0]["idx"] == 295


def test_get_device_records_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_device_records",
        json=load_mock_response("device_records.json"),
    )

    response = get_device_records_command(client, {})
    assert response.outputs_prefix == "JizoM.Device.Records"
    assert "severity" in response.outputs["alerts_flows"]["data"][0]


def test_get_device_alerts_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_devicealerts",
        json=load_mock_response("device_alerts.json"),
    )

    response = get_device_alerts_command(client, {})

    assert response.outputs_prefix == "JizoM.Device.Alerts"
    assert type(response.outputs["alerts_flows"]["data"][0]["port_src"]) == int


def test_fetch_incidents(requests_mock):
    """
    To test fetch_incidents command when success response come.
    Given
        - A valid response
    Then
        - Ensure fetch_incidents returns the valid response
    """

    from JizoM import fetch_incidents, formatting_date, convert_to_demisto_severity
    requests_mock.get(f"{MOCK_URL}/jizo_query_records", json=load_mock_response("fetch_incidents.json"))
    next_run, incidents = fetch_incidents(client,max_results=2,last_run={},first_fetch_time="2024-01-01")
    
    assert len(incidents)==2
    assert incidents[0]["type"]== "Jizo Alert"
    raw_alert= json.loads(incidents[0]["rawJSON"])
    assert "295" in incidents[0]["name"]
    assert incidents[0]["severity"]==convert_to_demisto_severity(raw_alert["severity"])
    assert incidents[0]["occurred"]== formatting_date("2024-03-14 17:20:10.000000")
    assert "last_fetch" in next_run
    assert next_run["last_fetch"]== incidents[-1]["occurred"]
    assert 294 in next_run["last_ids"]
    assert next_run["first_fetched_ids"]==[295]
    
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


def test_get_protocols_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_protocols",
        json=load_mock_response("protocols.json"),
    )
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
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
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
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
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
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
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
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
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
    )
    response = get_device_records_command(client, {})
    assert response.outputs_prefix == "JizoM.Device.Records"
    assert "severity" in response.outputs["alerts_flows"]["data"][0]


def test_get_device_alerts_command(requests_mock):

    requests_mock.get(
        f"{MOCK_URL}/jizo_get_devicealerts",
        json=load_mock_response("device_alerts.json"),
    )
    client = Client(
        base_url=MOCK_URL,
        auth=("user_role", "fake_password"),
        verify=False,
        proxy=False,
    )
    response = get_device_alerts_command(client, {})

    assert response.outputs_prefix == "JizoM.Device.Alerts"
    assert type(response.outputs["alerts_flows"]["data"][0]["port_src"]) == int

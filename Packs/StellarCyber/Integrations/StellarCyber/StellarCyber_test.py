import pytest
from CommonServerPython import *
from StellarCyber import (
    Client,
    get_alert_command,
    update_case_command,
    fetch_incidents,
    get_modified_remote_data_command,
    get_remote_data_command,
    demisto_alert_normalization,
    get_xsoar_severity,
)

SERVER_URL = "https://test.example.com"


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(dp_host="test.example.com", username="test", password="test", verify=True, proxy=False, tenantid=None)


def test_get_alert_command(client, requests_mock):
    args = {"alert_id": "1710883791406342b1f41b2247774d60bf035a6f98e5ff21"}
    mock_response_get_alert = util_load_json("./test_data/outputs/get_alert.json")
    mock_results = util_load_json("./test_data/outputs/get_alert_command.json")
    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post(f"{SERVER_URL}/connect/api/v1/access_token", json=mock_token)
    requests_mock.get(f"{SERVER_URL}/connect/api/data/aella-ser-*/_search?q=_id:{args['alert_id']}", json=mock_response_get_alert)
    results = get_alert_command(client=client, args=args)
    assert results.outputs_prefix == "StellarCyber.Alert"
    assert results.outputs_key_field == "alert_id"
    assert results.outputs == mock_results.get("outputs")


def test_update_case_command(client, requests_mock):
    args = {"stellar_case_id": "65f340d9b190d36b26ad2bdc", "stellar_case_status": "New"}
    mock_response_update_case = util_load_json("./test_data/outputs/update_case.json")
    mock_results = util_load_json("./test_data/outputs/update_case_command.json")
    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post(f"{SERVER_URL}/connect/api/v1/access_token", json=mock_token)
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/incidents?id={args["stellar_case_id"]}', json=mock_response_update_case)
    results = update_case_command(client=client, args=args)
    assert results.outputs_prefix == "StellarCyber.Case.Update"
    assert results.outputs_key_field == "_id"
    assert results.outputs == mock_results.get("outputs")


def test_fetch_incidents(client, requests_mock):
    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    mock_new_incidents = util_load_json("./test_data/outputs/get_new_incidents.json")
    mock_case_summary = util_load_json("./test_data/outputs/get_incident_summary.json")
    mock_response_get_alert = util_load_json("./test_data/outputs/get_alert.json")
    params = {"first_fetch": "3 days", "max_fetch": 200, "mirror_direction": "None"}
    test_incident_id = "65f9d988b190d36b26ad2e02"
    test_alert_id = "1710883791406342b1f41b2247774d60bf035a6f98e5ff21"
    mock_response_fetch_incidents = util_load_json("./test_data/outputs/fetch_incidents.json")
    requests_mock.post(f"{SERVER_URL}/connect/api/v1/access_token", json=mock_token)
    requests_mock.get(f"{SERVER_URL}/connect/api/v1/incidents", json=mock_new_incidents)
    requests_mock.get(f"{SERVER_URL}/connect/api/v1/cases/{test_incident_id}/summary", json=mock_case_summary)
    requests_mock.get(
        f"{SERVER_URL}/connect/api/data/stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033/_search?q=_id:{test_alert_id}",  # noqa: E501
        json=mock_response_get_alert,
    )
    results = fetch_incidents(client, params)
    assert results == mock_response_fetch_incidents


def test_get_modified_remote_data_command(client, requests_mock):
    args = {"lastUpdate": "2021-05-01T00:00:00"}
    mock_get_updated_cases = util_load_json("./test_data/outputs/get_new_incidents.json")
    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post(f"{SERVER_URL}/connect/api/v1/access_token", json=mock_token)
    requests_mock.get(f"{SERVER_URL}/connect/api/v1/incidents", json=mock_get_updated_cases)
    results = get_modified_remote_data_command(client=client, args=args)
    assert results.modified_incident_ids == ["7443:6aeb2aae7d8d4ef0820136f42d107db4"]  # type: ignore


def test_get_remote_data_command(client, requests_mock):
    args = {"id": "7443:6aeb2aae7d8d4ef0820136f42d107db4", "lastUpdate": "2021-05-01T00:00:00"}
    mock_get_updated_case = util_load_json("./test_data/outputs/get_new_incidents.json")
    mock_case_summary = util_load_json("./test_data/outputs/get_incident_summary.json")
    mock_response_get_alert = util_load_json("./test_data/outputs/get_alert.json")
    mock_command_response = util_load_json("./test_data/outputs/fetch_incidents.json")
    mock_command_response = json.loads(mock_command_response[0].get("rawJSON"))
    del mock_command_response["mirror_direction"]
    del mock_command_response["mirror_id"]
    del mock_command_response["mirror_instance"]
    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    test_incident_id = "65f9d988b190d36b26ad2e02"
    test_alert_id = "1710883791406342b1f41b2247774d60bf035a6f98e5ff21"
    requests_mock.post(f"{SERVER_URL}/connect/api/v1/access_token", json=mock_token)
    requests_mock.get(f"{SERVER_URL}/connect/api/v1/incidents", json=mock_get_updated_case)
    requests_mock.get(f"{SERVER_URL}/connect/api/v1/cases/{test_incident_id}/summary", json=mock_case_summary)
    requests_mock.get(
        f"{SERVER_URL}/connect/api/data/stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033/_search?q=_id:{test_alert_id}",  # noqa: E501
        json=mock_response_get_alert,
    )
    results = get_remote_data_command(client=client, args=args)
    # print(results.mirrored_object)
    assert results.mirrored_object == mock_command_response  # type: ignore


def test_demisto_alert_normalization():
    test_alert = {
        "xdr_event": {
            "tactic": {"name": "Test Tactic", "id": "TTA-001"},
            "technique": {"name": "Test Technique", "id": "TTE-001"},
            "display_name": "Test Display Name",
            "description": "Test Description",
        },
        "tenantid": "",
        "tenant_name": "Test Tenant",
        "detected_field": "test_field",
        "detected_value": "Test Value",
    }
    test_alert_id = "1710883791406342b1f41b2247774d60bf035a6f98e5ff21"
    test_alert_index = "aella-ser-*"
    test_dp_host = "test.example.com"
    results = demisto_alert_normalization(test_alert, test_alert_id, test_alert_index, test_dp_host)
    assert results.get("alert_id") == test_alert_id
    assert results.get("alert_index") == test_alert_index


def test_get_xsoar_severity():
    test_severity = "High"
    results = get_xsoar_severity(test_severity)
    assert results == 3

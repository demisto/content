"""Cohesity Helios Cortex XSOAR - Unit Tests file
"""

import json
import io

BASE_URL = "https://helios.cohesity.com/"
ALERTS_URL = BASE_URL + "mcm/alerts"
ALERT_DETAIL_URL = BASE_URL + "mcm/alerts/6595940238747379:1630539139046817"
RESTORE_OBJECT_URL = BASE_URL + "irisservices/api/v1/public/restore/recover"
MOCK_OBJECT_NAME = "mock-testing03"
MOCK_ALERTS_RESP_FILE = "test_data/get_ransomware_alerts_resp.json"
MOCK_ALERT_DETAIL_RESP_FILE = "test_data/get_ransomware_alert_detail_resp.json"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests test-module command function.

    Checks the output of the command function with the expected output.
    """
    from CohesityHelios import Client, test_module

    client = Client(
        base_url=BASE_URL,
        verify=False)

    # set up mock response.
    mock_response = {}
    requests_mock.get(ALERTS_URL, json=mock_response)

    response = test_module(client)

    assert response == "ok"


def test_fetch_incidents_command(requests_mock):
    """Tests fetch incidents. Since fetch_incidents_command calls
       get_ransomware_alerts_command(), that command is also tested.

    Checks the output of the command function with the expected output.
    """
    from CohesityHelios import Client, fetch_incidents_command

    client = Client(
        base_url=BASE_URL,
        verify=False)

    # set up mock response.
    mock_response = util_load_json(MOCK_ALERTS_RESP_FILE)
    requests_mock.get(ALERTS_URL, json=mock_response)

    response = fetch_incidents_command(client)
    assert len(response) == 1
    incident = response[0]
    assert incident['CustomFields']['anomalous_object'] == MOCK_OBJECT_NAME
    assert incident['CustomFields']['environment'] == 'kVMware'


def test_ignore_ransomware_anomaly_command(requests_mock):
    """Tests ignore_ransomware_anomaly_command.

    Checks the output of the command function with the expected output.
    """
    from CohesityHelios import Client, ignore_ransomware_anomaly_command

    client = Client(
        base_url=BASE_URL,
        verify=False)

    # set up mock response.
    mock_response_alerts = util_load_json(MOCK_ALERTS_RESP_FILE)
    requests_mock.get(ALERTS_URL, json=mock_response_alerts)

    mock_response_alert_detail = util_load_json(MOCK_ALERT_DETAIL_RESP_FILE)
    requests_mock.patch(ALERT_DETAIL_URL, json=mock_response_alert_detail)

    args = {'object_name': MOCK_OBJECT_NAME}
    response = ignore_ransomware_anomaly_command(client, args)
    assert response == f"Ignored object {MOCK_OBJECT_NAME}."


def test_restore_latest_clean_snapshot(requests_mock):
    """Tests restore_latest_clean_snapshot

    Checks the output of the command function with the expected output.
    """
    from CohesityHelios import Client, restore_latest_clean_snapshot

    client = Client(
        base_url=BASE_URL,
        verify=False)

    # set up mock response.
    mock_response_alerts = util_load_json(MOCK_ALERTS_RESP_FILE)
    requests_mock.get(ALERTS_URL, json=mock_response_alerts)

    mock_response_alert_detail = util_load_json(MOCK_ALERT_DETAIL_RESP_FILE)
    requests_mock.patch(ALERT_DETAIL_URL, json=mock_response_alert_detail)

    requests_mock.post(RESTORE_OBJECT_URL, json={})

    args = {'object_name': MOCK_OBJECT_NAME}
    response = restore_latest_clean_snapshot(client, args)
    assert response == f"Restored object {MOCK_OBJECT_NAME}."

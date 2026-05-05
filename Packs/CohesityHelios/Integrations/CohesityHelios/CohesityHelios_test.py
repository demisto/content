"""Cohesity Helios Cortex XSOAR - Unit Tests file"""

import json

BASE_URL = "https://helios.cohesity.com/"
ALERTS_V2_URL = BASE_URL + "v2/mcm/alerts"
ALERT_PATCH_URL = BASE_URL + "mcm/alerts/"
INCIDENCES_URL = BASE_URL + "mcm/argus/api/v1/public/incidences"
RECOVERIES_URL = BASE_URL + "v2/data-protect/recoveries"

MOCK_ALERT_ID = "6595940238747379:1630539139046817"
MOCK_ALERTS_RESP_FILE = "test_data/get_ransomware_alerts_resp.json"
MOCK_ALERT_DETAIL_RESP_FILE = "test_data/get_ransomware_alert_detail_resp.json"
MOCK_INCIDENCE_RESP_FILE = "test_data/get_incidence_details_resp.json"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests test-module command function."""
    from CohesityHelios import Client, test_module

    client = Client(base_url=BASE_URL, verify=False)

    mock_response = {"alertsList": []}
    requests_mock.get(ALERTS_V2_URL, json=mock_response)

    response = test_module(client)
    assert response == "ok"


def test_fetch_incidents_command(requests_mock):
    """Tests fetch incidents command with v2 API response format."""
    from CohesityHelios import Client, fetch_incidents_command

    client = Client(base_url=BASE_URL, verify=False)

    mock_response = util_load_json(MOCK_ALERTS_RESP_FILE)
    requests_mock.get(ALERTS_V2_URL, json=mock_response)

    response = fetch_incidents_command(client)
    assert len(response) == 1

    incident = response[0]
    assert incident["name"] == "DataIngestAnomalyAlert"
    assert incident["CustomFields"]["cohesityheliosalertid"] == MOCK_ALERT_ID
    assert incident["CustomFields"]["cohesityheliosobjectid"] == "2294"
    assert incident["CustomFields"]["cohesityheliosclustername"] == "sac01-pm-haswell2-p1"
    assert incident["CustomFields"]["cohesityheliosclusterid"] == 6573823962906680


def test_get_ransomware_alerts_command(requests_mock):
    """Tests get_ransomware_alerts_command with v2 API response format."""
    from CohesityHelios import Client, get_ransomware_alerts_command

    client = Client(base_url=BASE_URL, verify=False)

    mock_response = util_load_json(MOCK_ALERTS_RESP_FILE)
    requests_mock.get(ALERTS_V2_URL, json=mock_response)

    args = {"limit": "10"}
    result = get_ransomware_alerts_command(client, args)

    assert result.outputs_prefix == "CohesityHelios.RansomwareAlert"
    assert len(result.outputs) == 1
    assert result.outputs[0]["alert_id"] == MOCK_ALERT_ID
    assert result.outputs[0]["entity_id"] == "2294"
    assert result.outputs[0]["job_id"] == "245242"
    assert result.outputs[0]["cluster_name"] == "sac01-pm-haswell2-p1"


def test_ignore_ransomware_anomaly_command(requests_mock):
    """Tests ignore_ransomware_anomaly_command with alert_id argument."""
    from CohesityHelios import Client, ignore_ransomware_anomaly_command

    client = Client(base_url=BASE_URL, verify=False)

    requests_mock.patch(ALERT_PATCH_URL + MOCK_ALERT_ID, status_code=200, text="")

    args = {"alert_id": MOCK_ALERT_ID}
    response = ignore_ransomware_anomaly_command(client, args)
    assert response == f"Ignored alert {MOCK_ALERT_ID}."


def test_restore_latest_clean_snapshot(requests_mock):
    """Tests restore_latest_clean_snapshot with incidences and recoveries APIs."""
    from CohesityHelios import Client, restore_latest_clean_snapshot

    client = Client(base_url=BASE_URL, verify=False)

    mock_incidence_resp = util_load_json(MOCK_INCIDENCE_RESP_FILE)
    requests_mock.get(INCIDENCES_URL, json=mock_incidence_resp)

    requests_mock.post(RECOVERIES_URL, json={})

    requests_mock.patch(ALERT_PATCH_URL + MOCK_ALERT_ID, status_code=200, text="")

    args = {"alert_id": MOCK_ALERT_ID}
    response = restore_latest_clean_snapshot(client, args)
    assert response == "Restored mock-testing03 (id=2294) from latest clean snapshot."

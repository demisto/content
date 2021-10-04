import pytest
import os
from Opsgeniev2 import Client
import json
from unittest.mock import call

"""
Test script for the OpsGenieV2 Integration

Envvars:
    API_TOKEN: If configured, runs integration tests.
    GEN_TEST_DATA: If set, copies the raw output* of the API queries into test_data.

* In the case of Paged data, the raw_response only contains the data of the request response and not the
paging information. Compare list_alerts_paged.json to list_alerts.json to see the difference.

Integration steps use the real OpsGenie API to go through the lifecycle of an alert, schedule, and on-call.

You must get the API_TOKEN from within an opsgenie "team" integration;
teams->[team]->Integrations->Add integration->Rest API Over JSON
"""

PARAMS = {
    "url": "https://api.opsgenie.com",
    "token": os.getenv("API_TOKEN"),
}
ARGS = {
    "message": "This is a test alert!"
}


@pytest.fixture
def testclient():
    """
    Setup a test client, used as a fixture for Integration tests.
    """
    base_url = PARAMS.get("url") + "/v2"
    client = Client(
        base_url=base_url,
        headers={
            "Authorization": f"GenieKey {PARAMS.get('token')}",
        }
    )
    return client


def test_integration_tests(mocker, testclient):
    """
    Creates, lists, and then delets an alert.
    """
    if not PARAMS.get("token"):
        # Pass if no token for acceptance tests
        return

    test_data = {}
    test_data["list_schedules"] = list_schedule_tester(testclient)
    test_data["get_schedules"] = get_schedule_tester(testclient, test_data["list_schedules"]["data"][0]["id"])
    test_data["on_call"] = get_on_call_tester(testclient, test_data["list_schedules"]["data"][0]["id"])

    # Create alert
    alert_raw_response = create_alerts_tester(testclient)
    test_data["create_alert"] = alert_raw_response
    alert_id = alert_raw_response.get("alertId")
    # List alerts
    test_data["list_alerts"] = list_alerts_tester(testclient)
    # Get the alert we just created
    test_data["get_alert"] = get_alert_tester(testclient, alert_id)
    # Ack the same alert
    test_data["ack_alert"] = ack_alert_tester(testclient, alert_id)
    # Close the same alert
    test_data["close_alert"] = close_alert_tester(testclient, alert_id)
    # Delete the alert we just created
    test_data["delete_alert"] = delete_alert_tester(testclient, alert_id)

    if os.getenv("GEN_TEST_DATA"):
        # If set, test JSON added to test_data
        for k, v in test_data.items():
            with open(f"test_data/{k}.json", "w") as fh:
                json.dump(v, fh, indent=4, sort_keys=True)


def create_alerts_tester(testclient):
    from Opsgeniev2 import create_alert

    r = create_alert(testclient, ARGS)
    assert r.raw_response.get("alertId")
    return r.raw_response


def list_alerts_tester(testclient):
    from Opsgeniev2 import list_alerts
    r = list_alerts(testclient, 40, "createdBy")
    assert len(r.outputs) > 0
    return r.raw_response


def delete_alert_tester(testclient, alert_id):
    from Opsgeniev2 import delete_alert

    r = delete_alert(testclient, alert_id)
    assert r.outputs
    return r.raw_response


def get_alert_tester(testclient, alert_id):
    from Opsgeniev2 import get_alert

    r = get_alert(testclient, alert_id)
    assert r.outputs
    return r.raw_response


def ack_alert_tester(testclient, alert_id):
    from Opsgeniev2 import ack_alert

    r = ack_alert(testclient, {"alert-id": alert_id})
    assert r.outputs
    return r.raw_response


def close_alert_tester(testclient, alert_id):
    from Opsgeniev2 import close_alert

    r = close_alert(testclient, {"alert-id": alert_id})
    assert r.outputs
    return r.raw_response


def list_schedule_tester(testclient):
    from Opsgeniev2 import list_schedules

    r = list_schedules(testclient, 20, "createdAt")
    assert r.outputs
    return r.raw_response


def get_schedule_tester(testclient, schedule_id):
    from Opsgeniev2 import get_schedule

    r = get_schedule(testclient, schedule_id)
    assert r.outputs
    return r.raw_response


def get_on_call_tester(testclient, schedule_id):
    from Opsgeniev2 import get_on_calls

    r = get_on_calls(testclient, schedule_id)
    assert r.outputs
    return r.raw_response


def test_paging(mocker, testclient):
    """
    Test the paging functionality works as expected
    """
    # Patch to return list_alerts json data
    with open("./test_data/list_alerts_paged.json") as list_alerts_paged:
        list_alerts_response = json.load(list_alerts_paged)
    with open("./test_data/list_alerts_empty.json") as list_alerts_empty:
        mocker.patch.object(Client, "_http_request", side_effect=[
            list_alerts_response,
            json.load(list_alerts_empty),
        ])
    data = testclient.get_paged(40, url_suffix="/not_real", method="GET")

    assert len(data) == 29
    calls = [
        call(url_suffix="/not_real", method="GET"),
        call(full_url=list_alerts_response.get("paging").get("next"),
             url_suffix="/not_real",
             method="GET",
             )
    ]
    Client._http_request.assert_has_calls(calls)

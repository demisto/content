import pytest
import os
from OpsGenieV3 import Client
from CommonServerPython import DemistoException
import json
from unittest.mock import call

"""
Test script for the OpsGenieV3 Integration

Envvars:
    API_TOKEN: If configured, runs integration tests.

You must get the API_TOKEN from within an opsgenie "team" integration;
teams->[team]->Integrations->Add integration->Rest API Over JSON
"""

PARAMS = {
    "url": "https://api.opsgenie.com",
    # "token": os.getenv("API_TOKEN"),
    "token": "044a2e50-fd34-4e11-9eff-69f16f2413af"
}
ARGS = {
    "message": "This is a test alert!"
}


@pytest.fixture
def testclient():
    """
    Setup a test client, used as a fixture for Integration tests.
    """
    base_url = PARAMS.get("url")
    client = Client(
        base_url=base_url,
        headers={
            "Authorization": f"GenieKey {PARAMS.get('token')}",
        }
    )
    return client


def test_get_escalations(testclient):
    from OpsGenieV3 import get_escalations
    r = get_escalations(testclient, {})
    assert r.outputs
    return r.raw_response


def test_get_alert_attachments_without_alert_id(testclient):
    from OpsGenieV3 import get_alert_attachments
    with pytest.raises(DemistoException):
        r = get_alert_attachments(testclient, {})


def test_get_schedules(testclient):
    from OpsGenieV3 import get_schedules
    r = get_schedules(testclient, {})
    assert r.outputs
    return r.raw_response


def test_get_schedule_overrides_without_args(testclient):
    from OpsGenieV3 import get_schedule_overrides
    with pytest.raises(DemistoException):
        get_schedule_overrides(testclient, {})


def get_schedule_overrides_tester(testclient, schedule_id):
    from OpsGenieV3 import get_schedule_overrides
    r = get_schedule_overrides(testclient, schedule_id)
    assert r.outputs
    return r.raw_response


def test_get_on_call_without_args(testclient):
    from OpsGenieV3 import get_on_call
    with pytest.raises(DemistoException):
        get_on_call(testclient, {})


def get_on_call_tester(testclient, schedule_id):
    from OpsGenieV3 import get_on_call
    r = get_on_call(testclient, {"schedule_id": schedule_id})
    assert r.outputs
    return r.raw_response

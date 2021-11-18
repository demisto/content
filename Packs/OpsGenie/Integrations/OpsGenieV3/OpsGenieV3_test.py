import pytest
import os
from OpsGenieV3 import Client
from CommonServerPython import DemistoException
import json
from unittest.mock import call


class MockClient:
    def __init__(self):
        pass


def test_get_schedule_overrides_without_args():
    from OpsGenieV3 import get_schedule_overrides
    test_client = MockClient()
    with pytest.raises(DemistoException):
        get_schedule_overrides(test_client, {})


def test_assign_alert_without_args():
    from OpsGenieV3 import assign_alert
    test_client = MockClient()
    with pytest.raises(DemistoException):
        assign_alert(test_client, {})


def test_escalate_alert_without_args():
    from OpsGenieV3 import escalate_alert
    test_client = MockClient()
    with pytest.raises(DemistoException):
        escalate_alert(test_client, {})


def test_get_schedule_overrides_without_args():
    from OpsGenieV3 import get_schedule_overrides
    test_client = MockClient()
    with pytest.raises(DemistoException):
        get_schedule_overrides(test_client, {})


def test_get_on_call_without_args():
    from OpsGenieV3 import get_on_call
    test_client = MockClient()
    with pytest.raises(DemistoException):
        get_on_call(test_client, {})


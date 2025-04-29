"""
Test script for the SIGNL4 ntegration

PARAMS:
    secret: The SIGNL4 team or integration secret.

"""

from CommonServerPython import DemistoException
from SIGNL4 import (
    Client,
    send_signl4_alert,
    close_signl4_alert,
)


# Test secret
mock_secret = "****"


def test_signl4_alert():

    client = Client(secret=mock_secret, verify=False)
    args = {
        "title": "Alert from Cortex XSOAR",
        "message": "Hello world.",
        "s4_external_id": "id1234"
    }
    outputs = send_signl4_alert(client, args).outputs

    assert "eventId" in outputs


def test_signl4_close_alert():

    client = Client(secret=mock_secret, verify=False)
    args = {
        "s4_external_id": "id1234"
    }
    outputs = close_signl4_alert(client, args).outputs

    assert "eventId" in outputs


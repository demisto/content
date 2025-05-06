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

def test_send_signl4_alert_success(mocker: MockerFixture):
    """
    Given: A Client instance and alert data with all required fields.
    When: The send_signl4_alert function is called with the alert data.
    Then: The function should return a CommandResults object with the alert data.
    """
    # Mock client
    client = Client(base_url="https://connect.signl4.com/webhook/mock-secret", verify=False)
    
    # Mock client's send_signl4_alert method
    mock_response = {"eventId": "mock-event-id-12345"}
    mocker.patch.object(client, 'send_signl4_alert', return_value=mock_response)
    
    # Test data
    json_data = {
        "title": "Test Alert",
        "message": "This is a test alert",
        "s4_external_id": "test-id-12345"
    }
    
    # Execute
    result = send_signl4_alert(client, json_data)
    
    # Assert
    assert result.outputs_prefix == "SIGNL4.AlertCreated"
    assert result.outputs_key_field == "eventId"
    assert result.outputs == mock_response
    assert isinstance(result, CommandResults)
    assert "SIGNL4 alert created" in result.readable_output


def test_signl4_close_alert_success(mocker: MockerFixture):
    """
    Given: A Client instance and alert data with all required fields.
    When: The close_signl4_alert function is called with the alert data.
    Then: The function should return a CommandResults object with the alert data.
    """
    # Mock client
    client = Client(base_url="https://connect.signl4.com/webhook/mock-secret", verify=False)
    
    # Mock client's send_signl4_alert method
    mock_response = {"eventId": "mock-event-id-12345"}
    mocker.patch.object(client, 'close_signl4_alert', return_value=mock_response)
    
    # Test data
    json_data = {
        "s4_external_id": "test-id-12345"
    }
    
    # Execute
    result = close_signl4_alert(client, json_data)
    
    # Assert
    assert result.outputs_prefix == "SIGNL4.AlertClosed"
    assert result.outputs_key_field == "eventId"
    assert result.outputs == mock_response
    assert isinstance(result, CommandResults)
    assert "SIGNL4 alert closed" in result.readable_output

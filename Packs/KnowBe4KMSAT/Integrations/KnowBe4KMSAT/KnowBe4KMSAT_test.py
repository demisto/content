"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from typing import Dict

from KnowBe4KMSAT import Client, UserEventClient

USER_EVENT_BASE_URL = "https://api.events.knowbe4.com"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_user_event_types(requests_mock):
    """
    Given
            no params
    When
            Calling https://api.events.knowbe4.com/event_types
    Then
            Make sure the data array contains event_types with expected values
    """
    
    mock_response_data = util_load_json('test_data/user_event_types_response.json')
    from KnowBe4KMSAT import get_user_event_types
    requests_mock.get(f"{USER_EVENT_BASE_URL}/event_types", json=mock_response_data, status_code=200)
    
    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL, 
        verify=False, 
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        }
    )
    
    args: Dict = {}
    result = get_user_event_types(userEventClient, args)
    assert result.outputs_prefix == "KMSAT_User_Event_Types_Returned"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_get_user_events(requests_mock):
    """
    Given
            no params
    When
            Calling https://api.events.knowbe4.com/events
    Then
            Make sure the data array contains event_types with expected values
    """
    
    mock_response_data = util_load_json('test_data/user_events_response.json')
    from KnowBe4KMSAT import get_user_events
    requests_mock.get(f"{USER_EVENT_BASE_URL}/events", json=mock_response_data, status_code=200)
    
    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL, 
        verify=False, 
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        }
    )
    
    args: Dict = {}
    result = get_user_events(userEventClient, args)
    assert result.outputs_prefix == "KMSAT_User_Events_Returned"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]

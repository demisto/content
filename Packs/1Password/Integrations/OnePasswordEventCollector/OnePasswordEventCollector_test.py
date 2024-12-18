import json
import pytest
from OnePasswordEventCollector import Client


BASE_URL = 'http://example.com'
HEADERS = {'Authorization': 'Bearer MY-TOKEN-123', 'Content-Type': 'application/json'},


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def authenticated_client() -> Client:
    """Fixture to create a OnePasswordEventCollector.Client instance"""
    return Client(base_url=BASE_URL, verify=False, proxy=False, headers=HEADERS)


def test_get_unauthorized_event_types():
    """
    Given:
        - JSON response from 'Auth introspect' endpoint and a list of configured event types.

    When:
        - Calling get_unauthorized_event_types.

    Assert:
        - Ensure correct list of unauthorized event types.
    """
    from OnePasswordEventCollector import get_unauthorized_event_types

    event_types = ['Audit events', 'Item usage actions', 'Sign in attempts']
    mock_response = util_load_json('test_data/introspection_response.json')
    unauthorized_event_types = get_unauthorized_event_types(mock_response, event_types)
    assert unauthorized_event_types == []


@pytest.mark.parametrize(
    'event_type, error_message',
    [
        pytest.param(
            'Random event',
            'Invalid or unsupported 1Password event type: Random event.',
            id='Invalid Event Type',
        ),
        pytest.param(
            'Audit events',
            "Either a 'pagination_cursor' or a 'start_time' need to be specified.",
            id='Valid event type but missing other params',
        )
    ]
)
def test_client_get_events_invalid_inputs(authenticated_client: Client, event_type: str, error_message: str):
    """
    Given:
        - Case 1: A OnePasswordEventCollector.Client instance with an invalid event type.
        - Case 2: A OnePasswordEventCollector.Client instance with an valid event type (but missing other params).

    When:
        - Calling Client.get_events.

    Assert:
        - Ensure a ValueError is raised with the appropriate error message.
    """
    with pytest.raises(ValueError, match=error_message):
        authenticated_client.get_events(event_type)

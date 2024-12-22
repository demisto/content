import json
import pytest
from pytest_mock import MockerFixture
from datetime import datetime
from OnePasswordEventCollector import Client


BASE_URL = 'http://example.com'
HEADERS = {'Authorization': 'Bearer MY-TOKEN-123', 'Content-Type': 'application/json'}


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def authenticated_client() -> Client:
    """Fixture to create a OnePasswordEventCollector.Client instance"""
    return Client(base_url=BASE_URL, verify=False, proxy=False, headers=HEADERS)


def test_get_limit_param():
    """
    Given:
        - Integration instance Configuration params containing 'limit' values.

    When:
        - Calling get_limit_param.

    Assert:
        - Ensure the 'limit' value of the specified event type is as expected.
    """
    from OnePasswordEventCollector import get_limit_param

    expected_audit_events_limit = '500'
    expected_sign_in_attempts_limit = '4000'
    params = {
        'audit_events_limit': expected_audit_events_limit,
        'sign_in_attempts_limit': expected_sign_in_attempts_limit,
    }

    audit_events_limit = get_limit_param(params, event_type='audit events')
    sign_in_attempts_limit = get_limit_param(params, event_type='sign in attempts')

    assert audit_events_limit == int(expected_audit_events_limit)
    assert sign_in_attempts_limit == int(expected_sign_in_attempts_limit)


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

    event_types = ['audit events', 'item usage actions', 'sign in attempts']
    mock_response = util_load_json('test_data/introspection_response.json')
    unauthorized_event_types = get_unauthorized_event_types(mock_response, event_types)
    assert unauthorized_event_types == []


def test_add_fields_event():
    """
    Given:
        - A raw 1Password event of type 'audit event'.

    When:
        - Calling add_fields_to_event.

    Assert:
        - Ensure the '_time' and 'event_type' fields are added and correctly set.
    """
    from OnePasswordEventCollector import add_fields_to_event, arg_to_datetime, DATE_FORMAT

    event_timestamp = '2024-12-02T11:54:19.710457472Z'
    expected_event_time = arg_to_datetime(event_timestamp).strftime(DATE_FORMAT)

    event_type = 'audit event'
    raw_event = {
        'uuid': '12345',
        'timestamp': event_timestamp,
        'action': 'create',
        'object_type': 'device',
    }
    add_fields_to_event(raw_event, event_type)

    assert raw_event['_time'] == expected_event_time
    assert raw_event['event_type'] == event_type


@pytest.mark.parametrize(
    'event_type, error_message',
    [
        pytest.param(
            'Random event',
            'Invalid or unsupported 1Password event type: Random event.',
            id='Invalid Event Type',
        ),
        pytest.param(
            'audit events',
            "Either a 'pagination_cursor' or a 'from_date' need to be specified.",
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


def test_fetch_events(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A 1Password event type, first fetch date, and the maximum number of events per fetch.

    When:
        - Calling fetch_events (which calls get_events_from_client).

    Assert:
        - Ensure correct inputs to get_events_from_client.
        - Ensure correct fetch_events outputs (last_run, events).
    """
    from OnePasswordEventCollector import fetch_events

    # Inputs
    event_type = 'sign in attempts'
    first_fetch_date = datetime(2024, 12, 2, 11, 50)

    # Expected outputs
    expected_last_run = {'from_date': '2024-12-02T11:59:40.510481428Z', 'ids': ['5678']}
    mock_response = util_load_json('test_data/signinattempts_response.json')
    expected_events = mock_response['items']

    get_events_from_client = mocker.patch('OnePasswordEventCollector.get_events_from_client', return_value=expected_events)
    last_run, events = fetch_events(authenticated_client, event_type=event_type,
                                    first_fetch_date=first_fetch_date, event_last_run={}, max_events=1000)

    get_events_from_client_kwargs = get_events_from_client.call_args.kwargs

    # Assert correct inputs
    assert get_events_from_client_kwargs['event_type'] == event_type
    assert get_events_from_client_kwargs['from_date'] == first_fetch_date

    # Assert correct outputs
    assert last_run == expected_last_run
    assert events == expected_events

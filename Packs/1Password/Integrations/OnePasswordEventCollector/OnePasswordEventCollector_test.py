import json
from contextlib import contextmanager
from datetime import datetime

import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestsMock

from OnePasswordEventCollector import Client


BASE_URL = 'http://example.com'
HEADERS = {'Authorization': 'Bearer MY-TOKEN-123', 'Content-Type': 'application/json'}


def util_load_json(path: str) -> list | dict:
    """Loads the contents of a JSON file with the given path.

    Args:
        path (str): Path to JSON file.

    Returns:
        dict | list: Decoded JSON file contents.
    """
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@contextmanager
def assert_not_raises(exception: type[BaseException]):
    """Asserts the given exception is not raised during a unit test.

    Args:
        exception (type[BaseException]): Any type of exception.

    Raises:
        pytest.fail: If the given exception is raised.
    """
    try:
        yield
    except exception:
        raise pytest.fail(f'Raised {exception}')


@pytest.fixture
def authenticated_client() -> Client:
    """Fixture to create a OnePasswordEventCollector.Client instance"""
    return Client(base_url=BASE_URL, verify=False, proxy=False, headers=HEADERS)


def mock_client_get_events(event_type: str, from_date: datetime | None = None, *args, **kwargs):
    if event_type and from_date:
        # First iteration (from_date filter used)
        response = util_load_json('test_data/auditevents_response_1.json')  # {'has_more': True, 'cursor': 'qwerty4567', ... }
    else:
        # Second and final iteration (pagination cursor from first response used)
        response = util_load_json('test_data/auditevents_response_2.json')  # {'has_more': False, ... }

    return response


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


def test_client_get_events_valid_inputs(authenticated_client: Client, requests_mock: RequestsMock):
    """
    Given:
        - A OnePasswordEventCollector.Client instance with valid inputs to the get_events method.

    When:
        - Calling Client.get_events.

    Assert:
        - Ensure no exception is raised and the raw API response is as expected.
    """
    from OnePasswordEventCollector import urljoin

    event_type = 'sign in attempts'
    from_date = datetime(2024, 12, 2, 11, 50)

    event_url = urljoin(BASE_URL, '/signinattempts')
    mock_response = util_load_json('test_data/signinattempts_response.json')
    requests_mock.post(event_url, json=mock_response)

    with assert_not_raises(Exception):
        response = authenticated_client.get_events(event_type=event_type, from_date=from_date)

    assert response == mock_response


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


def test_get_events_from_client(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A 1Password event type, from date, and the maximum number of events.

    When:
        - Calling get_events_from_client (which calls Client.get_events).

    Assert:
        - Ensure Client.get_events is called twice (because first response['has_more'] is True).
        - Ensure the number of events does not exceed the specified maximum and the events are as expected.
    """
    from OnePasswordEventCollector import get_events_from_client

    event_type = 'audit events'
    from_date = datetime(2024, 12, 2, 11, 50)
    max_events = 20

    client_get_events = mocker.patch.object(authenticated_client, 'get_events', side_effect=mock_client_get_events)

    events = get_events_from_client(authenticated_client, event_type=event_type, from_date=from_date, max_events=max_events)

    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    assert client_get_events.call_count == 2
    assert len(events) <= max_events  # Sanity check
    assert events == expected_events


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
    event_type = 'audit events'
    first_fetch_date = datetime(2024, 12, 2, 11, 55)

    # Expected outputs
    expected_last_run = {'from_date': '2024-12-02T11:55:21.297797084Z', 'ids': ['NTKKXWCQJDPCEVSYGCBC4SDR64']}
    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    get_events_from_client = mocker.patch('OnePasswordEventCollector.get_events_from_client', return_value=expected_events)
    last_run, events = fetch_events(
        authenticated_client,
        event_type=event_type,
        first_fetch_date=first_fetch_date,
        event_last_run={},
        max_events=1000,
    )

    get_events_from_client_kwargs = get_events_from_client.call_args.kwargs

    # Assert correct inputs
    assert get_events_from_client_kwargs['event_type'] == event_type
    assert get_events_from_client_kwargs['from_date'] == first_fetch_date

    # Assert correct outputs
    assert last_run == expected_last_run
    assert events == expected_events


def test_get_events_command(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A 1Password event type, from date, and the maximum number of events (limit).

    When:
        - Calling get_events_command (which calls get_events_from_client and tableToMarkdown).

    Assert:
        - Ensure correct inputs to tableToMarkdown.
        - Ensure correct get_events_command outputs.
    """
    from OnePasswordEventCollector import get_events_command, flattenTable

    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    mocker.patch('OnePasswordEventCollector.get_events_from_client', return_value=expected_events)
    table_to_markdown = mocker.patch('OnePasswordEventCollector.tableToMarkdown')
    event_type = 'audit events'
    args = {'event_type': event_type, 'limit': '10', 'from_date': '2024-12-02T11:55:00.000000Z'}

    events, _ = get_events_command(authenticated_client, args)
    table_to_markdown_kwargs = table_to_markdown.call_args.kwargs

    assert table_to_markdown_kwargs['name'] == f'Events of type: {event_type}'
    assert table_to_markdown_kwargs['t'] == flattenTable(expected_events)

    assert events == expected_events

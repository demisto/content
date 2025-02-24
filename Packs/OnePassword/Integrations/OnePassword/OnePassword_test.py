import json
from datetime import datetime


import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestsMock
import dateparser

from OnePassword import Client


BASE_URL = 'http://example.com'
HEADERS = {'Authorization': 'Bearer MY-TOKEN-123', 'Content-Type': 'application/json'}


def util_load_json(path: str):
    """Loads the contents of a JSON file with the given path.

    Args:
        path (str): Path to JSON file.

    Returns:
        Decoded JSON file contents.
    """
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def authenticated_client() -> Client:
    """Fixture to create a OnePassword.Client instance"""
    return Client(base_url=BASE_URL, verify=False, proxy=False, headers=HEADERS)


def mock_client_get_events(event_feature: str, body: dict):
    if body.get('start_time'):
        # First iteration (from_date filter used)
        # response = {'has_more': True, 'cursor': 'qwerty4567', ... }
        response = util_load_json(f'test_data/{event_feature}_response_1.json')
    else:
        # Second and final iteration (pagination cursor from first response used)
        # response = {'has_more': False, ... }
        response = util_load_json(f'test_data/{event_feature}_response_2.json')

    return response


def test_get_limit_param_for_event_type():
    """
    Given:
        - Integration instance Configuration params containing 'limit' values.

    When:
        - Calling get_limit_param_for_event_type.

    Assert:
        - Ensure the 'limit' value of the specified event type is as expected.
    """
    from OnePassword import get_limit_param_for_event_type

    expected_audit_events_limit = '500'
    expected_sign_in_attempts_limit = '4000'
    params = {
        'audit_events_limit': expected_audit_events_limit,
        'sign_in_attempts_limit': expected_sign_in_attempts_limit,
    }

    audit_events_limit = get_limit_param_for_event_type(params, event_type='audit events')
    sign_in_attempts_limit = get_limit_param_for_event_type(params, event_type='sign in attempts')

    assert audit_events_limit == int(expected_audit_events_limit)
    assert sign_in_attempts_limit == int(expected_sign_in_attempts_limit)


def test_add_fields_event():
    """
    Given:
        - A raw 1Password event of type 'audit event'.

    When:
        - Calling add_fields_to_event.

    Assert:
        - Ensure the '_time' and 'SOURCE_LOG_TYPE' fields are added and correctly set.
    """
    from OnePassword import add_fields_to_event, arg_to_datetime, EVENT_DATE_FORMAT, FILTER_DATE_FORMAT

    event_timestamp = '2024-12-02T11:54:19.710457472Z'

    event_type = 'audit event'
    raw_event = {
        'uuid': '12345',
        'timestamp': event_timestamp,
        'action': 'create',
        'object_type': 'device',
    }
    add_fields_to_event(raw_event, event_type)

    assert raw_event['_time'] == arg_to_datetime(event_timestamp).strftime(EVENT_DATE_FORMAT)
    assert raw_event['timestamp_ms'] == arg_to_datetime(event_timestamp).strftime(FILTER_DATE_FORMAT)
    assert raw_event['SOURCE_LOG_TYPE'] == event_type.upper()


def test_create_get_events_request_body_invalid_inputs():
    """
    Given:
        - Missing pagination cursor and from date.

    When:
        - Calling create_get_events_request_body.

    Assert:
        - Ensure a ValueError is raised with the appropriate error message.
    """
    from OnePassword import create_get_events_request_body

    with pytest.raises(ValueError, match="Either a 'pagination_cursor' or a 'from_date' need to be specified."):
        create_get_events_request_body()


@pytest.mark.parametrize(
    'from_date, pagination_cursor, expected_request_body',
    [
        pytest.param(
            datetime(2024, 12, 2, 11, 50),
            None,
            {'limit': 1000, 'start_time': '2024-12-02T11:50:00.000000Z'},
            id='Reset cursor (date filter)',
        ),
        pytest.param(
            None,
            'PAGE123',
            {'cursor': 'PAGE123'},
            id='Pagination cursor',
        )
    ]
)
def test_create_get_events_request_body_valid_inputs(
    from_date: datetime | None,
    pagination_cursor: str | None,
    expected_request_body: dict,
):
    """
    Given:
        - A from date or a pagination cursor.

    When:
        - Calling create_get_events_request_body.

    Assert:
        - Ensure the request body is as expected.
    """
    from OnePassword import create_get_events_request_body

    request_body = create_get_events_request_body(from_date=from_date, pagination_cursor=pagination_cursor)

    assert request_body == expected_request_body


def test_client_get_events(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A OnePassword.Client instance with valid inputs to the get_events method.

    When:
        - Calling Client.get_events.

    Assert:
        - Ensure no exception is raised and the raw API response is as expected.
    """

    event_feature = 'signinattempts'
    request_body = {'cursor': '12345'}

    client_http_request = mocker.patch.object(authenticated_client, '_http_request')

    authenticated_client.get_events(event_feature, request_body)

    client_http_request_kwargs = client_http_request.call_args.kwargs

    assert client_http_request_kwargs['method'] == 'POST'
    assert client_http_request_kwargs['url_suffix'] == '/api/v2/signinattempts'
    assert client_http_request_kwargs['json_data'] == request_body
    assert client_http_request_kwargs['raise_on_status'] is True


def test_get_events_from_client_no_skip(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A 1Password event type, from date, and the maximum number of events.

    When:
        - Calling get_events_from_client (which calls Client.get_events).

    Assert:
        - Ensure Client.get_events is called twice (because first response['has_more'] is True).
        - Ensure the number of events does not exceed the specified maximum and the events are as expected.
    """
    from OnePassword import get_events_from_client

    event_type = 'audit events'
    from_date = datetime(2024, 12, 2, 11, 50)
    max_events = 3

    client_get_events = mocker.patch.object(authenticated_client, 'get_events', side_effect=mock_client_get_events)

    events = get_events_from_client(authenticated_client, event_type=event_type, from_date=from_date, max_events=max_events)

    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    assert client_get_events.call_count == 2
    assert events == expected_events


def test_get_events_from_client_skip_ids(authenticated_client: Client, mocker: MockerFixture):
    """
    Given:
        - A 1Password event type, from date, and the maximum number of events.

    When:
        - Calling get_events_from_client (which calls Client.get_events).

    Assert:
        - Ensure Client.get_events is called once (because response['has_more'] is False).
        - Ensure no events are returned (because the event ID in the response should be skipped).
    """
    from OnePassword import get_events_from_client

    event_type = 'audit events'
    from_date = datetime(2024, 12, 2, 11, 50)
    max_events = 2

    response = util_load_json('test_data/auditevents_response_2.json')
    already_fetched_ids_to_skip = {'last event'}
    client_get_events = mocker.patch.object(authenticated_client, 'get_events', return_value=response)

    events = get_events_from_client(
        authenticated_client,
        event_type=event_type,
        from_date=from_date,
        max_events=max_events,
        already_fetched_ids_to_skip=already_fetched_ids_to_skip)

    assert client_get_events.call_count == 1
    assert events == []  # No new events because event ID in response has already been fetched and should be skipped


def test_push_events(mocker: MockerFixture):
    """
    Given:
        - A list of 1Password events of type 'audit events'.

    When:
        - Calling push_events.

    Assert:
        - Ensure send_events_to_xsiam is called once with the correct inputs.
    """
    from OnePassword import push_events, VENDOR as EXPECTED_VENDOR, PRODUCT as EXPECTED_PRODUCT

    send_events_to_xsiam = mocker.patch('OnePassword.send_events_to_xsiam')

    expected_events = util_load_json('test_data/auditevents_expected_events.json')
    push_events(expected_events)

    send_events_to_xsiam_kwargs = send_events_to_xsiam.call_args.kwargs

    assert send_events_to_xsiam.call_count == 1
    assert send_events_to_xsiam_kwargs['events'] == expected_events
    assert send_events_to_xsiam_kwargs['vendor'] == EXPECTED_VENDOR
    assert send_events_to_xsiam_kwargs['product'] == EXPECTED_PRODUCT


def test_set_next_run(mocker: MockerFixture):
    """
    Given:
        - A next run dictionary for 1Password event feature 'auditevents'.

    When:
        - Calling set_next_run.

    Assert:
        - Ensure demisto.setLastRun is called once with the correct inputs.
    """
    from OnePassword import set_next_run

    demisto_set_last_run = mocker.patch('OnePassword.demisto.setLastRun')

    next_run = {'auditevents': {'from_date': '2024-12-02T11:55:20.710457Z', 'ids': ['last event']}}
    set_next_run(next_run)

    assert demisto_set_last_run.call_count == 1
    assert demisto_set_last_run.call_args[0][0] == next_run


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
    from OnePassword import fetch_events

    # Inputs
    event_type = 'audit events'
    from_date = '2024-12-02T11:54:11Z'

    # Expected outputs
    expected_type_next_run = {'from_date': '2024-12-02T11:55:20.710457Z', 'ids': ['middle event', 'last event']}
    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    get_events_from_client = mocker.patch('OnePassword.get_events_from_client', return_value=expected_events)
    type_next_run, events = fetch_events(
        authenticated_client,
        event_type=event_type,
        event_type_last_run={'from_date': from_date, 'ids': []},
        event_type_max_results=1000,
    )

    get_events_from_client_kwargs = get_events_from_client.call_args.kwargs

    # Assert correct inputs
    assert get_events_from_client_kwargs['event_type'] == event_type
    assert get_events_from_client_kwargs['from_date'] == dateparser.parse(from_date)

    # Assert correct outputs
    assert type_next_run['from_date'] == expected_type_next_run['from_date']
    assert sorted(type_next_run['ids']) == sorted(expected_type_next_run['ids'])
    assert events == expected_events


def test_test_module_command(authenticated_client: Client, requests_mock: RequestsMock):
    """
    Given:
        - A list of 1Password event types and a OnePassword.Client instance.

    When:
        - Calling test_module_command (which calls Client.get_events).

    Assert:
        - Ensure client errors are gracefully handled and the correct error message appears.
    """
    from OnePassword import test_module_command, urljoin

    event_types = ['Sign in attempts']

    event_url = urljoin(BASE_URL, 'api/v2/signinattempts')
    mock_response = {"Error": {"Message": "Unauthorized"}}
    requests_mock.post(event_url, json=mock_response, status_code=401)

    result = test_module_command(authenticated_client, event_types)

    assert result == 'Authorization Error: Make sure the API server URL and token are correctly set'


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
    from OnePassword import get_events_command, flattenTable

    expected_events = util_load_json('test_data/auditevents_expected_events.json')

    mocker.patch('OnePassword.get_events_from_client', return_value=expected_events)
    table_to_markdown = mocker.patch('OnePassword.tableToMarkdown')
    event_type = 'audit events'
    args = {'event_type': event_type, 'limit': '10', 'from_date': '2024-12-02T11:55:00Z'}

    events, _ = get_events_command(authenticated_client, args)
    table_to_markdown_kwargs = table_to_markdown.call_args.kwargs

    assert table_to_markdown_kwargs['name'] == event_type.capitalize()
    assert table_to_markdown_kwargs['t'] == flattenTable(expected_events)

    assert events == expected_events

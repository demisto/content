import json
from urllib.parse import urljoin
import pytest
from freezegun import freeze_time
from pytest_mock.plugin import MockerFixture
from requests_mock.mocker import Mocker as RequestsMock
from DigitalGuardianARCEventCollector import Client


CLIENT_KWARGS = {
    'verify': False,
    'proxy': False,
    'auth_url': 'https://example.com',
    'base_url': 'https://example.com',
    'client_id': '11',
    'client_secret': '22',
}
EXPORT_PROFILE = 'demisto'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def authenticated_client(requests_mock: RequestsMock) -> Client:
    """Fixture to create a Digital Guardian Client instance."""
    token_url = urljoin(CLIENT_KWARGS['auth_url'], '/as/token.oauth2')
    requests_mock.post(token_url, json={'access_token': '123', 'expires_in': 10000})

    return Client(**CLIENT_KWARGS)


@freeze_time("2024-11-30 12:12:12 UTC")
def test_get_or_generate_access_token(mocker: MockerFixture):
    """
    Given:
        - A valid access token in the integration context
    When:
        - Calling Client._get_or_generate_access_token
    Then:
        - Ensure the token in the integration context is returned and no new token is requested.
    """
    integration_context_token = {'token': '123', 'valid_until': 1733128972}  # 2024-12-02 08:43:55 UTC
    mocker.patch('DigitalGuardianARCEventCollector.get_integration_context', return_value=integration_context_token)
    get_new_token_request = mocker.patch.object(Client, '_http_request')

    client = Client(**CLIENT_KWARGS)
    access_token = client._get_or_generate_access_token()

    assert access_token == integration_context_token['token']
    assert get_new_token_request.called is False


@pytest.mark.parametrize('index', [0, 1])
def test_create_events_for_push(index: int):
    """
    Given:
        - Index of an item in a list of events and a limit value
    When:
        - Calling create_events_for_push
    Then:
        - Ensure the _time key is added to the events
    """
    from DigitalGuardianARCEventCollector import create_events_for_push, arg_to_datetime, DATE_FORMAT

    limit = 2
    raw_response = util_load_json('test_data/mock_response.json')

    outputted_events = create_events_for_push(raw_response, EXPORT_PROFILE, limit)
    expected_event_time = arg_to_datetime(outputted_events[index]['dg_time']).strftime(DATE_FORMAT)

    assert outputted_events[index]['_time'] == expected_event_time
    assert outputted_events[index]['dg_export_profile'] == EXPORT_PROFILE
    assert len(outputted_events) == limit


def test_get_fetch_events(mocker: MockerFixture, authenticated_client: Client):
    """
    Given:
        - Digital Guardian ARC client and number of days to get events
    When:
        - Calling fetch_events
    Then:
        - Ensure the events and last run are returned as expected
    """
    from DigitalGuardianARCEventCollector import fetch_events

    raw_response = util_load_json('test_data/mock_response.json')  # contains duplicate events
    mocker.patch.object(authenticated_client, 'export_events', return_value=raw_response)
    expected_events = util_load_json('test_data/expected_events.json')

    outputted_events, last_run = fetch_events(authenticated_client, EXPORT_PROFILE)

    assert outputted_events == expected_events
    assert last_run['bookmark_values'] == raw_response['bookmark_values']
    assert last_run['search_after_values'] == raw_response['search_after_values']


def test_get_events_command(mocker: MockerFixture, authenticated_client: Client):
    """
    Given:
        - Digital Guardian ARC client and limit of events to get
    When:
        - Calling get_events_command
    Then:
        - Ensure the events are returned as expected and correct arguments are passed to tableToMarkdown
    """
    from DigitalGuardianARCEventCollector import get_events_command

    limit = 1
    raw_response = util_load_json('test_data/mock_response.json')
    mocker.patch.object(authenticated_client, 'export_events', return_value=raw_response)
    table_to_markdown = mocker.patch('DigitalGuardianARCEventCollector.tableToMarkdown')

    outputted_events, *_ = get_events_command(authenticated_client, args={'limit': limit}, export_profile=EXPORT_PROFILE)

    expected_events = util_load_json('test_data/expected_events.json')[:limit]
    table_to_markdown_kwargs: dict = table_to_markdown.call_args.kwargs

    assert outputted_events == expected_events
    assert table_to_markdown_kwargs['name'] == f'Events for Profile {EXPORT_PROFILE}'
    assert table_to_markdown_kwargs['t'] == expected_events


def test_push_events(mocker: MockerFixture):
    """
    Given:
        - Digital Guardian ARC client and parsed events
    When:
        - Calling push_events
    Assert:
        - Ensure events are sent to XSIAM with the correct product and vendor.
    """
    from DigitalGuardianARCEventCollector import push_events, VENDOR, PRODUCT

    events = util_load_json('test_data/expected_events.json')

    send_events_to_xsiam = mocker.patch('DigitalGuardianARCEventCollector.send_events_to_xsiam')

    push_events(events, EXPORT_PROFILE)
    send_events_to_xsiam_kwargs: dict = send_events_to_xsiam.call_args.kwargs

    assert send_events_to_xsiam.call_count == 1
    assert send_events_to_xsiam_kwargs['events'] == events
    assert send_events_to_xsiam_kwargs['vendor'] == VENDOR
    assert send_events_to_xsiam_kwargs['product'] == PRODUCT


def test_set_export_bookmark(mocker: MockerFixture, authenticated_client: Client):
    """
    Given:
        - Digital Guardian ARC client and events last run
    When:
        - Calling set_export_bookmark
    Assert:
        - Ensure correct API call is performed.
    """
    from DigitalGuardianARCEventCollector import set_export_bookmark

    last_run = {'bookmark_values': [], 'search_after_values': []}

    client_http_request = mocker.patch.object(authenticated_client, '_http_request')

    set_export_bookmark(authenticated_client, last_run, EXPORT_PROFILE)
    client_http_request_kwargs: dict = client_http_request.call_args.kwargs

    assert client_http_request.call_count == 1
    assert client_http_request_kwargs['method'] == 'POST'
    assert client_http_request_kwargs['url_suffix'] == f'/rest/2.0/export_profiles/{EXPORT_PROFILE}/acknowledge'

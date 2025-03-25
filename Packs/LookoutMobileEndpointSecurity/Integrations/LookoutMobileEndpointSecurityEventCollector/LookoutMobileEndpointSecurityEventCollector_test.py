import pytest
import demistomock as demisto
from LookoutMobileEndpointSecurityEventCollector import create_response_object, stream_events

EVENTS_OUTPUT = '{"events":[{"id":"1","created_time":"2025-03-24T11:13:24.915+00:00","type":"DEVICE","change_type":"UPDATED","device":{"guid":"guid","platform":"IOS","status":{"security_status":"SECURE","activation_status":"ACTIVATED","protection_status":"PROTECTED"},"hardware":{"manufacturer":"apple","model":"iphone17,2"},"software":{"os_version":"18.3.1","sdk_version":"0"},"client":{"ota_version":"1","package_name":"name","package_version":"9.2.0"},"parent_status":{}},"target":{"guid":"guid","type":"DEVICE"},"actor":{"guid":"guid","type":"DEVICE"}},{"id":"2","created_time":"2025-03-24T11:13:28.375+00:00","type":"THREAT","change_type":"CREATED","threat":{"guid":"guid","status":"RESOLVED","severity":"LOW","type":"WEB_CONTENT","classifications":["UNAUTHORIZED_CONTENT"],"details":{"reason":"OBJECTIONABLE_CONTENT","response":"NONE","reputation":0.6}},"target":{"guid":"guid","type":"THREAT"},"actor":{"guid":"guid","type":"DEVICE"}}]}'  # noqa: E501


class Event:
    """Representation of an event from the event stream."""

    def __init__(self, id=None, event='message', data='', retry=None):
        self.id = id
        self.event = event
        self.data = data
        self.retry = retry


@pytest.fixture(autouse=True)
def client(mocker):
    from LookoutMobileEndpointSecurityEventCollector import Client

    event_type_query = "THREAT"
    app_key = 'app_key'
    server_url = 'https://www.test.com/'
    mocker.patch.object(Client, "_http_request", json={'access_token': 'access_token', 'expires_at': 0})
    return Client(
        base_url=server_url,
        verify=False,
        proxy=False,
        event_type_query=event_type_query,
        app_key=app_key,
    )


@pytest.fixture(autouse=True)
def sse_client(mocker):
    from LookoutMobileEndpointSecurityEventCollector import SSEClient
    event = Event('2', 'event', EVENTS_OUTPUT)
    mocker.patch.object(SSEClient, "events", return_value=[event])
    return SSEClient(R'https://www.test.com/')


def test_create_response_object(client, mocker, requests_mock):
    """
    Given: A mock client, and a mock response.
    When: Running create_response_object.
    Then: The response was build correctly.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'token_expiration': 0})
    # headers = {'Accept': 'text/event-stream', 'Authorization': 'Bearer access_token'}
    requests_mock.get('https://www.test.com/mra/stream/v2/events?type=THREAT&id=', status_code='200', json={})
    response = create_response_object(client=client)
    assert response.status_code == '200'


def test_stream_events(sse_client, mocker, requests_mock):
    """
    Given: A mock sse client, and a mock events response.
    When: Running stream_events.
    Then: The setIntegrationContext was called with the correct last_event_id.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'token_expiration': 0})
    context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={'token_expiration': 0})
    mocker.patch('LookoutMobileEndpointSecurityEventCollector.send_events_to_xsiam', return_value=None)
    stream_events(sse_client, 0)

    assert context.call_args[0][0] == {'token_expiration': 0, 'last_event_id': '2'}

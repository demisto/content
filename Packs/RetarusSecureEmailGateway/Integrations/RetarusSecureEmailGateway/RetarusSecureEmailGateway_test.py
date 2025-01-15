import json
import io
from unittest.mock import Mock, patch
import uuid
import pytest
from contextlib import contextmanager
import RetarusSecureEmailGateway
import CommonServerPython
from RetarusSecureEmailGateway import (
    fetch_events,
    json,
    demisto,
    datetime,
    timedelta,
    websocket_connection,
    perform_long_running_loop,
    DemistoException,
    Connection,
    EventConnection,
    long_running_execution_command,
)
from CommonServerPython import *

CURRENT_TIME: datetime | None = None

EVENTS = [
    {"ts": "2023-08-16T13:24:12.147573+0100", "_id": "1"},
    {"ts": "2023-08-14T13:24:12.147573+0200", "_id": "2"},
    {"ts": "2023-08-12T13:24:11.147573+0000", "_id": "3"}
]

def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    global CURRENT_TIME
    if not CURRENT_TIME:
        CURRENT_TIME = fetch_start_time
    return fetch_start_time + timedelta(seconds=fetch_interval) < CURRENT_TIME


@pytest.fixture
def connection():
    # Set up a mock connection
    return MockConnection()


class MockConnection(Connection):
    def __init__(
        self,
    ):
        global CURRENT_TIME
        self.id = uuid.uuid4()
        self.events = EVENTS
        self.index = 0
        self.pongs = 0
        self.create_time = datetime.now()

    def recv(self, timeout):
        global CURRENT_TIME
        # pretend to sleep for 4 seconds
        assert CURRENT_TIME
        CURRENT_TIME += timedelta(seconds=4)

        if self.index >= len(self.events):
            raise TimeoutError
        event = self.events[self.index]
        self.index += 1
        return json.dumps(event)

    def pong(self):
        self.pongs += 1
        
           
def test_handle_failures_of_send_events(mocker, capfd):
    """
    Given:
        - A connection to the websocket, and events are fetched from the socket

    When:
        - Sending events to XSIAM are failing.

    Then:
        - Add the failing events to the context, and try again in the next run.
    """
    def fetch_events_mock(connection: EventConnection, fetch_interval: int):
        return EVENTS

    def sends_events_to_xsiam_mock(events, **kwargs):
        raise DemistoException("Message")

    mocker.patch.object(RetarusSecureEmailGateway, "fetch_events", side_effect=fetch_events_mock)
    mocker.patch.object(RetarusSecureEmailGateway, "send_events_to_xsiam", side_effect=sends_events_to_xsiam_mock)
    with capfd.disabled():
        perform_long_running_loop(EventConnection(MockConnection()), 60)

    context = demisto.getIntegrationContext()
    assert context["events"] == EVENTS

    second_try_send_events_mock = mocker.patch.object(RetarusSecureEmailGateway, "send_events_to_xsiam")
    with capfd.disabled():
        perform_long_running_loop(EventConnection(MockConnection()), 60)
        
    context = demisto.getIntegrationContext()
    # check the the context is cleared
    assert not context
    # check that the events failed events were sent to xsiam
    for event in EVENTS:
        assert event in second_try_send_events_mock.call_args_list[0][0][0]


def test_heartbeat(mocker, connection):
    """
    Given:
        - A connection object with scarce messages

    When:
        - The long running execution loop runs

    Then:
        - Periodic keep-alive messages (pongs) are sent to the websocket connection to prevent it from closing.

    """
    idle_timeout = 3

    @contextmanager
    def mock_websocket_connection(host, cluster_id, api_key, since_time=None, to_time=None, fetch_interval=60):
        yield EventConnection(connection, fetch_interval, idle_timeout)

    def mock_perform_long_running_loop(connection, interval):
        # This mock will raise exceptions to stop the long running loop
        # StopIteration exception marks success
        if connection.connection.pongs:
            raise StopIteration(f'Sent {connection.connection.pongs} pongs')
        if datetime.now() > connection.create_time + timedelta(seconds=idle_timeout + 2):
            # Heartbeat should've been sent already
            raise TimeoutError(f'No heartbeat sent within {idle_timeout} seconds')

    mocker.patch.object(RetarusSecureEmailGateway, 'websocket_connection',
                        side_effect=mock_websocket_connection)
    mocker.patch.object(RetarusSecureEmailGateway, 'perform_long_running_loop',
                        side_effect=mock_perform_long_running_loop)

    with pytest.raises(StopIteration):
        long_running_execution_command(url='url', token_id='token_id', fetch_interval=60, channel='channel', verify_ssl=False)

    assert connection.pongs > 0


def test_fetch_events(mocker, connection):
    """
    Given:
        A connection to the websocket

    When:
        Calling fetch_events function to get events from the websocket connection

    Then:
        - Ensure that the function returns the events from the websocket connection
        - Ensure that the function converts the timestamp to UTC
        - Ensure that the function returns the events collected in the interval.
    """

    # We set fetch_interval to 7 to get this first two events (as we "wait" 4 seconds between each event)
    fetch_interval = 7
    event_connection = EventConnection(connection=connection)
    mocker.patch.object(RetarusSecureEmailGateway, "is_interval_passed", side_effect=is_interval_passed)
    debug_logs = mocker.patch.object(demisto, "debug")
    events = fetch_events(connection=event_connection, fetch_interval=fetch_interval)

    assert len(events) == 2
    assert events[0]["_time"] == "2023-08-16T12:24:12.147573+00:00"
    assert events[0]["id"] == "1"
    assert events[1]["_time"] == "2023-08-14T11:24:12.147573+00:00"
    assert events[1]["id"] == "2"
    
    debug_logs.assert_any_call("Retarus-logs Fetched 2 events")


# def test_websocket_connection(mocker):
#     """
#     Given: url, token_id, fetch_interval, channel, verify_ssl
#     When: Calling websocket_connection func
#     Then: -connect function is called with the right arguments
#           -EventConnection object is set with the right fields
#     """
#     from unittest.mock import patch
#     mock_event_connection = mocker.patch('RetarusSecureEmailGateway.EventConnection', side_effect = EventConnection(None, 10, 5))
#     with mocker.patch('RetarusSecureEmailGateway.connect') as mock_connect:
        
#         mock_event_connection.return_value = Mock()

#         with websocket_connection("url_1", "token_id_1", 10, "channel_1", True):
#             pass

#             mock_connect.assert_called_with(
#                 "wss://url_1/email/siem/v1/websocket?channel=channel_1",
#                 additional_headers={"Authorization: Bearer token_id_1"},
#                 ssl=ssl.create_default_context()
#             )


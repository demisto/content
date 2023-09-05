import uuid
import pytest
from ProofpointEmailSecurityEventCollector import (
    fetch_events,
    json,
    demisto,
    EventType,
    datetime,
    timedelta,
    websocket_connections,
)
import ProofpointEmailSecurityEventCollector
from freezegun import freeze_time

CURRENT_TIME: datetime | None = None


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    global CURRENT_TIME
    if not CURRENT_TIME:
        CURRENT_TIME = fetch_start_time
    return fetch_start_time + timedelta(seconds=fetch_interval) < CURRENT_TIME


@pytest.fixture
def connection():
    # Set up a mock connection
    return MockConnection()


class MockConnection:
    def __init__(
        self,
    ):
        global CURRENT_TIME
        self.id = uuid.uuid4()
        self.events = [
            {"ts": "2023-08-16T13:24:12.147573+0100", "message": "Test message 1", "id": 1},
            {"ts": "2023-08-14T13:24:12.147573+0200", "message": "Test message 2", "id": 2},
            {"ts": "2023-08-12T13:24:11.147573+0000", "message": "Test message 3", "guid": 3},
        ]
        self.index = 0

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


def test_fetch_events(mocker, connection):
    """
    Given:
        A connection to the websocket

    When:
        Calling fetch_events function to get events from the websocket connection

    Then:
        - Ensure that the function returns the events from the websocket connection
        - Ensure that the function converts the timestamp to UTC
        - Ensure that the function returns the events collected in the interval until events finished
    """

    # We set fetch_interval to 7 to get this first two events (as we "wait" 4 seconds between each event)
    fetch_interval = 7
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "is_interval_passed", side_effect=is_interval_passed)
    debug_logs = mocker.patch.object(demisto, "debug")
    events = fetch_events(event_type=EventType.MESSAGE, connection=connection, fetch_interval=fetch_interval)

    assert len(events) == 2
    assert events[0]["message"] == "Test message 1"
    assert events[0]["_time"] == "2023-08-16T12:24:12.147573+00:00"
    assert events[0]["event_type"] == "message"
    assert events[1]["message"] == "Test message 2"
    assert events[1]["_time"] == "2023-08-14T11:24:12.147573+00:00"
    assert events[1]["event_type"] == "message"

    assert debug_logs.call_args_list[0][0][0] == "Fetched 2 events of type message"
    assert debug_logs.call_args_list[1][0][0] == "The fetched events ids are: 1, 2"
    # Now we want to freeze the time, so we will get the next interval
    with freeze_time(CURRENT_TIME):
        debug_logs = mocker.patch.object(demisto, "debug")
        events = fetch_events(event_type=EventType.MESSAGE, connection=connection, fetch_interval=fetch_interval)
    assert len(events) == 1
    assert events[0]["message"] == "Test message 3"
    assert events[0]["_time"] == "2023-08-12T13:24:11.147573+00:00"
    assert events[0]["event_type"] == "message"

    assert debug_logs.call_args_list[0][0][0] == "Fetched 1 events of type message"
    assert debug_logs.call_args_list[1][0][0] == "The fetched events ids are: 3"


@freeze_time("2023-08-16T13:24:12.147573+0100")
def test_connects_to_websocket(mocker):
    # Mock the connect function from websockets.sync.client
    connect_mock = mocker.patch.object(ProofpointEmailSecurityEventCollector, "connect")

    # Call the websocket_connections function without since_time and to_time
    with websocket_connections("host", "cluster_id", "api_key") as (message_connection, maillog_connection):
        pass

    assert connect_mock.call_count == 2
    assert (
        connect_mock.call_args_list[0][0][0]
        == "wss://host/v1/stream?cid=cluster_id&type=message&sinceTime=2023-08-16T12:24:12.147573"
    )
    assert (
        connect_mock.call_args_list[1][0][0]
        == "wss://host/v1/stream?cid=cluster_id&type=maillog&sinceTime=2023-08-16T12:24:12.147573"
    )
    assert connect_mock.call_args_list[0][1]["additional_headers"]["Authorization"] == "Bearer api_key"
    assert connect_mock.call_args_list[1][1]["additional_headers"]["Authorization"] == "Bearer api_key"

    connect_mock = mocker.patch.object(ProofpointEmailSecurityEventCollector, "connect")

    # Call the websocket_connections function with since_time and to_time
    with websocket_connections(
        "host", "cluster_id", "api_key", since_time="2023-08-14T12:24:12.147573", to_time="2023-08-16T12:24:12.147573"
    ) as (message_connection, maillog_connection):
        pass

    assert connect_mock.call_count == 2
    assert (
        connect_mock.call_args_list[0][0][0]
        == "wss://host/v1/stream?cid=cluster_id&type=message&sinceTime=2023-08-14T12:24:12.147573&toTime=2023-08-16T12:24:12.147573"  # noqa: E501
    )
    assert (
        connect_mock.call_args_list[1][0][0]
        == "wss://host/v1/stream?cid=cluster_id&type=maillog&sinceTime=2023-08-14T12:24:12.147573&toTime=2023-08-16T12:24:12.147573"  # noqa: E501
    )

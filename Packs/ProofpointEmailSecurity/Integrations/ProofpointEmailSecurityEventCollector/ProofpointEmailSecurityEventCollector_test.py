import uuid
from contextlib import ExitStack, contextmanager

import ProofpointEmailSecurityEventCollector
import pytest
from freezegun import freeze_time
from CommonServerPython import arg_to_datetime
from ProofpointEmailSecurityEventCollector import (
    EVENT_TYPES,
    Connection,
    DemistoException,
    EventConnection,
    datetime,
    demisto,
    fetch_events,
    json,
    long_running_execution_command,
    perform_long_running_loop,
    timedelta,
    websocket_connections,
    PING_TIMEOUT,
    CLOSE_TIMEOUT,
)

CURRENT_TIME: datetime | None = None

EVENTS = [
    {"ts": "2023-08-16T13:24:12.147573+0100", "message": "Test message 1", "id": 1},
    {"ts": "2023-08-14T13:24:12.147573+0200", "message": "Test message 2", "id": 2},
    {"ts": "2023-08-12T13:24:11.147573+0000", "message": "Test message 3", "guid": 3},
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

    # Mock the connect method to return the mock connection
    mocker.patch.object(EventConnection, "connect", return_value=connection)

    # We set fetch_interval to 7 to get this first two events (as we "wait" 4 seconds between each event)
    fetch_interval = 7
    event_connection = EventConnection(event_type="message", url="wss://testing", headers={})
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "is_interval_passed", side_effect=is_interval_passed)
    debug_logs = mocker.patch.object(demisto, "debug")
    events = fetch_events(
        connection=event_connection, fetch_interval=fetch_interval, integration_context={}, should_skip_sleeping=[]
    )

    assert len(events) == 2
    assert events[0]["message"] == "Test message 1"
    assert events[0]["_time"] == "2023-08-16T12:24:12.147573+00:00"
    assert events[0]["event_type"] == "message"
    assert events[1]["message"] == "Test message 2"
    assert events[1]["_time"] == "2023-08-14T11:24:12.147573+00:00"
    assert events[1]["event_type"] == "message"

    debug_logs.assert_any_call("[message] Fetched events IDs: 1, 2.")
    # Now we want to freeze the time, so we will get the next interval
    with freeze_time(CURRENT_TIME):
        debug_logs = mocker.patch.object(demisto, "debug")
        events = fetch_events(
            connection=event_connection, fetch_interval=fetch_interval, integration_context={}, should_skip_sleeping=[]
        )
    assert len(events) == 1
    assert events[0]["message"] == "Test message 3"
    assert events[0]["_time"] == "2023-08-12T13:24:11.147573+00:00"
    assert events[0]["event_type"] == "message"

    debug_logs.assert_any_call("[message] Fetched events IDs: 3.")


@freeze_time("2023-08-16T13:24:12.147573+0100")
def test_connects_to_websocket(mocker):
    """
    Given:
        - A host with cluster id and api key to connect to

    When:
        - Creating a connection to the websocket

    Then:
        - Ensure that the function connects to the websocket with the correct url
    """
    # Mock the connect function from websockets.sync.client
    connect_mock = mocker.patch.object(ProofpointEmailSecurityEventCollector, "connect")

    # Call the websocket_connections function without since_time and to_time
    with websocket_connections("wss://host", "cluster_id", "api_key", since_time="2023-08-16T12:24:12.147573"):
        pass

    assert connect_mock.call_count == len(EVENT_TYPES)
    for event_type in EVENT_TYPES:
        connect_mock.assert_any_call(
            f"wss://host/v1/stream?cid=cluster_id&type={event_type}&sinceTime=2023-08-16T12:24:12.147573",
            additional_headers={"Authorization": "Bearer api_key"},
            ping_timeout=PING_TIMEOUT,
            close_timeout=CLOSE_TIMEOUT,
        )

    connect_mock = mocker.patch.object(ProofpointEmailSecurityEventCollector, "connect")

    # Call the websocket_connections function with since_time and to_time
    with websocket_connections(
        "wss://host", "cluster_id", "api_key", since_time="2023-08-14T12:24:12.147573", to_time="2023-08-16T12:24:12.147573"
    ):
        pass

    assert connect_mock.call_count == len(EVENT_TYPES)
    for event_type in EVENT_TYPES:
        connect_mock.assert_any_call(
            f"wss://host/v1/stream?cid=cluster_id&type={event_type}&sinceTime=2023-08-14T12:24:12.147573&toTime=2023-08-16T12:24:12.147573",
            additional_headers={"Authorization": "Bearer api_key"},
            ping_timeout=PING_TIMEOUT,
            close_timeout=CLOSE_TIMEOUT,
        )


def test_handle_failures_of_send_events(mocker, capfd):
    """
    Given:
        - A connection to the websocket, and events are fetched from the socket

    When:
        - Sending events to XSIAM are failing.

    Then:
        - Add the failing events to the context, and try again in the next run.
    """

    def fetch_events_mock(connection: EventConnection, fetch_interval: int, integration_context, should_skip_sleeping):
        if connection.event_type == "message":
            return EVENTS[:2]
        return EVENTS[2:]

    def sends_events_to_xsiam_mock(events, **kwargs):
        raise DemistoException("Message")

    mocker.patch.object(ProofpointEmailSecurityEventCollector, "fetch_events", side_effect=fetch_events_mock)
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "send_events_to_xsiam", side_effect=sends_events_to_xsiam_mock)

    # Mock the connect method to return the mock connection
    mocker.patch.object(EventConnection, "connect", return_value=MockConnection())
    with capfd.disabled():
        perform_long_running_loop(
            [
                EventConnection("message", url="wss://test", headers={}),
                EventConnection("maillog", url="wss://test", headers={}),
            ],
            60,
            [],
        )
    context = demisto.getIntegrationContext()
    assert context["message"] == EVENTS[:2]
    assert context["maillog"] == EVENTS[2:]

    second_try_send_events_mock = mocker.patch.object(ProofpointEmailSecurityEventCollector, "send_events_to_xsiam")
    with capfd.disabled():
        perform_long_running_loop(
            [
                EventConnection("message", url="wss://test", headers={}),
                EventConnection("maillog", url="wss://test", headers={}),
            ],
            60,
            [],
        )
    context = demisto.getIntegrationContext()
    # check the context is cleared
    for event in EVENTS:
        assert str(event) not in str(context)
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
    def mock_websocket_connections(
        host, cluster_id, api_key, since_time=None, to_time=None, fetch_interval=60, event_types=["audit"]
    ):
        with ExitStack():
            yield [
                EventConnection("audit", url="wss://test", headers={}, fetch_interval=fetch_interval, idle_timeout=idle_timeout)
            ]

    def mock_perform_long_running_loop(connections, interval, should_skip_sleeping):
        # This mock will raise exceptions to stop the long running loop
        # StopIteration exception marks success
        connection = connections[0].connection
        if connection.pongs:
            raise StopIteration(f"Sent {connections[0].connection.pongs} pongs")
        if datetime.now() > connection.create_time + timedelta(seconds=idle_timeout + 2):
            # Heartbeat should've been sent already
            raise TimeoutError(f"No heartbeat sent within {idle_timeout} seconds")

    mocker.patch.object(ProofpointEmailSecurityEventCollector, "websocket_connections", side_effect=mock_websocket_connections)
    mocker.patch.object(
        ProofpointEmailSecurityEventCollector, "perform_long_running_loop", side_effect=mock_perform_long_running_loop
    )
    mocker.patch.object(EventConnection, "connect", return_value=connection)
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "support_multithreading")
    mocker.patch.object(demisto, "error", side_effect=StopIteration("Interrupted execution"))  # to break endless loop.

    with pytest.raises(StopIteration):
        long_running_execution_command("host", "cid", "key", 60, ["audit"])

    assert connection.pongs > 0


def test_recovering_execution(mocker, connection):
    """
    Running long_running_execution_command and throwing error every time mock_perform_long_running_loop is
    called to ensure it is being called more than once (i.e, can recover from the failure)
    """
    idle_timeout = 3

    execution_count = 0

    def count_iterations(msg):
        nonlocal execution_count
        execution_count += 1
        if execution_count > 1:
            raise StopIteration("Interrupted execution")

    @contextmanager
    def mock_websocket_connections(
        host, cluster_id, api_key, since_time=None, to_time=None, fetch_interval=60, event_types=["audit"]
    ):
        with ExitStack():
            yield [
                EventConnection("audit", url="wss://test", headers={}, fetch_interval=fetch_interval, idle_timeout=idle_timeout)
            ]

    def mock_perform_long_running_loop(connections, interval, should_skip_sleeping):
        # This mock will raise exceptions to stop the long running loop
        # StopIteration exception marks success
        raise StopIteration(f"Sent {connections[0].connection.pongs} pongs")

    mocker.patch.object(ProofpointEmailSecurityEventCollector, "websocket_connections", side_effect=mock_websocket_connections)
    mocker.patch.object(
        ProofpointEmailSecurityEventCollector, "perform_long_running_loop", side_effect=mock_perform_long_running_loop
    )
    mocker.patch.object(EventConnection, "connect", return_value=connection)
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "support_multithreading")
    demisto_error_mocker = mocker.patch.object(demisto, "error", side_effect=count_iterations)  # to break endless loop.

    with pytest.raises(StopIteration):
        long_running_execution_command("host", "cid", "key", 60, ["audit"])

    assert demisto_error_mocker.call_count > 1


@pytest.mark.parametrize(
    "args, expected_since, expected_to",
    [
        pytest.param(
            {"since_time": "2023-01-01T10:00:00", "to_time": "2023-01-01T11:00:00", "timezone_offset": "-5"},
            "2023-01-01T10:00:00-0500",
            "2023-01-01T11:00:00-0500",
            id="Negative timezone offset",
        ),
        pytest.param(
            {"since_time": "2023-02-01T00:00:00", "to_time": "2023-02-01T01:00:00"},
            "2023-02-01T00:00:00+0000",
            "2023-02-01T01:00:00+0000",
            id="No timezone offset (default to UTC)",
        ),
        pytest.param(
            {"since_time": "2023-03-01T12:00:00", "to_time": "2023-03-01T13:00:00", "timezone_offset": "3"},
            "2023-03-01T12:00:00+0300",
            "2023-03-01T13:00:00+0300",
            id="Positive timezone offset",
        ),
        pytest.param(
            {"since_time": "3 days ago", "to_time": "2 days ago"},
            "2024-10-22T12:00:00+0000",
            "2024-10-23T12:00:00+0000",
            id="Relative time",
        ),
    ],
)
@freeze_time("2024-10-25T12:00:00Z")
def test_get_events_command(mocker, connection, args, expected_since, expected_to):
    """
    Given:
        - A request to get historical events with a specified time range.

    When:
        - The get_events_command is called.

    Then:
        - Ensure the command processes the arguments correctly.
        - Ensure it calls websocket_connections with correctly formatted time strings.
        - Ensure it returns the list of events fetched.
    """
    mock_events = [{"event": 1}, {"event": 2}]
    mocker.patch.object(ProofpointEmailSecurityEventCollector, "fetch_events", return_value=mock_events)

    @contextmanager
    def mock_websocket_connections(host, cluster_id, api_key, **kwargs):
        with ExitStack():
            yield [EventConnection("audit", url="wss://test", headers={}, check_heartbeat=False)]

    websocket_connections_mocker = mocker.patch.object(
        ProofpointEmailSecurityEventCollector,
        "websocket_connections",
        side_effect=mock_websocket_connections,
    )
    mocker.patch.object(EventConnection, "connect", return_value=connection)

    events, _ = ProofpointEmailSecurityEventCollector.get_events_command("host", "cid", "key", args)

    assert events == mock_events

    websocket_connections_kwargs = websocket_connections_mocker.call_args.kwargs
    assert websocket_connections_kwargs["since_time"] == expected_since
    assert websocket_connections_kwargs["to_time"] == expected_to


def test_receive_event(mocker, connection: MockConnection):
    """
    Given:
        - A connection to the websocket with a valid event

    When:
        - Calling receive_event function to process a single event

    Then:
        - Ensure that the function returns the event with proper metadata
        - Ensure that the timestamp is in ISO format and converted to UTC
        - Ensure that the event_type is added to the event
    """
    event_type = "message"
    received_event = {"ts": "2023-08-16T13:24:12.147573+0100", "message": "Test message", "id": 123}

    mocker.patch.object(EventConnection, "connect", return_value=connection)
    mocker.patch.object(EventConnection, "receive", return_value=received_event)
    event_connection = EventConnection(event_type, url="wss://testing", headers={})

    event = ProofpointEmailSecurityEventCollector.receive_event(event_connection, timeout=1)

    assert event["message"] == received_event["message"]
    assert event["id"] == received_event["id"]
    assert event["_time"] == arg_to_datetime(received_event["ts"]).isoformat()
    assert event["event_type"] == event_type


def test_receive_events_after_disconnection(mocker, connection: MockConnection):
    """
    Given:
        - A connection that has been disconnected with in-transit events

    When:
        - Calling receive_events_after_disconnection to collect remaining events

    Then:
        - Ensure that all in-transit events are collected
        - Ensure that the function stops when no more events are available
    """
    in_transit_events = [
        {"ts": "2023-08-16T13:24:12.147573+0100", "message": "In-transit 1", "id": 10},
        {"ts": "2023-08-16T13:24:13.147573+0100", "message": "In-transit 2", "id": 11},
    ]

    call_count = 0

    def mock_receive_event(conn, timeout=1):
        nonlocal call_count
        if call_count < len(in_transit_events):
            event = in_transit_events[call_count].copy()
            event["_time"] = "2023-08-16T12:24:12.147573+00:00"
            event["event_type"] = conn.event_type
            call_count += 1
            return event
        raise TimeoutError("No more events from websocket")

    mocker.patch.object(ProofpointEmailSecurityEventCollector, "receive_event", side_effect=mock_receive_event)

    mocker.patch.object(EventConnection, "connect", return_value=connection)
    event_connection = EventConnection(event_type="message", url="wss://testing", headers={})

    events = ProofpointEmailSecurityEventCollector.receive_events_after_disconnection(event_connection)

    assert len(events) == 2
    assert events[0]["message"] == "In-transit 1"
    assert events[1]["message"] == "In-transit 2"


def test_recover_after_disconnection_with_reconnect(mocker, connection: MockConnection):
    """
    Given:
        - A connection that has been disconnected
        - Some events already collected
        - In-transit events available

    When:
        - Calling recover_after_disconnection with reconnect=True

    Then:
        - Ensure that in-transit events are collected
        - Ensure that events and event_ids are updated
        - Ensure that reconnect is called
    """
    existing_events = [{"id": "1", "message": "Event 1"}]
    existing_event_ids = {"1"}

    in_transit_events = [
        {"id": "2", "message": "In-transit 1", "_time": "2023-08-16T12:00:00+00:00", "event_type": "message"},
        {"guid": "3", "message": "In-transit 2", "_time": "2023-08-16T12:00:01+00:00", "event_type": "message"},
    ]

    mocker.patch.object(
        ProofpointEmailSecurityEventCollector, "receive_events_after_disconnection", return_value=in_transit_events
    )

    mocker.patch.object(EventConnection, "connect", return_value=connection)
    reconnect_mock = mocker.patch.object(EventConnection, "reconnect")
    event_connection = EventConnection(event_type="message", url="wss://testing", headers={})

    ProofpointEmailSecurityEventCollector.recover_after_disconnection(
        connection=event_connection,
        events=existing_events,
        event_ids=existing_event_ids,
        reconnect=True,
    )

    assert len(existing_events) == 3
    assert existing_events[1]["message"] == "In-transit 1"
    assert existing_events[2]["message"] == "In-transit 2"
    assert "2" in existing_event_ids
    assert "3" in existing_event_ids
    assert reconnect_mock.call_count == 1  # Should not be called because reconnect=False


def test_recover_after_disconnection_without_reconnect(mocker, connection: MockConnection):
    """
    Given:
        - A connection that has been disconnected
        - Some events already collected

    When:
        - Calling recover_after_disconnection with reconnect=False

    Then:
        - Ensure that in-transit events are collected
        - Ensure that reconnect is NOT called
    """
    existing_events = []
    existing_event_ids = set()

    in_transit_events = [{"id": 1, "message": "In-transit", "_time": "2023-08-16T12:00:00+00:00", "event_type": "audit"}]

    mocker.patch.object(
        ProofpointEmailSecurityEventCollector,
        "receive_events_after_disconnection",
        return_value=in_transit_events,
    )
    mocker.patch.object(EventConnection, "connect", return_value=connection)
    reconnect_mock = mocker.patch.object(EventConnection, "reconnect")
    event_connection = EventConnection(event_type="audit", url="wss://testing", headers={})

    ProofpointEmailSecurityEventCollector.recover_after_disconnection(
        event_connection, existing_events, existing_event_ids, reconnect=False
    )

    assert len(existing_events) == 1
    assert 1 in existing_event_ids
    assert reconnect_mock.call_count == 0  # Should not be called because reconnect=False

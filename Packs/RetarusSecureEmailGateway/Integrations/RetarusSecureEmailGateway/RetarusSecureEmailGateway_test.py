import uuid
import pytest
import demistomock as demisto
from contextlib import contextmanager
import RetarusSecureEmailGateway
from RetarusSecureEmailGateway import (
    fetch_events,
    json,
    datetime,
    timedelta,
    Connection,
    EventConnection,
    long_running_execution_command,
)
from CommonServerPython import *

CURRENT_TIME: datetime | None = None

EVENTS = [
    {"ts": "2023-08-16T13:24:12.147573+0100", "id": "1"},
    {"ts": "2023-08-14T13:24:12.147573+0200", "id": "2"},
    {"ts": "2023-08-12T13:24:11.147573+0000", "id": "3"}
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
    assert events[1]["_time"] == "2023-08-14T11:24:12.147573+00:00"

    debug_logs.assert_any_call("Retarus-logs Fetched 2 events")


def test_get_last_run_results_command__with_results(mocker):
    cnx = {"last_run_results": "results"}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=cnx)
    res = RetarusSecureEmailGateway.get_last_run_results_command()
    assert res.readable_output == "results"


def test_get_last_run_results_command__no_results(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    res = RetarusSecureEmailGateway.get_last_run_results_command()
    assert "No results from the last run yet." in res.readable_output

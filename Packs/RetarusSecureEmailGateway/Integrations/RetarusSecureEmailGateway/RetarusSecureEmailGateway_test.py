import json
import io
import uuid
import pytest
from contextlib import contextmanager

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
import RetarusSecureEmailGateway

CURRENT_TIME: datetime | None = None

EVENTS = [
    {"ts": "2023-08-16T13:24:12.147573+0100", "type": "type_1", "_id": "1"},
    {"ts": "2023-08-14T13:24:12.147573+0200", "type": "type_2", "_id": "2"},
    {"ts": "2023-08-12T13:24:11.147573+0000", "type": "type_3", "_id": "3"}
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
    from RetarusSecureEmailGateway import long_running_execution_command
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


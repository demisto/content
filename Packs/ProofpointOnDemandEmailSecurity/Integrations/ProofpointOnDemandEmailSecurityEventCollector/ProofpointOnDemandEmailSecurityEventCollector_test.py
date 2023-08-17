import uuid
import pytest
from ProofpointOnDemandEmailSecurityEventCollector import fetch_events, json, demisto
import ProofpointOnDemandEmailSecurityEventCollector


@pytest.fixture
def connection():
    # Set up a mock maillog connection
    return MockConnection()


class MockConnection:
    def __init__(self):
        self.id = uuid.uuid4()
        self.events = [
            {"ts": "2023-08-16T13:24:12.147573+0100", "message": "Test message 1"},
            {"ts": "2023-08-14T13:24:12.147573+0200", "message": "Test message 2"},
            {"ts": "2023-08-12T13:24:11.147573+0000", "message": "Test message 3"}
        ]
        self.index = 0

    def recv(self, timeout):
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
        - Ensure that the function skips and prints debug logs if TimeoutError is raised
    """
    mocker.patch.object(ProofpointOnDemandEmailSecurityEventCollector, "EVENTS_TO_FETCH", 2)
    events = fetch_events(connection)
    assert len(events) == 2
    assert events[0]["message"] == "Test message 1"
    assert events[0]["_time"] == "2023-08-16T12:24:12.147573+00:00"
    assert events[1]["message"] == "Test message 2"
    assert events[1]["_time"] == "2023-08-14T11:24:12.147573+00:00"
    debug_logs = mocker.patch.object(demisto, "debug")
    events = fetch_events(connection)
    assert len(events) == 1
    assert events[0]["message"] == "Test message 3"
    assert events[0]["_time"] == "2023-08-12T13:24:11.147573+00:00"
    assert "Timeout reached when receiving" in debug_logs.call_args_list[1][0][0]

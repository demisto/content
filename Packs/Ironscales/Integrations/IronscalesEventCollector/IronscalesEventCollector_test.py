import pytest
from IronscalesEventCollector import *


@pytest.fixture
def client(mocker):
    def mock_get_incident(inc_id):
        return {
            "incident_id": inc_id,
            "first_reported_date": f"{4 - inc_id} days ago",
        }
    mocked_client = mocker.Mock()
    mocked_client.get_open_incidents.return_value = {"incident_ids": [0, 1, 3, 4]}
    mocked_client.get_incident.side_effect = mock_get_incident
    return mocked_client


def test_fetch_events_by_last_id(client):
    res, last_run = fetch_events_command(
        client,
        last_run={"last_id": 1},
        first_fetch=dateparser.parse("2 days ago"),  # type: ignore
        max_fetch=10,
    )
    assert res[0]["incident_id"] == 3
    assert res[-1]["incident_id"] == 4


def test_fetch_events_by_fetch_time(client):
    events, last_run = fetch_events_command(
        client,
        last_run={},
        first_fetch=dateparser.parse("2 days ago"),  # type: ignore
        max_fetch=1,
    )
    assert len(events) == 1
    assert events[0]["incident_id"] == 3
    assert last_run["last_id"] == 3


def test_get_events(client):
    _, events = get_events_command(client, {"limit": 1})
    assert len(events) == 1
    assert events[0]["incident_id"] == 0

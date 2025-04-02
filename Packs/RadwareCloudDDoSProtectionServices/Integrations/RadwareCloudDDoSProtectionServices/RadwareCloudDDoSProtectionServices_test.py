import pytest
from RadwareCloudDDoSProtectionServices import Client, fetch_events, fetch_alerts

@pytest.fixture()
def client() -> Client:
    """
    Create a Client instance for testing.
    """
    return Client(
        base_url="test/api",
        account_id="test_account_id",
        api_key="test_api_key",
        verify=False,
        proxy=False,
    )


def test_fetch_events_no_last_run(mocker, client):
    """
    Given:
     - no last_run (first time fetching).

    When:
     - running the fetch_events function.

    Then:
     - make sure events are fetched and processed correctly.
     - make sure last_run is updated correctly.
    """
    last_run = {}
    response = {
        "documents": [
            {"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000},
            {"timestamp": "2023-10-10T10:10:20Z", "endTimestamp": 1602323420000},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_events(client, last_run)
    assert len(events) == 2
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("last_fetch_events") == 1602323410000


def test_fetch_events_with_pagination(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - 700 events in the response.

    When:
     - running the fetch_events function with pagination.

    Then:
     - make sure all 700 events are fetched and processed correctly.
     - make sure last_run is updated to indicate more events need to be fetched.
    """
    last_run = {
        "last_fetch_events": 1602323123456,
    }
    documents = [{"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000}] * 700
    response = {
        "documents": documents
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_events(client, last_run)
    assert len(events) == 700
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("continue_fetch_events")


def test_fetch_events_with_less_than_700(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - less than 700 events in the response.

    When:
     - running the fetch_events function.

    Then:
     - make sure all events are fetched and processed correctly.
     - make sure last_run is updated correctly.
    """
    last_run = {
        "last_fetch_events": 1602323123456,
    }
    response = {
        "documents": [
            {"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000},
            {"timestamp": "2023-10-10T10:10:20Z", "endTimestamp": 1602323420000},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_events(client, last_run)
    assert len(events) == 2
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("last_fetch_events") == 1602323410000
    assert not new_last_run.get("continue_fetch_events")


def test_fetch_alerts_no_last_run(mocker, client):
    """
    Given:
     - no last_run (first time fetching).

    When:
     - running the fetch_alerts function.

    Then:
     - make sure alerts are fetched and processed correctly.
     - make sure last_run is updated correctly.
    """
    last_run = {}
    response = {
        "documents": [
            {"context": {"_timestamp": 1602323410000}},
            {"context": {"_timestamp": 1602323420000}},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_alerts(client, last_run)
    assert len(alerts) == 2
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("last_fetch_alerts") == 1602323410000


def test_fetch_alerts_with_pagination(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - 700 alerts in the response.

    When:
     - running the fetch_alerts function with pagination.

    Then:
     - make sure all 700 alerts are fetched and processed correctly.
     - make sure last_run is updated to indicate more alerts need to be fetched.
    """
    last_run = {
        "last_fetch_alerts": 1602323123456,
    }
    documents = [{"context": {"_timestamp": 1602323410000}}] * 700
    response = {
        "documents": documents
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_alerts(client, last_run)
    assert len(alerts) == 700
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("continue_fetch_alerts")


def test_fetch_alerts_with_less_than_700(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - less than 700 alerts in the response.

    When:
     - running the fetch_alerts function.

    Then:
     - make sure all alerts are fetched and processed correctly.
     - make sure last_run is updated correctly.
    """
    last_run = {
        "last_fetch_alerts": 1502323411234,
    }
    response = {
        "documents": [
            {"context": {"_timestamp": 1602323410000}},
            {"context": {"_timestamp": 1602323420000}},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_alerts(client, last_run)
    assert len(alerts) == 2
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("last_fetch_alerts") == 1602323410000
    assert not new_last_run.get('continue_fetch_alerts')

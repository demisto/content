import pytest
from RadwareCloudDDoSProtectionServices import Client, fetch_data


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
     - make sure 2 events are fetched.
     - make sure each event has a '_time' field.
     - make sure each event has a 'source_log_type' field.
     - make sure 'last_fetch_events' in last_run is updated correctly to the latest event timestamp.
    """
    last_run = {}
    response = {
        "documents": [
            {"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000, "_id": "1"},
            {"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000, "_id": "2"},
            {"timestamp": "2023-10-10T10:10:20Z", "endTimestamp": 1602323430000, "_id": "3"},

        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_data(client, last_run, 'events')

    assert len(events) == 3
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("last_fetch_events") == {'latest_ids': ['1', '2'], 'latest_timestamp': 1602323410000}


def test_fetch_events_with_pagination(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - 700 events in the response.

    When:
     - running the fetch_events function with pagination.

    Then:
     - make sure all 700 events are fetched.
     - make sure each event has a '_time' field.
     - make sure each event has a 'source_log_type' field.
     - make sure last_run is updated to indicate that more events need to be fetched.
    """
    last_run = {
        "last_fetch_events": {'latest_ids': ['1', '2'], 'latest_timestamp': 1602323410000},
    }
    documents = [{"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323420000}] * 700
    response = {
        "documents": documents
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_data(client, last_run, 'events')

    assert len(events) == 700
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("iteration_cache_fetch_events").get('end_time')
    assert new_last_run.get("iteration_cache_fetch_events").get('start_time')
    assert new_last_run.get("iteration_cache_fetch_events").get('fetched_events')


def test_fetch_events_with_less_than_max_results(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - less than 700 events in the response.

    When:
     - running the fetch_events function.

    Then:
     - make sure all events are fetched.
     - make sure each event has a '_time' field.
     - make sure each event has a 'source_log_type' field.
     - make sure 'last_fetch_events' in last_run is updated correctly to the latest event timestamp.
     - make sure 'continue_fetch_events' is not set in last_run, indicating no more pages to fetch.
    """
    last_run = {
        "last_fetch_events": {'latest_ids': ['1', '2'], 'latest_timestamp': 1602323410000},
    }
    response = {
        "documents": [
            {"timestamp": "2023-10-10T10:20:10Z", "endTimestamp": 1602323420000, "_id": "2"},
            {"timestamp": "2023-10-10T10:10:10Z", "endTimestamp": 1602323410000, "_id": "1"},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    events, new_last_run = fetch_data(client, last_run, 'events')

    assert len(events) == 1
    assert "_time" in events[0]
    assert "source_log_type" in events[0]
    assert new_last_run.get("last_fetch_events") == {'latest_ids': ['2'], 'latest_timestamp': 1602323420000}
    assert not new_last_run.get("iteration_cache_fetch_events")


def test_fetch_alerts_no_last_run(mocker, client):
    """
    Given:
     - no last_run (first time fetching).

    When:
     - running the fetch_alerts function.

    Then:
     - make sure 2 alerts are fetched.
     - make sure each alert has a '_time' field.
     - make sure each alert has a 'source_log_type' field.
     - make sure 'last_fetch_alerts' in last_run is updated correctly to the latest alert timestamp.
    """
    last_run = {}
    response = {
        "documents": [
            {"context": {"_timestamp": 1602323420000}, "_id": "1"},
            {"context": {"_timestamp": 1602323420000}, "_id": "2"},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_data(client, last_run, 'alerts')

    assert len(alerts) == 2
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("last_fetch_alerts") == {'latest_ids': ['1', '2'], 'latest_timestamp': 1602323420000}


def test_fetch_alerts_with_pagination(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - 700 alerts in the response.

    When:
     - running the fetch_alerts function with pagination.

    Then:
     - make sure all 700 alerts are fetched.
     - make sure each alert has a '_time' field.
     - make sure each alert has a 'source_log_type' field.
     - make sure last_run is updated to indicate that more alerts need to be fetched.
    """
    last_run = {
        "last_fetch_alerts": {'latest_ids': ['1', '2'], 'latest_timestamp': 1602323410000},
    }
    documents = [{"context": {"_timestamp": 1602323410000}}] * 700
    response = {
        "documents": documents
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_data(client, last_run, 'alerts')

    assert len(alerts) == 700
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("iteration_cache_fetch_alerts").get('end_time')
    assert new_last_run.get("iteration_cache_fetch_alerts").get('start_time')
    assert new_last_run.get("iteration_cache_fetch_alerts").get('fetched_alerts')


def test_fetch_alerts_with_less_than_max_results(mocker, client):
    """
    Given:
     - a last_run with a specific timestamp.
     - less than 700 alerts in the response.

    When:
     - running the fetch_alerts function.

    Then:
     - make sure all alerts are fetched.
     - make sure each alert has a '_time' field.
     - make sure each alert has a 'source_log_type' field.
     - make sure 'last_fetch_alerts' in last_run is updated correctly to the latest alert timestamp.
     - make sure 'continue_fetch_alerts' is not set in last_run, indicating no more pages to fetch.
    """
    last_run = {
        "last_fetch_alerts": {'latest_ids': ['1'], 'latest_timestamp': 1602323410000},
    }
    response = {
        "documents": [
            {"context": {"_timestamp": 1602323420000}, "_id": "2"},
            {"context": {"_timestamp": 1602323410000}, "_id": "1"},
        ]
    }
    mocker.patch.object(client, "_http_request", return_value=response)
    alerts, new_last_run = fetch_data(client, last_run, 'alerts')

    assert len(alerts) == 1
    assert "_time" in alerts[0]
    assert "source_log_type" in alerts[0]
    assert new_last_run.get("last_fetch_alerts") == {'latest_ids': ['2'], 'latest_timestamp': 1602323420000}
    assert not new_last_run.get('iteration_cache_fetch_alerts')

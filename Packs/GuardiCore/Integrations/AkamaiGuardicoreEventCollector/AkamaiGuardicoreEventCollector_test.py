import pytest
from pytest_mock import MockerFixture


def test_test_module_success(mocker: MockerFixture):
    """
    Given:
        Client with valid credentials
    When:
        test_module is called
    Then:
        It should return 'ok'
    """
    from AkamaiGuardicoreEventCollector import test_module

    client = mocker.Mock()
    client.login.return_value = None
    assert test_module(client) == "ok"


def test_test_module_failure(mocker: MockerFixture):
    """
    Given:
        Client with invalid credentials
    When:
        test_module is called
    Then:
        It should raise an exception
    """
    from AkamaiGuardicoreEventCollector import test_module

    client = mocker.Mock()
    client.login.side_effect = Exception("Something")

    with pytest.raises(Exception):
        test_module(client)


def test_test_module_failure_Unauthorized(mocker: MockerFixture):
    """
    Given:
        Client with invalid credentials
    When:
        test_module is called
    Then:
        It should return an error message
    """
    from AkamaiGuardicoreEventCollector import test_module

    client = mocker.Mock()
    client.login.side_effect = Exception("UNAUTHORIZED")

    result = test_module(client)
    assert (
        result
        == "Authorization Error: make sure the username and password are correctly set"
    )


def test_add_time_to_events(mocker: MockerFixture):
    """
    Given:
        A list of events
    When:
        Calling add_time_to_events
    Then:
        Added the _time key from the start_time field to the event
    """
    from AkamaiGuardicoreEventCollector import add_time_to_events

    events = [{"id": 1, "start_time": 100}, {"id": 2, "start_time": 100}]
    expected = [
        {"id": 1, "start_time": 100, "_time": "1970-01-01T00:01:40Z"},
        {"id": 2, "start_time": 100, "_time": "1970-01-01T00:01:40Z"},
    ]

    mocker.patch(
        "AkamaiGuardicoreEventCollector.timestamp_to_datestring",
        return_value="1970-01-01T00:01:40Z",
    )
    add_time_to_events(events)

    assert events == expected


def test_delete_id_key_from_events():
    """
    Given:
        A list of events
    When:
        Calling delete_id_key_from_events
    Then:
        The "_id" field should be removed from each event
    """
    from AkamaiGuardicoreEventCollector import delete_id_key_from_events

    events = [{"_id": "1", "id": "1"}]

    delete_id_key_from_events(events)

    assert "_id" not in events[0]


def test_handle_events_labels():
    """
    Given:
        A list of events with labels
    When:
        Calling handle_events_labels
    Then:
        The labels should be added to the source and destination assets
    """
    from AkamaiGuardicoreEventCollector import handle_events_labels

    events = [
        {
            "id": "1",
            "destination_asset": {"vm_id": "1"},
            "source_asset": {"vm_id": "2"},
            "labels": [
                {"asset_ids": ["1"], "key": "key1", "value": "value1"},
                {"asset_ids": ["2"], "key": "key2", "value": "value2"},
                {"asset_ids": ["1", "2"], "key": "key3", "value": "value3"},
            ],
        }
    ]

    handle_events_labels(events)

    assert events[0]["destination_asset"]["labels"] == {
        "key1": "value1",
        "key3": "value3",
    }
    assert events[0]["source_asset"]["labels"] == {"key2": "value2", "key3": "value3"}


def test_create_last_run():
    """
    Given:
        A list with events, some with the same start time (if the milliseconds is ignored)
    When:
        create_last_run is called
    Then:
        It should return a dict with the last event's start time and all ids that match
    """
    from AkamaiGuardicoreEventCollector import create_last_run

    events = [
        {"id": "1", "start_time": 1222222222555},
        {"id": "2", "start_time": 1222222223555},
        {"id": "3", "start_time": 1222222223755},
    ]
    result = create_last_run(events, 0, [])
    assert result == {
        "from_ts": 1222222223755,
        "last_events_ids": ["2", "3"],
    }


def test_get_events_success(mocker: MockerFixture):
    """
    Given:
        - Client instance
        - Valid args
    When:
        - Calling get_events
    Then:
        - Should return events and CommandResults
    """
    from AkamaiGuardicoreEventCollector import get_events

    client = mocker.Mock()
    mocker.patch(
        "AkamaiGuardicoreEventCollector.format_events",
        return_value=None,
    )
    mock_events = [{"id": 1}]
    client.get_events.return_value = {"objects": mock_events}

    args = {"from_date": "1 minute ago"}

    events, results = get_events(client, args)

    assert events == mock_events
    assert results.readable_output
    assert results.raw_response == mock_events


def test_fetch_events_full_fetch(mocker: MockerFixture):
    """
    Given:
        - Client
        - Last run with no IDs
        - Params with high limit
    When:
        fetch_events is called
    Then:
        It should return all events from API
    """
    from AkamaiGuardicoreEventCollector import fetch_events

    mocker.patch(
        "AkamaiGuardicoreEventCollector.format_events",
        return_value=None,
    )
    mocker.patch(
        "AkamaiGuardicoreEventCollector.create_last_run",
        return_value={},
    )

    client = mocker.Mock()
    client.get_events.return_value = {"objects": [{"id": 1}, {"id": 2}]}

    last_run = {}
    params = {"max_events_per_fetch": 1000}

    events, _ = fetch_events(client, params, last_run)

    assert len(events) == 2


def test_fetch_events_partial_fetch(mocker: MockerFixture):
    """
    Given:
        - Client
        - Last run with some IDs
        - Params with low limit
    When:
        fetch_events is called
    Then:
        It should only return new events, without duplicated IDs
    """
    from AkamaiGuardicoreEventCollector import fetch_events

    mocker.patch(
        "AkamaiGuardicoreEventCollector.format_events",
        return_value=None,
    )
    mocker.patch(
        "AkamaiGuardicoreEventCollector.create_last_run",
        return_value={},
    )
    client = mocker.Mock()
    client.get_events.return_value = {"objects": [{"id": 1}, {"id": 2}, {"id": 3}]}

    last_run = {"last_events_ids": [1]}
    params = {"max_events_per_fetch": 2}

    events, _ = fetch_events(client, params, last_run)

    assert len(events) == 2
    assert not any(event["id"] == 1 for event in events)

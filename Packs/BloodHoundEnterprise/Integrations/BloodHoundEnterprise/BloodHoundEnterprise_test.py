from unittest.mock import patch
from freezegun import freeze_time
import demistomock as demisto


def mock_client():
    """
    Create a mock client for testing.
    """
    from BloodHoundEnterprise import Client, Credentials

    return Client(
        base_url="example.com",
        verify=False,
        proxy=False,
        credentials=Credentials(token_id="token_id", token_key="token_key"),
    )


@freeze_time("2024-11-20T13:17:24.074375+02:00")
def test_fetch_events_first_time(mocker):
    """
    Given:
    - fetch events command (fetches detectPions)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
    """
    from BloodHoundEnterprise import fetch_events

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "debug")
    client = mock_client()
    mocker.patch.object(
        client,
        "search_events",
        return_value=[
            {"id": 2043, "created_at": "2024-11-20T11:18:15.516244Z", "actor_id": ""},
            {
                "id": 2044,
                "created_at": "2024-11-20T11:18:16.592573Z",
                "actor_id": "testExample",
            },
        ],
    )
    next_run, events = fetch_events(
        client=client,
        params={},
    )

    assert len(events) == 2
    assert next_run == {
        "last_event_created_at": "2024-11-20T11:18:16.592573Z",
        "last_event_id": 2044,
        "prev_fetch_id": 1,
    }
    assert events[0].get("id") == 2043


@freeze_time("2024-11-20T13:17:24.074375+02:00")
def test_fetch_events_second_time(mocker):
    """
    Given:
    - fetch events command (fetches detectPions)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
    """
    from BloodHoundEnterprise import fetch_events

    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={
            "last_event_created_at": "2024-11-20T11:18:16.592573Z",
            "last_event_id": 2043,
            "prev_fetch_id": 1,
        },
    )
    mocker.patch.object(demisto, "debug")
    client = mock_client()
    mocker.patch.object(
        client,
        "search_events",
        return_value=[
            {"id": 2043, "created_at": "2024-11-20T11:18:15.516244Z", "actor_id": ""},
            {
                "id": 2044,
                "created_at": "2024-11-20T11:18:16.592573Z",
                "actor_id": "testExample",
            },
        ],
    )
    next_run, events = fetch_events(
        client=client,
        params={},
    )

    assert len(events) == 1
    assert next_run == {
        "last_event_created_at": "2024-11-20T11:18:16.592573Z",
        "last_event_id": 2044,
        "prev_fetch_id": 2,
    }
    assert events[0].get("id") == 2044


def test_test_module_command(mocker):
    """
    Given:
    - test module command (fetches detections)

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    from BloodHoundEnterprise import test_module

    client = mock_client()
    mocker.patch.object(client, "_request")
    res = test_module(client)
    assert res == "ok"


def test_get_events_command(mocker):
    """
    Given:
    - get_events command (fetches detections)

    When:
    - running get events command

    Then:
    - events and human readable as expected
    """
    from BloodHoundEnterprise import get_events_command

    args = {
        "start": "2024-11-18T11:16:09.076711Z",
        "end": "2024-11-18T14:00:20.303699Z",
    }
    client = mock_client()
    mocker.patch.object(
        client,
        "search_events",
        return_value=[
            {
                "id": 1990,
                "created_at": "2024-11-18T11:16:09.076711Z",
            },
            {
                "id": 1991,
                "created_at": "2024-11-18T14:00:20.301456Z",
            },
            {
                "id": 1992,
                "created_at": "2024-11-18T14:00:20.303699Z",
            },
        ],
    )
    events, hr = get_events_command(
        client=client,
        args=args,
    )

    assert len(events) == 3
    assert events[0].get("id") == 1990
    assert "1992" in hr.readable_output


def test_client_request(mocker):
    query_params = {
        "limit": 50,
        "sort_by": "created_at",
        "after": "2024-11-18T11:16:09.076711Z",
        "before": "2024-11-18T14:00:20.303699Z",
    }
    client = mock_client()
    mocker.patch.object(client, "_http_request")
    log = mocker.patch.object(demisto, "debug")
    client._request(query_params=query_params)
    found = any(
        "/api/v2/audit?limit=50&sort_by=created_at&after=2024-11-18T11%3A16%3A09.076711Z&before=2024-11-18T14%3A00%3A20.303699Z,"
        in call.args[0]
        for call in log.call_args_list
    )
    assert found, "'aaa' was not found in any demisto.debug calls."

from datetime import datetime, timedelta, UTC

from freezegun import freeze_time
from CommonServerPython import *


import pytest
from IBMSecurityVerify import Client, get_events_command, fetch_events, max_limit_validation

EVENTS = [
    {"indexed_at": "2", "tenantname": "Test Event 2", "id": "123"}
]

RESPONSE = {
    "response": {
        "events": {
            "events": EVENTS
        }
    }
}


@pytest.fixture()
def mock_client(mocker) -> Client:
    mocker.patch.object(Client, "_authenticate")
    client = Client(
        base_url="https://www.example.com",
        client_id="DUMMY_CLIENT_ID",
        client_secret="DUMMY_SECRET_KEY",
        verify=False,
        proxy=False,
    )
    client._headers = {"Authorization": "Bearer DUMMY_TOKEN"}
    return client


@pytest.mark.parametrize(
    "token_data, expected_result",
    [
        (
            {
                "access_token": "valid_token",
                "expiry_time_utc": (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
            },
            True
        ),
        (
            {
                "access_token": "valid_token",
                "expiry_time_utc": datetime.now(UTC).isoformat()
            },
            False
        ),
    ]
)
def test_is_token_valid(mock_client, token_data, expected_result):
    result = mock_client._is_token_valid(token_data)
    assert result == expected_result


@freeze_time("2024-08-29 12:00:00")
def test_get_new_token(mocker, mock_client):
    expires_in = 7200
    expiry_time_utc = datetime.now(UTC) + timedelta(seconds=expires_in)
    expected_result = {"access_token": "DUMMY_TOKEN", "expiry_time_utc": expiry_time_utc.isoformat()}

    response = {"access_token": "DUMMY_TOKEN", "expires_in": expires_in}
    http_request = mocker.patch.object(Client, "_http_request", return_value=response)

    rustle = mock_client._get_new_token()

    http_request.assert_called_with(
        method="POST",
        url_suffix="/endpoint/default/token",
        data={
            "client_id": "DUMMY_CLIENT_ID",
            "client_secret": "DUMMY_SECRET_KEY",
            "grant_type": "client_credentials",
        },
    )

    assert rustle == expected_result


def test_max_limit_validation(mock_client):
    MAX_LIMIT = 50_000
    max_limit_validation(1_000)
    with pytest.raises(DemistoException):
        max_limit_validation(MAX_LIMIT + 1)
    with pytest.raises(DemistoException):
        max_limit_validation(0)


def test_search_events(mocker, mock_client):
    http_request = mocker.patch.object(Client, "_http_request", return_value=RESPONSE)

    limit = 2
    sort_order = "asc"
    last_item = {"last_id": "123", "after_time": "456"}

    _, events = mock_client.search_events(limit, sort_order, last_item)

    expected_events = [
        {"indexed_at": "2", "tenantname": "Test Event 2", "id": "123"}
    ]
    assert events == expected_events

    http_request.assert_called_with(
        method="GET",
        url_suffix="events",
        params={
            "size": limit,
            "range_type": "indexed_at",
            "all_events": "yes",
            "sort_order": sort_order,
            "after_time": last_item.get("last_time"),
            "after_id": last_item.get("last_id")
        },
    )


def test_get_events_command(mocker, mock_client):
    """

    """
    args = {"limit": 2, "sort_order": "Desc", "last_id": "123", "last_time": "456"}

    search_events = mocker.patch.object(mock_client, "search_events", return_value=({}, []))
    get_events_command(mock_client, args)

    search_events.assert_called_with(
        limit=2,
        sort_order="desc",
        last_item={"last_id": "123", "last_time": "456"}
    )


def test_fetch_events(mocker, mock_client):
    """
    """
    # First fetch
    search_events = mocker.patch.object(mock_client, "search_events", return_value=({}, EVENTS))
    last_run = {}

    # Verify the first fetch initializes last_run with the latest event
    last_run, _ = fetch_events(client=mock_client, last_run=last_run, limit=2)
    search_events.assert_any_call(limit=1, sort_order="desc")

    # Second fetch
    updated_last_run, _ = fetch_events(client=mock_client, last_run=last_run, limit=2)

    # Verify that the second fetch uses the last_run from the first fetch
    search_events.assert_any_call(limit=2, sort_order="asc", last_item=updated_last_run)

"""
Unit testing for CiscoAMP (Advanced Malware Protection)
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import io
import os
import pytest
from CiscoAMPEventCollector import Client

API_KEY = "API_Key"
CLIENT_ID = "Client_ID"
SERVER_URL = "https://api.eu.amp.cisco.com"
BASE_URL = f"{SERVER_URL}/{Client.API_VERSION}"


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    path = os.path.join("test_data", file_name)

    with open(path, encoding="utf-8") as mock_file:
        if os.path.splitext(file_name)[1] == ".json":
            return json.loads(mock_file.read())

        return mock_file


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """
    Establish a connection to the client with a URL and API key.
    Returns:
        Client: Connection to client.
    """
    return Client(server_url=SERVER_URL, api_key=API_KEY, client_id=CLIENT_ID, proxy=False, verify=False)


@pytest.mark.parametrize(
    "last_run, limit, expeted_previous_ids",
    [
        (
            {
                "last_fetch": "2022-07-18T00:00:00.000Z",
                "previous_ids": ["6159258594551267592", "6159258594551267593", "6159258594551267594"]
            },
            1,
            ["6159258594551267595"]
        ),
        (
            {},
            2,
            ["6159258594551267592", "6159258594551267593"]
        ),
        (
            {
                "last_fetch": "1 day",
                "previous_ids": ["6159258594551267592"]
            },
            1,
            ["6159258594551267592", "6159258594551267593"]
        )
    ]
)
def test_fetch_events(
    mock_client,
    mocker,
    last_run: dict[str, str | list[str]],
    limit: int,
    expeted_previous_ids: list[str],
):
    """
    Given:
        - cass 1: we have "last_fetch" and "previous ids" with several ids.
        - cass 2: last run is empty.
        - cass 3: we have "last_fetch" and "previous_ids" with one id.
    When:
        - run `fetch_events` function and we got.
        - cass 1: several event of new and old.
        - cass 2: 2 new events with the same 'last_fetch' that was not fetched already.
        - cass 3: new event with the same 'last_fetch' as one that was fetched already.
    Then:
        - cass 1: Ensure in case previous_ids is provided it does not fetch
          the events with ids already fetched.
        - cass 2: Ensure that when there are two events with the same time
          the previous_ids returned contains both ids.
        - cass 3: Ensure that when the last event retrieved has the same time
          as the event with the id provided in previous_ids
          then it returns both ids.
    """
    mock_response_1 = load_mock_response("incidents_response_1.json")
    mock_response_2 = load_mock_response("incidents_response_2.json")
    mock_response_3 = load_mock_response("incidents_response_3.json")

    mocker.patch.object(Client, "get_events", side_effect=[mock_response_1, mock_response_2, mock_response_3])
    mocker.patch("CiscoAMPEventCollector.date_to_timestamp", return_value=1699360451000)

    from CiscoAMPEventCollector import fetch_events

    next_run, incidents = fetch_events(client=mock_client, last_run=last_run,
                                       params={'first_fetch_time': "2023-11-01T23:17:39.000Z", 'max_events_per_fetch': limit})

    # Validate response
    for previous_id in expeted_previous_ids:
        assert previous_id in next_run["previous_ids"]
    assert len(incidents) == limit


def test_fetch_events_with_no_new_incidents(
    mock_client,
    mocker,
):
    """
    Given:
        - args with last_run that has previous_ids
          (Simulates a given situation where there are no new incidents).
    When:
        - run `fetch_events` function.
    Then:
        - Ensure the no incidents returned.
        - Ensure the `previous_ids` does not change and stays with the provided id.
    """
    mock_response = load_mock_response("incidents_response_3.json")

    mocker.patch.object(Client, "get_events", return_value=mock_response)

    from CiscoAMPEventCollector import fetch_events

    next_run, incidents = fetch_events(client=mock_client,
                                       last_run={
                                           "last_fatch": "2023-11-15T00:00:00.000Z",
                                           "previous_ids": ["6159258594551267595"]
                                       },
                                       params={
                                           'max_events_per_fetch': 100
                                       })

    # Validate response
    assert "6159258594551267595" in next_run["previous_ids"]
    assert len(incidents) == 0


def test_test_module(mock_client, mocker):
    """
    Given:
        - params and a successful response.
    When:
        - run `test-module` function.
    Then:
        - Ensure it pass successfully.
    """
    mock_response = load_mock_response("incidents_response_3.json")
    mocker.patch.object(Client, 'get_events', return_value=mock_response)
    mocker.patch.object(demisto, 'params', return_value={'credentials': {'identifier': 1234, 'password': 1234},
                                                         'url': 'https://some_url.com'})
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    from CiscoAMPEventCollector import main

    main()

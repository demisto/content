import json
import io
import pytest
import demistomock as demisto
from WithSecureEventCollector import Client, get_events_command, fetch_events_command


def mock_client():
    return Client(base_url="https://test.com", verify=False, proxy=False, client_id="client_id", client_secret="client_secret")


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


TOKEN_TEST = [
    ({"access_token": "integration_context_token", "valid_until": 1000}, "integration_context_token"),
    ({}, "new_access_token"),
    ({"access_token": "integration_context_token", "valid_until": -1}, "new_access_token"),
]


@pytest.mark.parametrize("integration_context, expected_token", TOKEN_TEST)
def test_get_access_token(mocker, requests_mock, integration_context, expected_token):
    client = mock_client()
    import WithSecureEventCollector

    mocker.patch.object(WithSecureEventCollector, "get_integration_context", return_value=integration_context)
    mocker.patch.object(WithSecureEventCollector, "time", return_value=0)
    requests_mock.post("https://test.com/as/token.oauth2", json={"access_token": "new_access_token", "expires_in": 1})
    result = client.get_access_token()
    assert result == expected_token


def test_get_events_command(requests_mock, mocker):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.
    """
    client = mock_client()
    mock_response = util_load_json("test_data/get_events.json")
    args = {"fetch_from": "2022-12-26T00:00:00Z", "limit": 2}
    mocker.patch.object(Client, "get_access_token", return_value={"access_token": "access_token"})
    requests_mock.get(
        "https://test.com/security-events/v1/security-events?limit=2&serverTimestampStart=2022-12-26T00:00:00Z",
        json=mock_response,
    )
    events, response = get_events_command(client, args)

    assert len(events) == 2
    assert events == mock_response.get("items")


def test_fetch_events_command(requests_mock, mocker):
    """Tests fetch-events command function.
    Given: and already fetched event id, and a latested fetched event timestamp
    When: running fetch-event command
    Check: the already fetched event does not get fetched again
    """

    client = mock_client()
    mock_response = util_load_json("test_data/fetch_events.json")
    mocker.patch.object(Client, "get_access_token", return_value={"access_token": "access_token"})
    mocker.patch.object(demisto, "getLastRun", return_value={"fetch_from": "2023-03-15T14:39:13Z", "event_id": "test_id"})
    requests_mock.get(
        "https://test.com/security-events/v1/security-events?serverTimestampStart=2023-03-15T14:39:13Z&limit=100",
        json=mock_response,
    )
    events, _ = fetch_events_command(client, first_fetch="1 day", limit=100)
    for ev in mock_response.get("items"):
        ev["_time"] = ev.get("clientTimestamp")
    expected = [mock_response.get("items")[0]]
    assert len(events) == 1
    assert events == expected

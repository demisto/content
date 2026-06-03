from datetime import timedelta

from CommonServerPython import *
from ProofpointThreatResponseEventCollector import (
    MAX_API_REQUESTS,
    TIME_FORMAT,
    Client,
    fetch_events_command,
    get_incidents_batch_by_time_request,
    list_incidents_command,
)


def test_fetch_events_command(requests_mock):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command

    Then:
    - Ensure last-fetch id is 2
    """
    base_url = "https://server_url/"
    with open("./test_data/raw_response.json") as f:
        incidents = json.loads(f.read())
    with open("./test_data/expected_result.json") as f:
        expected_result = json.loads(f.read())
    requests_mock.get(f"{base_url}api/incidents", json=incidents)
    client = Client(base_url=base_url, verify=True, headers={}, proxy=False)
    first_fetch, _ = parse_date_range("2 hours", date_format=TIME_FORMAT)
    events, last_fetch = fetch_events_command(
        client=client, first_fetch=first_fetch, last_run={}, fetch_limit="100", fetch_delta="6 hours", incidents_states=["open"]
    )
    assert events == expected_result


def test_list_incidents_command(requests_mock):
    """
    Given:
    - list_incidents_command

    When:
    - Want to list all existing incidents

    Then:
    - Ensure List Incidents Results in human-readable.
    """
    base_url = "https://server_url/"
    with open("./test_data/raw_response.json") as f:
        incidents = json.loads(f.read())
    requests_mock.get(f"{base_url}api/incidents", json=incidents)
    client = Client(base_url=base_url, verify=True, headers={}, proxy=False)
    args = {"limit": 2}
    incidents, human_readable, raw_response = list_incidents_command(client, args)
    assert "List Incidents Results:" in human_readable


def test_get_incidents_batch_by_time_request_max_api_requests(mocker, requests_mock):
    """
    Given:
    - A created_after timestamp far enough in the past that the batch loop cannot reach current_time
      within MAX_API_REQUESTS iterations (using a 1-minute fetch_delta).

    When:
    - get_incidents_batch_by_time_request is called and the loop exceeds MAX_API_REQUESTS.

    Then:
    - The [BATCH_API_LIMIT] debug log is written.
    - The returned final_created_after equals the initial created_after advanced by
      MAX_API_REQUESTS time windows (1 minute each), i.e. 50 minutes ahead.
    - The returned incidents list is empty (API returns no incidents).
    """
    base_url = "https://server_url/"
    requests_mock.get(f"{base_url}api/incidents", json=[])
    client = Client(base_url=base_url, verify=True, headers={}, proxy=False)

    fetch_delta = "1 minute"
    # Set created_after far enough in the past so the loop won't reach current_time in 50 iterations
    # (50 iterations * 1 minute = 50 minutes, so we need created_after to be more than 50 minutes ago)
    created_after = (datetime.now() - timedelta(hours=2)).strftime(TIME_FORMAT)

    params = {
        "created_after": created_after,
        "last_fetched_id": "0",
        "fetch_delta": fetch_delta,
        "state": "open",
        "fetch_limit": "100",
    }

    debug_mock = mocker.patch("ProofpointThreatResponseEventCollector.demisto.debug")

    incidents_list, final_created_after = get_incidents_batch_by_time_request(client, params)

    # Verify the [BATCH_API_LIMIT] debug log was written
    debug_calls = [call.args[0] for call in debug_mock.call_args_list]
    batch_api_limit_logs = [msg for msg in debug_calls if "[BATCH_API_LIMIT]" in msg]
    assert len(batch_api_limit_logs) == 1, f"Expected exactly one [BATCH_API_LIMIT] debug log, found {len(batch_api_limit_logs)}"

    # Verify the final_created_after is correct:
    # The loop runs MAX_API_REQUESTS (50) iterations, each advancing created_after by 1 minute.
    # So final_created_after = initial created_after + 50 minutes.
    expected_final = (datetime.strptime(created_after, TIME_FORMAT) + timedelta(minutes=MAX_API_REQUESTS)).strftime(TIME_FORMAT)
    assert final_created_after == expected_final, f"Expected final_created_after={expected_final}, got {final_created_after}"

    # Verify no incidents were returned
    assert incidents_list == []

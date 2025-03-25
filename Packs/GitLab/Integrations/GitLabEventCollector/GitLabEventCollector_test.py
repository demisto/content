import pytest

from GitLabEventCollector import Client, prepare_query_params
from requests import Session


class MockResponse:
    def __init__(self, data: list):
        self.ok = True
        self.status_code = 200
        self.data = data
        self.links = None

    def json(self):
        return self.data

    def raise_for_status(self):
        pass


""" Test methods """


@pytest.mark.parametrize(
    "params, last_run, expected_params_url",
    [
        ({"after": "02/02/2022T15:00:00Z"}, {}, "pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100"),
        (
            {"after": "02/02/2022T15:01:00Z"},
            {"next_url": "pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100&cursor=examplecursor"},
            "pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100&cursor=examplecursor",
        ),
    ],
)
def test_gitlab_events_params_good(params, last_run, expected_params_url):
    """
    Given:
        - Various params and LastRun dictionary values.
    When:
        - preparing the parameters.
    Then:
        - Make sure they are parsed correctly into the URL suffix.
    """
    assert expected_params_url == prepare_query_params(params, last_run)


def test_fetch_events(mocker):
    """
    Given:
        - fetch-events call, where last_id = 1
    When:
        - Three following results are retrieved from the API:
            1. id = 1, created_at = '2023-10-28T20:29:34.872Z'
            2. id = 2, created_at = '2023-10-28T20:29:34.872Z'
            3. id = 3, created_at = '2023-10-28T20:29:34.872Z'
    Then:
        - Make sure only events 2 and 3 are returned (1 should not).
        - Verify the new lastRun is calculated correctly.
    """
    from GitLabEventCollector import fetch_events_command, main, demisto

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value={"url": ""})
    mocker.patch.object(demisto, "getLastRun", return_value={"audit_events": {"last_id": "1"}})

    last_run = {"audit_events": {"last_id": "1"}}

    mock_response = MockResponse(
        [
            {"id": "3", "created_at": "2023-10-28T20:29:34.872Z"},
            {"id": "2", "created_at": "2023-10-28T20:29:34.872Z"},
            {"id": "1", "created_at": "2023-10-28T20:29:34.872Z"},
        ]
    )
    mocker.patch.object(Session, "request", return_value=mock_response)
    events, _, new_last_run = fetch_events_command(Client(base_url=""), params={}, last_run=last_run, events_types_ids={})

    assert len(events) == 2
    assert events[0].get("id") != "1"
    assert new_last_run["audit_events"]["last_id"] == "3"

    # Tests main()
    mock_setLastRun = mocker.patch.object(demisto, "setLastRun")
    mock_events_result = mocker.patch("GitLabEventCollector.send_events_to_xsiam")
    main()

    assert len(mock_events_result.call_args[0][0]) == 2
    assert mock_events_result.call_args[0][0][0].get("id") != "1"
    assert mock_setLastRun.call_args[0][0]["audit_events"]["last_id"] == "3"


def test_fetch_events_with_two_iterations(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 300.
        - A single logs API call retrieves 200 events.
        - first_id is saved in lastRun.
    Then:
        - Make sure the logs API is called twice.
        - Make sure the first event has the same id as the first_id in the lastRun.
    """
    from GitLabEventCollector import fetch_events_command

    first_id = 2
    last_run = {"groups": {}, "projects": {}, "audit_events": {"first_id": first_id}}

    mock_response = MockResponse([{"id": i, "created_at": 1521214343} for i in range(200)])
    mock_response.links = {"next": {"url": "https://example.com?param=value"}}
    mock_request = mocker.patch.object(Session, "request", return_value=mock_response)
    events, _, _ = fetch_events_command(Client(base_url=""), params={"limit": 300}, last_run=last_run, events_types_ids={})

    assert events[0].get("id") == first_id
    assert mock_request.call_count == 2


def test_fetch_events_with_groups_and_projects(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 300.
        - A single logs API call retrieves 200 events.
    Then:
        - Make sure the logs API is called twice.
    """
    from GitLabEventCollector import fetch_events_command

    last_run = {"groups": {}, "projects": {"last_id": "2"}, "audit_events": {"last_id": "1"}}

    mock_response = MockResponse(
        [
            {"id": "5", "created_at": 1521214345},
            {"id": "4", "created_at": 1521214343},
            {"id": "3", "created_at": 1521214345},
            {"id": "2", "created_at": 1521214343},
            {"id": "1", "created_at": 1521214343},
        ]
    )

    mocker.patch.object(Session, "request", return_value=mock_response)
    audit_events, group_and_project_events, new_last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 4, "url": ""},
        last_run=last_run,
        events_types_ids={"groups_ids": [1], "projects_ids": [2, 3, 4]},
    )

    assert len(audit_events) == 4
    assert len(group_and_project_events) == 7
    assert new_last_run["audit_events"]["last_id"] == "5"
    assert new_last_run["projects"]["last_id"] == "5"
    assert new_last_run["groups"]["last_id"] == "5"
    assert new_last_run["groups"]["first_id"] == "1"
    assert "first_id" not in new_last_run["projects"]


def test_get_events(mocker):
    """
    Given:
        - gitlab-get-events call
    When:
        - Three following results are retrieved from the API:
            1. id = 1, created_at = 1521214343
            2. id = 2, created_at = 1521214343
            3. id = 3, created_at = 1521214345
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from GitLabEventCollector import get_events_command, main, demisto

    mocker.patch.object(demisto, "command", return_value="gitlab-get-events")
    mocker.patch.object(demisto, "params", return_value={"url": ""})

    mock_response = MockResponse(
        [
            {"id": "3", "created_at": 1521214345},
            {"id": "2", "created_at": 1521214343},
            {"id": "1", "created_at": 1521214343},
        ]
    )
    mocker.patch.object(Session, "request", return_value=mock_response)
    _, results = get_events_command(Client(base_url=""), args={})

    assert len(results.raw_response) == 3
    assert results.raw_response == mock_response.json()

    # Tests main()
    mock_results = mocker.patch.object(demisto, "results")
    main()
    assert mock_results.call_args[0][0]["Contents"] == mock_response.json()


def test_test_module(mocker):
    """
    Given:
        - test-module call.
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from GitLabEventCollector import test_module_command, main, demisto

    params = {"url": ""}
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value=params)

    mocker.patch.object(Session, "request", return_value=MockResponse([]))
    assert test_module_command(Client(base_url=""), {"url": ""}, {"groups_ids": [1, 2], "projects_ids": [3, 4, 5]}) == "ok"

    # Tests main()
    mock_results = mocker.patch.object(demisto, "results")
    main()
    assert mock_results.call_args[0][0] == "ok"

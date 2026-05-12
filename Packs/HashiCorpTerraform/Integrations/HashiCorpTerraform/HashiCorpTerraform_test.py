import re

import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestsMocker
from aiohttp import ClientResponseError, RequestInfo
from unittest.mock import AsyncMock
from freezegun import freeze_time
from CommonServerPython import *
from HashiCorpTerraform import (
    Client,
    AsyncClient,
    plan_get_command,
    policies_checks_list_command,
    policies_list_command,
    policy_set_list_command,
    run_action_command,
    runs_list_command,
    DEFAULT_AUDIT_TRAIL_PAGE_SIZE,
)

SERVER_URL = "https://test_url.com"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(url=SERVER_URL, token=None, default_organization_name=None, default_workspace_id=None, verify=None, proxy=None)


@pytest.fixture()
def async_client():
    return AsyncClient(base_url=SERVER_URL, token="test_token", verify=False, proxy=False)


def mock_async_session_response(
    response_json: dict | None = None,
    error_status_code: int | None = None,
    error_message: str = "Server error",
) -> AsyncMock | ClientResponseError:
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(return_value=response_json)
    if error_status_code:
        return ClientResponseError(
            status=error_status_code,
            history=(),
            request_info=RequestInfo("", "GET", {}),
            message=error_message,
        )
    else:
        mock_response.raise_for_status = AsyncMock()
        mock_response.status_code = 200
    return AsyncMock(__aenter__=AsyncMock(return_value=mock_response))


def test_runs_list_command(client: Client, requests_mock: RequestsMocker):
    """
    Given:
        - Client object.
    When:
        - run the list runs command.
    Then:
        - validate the results are as expected.
    """
    mock_response = util_load_json("./test_data/runs_list_request.json")["mock_response"]
    requests_mock.get(re.compile(f"{SERVER_URL}.*"), json=mock_response)
    expected_results = util_load_json("./test_data/runs_list_request.json")["expected_results"]

    results = runs_list_command(client=client, args={"workspace_id": "workspace_id"})

    assert results.to_context() == expected_results


def test_run_action_command(client: Client, requests_mock: RequestsMocker):
    """
    Given:
        - Client object.
    When:
        - error occurred when run the run action command.
    Then:
        - validate the exception raised as expected.
    """
    mock_response = util_load_json("./test_data/run_action_request.json")["mock_response"]
    requests_mock.post(re.compile(f"{SERVER_URL}.*"), json=mock_response, status_code=409)

    run_id = "run-ABCABCABCABCABCa"
    with pytest.raises(DemistoException) as err:
        run_action_command(client=client, args={"run_id": run_id, "action": "apply", "comment": "comment"})
    assert f"Error occurred when queued an apply request for run id {run_id}" in str(err)


def test_plan_get_command(client: Client, requests_mock: RequestsMocker):
    """
    Given:
        - Client object.
    When:
        - run the get plan command to get the plan meta data.
    Then:
        - validate the results are as expected.
    """
    args = {"plan_id": "plan-Abcabcabcabcabc4"}

    mock_response = util_load_json("./test_data/plan_get_request.json")["mock_response"]
    expected_results = util_load_json("./test_data/plan_get_request.json")["expected_results"]

    requests_mock.get(re.compile(f"{SERVER_URL}.*"), json=mock_response)
    results = plan_get_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policies_list_command(client: Client, requests_mock, mocker: MockerFixture):
    """
    Given:
        - Client object.
    When:
        - run the get policies list command.
    Then:
        - validate the results are as expected.
    """
    organization_name = "organization_name"
    args = {"organization_name": organization_name}

    mock_response = util_load_json("./test_data/policies_list_request.json")["mock_response"]
    expected_results = util_load_json("./test_data/policies_list_request.json")["expected_results"]

    requests_mock.get(f"{SERVER_URL}/organizations/{organization_name}/policies", json=mock_response)
    mocker.patch.object(demisto, "dt", side_effect=lambda _, key: key)

    results = policies_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policy_set_list_command(client: Client, requests_mock, mocker: MockerFixture):
    """
    Given:
        - Client object.
    When:
        - run the get policy set list command.
    Then:
        - validate the results are as expected.
    """

    organization_name = "organization_name"
    args = {"organization_name": organization_name}

    mock_response = util_load_json("./test_data/policy_set_list_request.json")["mock_response"]
    expected_results = util_load_json("./test_data/policy_set_list_request.json")["expected_results"]

    requests_mock.get(f"{SERVER_URL}/organizations/{organization_name}/policy-sets", json=mock_response)
    mocker.patch.object(demisto, "dt", side_effect=lambda _, key: key)
    results = policy_set_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policies_checks_list_command(client: Client, requests_mock: RequestsMocker):
    """
    Given:
        - Client object.
    When:
        - run the get policies checks list command.
    Then:
        - validate the results are as expected.
    """
    run_id = "run-abcabcabcabcabc1"
    args = {"run_id": run_id}

    mock_response = util_load_json("./test_data/policies_check_list_request.json")["mock_response"]
    expected_results = util_load_json("./test_data/policies_check_list_request.json")["expected_results"]

    requests_mock.get(f"{SERVER_URL}/runs/{run_id}/policy-checks", json=mock_response)
    results = policies_checks_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_test_module_command(client: Client, mocker: MockerFixture):
    """
    Given:
        - Client object with error occurred in test_connection.
    When:
        - run the test module command.
    Then:
        - validate the expected exception.
    """
    import HashiCorpTerraform

    mocker.patch.object(client, "test_connection", side_effect=Exception("Unauthorized"))

    with pytest.raises(DemistoException) as err:
        HashiCorpTerraform.test_module(client)

    assert "Unauthorized: Please be sure you put a valid API Token" in str(err)


@pytest.mark.asyncio
async def test_client_get_audit_trails(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling client.get_audit_trails with a given from_date and page_number.
    Then:
     - Ensure the correct HTTP GET request is made and the correct JSON response is returned.
    """
    from_date = "2025-01-01T00:00:00Z"
    page_number = 1

    mock_response_json = {"data": [{"id": "event-1", "timestamp": "2025-01-01T00:00:00Z"}], "pagination": {"total_pages": 1}}

    mock_responses = [
        mock_async_session_response(error_status_code=429),  # mock rate limit error
        mock_async_session_response(mock_response_json),  # mock successful response
    ]

    async with async_client as _client:
        mocker.patch.object(_client._session, "get", side_effect=mock_responses)
        response_json = await _client.get_audit_trails(from_date=from_date, page_number=page_number)

    assert response_json == mock_response_json
    assert _client._session.get.call_args.kwargs == {
        "url": f"{SERVER_URL}/organization/audit-trail",
        "params": {"since": from_date, "page[number]": str(page_number), "page[size]": str(DEFAULT_AUDIT_TRAIL_PAGE_SIZE)},
        "proxy": None,
    }
    assert _client._session.get.call_count == 2  # First time failed, retry again


@pytest.mark.asyncio
async def test_get_audit_trail_events_pagination_success(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit that requires fetching two pages of events.
    When:
     - Calling get_audit_trail_events.
    Then:
     - Ensure that three API calls are made and the events are aggregated (one for pagination, two others for events).
    """
    from HashiCorpTerraform import get_audit_trail_events

    page_size = DEFAULT_AUDIT_TRAIL_PAGE_SIZE
    mock_response_jsons = [
        {  # Page 1 (Newest events)
            "data": [{"id": f"event-A{i}", "timestamp": "2025-01-01T00:02:00.000Z"} for i in range(page_size)],
            "pagination": {"current_page": 1, "total_pages": 3},
        },
        {  # Page 2
            "data": [{"id": f"event-B{i}", "timestamp": "2025-01-01T00:01:00.000Z"} for i in range(page_size)],
            "pagination": {"current_page": 2, "total_pages": 3},
        },
        {  # Page 3 (Oldest events)
            "data": [{"id": f"event-C{i}", "timestamp": "2025-01-01T00:00:00.000Z"} for i in range(page_size)],
            "pagination": {"current_page": 3, "total_pages": 3},
        },
    ]

    mock_responses = [
        mock_async_session_response(mock_response_jsons[0]),  # First call to find total pages
        mock_async_session_response(mock_response_jsons[2]),  # Second call to last page (oldest events)
        mock_async_session_response(mock_response_jsons[1]),  # Third call to second to last page (newer events than last page)
    ]

    limit = DEFAULT_AUDIT_TRAIL_PAGE_SIZE + 5
    async with async_client as _client:
        mocker.patch.object(_client._session, "get", side_effect=mock_responses)
        events = await get_audit_trail_events(async_client, from_date="2025-01-01T00:00:00Z", limit=limit)

    assert len(events) == limit
    assert events[0]["timestamp"] < events[-1]["timestamp"]
    assert events[-1]["_time"] == "2025-01-01T00:01:00Z"
    assert _client._session.get.call_count == 3


@pytest.mark.asyncio
async def test_get_audit_trail_events_pagination_error(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit that requires fetching two pages of events.
    When:
     - Calling get_audit_trail_events.
    Then:
     - Ensure that the correct error message appears if one of the pagination requests fails.
    """
    from HashiCorpTerraform import get_audit_trail_events

    page_size = DEFAULT_AUDIT_TRAIL_PAGE_SIZE
    mock_response_jsons = [
        {  # Page 1 (Newest events)
            "data": [{"id": f"event-A{i}", "timestamp": "2025-01-01T00:02:00.000Z"} for i in range(page_size)],
            "pagination": {"current_page": 1, "total_pages": 3},
        },
        {  # Page 3 (Oldest events)
            "data": [{"id": f"event-C{i}", "timestamp": "2025-01-01T00:00:00.000Z"} for i in range(page_size)],
            "pagination": {"current_page": 3, "total_pages": 3},
        },
    ]

    mock_responses = [
        mock_async_session_response(mock_response_jsons[0]),  # First call successful
        mock_async_session_response(error_status_code=500, error_message="Server error"),  # Second call fails
        mock_async_session_response(mock_response_jsons[1]),  # Third call successful
    ]

    mock_demisto_error = mocker.patch.object(demisto, "error")

    limit = DEFAULT_AUDIT_TRAIL_PAGE_SIZE + 5
    async with async_client as _client:
        mocker.patch.object(_client._session, "get", side_effect=mock_responses)
        with pytest.raises(Exception):
            await get_audit_trail_events(async_client, from_date="2025-01-01T00:00:00Z", limit=limit)

    assert mock_demisto_error.call_count == 1
    assert mock_demisto_error.call_args[0][0] == "Request failed with status 500: Server error"


@freeze_time("2025-01-02T00:00:00Z")
@pytest.mark.asyncio
async def test_get_events_command(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient and command arguments.
    When:
     - Calling get_events_command.
    Then:
     - Ensure get_audit_trail_events is called with the correct arguments and returns the correct events.
     - Ensure tableToMarkdown is called with the correct arguments.
    """
    from HashiCorpTerraform import get_events_command

    mock_events = [{"id": "event-1", "timestamp": "2025-01-01T00:00:00Z", "_time": "2025-01-01T00:00:00Z"}]

    mock_get_audit_events = mocker.patch("HashiCorpTerraform.get_audit_trail_events", return_value=mock_events)
    mock_table_to_markdown = mocker.patch("HashiCorpTerraform.tableToMarkdown")

    args = {"limit": "10", "from_date": "1 day ago"}
    events, _ = await get_events_command(async_client, args)

    assert events == mock_events
    assert mock_get_audit_events.call_args[0][1] == "2025-01-01T00:00:00Z"  # One day before frozen time
    assert mock_get_audit_events.call_args[0][2] == 10

    assert mock_table_to_markdown.call_args.kwargs == {"name": "Terraform Audit Trail Events", "t": mock_events}


@pytest.mark.parametrize(
    "raw_response, all_fetched_ids, expected_events_count, expected_all_ids_count",
    [
        pytest.param(
            {
                "data": [
                    {"id": "event-1", "timestamp": "2025-01-01T00:00:00Z"},
                    {"id": "event-2", "timestamp": "2025-01-01T01:00:00Z"},
                ]
            },
            set(),
            2,
            2,
            id="No duplicates",
        ),
        pytest.param(
            {
                "data": [
                    {"id": "event-1", "timestamp": "2025-01-01T00:00:00Z"},
                    {"id": "event-2", "timestamp": "2025-01-01T01:00:00Z"},
                ]
            },
            {"event-1"},
            1,
            2,
            id="With duplicates",
        ),
        pytest.param(
            {"data": []},
            {"event-1"},
            0,
            1,
            id="Empty raw response",
        ),
        pytest.param(
            {"data": [{"id": "event-1", "timestamp": "2025-01-01T00:00:00Z"}]},
            {"event-1"},
            0,
            1,
            id="All duplicates",
        ),
    ],
)
@freeze_time("2025-01-02T00:00:00Z")
def test_deduplicate_and_format_events(
    raw_response: dict[str, Any],
    all_fetched_ids: set[str],
    expected_events_count: int,
    expected_all_ids_count: int,
):
    """
    Given:
     - A raw API response and a set of already fetched event IDs.
    When:
     - Calling deduplicate_and_format_events.
    Then:
     - Ensure that events are correctly deduplicated and formatted.
     - Ensure that the set of fetched IDs is correctly updated.
    """
    from HashiCorpTerraform import deduplicate_and_format_events, DATE_FORMAT

    new_events = deduplicate_and_format_events(raw_response, all_fetched_ids)

    assert len(new_events) == expected_events_count
    assert len(all_fetched_ids) == expected_all_ids_count

    for event in new_events:
        assert event["_time"] == arg_to_datetime(event["timestamp"]).strftime(DATE_FORMAT)


@pytest.mark.parametrize(
    "last_run, max_fetch, mock_events, expected_next_run",
    [
        pytest.param(
            {},
            10,
            [
                {"id": "event-1", "timestamp": "2025-01-01T00:00:00Z"},
                {"id": "event-2", "timestamp": "2025-01-01T01:00:00Z"},
            ],
            {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
            id="Initial run",
        ),
        pytest.param(
            {"from_date": "2025-01-01T00:00:00Z", "last_fetched_ids": ["event-1"]},
            5,
            [
                {"id": "event-2", "timestamp": "2025-01-01T01:00:00Z"},
                {"id": "event-3", "timestamp": "2025-01-01T01:00:00Z"},
            ],
            {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2", "event-3"]},
            id="Subsequent run",
        ),
        pytest.param(
            {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
            10,
            [],
            {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
            id="No new events",
        ),
    ],
)
@pytest.mark.asyncio
async def test_fetch_events_command(
    async_client: AsyncClient,
    mocker: MockerFixture,
    last_run: dict,
    max_fetch: int,
    mock_events: list,
    expected_next_run: dict,
):
    """
    Given:
     - An AsyncClient, last_run, and max_fetch parameters.
    When:
     - Calling fetch_events_command.
    Then:
     - Ensure that get_audit_trail_events is called with the correct arguments.
     - Ensure that the next_run object and events are returned correctly.
    """
    from HashiCorpTerraform import fetch_events_command, DEFAULT_AUDIT_TRAIL_FROM_DATE, DATE_FORMAT

    get_audit_trail_events_mock = mocker.patch("HashiCorpTerraform.get_audit_trail_events", return_value=mock_events)

    next_run, events = await fetch_events_command(async_client, last_run, max_fetch)

    assert get_audit_trail_events_mock.call_args.kwargs == {
        "client": async_client,
        "from_date": last_run.get("from_date") or DEFAULT_AUDIT_TRAIL_FROM_DATE.strftime(DATE_FORMAT),
        "limit": max_fetch,
        "last_fetched_ids": last_run.get("last_fetched_ids", []),
    }

    assert next_run == expected_next_run
    assert events == mock_events

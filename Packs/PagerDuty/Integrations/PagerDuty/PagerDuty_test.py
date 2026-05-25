import pytest
from CommonServerPython import *
from pytest_mock import MockerFixture
from requests_mock import MockerCore


def load_mock_response(file_name: str) -> dict:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f"test_data/{file_name}") as f:
        return json.loads(f.read())


def test_get_incidents(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - An incident with non-ascii character in its documentation

    When:
        - Running get incidents command

    Then:
        - Ensure command run without failing on UnicodeError
        - Verify the non-ascii character appears in the human readable output as expected
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "DefaultRequestor",
        },
    )
    from PagerDuty import get_incidents_command

    requests_mock.get(
        "https://api.pagerduty.com/incidents?include%5B%5D=assignees&statuses%5B%5D=triggered&statuses%5B%5D"
        "=acknowledged&include%5B%5D=first_trigger_log_entries&include%5B%5D=assignments&time_zone=UTC",
        json={"incidents": [{"first_trigger_log_entry": {"channel": {"details": {"Documentation": "•"}}}}]},
    )
    res = get_incidents_command({})
    assert "| Documentation: • |" in res["HumanReadable"]


def test_add_responders(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request.

    When:
        - Running PagerDuty-add-responders command.

    Then:
        - Ensure command returns the correct output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "incident_id": "PXP12GZ",
            "message": "Please help with issue - join bridge at +1(234)-567-8910",
            "user_requests": "P09TT3C,PAIXXX",
        },
    )
    requests_mock.post(
        "https://api.pagerduty.com/incidents/PXP12GZ/responder_requests",
        json=load_mock_response("responder_requests.json")["specific_users"],
    )

    from PagerDuty import add_responders_to_incident

    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ",".join([x["ID"] for x in res.outputs])
    assert demisto.args()["incident_id"] == res.outputs[0]["IncidentID"]
    assert demisto.args()["message"] == res.outputs[0]["Message"]
    assert demisto.params()["DefaultRequestor"] == res.outputs[1]["RequesterID"]
    assert demisto.args()["user_requests"] == expected_users_requested


def test_add_responders_default(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running add_responders_to_incident function.

    Then:
        - Ensure the function returns the correct output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_id": "PXP12GZ", "message": "Please help with issue - join bridge at +1(234)-567-8910"},
    )
    requests_mock.post(
        "https://api.pagerduty.com/incidents/PXP12GZ/responder_requests",
        json=load_mock_response("responder_requests.json")["default_user"],
    )

    from PagerDuty import add_responders_to_incident

    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ",".join([x["ID"] for x in res.outputs])
    assert demisto.args()["incident_id"] == res.outputs[0]["IncidentID"]
    assert demisto.args()["message"] == res.outputs[0]["Message"]
    assert demisto.params()["DefaultRequestor"] == res.outputs[0]["RequesterID"]
    assert demisto.params()["DefaultRequestor"] == expected_users_requested


def test_play_response_play(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running PagerDuty-run-response-play function.

    Then:
        - Ensure the function returns a valid status.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "incident_id": "PXP12GZ",
            "from_email": "john.doe@example.com",
            "response_play_uuid": "response_play_id",
        },
    )
    requests_mock.post("https://api.pagerduty.com/response_plays/response_play_id/run", json={"status": "ok"})

    from PagerDuty import run_response_play

    res = run_response_play(**demisto.args())

    assert res.raw_response == {"status": "ok"}


def test_get_users_on_call(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a request to get user on-call by schedule ID.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "scheduleID": "PI7DH85",
        },
    )
    requests_mock.get("https://api.pagerduty.com/schedules/PI7DH85/users", json=load_mock_response("schedules.json"))
    from PagerDuty import get_on_call_users_command

    res = get_on_call_users_command(**demisto.args())
    assert demisto.args()["scheduleID"] == res.outputs[0]["ScheduleID"]


def test_get_users_on_call_now(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a reqest to get user oncall by schedule ID without specifying responders.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "schedule_ids": "PI7DH85,PA7DH85",
        },
    )
    requests_mock.get("https://api.pagerduty.com/oncalls", json=load_mock_response("oncalls.json"))
    from PagerDuty import get_on_call_now_users_command

    res = get_on_call_now_users_command(**demisto.args())
    assert res.outputs[0]["ScheduleID"] in demisto.args()["schedule_ids"]
    assert "oncalls" in res.raw_response


def test_submit_event(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - a reqest to submit request.

    When:
        - Running submit_event function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    source = "test"
    summary = "test"
    severity = "test"
    action = "test"

    requests_mock.post(
        "https://events.pagerduty.com/v2/enqueue", json={"status": "status", "message": "message", "dedup_key": "dedup_key"}
    )
    from PagerDuty import submit_event_command

    res = submit_event_command(source, summary, severity, action)
    assert "### Trigger Event" in res["HumanReadable"]


def test_get_all_schedules_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a reqest to get all schedule

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )

    requests_mock.get(
        "https://api.pagerduty.com/schedules",
        json={
            "schedules": [
                {
                    "id": "id",
                    "name": "name",
                    "time_zone": "time_zone",
                    "escalation_policies": [{"id": "id", "summary": "summary"}],
                }
            ]
        },
    )
    from PagerDuty import get_all_schedules_command

    res = get_all_schedules_command()
    assert "### All Schedules" in res["HumanReadable"]


def test_get_users_contact_methods_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a reqest to get all schedule.

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )

    user_id = "id"

    requests_mock.get(
        f"https://api.pagerduty.com/users/{user_id}/contact_methods",
        json={"contact_methods": [{"id": "id", "address": "address", "country_code": "country_code"}]},
    )
    from PagerDuty import get_users_contact_methods_command

    res = get_users_contact_methods_command(user_id)
    assert "### Contact Methods" in res["HumanReadable"]


def test_get_users_notification_command(mocker: MockerFixture, requests_mock: MockerCore) -> None:
    """
    Given:
        - a request to get users notifications.

    When:
        - Running get_users_notification_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )

    user_id = "id"

    requests_mock.get(
        f"https://api.pagerduty.com/users/{user_id}/notification_rules",
        json={"notification_rules": [{"id": "id", "urgency": "urgency", "type": "type"}]},
    )
    from PagerDuty import get_users_notification_command

    res = get_users_notification_command(user_id)
    assert "### User notification rules" in res["HumanReadable"]


@pytest.mark.parametrize("severity, expected_result", [("high", 3), ("low", 1), ("other_severity", 0)])
def test_translate_severity(mocker: MockerFixture, severity: str, expected_result: int) -> None:
    """
    Given:
        - a severity.
    When:
        - Running translate_severity function.
    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "APIKey": "API_KEY",
            "ServiceKey": "SERVICE_KEY",
            "FetchInterval": "FETCH_INTERVAL",
            "DefaultRequestor": "P09TT3C",
        },
    )
    from PagerDuty import translate_severity

    res = translate_severity(severity)
    assert res == expected_result


def test_paginate_with_limit(mocker: MockerFixture):
    """This test verifies that the function correctly handles pagination when a limit is provided,
        making a single API request with the expected parameters and returning the correct results.
    Given:
        a test scenario where the `pagination_incidents` function is called with a specified limit,
    When:
        the function is invoked with a limit of 79,
    Then:
        it should make a single API request with the specified limit and offset 0,
        and the result should match the mocked API response.
    """
    from PagerDuty import pagination_incidents

    re = mocker.patch(
        "PagerDuty.http_request",
        side_effect=[{"incidents": list(range(79))}],
    )

    result = pagination_incidents({"user_ids": "test_id"}, {"limit": 79}, "")

    assert result == list(range(79))
    assert re.call_count == 1
    assert re.call_args_list[0].args == ("GET", "", {"user_ids": "test_id", "limit": 79, "offset": 0})


def test_paginate_with_limit_is_more_than_INCIDENT_API_LIMIT(mocker: MockerFixture):
    """This test ensures that the function correctly handles pagination for large limits,
        making multiple API calls to retrieve all incidents.

    Given:
        a test scenario where the requested limit exceeds the max incidents per page (100),
    When:
        the `pagination_incidents` function is called with a limit of 179,
    Then:
        it should make two API calls:
        - First call with limit 100 and offset 0.
        - Second call with limit 79 (to fetch the remaining incidents) and offset 100.

    """
    from PagerDuty import pagination_incidents

    re = mocker.patch(
        "PagerDuty.http_request",
        side_effect=[
            {"incidents": list(range(100))},  # the response for the first call
            {"incidents": list(range(100, 179))},  # the response for the secund call
        ],
    )

    result = pagination_incidents({"user_ids": "test_id"}, {"limit": 179}, "")

    assert result == list(range(179))
    assert re.call_count == 2
    assert re.call_args_list[0].args == ("GET", "", {"user_ids": "test_id", "limit": 100, "offset": 0})  # first call
    assert re.call_args_list[1].args == ("GET", "", {"user_ids": "test_id", "limit": 79, "offset": 100})  # secund call


def test_paginate_with_page_size(mocker: MockerFixture):
    """This test verifies that the pagination functionality correctly handles the provided page size
        and page number, making a single API request with the expected parameters.
    Given:
        a test scenario where pagination is performed with a specified page size,
    When:
        the `pagination_incidents` function is called with a page size of 100 and page number 2,
    Then:
        it should make a single API request to fetch results from offset 100 to 199.
    """
    from PagerDuty import pagination_incidents

    re = mocker.patch("PagerDuty.http_request", side_effect=[{"incidents": list(range(100, 200))}])
    result = pagination_incidents({"user_ids": "test_id"}, {"page_size": 100, "page": 2}, "")
    assert result == list(range(100, 200))
    assert re.call_count == 1
    assert re.call_args_list[0].args == ("GET", "", {"user_ids": "test_id", "limit": 100, "offset": 100})


def test_paginate_with_page_size_more_than_INCIDENT_API_LIMIT():
    """This test ensures that the function correctly handles the case where the provided page size exceeds the API limit,
    raising a DemistoException with the appropriate error message.
    Given:
        a test scenario where the `pagination_incidents` function is called with a page size greater than the API limit,
    When:
        the function is invoked with a page size of 200 and page number 2,
    Then:
        it should raise a DemistoException with the message "The max size for page is 100. Please provide a smaller page size."
    """
    from PagerDuty import pagination_incidents

    with pytest.raises(DemistoException, match="The max size for page is 100. Please provide a lower page size."):
        pagination_incidents({"user_ids": "test_id"}, {"page_size": 200, "page": 2}, "")


@pytest.mark.parametrize("add_content", [True, False])
def test_main_handles_httperror(requests_mock, mocker, add_content):
    """
    Given: params that causes http error.
    When: sending an HTTP request.
    Then: print the correct error message.
    """
    mocker.patch.object(demisto, "params", return_value={"APIKey": "test", "ServiceKey": "test", "FetchInterval": "1"})

    from PagerDuty import ON_CALLS_USERS_SUFFIX, SERVER_URL, main

    class Response:
        def __init__(self, add_content):
            if add_content:
                self.content = "Https error test"

    url = SERVER_URL + ON_CALLS_USERS_SUFFIX
    requests_mock.get(url, exc=requests.exceptions.HTTPError(response=Response(add_content)))

    mocker.patch.object(demisto, "command", return_value="test-module")
    error_method = mocker.patch("PagerDuty.return_error")
    main()

    assert error_method.call_count == 1
    if add_content:
        assert error_method.call_args.args[0] == "Error in API request Https error test"
    else:
        assert error_method.call_args.args[0] == "Error in API request "


def _mk_incident(
    idx: int,
    status: str = "triggered",
    created_at: str = "2026-05-24T10:00:00Z",
) -> dict:
    """Build a minimal PagerDuty incident dict the parser can consume."""
    return {
        "id": f"P{idx:04d}",
        "summary": f"incident {idx}",
        "status": status,
        "urgency": "high",
        "created_at": created_at,
        "html_url": f"https://example.pagerduty.com/incidents/P{idx:04d}",
        "service": {"id": "SVC1", "summary": "svc"},
        "first_trigger_log_entry": {"channel": {"details": "x"}},
        "assignments": [],
        "acknowledgements": [],
        "teams": [],
    }


def _page(
    incidents: list,
    more: bool = False,
    offset: int = 0,
    limit: int = 100,
    total: int | None = None,
) -> dict:
    """Build a PagerDuty `GET /incidents` style page response."""
    return {
        "incidents": incidents,
        "more": more,
        "offset": offset,
        "limit": limit,
        "total": total if total is not None else len(incidents),
    }


def _base_params(**overrides) -> dict:
    """Default integration params for fetch_incidents tests."""
    base = {
        "APIKey": "API_KEY",
        "ServiceKey": "SERVICE_KEY",
        "FetchInterval": "10",
        "DefaultRequestor": "DefaultRequestor",
    }
    base.update(overrides)
    return base


def test_fetch_incidents_paginated_over_25(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - max_fetch=120 and an API that returns 100 incidents on the first page
          and 20 incidents on the second page.

    When:
        - fetch_incidents is called.

    Then:
        - All 120 incidents are reported via demisto.incidents (i.e., pagination works
          and we do not silently drop the long tail past the first page).
    """
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    page1 = [_mk_incident(i, created_at=f"2026-05-24T10:{i:02d}:00Z") for i in range(100)]
    page2 = [_mk_incident(100 + i, created_at=f"2026-05-24T11:{i:02d}:00Z") for i in range(20)]

    def _responder(request, _context):
        qs = request.qs
        offset = int(qs.get("offset", ["0"])[0])
        return _page(page2 if offset == 100 else page1, more=(offset == 0), offset=offset, limit=100)

    requests_mock.get("https://api.pagerduty.com/incidents", json=_responder)

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params(max_fetch="120"))

    assert set_incidents.call_count == 1
    assert len(set_incidents.call_args.args[0]) == 120
    assert set_last_run.called


def test_fetch_incidents_more_false_short_circuit(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - The API returns 10 incidents with more=False on the first page.

    When:
        - fetch_incidents is called with default max_fetch.

    Then:
        - Only a single HTTP request is made and 10 incidents are emitted.
    """
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    incidents = [_mk_incident(i, created_at=f"2026-05-24T10:{i:02d}:00Z") for i in range(10)]
    matcher = requests_mock.get("https://api.pagerduty.com/incidents", json=_page(incidents, more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params())

    assert matcher.call_count == 1
    assert len(set_incidents.call_args.args[0]) == 10


def test_fetch_incidents_respects_max_fetch_cap(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - max_fetch is set absurdly high (9999) and the API would return 300 incidents.

    When:
        - fetch_incidents is called.

    Then:
        - The hard MAX_FETCH_CAP (200) is respected — at most 200 incidents are emitted.
    """
    mocker.patch.object(demisto, "params", return_value=_base_params(max_fetch="9999"))
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    full_pool = [_mk_incident(i, created_at=f"2026-05-24T{10 + i // 60:02d}:{i % 60:02d}:00Z") for i in range(300)]

    def _responder(request, _context):
        qs = request.qs
        offset = int(qs.get("offset", ["0"])[0])
        limit = int(qs.get("limit", ["100"])[0])
        chunk = full_pool[offset : offset + limit]
        return _page(chunk, more=(offset + limit < 300), offset=offset, limit=limit)

    requests_mock.get("https://api.pagerduty.com/incidents", json=_responder)

    from PagerDuty import MAX_FETCH_CAP, fetch_incidents

    fetch_incidents(_base_params(max_fetch="9999"))

    assert len(set_incidents.call_args.args[0]) <= MAX_FETCH_CAP


def test_fetch_incidents_passes_statuses_param(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - incident_statuses param is "triggered,acknowledged,resolved".

    When:
        - fetch_incidents is called.

    Then:
        - The outgoing request URL contains all three statuses encoded as statuses[].
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value=_base_params(incident_statuses="triggered,acknowledged,resolved"),
    )
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    matcher = requests_mock.get("https://api.pagerduty.com/incidents", json=_page([], more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params(incident_statuses="triggered,acknowledged,resolved"))

    assert matcher.call_count >= 1
    url = matcher.last_request.url
    assert "statuses%5B%5D=triggered" in url
    assert "statuses%5B%5D=acknowledged" in url
    assert "statuses%5B%5D=resolved" in url


def test_fetch_incidents_watermark_from_created_at(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - Two incidents with created_at T10:00:00 and T10:05:00.
        - Wall-clock now is T10:10:00.

    When:
        - fetch_incidents is called.

    Then:
        - setLastRun is called with time == max(created_at) ("2026-05-24T10:05:00Z"),
          NOT the wall-clock value.
    """
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    incidents = [
        _mk_incident(1, created_at="2026-05-24T10:00:00Z"),
        _mk_incident(2, created_at="2026-05-24T10:05:00Z"),
    ]
    requests_mock.get("https://api.pagerduty.com/incidents", json=_page(incidents, more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params())

    saved = set_last_run.call_args.args[0]
    assert saved["time"] == "2026-05-24T10:05:00Z"
    assert "P0002" in saved["ids"]


def test_fetch_incidents_dedup_against_lastrun_ids(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - lastRun contains ids=["P0001"].
        - The API returns P0001 (boundary duplicate) and P0002 (new).

    When:
        - fetch_incidents is called.

    Then:
        - Only P0002 is emitted, and the new ids buffer retains P0001 up to the retention cap.
    """
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"time": "2026-05-24T09:00:00Z", "ids": ["P0001"]},
    )
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    incidents = [
        _mk_incident(1, created_at="2026-05-24T09:00:00Z"),
        _mk_incident(2, created_at="2026-05-24T09:05:00Z"),
    ]
    requests_mock.get("https://api.pagerduty.com/incidents", json=_page(incidents, more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params())

    emitted = set_incidents.call_args.args[0]
    assert len(emitted) == 1
    assert emitted[0]["name"].startswith("P0002 - ")

    saved = set_last_run.call_args.args[0]
    assert "P0002" in saved["ids"]
    assert "P0001" in saved["ids"]
    # Watermark must advance to the newest incident's created_at (P0002), not stay pinned.
    assert saved["time"] == "2026-05-24T09:05:00Z"


def test_fetch_incidents_no_new_advances_watermark_to_now(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - lastRun = {"time": "T09:00:00Z", "ids": ["P0001"]}.
        - The API returns only P0001 (which is filtered out by dedup, so 0 new emitted).
        - Wall-clock now is mocked to a deterministic value.

    When:
        - fetch_incidents is called.

    Then:
        - demisto.incidents([]) is called and setLastRun advances `time` to the mocked `now`
          (so the next since→until window stays bounded). `ids` is preserved as the prior
          seen_ids (no merge — there are no new IDs in this branch).
    """
    last_run = {"time": "2026-05-24T09:00:00Z", "ids": ["P0001"]}
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    fixed_now = datetime(2026, 5, 24, 10, 0, 0)

    class _FixedDatetime(datetime):
        @classmethod
        def utcnow(cls):
            return fixed_now

    mocker.patch("PagerDuty.datetime", _FixedDatetime)
    expected_now_iso = datetime.isoformat(fixed_now)

    incidents = [_mk_incident(1, created_at="2026-05-24T09:00:00Z")]
    requests_mock.get("https://api.pagerduty.com/incidents", json=_page(incidents, more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params())

    assert set_incidents.call_args.args[0] == []
    saved = set_last_run.call_args.args[0]
    assert saved["time"] == expected_now_iso
    assert saved["ids"] == list(set(last_run["ids"]))


def test_fetch_incidents_first_run_uses_fetch_interval(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - No prior lastRun.
        - FetchInterval=10 minutes and a deterministic utcnow.

    When:
        - fetch_incidents is called.

    Then:
        - The outgoing request 'since' value is exactly 10 minutes before now.
    """
    mocker.patch.object(demisto, "params", return_value=_base_params(FetchInterval="10"))
    mocker.patch.object(demisto, "getLastRun", return_value=None)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    fixed_now = datetime(2026, 5, 24, 12, 0, 0)

    class _FixedDatetime(datetime):
        @classmethod
        def utcnow(cls):
            return fixed_now

    mocker.patch("PagerDuty.datetime", _FixedDatetime)

    matcher = requests_mock.get("https://api.pagerduty.com/incidents", json=_page([], more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params(FetchInterval="10"))

    from urllib.parse import unquote

    expected_since = "2026-05-24T11:50:00"
    url = unquote(matcher.last_request.url)
    assert f"since={expected_since}" in url


def test_fetch_incidents_empty_dicts_filtered(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - The API returns {"incidents": [{}]} (the paginator's empty-dict fallback shape).
        - Wall-clock now is mocked to a deterministic value.

    When:
        - fetch_incidents is called with a fresh lastRun.

    Then:
        - No exception is raised, demisto.incidents([]) is called, and setLastRun advances
          `time` to the mocked `now` (since 0 new incidents were emitted, per the hybrid rule).
          `ids` is preserved as the prior (empty) seen_ids.
    """
    prior_last_run: dict = {}
    mocker.patch.object(demisto, "params", return_value=_base_params())
    mocker.patch.object(demisto, "getLastRun", return_value=prior_last_run)
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    set_incidents = mocker.patch.object(demisto, "incidents")

    fixed_now = datetime(2026, 5, 24, 12, 0, 0)

    class _FixedDatetime(datetime):
        @classmethod
        def utcnow(cls):
            return fixed_now

    mocker.patch("PagerDuty.datetime", _FixedDatetime)
    expected_now_iso = datetime.isoformat(fixed_now)

    requests_mock.get("https://api.pagerduty.com/incidents", json={"incidents": [{}]})

    from PagerDuty import fetch_incidents

    fetch_incidents(_base_params())

    assert set_incidents.call_args.args[0] == []
    saved = set_last_run.call_args.args[0]
    assert saved["time"] == expected_now_iso
    assert saved["ids"] == []


def test_fetch_incidents_accepts_list_statuses(requests_mock: MockerCore, mocker: MockerFixture) -> None:
    """
    Given:
        - params["incident_statuses"] is delivered as a Python list (XSOAR multiSelect type 16
          may serialize the value either as a comma-string or as a list).

    When:
        - fetch_incidents is called.

    Then:
        - No AttributeError is raised, and the outgoing request URL contains BOTH
          statuses[]=triggered AND statuses[]=resolved.
    """
    params = _base_params(incident_statuses=["triggered", "resolved"])
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    matcher = requests_mock.get("https://api.pagerduty.com/incidents", json=_page([], more=False))

    from PagerDuty import fetch_incidents

    fetch_incidents(params)

    from urllib.parse import unquote

    assert matcher.last_request is not None
    url = unquote(matcher.last_request.url)
    assert "statuses[]=triggered" in url
    assert "statuses[]=resolved" in url

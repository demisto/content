import json
from datetime import datetime

import demistomock as demisto
import requests_mock

URL = "https://example.my.idaptive.app/"
DEMISTO_PARAMS = {
    "url": URL,
    "credentials": {
        "identifier": "admin@example.com.11",
        "password": "123456",
    },
    "from": "3 days",
    "app_id": "test_app",
    "limit": 100,
}


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


# @freeze_time('2022-05-12T00:00:00Z')
def test_fetch_events_few_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Verify that all 3 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert last_run.get("from") == "2022-05-15T13:35:26.645000"
    assert len(last_run.get("ids")) == len(events) == 3


def test_fetch_events_no_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json={"Result": {}})

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args
    assert not last_run
    assert not events


def _build_row(index: int, when_occurred_ms: int) -> dict:
    """Build a single RedRock 'Results' entry with a unique ID and WhenOccurred."""
    return {
        "Entities": [{"Type": "User", "Key": f"key-{index}", "IsForeignKey": True}],
        "Row": {
            "_TableName": "events",
            "ID": f"event-{index}",
            "Level": "Info",
            "WhenOccurred": f"/Date({when_occurred_ms})/",
            "WhenLogged": f"/Date({when_occurred_ms})/",
        },
    }


def test_fetch_events_paginates_full_backlog(mocker):
    """
    Given
        - 2500 events match the fetch window in CyberArk (more than a single RedRock page of 1000).
    When
        - fetch-events is running.
    Then
        - Verify the integration pages through ALL results (3 pages) and collects every event,
          so no events are dropped when the backlog exceeds one page.
        - Verify the last_run cursor is set to the max WhenOccurred of the whole backlog.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE

    total_events = 2500
    base_ms = 1652621700000
    all_rows = [_build_row(i, base_ms + i) for i in range(total_events)]

    def redrock_callback(request, context):
        body = json.loads(request.text)
        page_number = body["args"]["PageNumber"]
        start = (page_number - 1) * PAGE_SIZE
        page_rows = all_rows[start : start + PAGE_SIZE]
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(page_rows), "FullCount": total_events, "Results": page_rows}}

    demisto_params = dict(DEMISTO_PARAMS)
    demisto_params["limit"] = 1000
    params = mocker.patch.object(demisto, "params", return_value=demisto_params)
    args = mocker.patch.object(demisto, "args", return_value={})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock_callback)

        from CyberArkIdentityEventCollector import main

        main("fetch-events", params.return_value | args.return_value)

    events = sent.call_args[0][0]
    # All 2500 events must be collected across the 3 pages (1000 + 1000 + 500) - none dropped.
    assert len(events) == total_events
    last_run = mock_last_run.call_args[0][0]
    # Cursor must advance to the newest event in the whole backlog, not just the first page.
    assert last_run.get("from") == datetime.utcfromtimestamp((base_ms + total_events - 1) / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    assert len(last_run.get("ids")) == total_events


def test_fetch_events_already_fetched_ids_are_skipped(mocker):
    """
    Given
        - A single page of 3 events, two of which were already fetched in the previous run.
    When
        - fetch-events is running.
    Then
        - Verify only the one new event is sent to XSIAM (dedup by ID works with pagination).
    """
    total_events = 3
    base_ms = 1652621700000
    all_rows = [_build_row(i, base_ms + i) for i in range(total_events)]

    def redrock_callback(request, context):
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(all_rows), "FullCount": total_events, "Results": all_rows}}

    params = mocker.patch.object(demisto, "params", return_value=dict(DEMISTO_PARAMS))
    args = mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    mocker.patch.object(demisto, "getLastRun", return_value={"ids": ["event-0", "event-1"]})
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock_callback)

        from CyberArkIdentityEventCollector import main

        main("fetch-events", params.return_value | args.return_value)

    events = sent.call_args[0][0]
    assert len(events) == 1
    assert events[0]["ID"] == "event-2"


def test_request_params_include_order_by_and_caching():
    """
    Given
        - Fetch parameters.
    When
        - Building the RedRock request params.
    Then
        - Verify the query is ordered ascending by WhenOccurred and requests live (non-cached) data,
          which is required for safe pagination and a monotonic last-run cursor.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE, get_request_params

    params = get_request_params(url=URL, **{"from": "3 days"}, limit=50)
    body = json.loads(params["data"])
    assert "ORDER BY WhenOccurred ASC" in body["Script"]
    assert body["args"]["Caching"] == -1
    assert body["args"]["PageSize"] == PAGE_SIZE
    assert body["args"]["PageNumber"] == 1


def test_fetch_events_limit_set_to_one(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    demisto_params = DEMISTO_PARAMS
    demisto_params["limit"] = 1
    params = mocker.patch.object(demisto, "params", return_value=demisto_params)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert last_run.get("from") == "2022-05-15T13:35:03.570000"
    assert len(last_run.get("ids")) == len(events) == 1

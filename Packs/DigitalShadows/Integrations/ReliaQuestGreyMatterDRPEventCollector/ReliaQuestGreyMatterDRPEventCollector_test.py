
from CommonServerPython import *

import pytest
import hashlib
from ReliaQuestGreyMatterDRPEventCollector import DATE_FORMAT, ReilaQuestClient
import json
from freezegun import freeze_time
from ReliaQuestGreyMatterDRPEventCollector import FOUND_IDS_LAST_RUN

TEST_URL = "https://test.com/api"


@pytest.fixture()
def client() -> ReilaQuestClient:
    return ReilaQuestClient(
        url=TEST_URL,
        account_id="1234",
        username="test",
        password="test",
    )


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode('utf-8')
    mocked_response.status_code = status_code
    return mocked_response


def create_triage_items_events(num_of_events: int, start_time: str, offset: int = 3, start_event_num: int = 1) -> tuple[requests.Response, List[Dict]]:
    start_datetime = dateparser.parse(start_time)
    events = []

    for event_num in range(start_event_num, num_of_events + start_event_num):
        seconds_offset = (event_num - 1) // offset
        event_created = start_datetime + timedelta(seconds=seconds_offset)
        event_created_str = event_created.strftime(DATE_FORMAT)

        events.append(
            {
                "event-num": event_num,
                "event-created": event_created_str,
                "triage-item-id": event_num,
            }
        )
    return create_mocked_response(events), events


def create_triage_items_from_events(events: List[Dict], item_type: str) -> List[Dict]:
    if item_type not in {"incident-id", "alert-id"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')
    triaged_items = []
    for item_type_id, event in enumerate(events, start=1):
        triaged_items.append(
            {
                "id": event.get("triage-item-id"),
                "title": "title",
                "source": {
                    item_type: item_type_id
                }
            }
        )
    return triaged_items


def create_incidents_and_alerts_from_triaged_items(triaged_alert_ids: List[Dict], item_type: str, amount_of_assets: int = 0) -> tuple[requests.Response, List[Dict]]:
    if item_type not in {"incident-id", "alert-id"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')
    events = []
    for triaged_alert in triaged_alert_ids:
        _id = triaged_alert.get("source", {}).get(item_type)
        events.append(
            {
                "id": _id,
                "title": f'{item_type}-{_id}',
                "assets": []
            }
        )

    if amount_of_assets > 0:
        for i, event in enumerate(events):
            event_copy = event.copy()
            event_copy["unique_id"] = i
            event["assets"].append({"id": hashlib.sha256(json.dumps(event_copy, sort_keys=True).encode()).hexdigest()})

    return create_mocked_response(events), events


def create_assets(assets: List[Dict]) -> requests.Response:
    return create_mocked_response(
        [
            {
                "id": asset.get("id"),
                "type": f"asset-{asset.get('id')}"
            } for asset in assets
        ]
    )


def test_the_test_module(requests_mock, client: ReilaQuestClient):
    """
    Given:
     - a single event
     - api returns 200 ok

    When:
     - running test-module

    Then:
     - make sure the test is successful.
    """
    from ReliaQuestGreyMatterDRPEventCollector import test_module
    requests_mock.get(
        f"{TEST_URL}/triage-item-events?limit=1",
        json=create_triage_items_events(num_of_events=1, start_time="2020-09-24T16:30:10.016Z")
    )
    assert test_module(client) == "ok"


@freeze_time("2020-09-24T16:30:10.016Z")
def test_http_request_rate_limits(mocker, client: ReilaQuestClient):
    """
    Given:
     - api rate limit reached
     - api informs to try a resend the request after a milisecond
     - second api response 200 ok

    When:
     - running http_request

    Then:
     - make sure the response is returned properly
    """
    mocked_responses = [
        create_mocked_response({"retry-after": "2020-09-24T16:30:10.017Z"}, status_code=429),
        create_mocked_response([{"test": "test"}])
    ]
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=mocked_responses
    )
    assert client.http_request("suffix") == [{"test": "test"}]


class TestFetchEvents:

    def test_fetch_events_no_last_run_single_iteration_sanity_test(self, mocker, client: ReilaQuestClient):
        """
        Given:
         - 100 events
         - no last run

        When:
         - running the entire fetch-events flow

        Then:
         - make sure the events are enriched as expected
         - make sure all the 100 events are fetched
        """
        import ReliaQuestGreyMatterDRPEventCollector

        send_events_mocker = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', return_value={})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        mocker.patch.object(
            demisto, 'params',
            return_value={
                "url": TEST_URL,
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch_events": 200
            }
        )
        mocker.patch.object(demisto, 'command', return_value='fetch-events')

        events_response, events = create_triage_items_events(100, start_time="2020-09-24T16:30:10.016Z")
        triaged_alerts = create_triage_items_from_events(events[0:50], item_type="alert-id")
        triaged_incidents = create_triage_items_from_events(events[50:100], item_type="incident-id")

        alerts_response, alerts = create_incidents_and_alerts_from_triaged_items(
            triaged_alerts, item_type="alert-id", amount_of_assets=3
        )
        incidents_response, incidents = create_incidents_and_alerts_from_triaged_items(
            triaged_incidents, item_type="incident-id", amount_of_assets=3
        )

        assets = []
        for alert in alerts:
            assets.extend(alert["assets"])

        for incident in incidents:
            assets.extend(incident["assets"])

        assets_response = create_assets(assets)

        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=[
                events_response,
                create_mocked_response(triaged_alerts + triaged_incidents),
                alerts_response,
                incidents_response,
                assets_response,
                create_mocked_response([]),  # empty response to stop pagination
            ]
        )

        ReliaQuestGreyMatterDRPEventCollector.main()
        assert send_events_mocker.call_count == 1
        events = send_events_mocker.call_args[0][0]
        assert len(events) == 100

        assert set_last_run_mocker.call_args[0][0][FOUND_IDS_LAST_RUN] == [100]
        for event in events[0:50]:
            assert event["triage-item"]
            assert event["alert"]
            assert event["assets"]

        for event in events[50:100]:
            assert event["triage-item"]
            assert event["incident"]
            assert event["assets"]

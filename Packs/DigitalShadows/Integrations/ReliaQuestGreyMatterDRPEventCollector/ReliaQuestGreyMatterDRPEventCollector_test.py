
from CommonServerPython import *

import pytest
import hashlib
from ReliaQuestGreyMatterDRPEventCollector import (
    ReilaQuestClient, RateLimitError, RATE_LIMIT_LAST_RUN, LAST_FETCHED_EVENT_NUM
)
import json

TEST_URL = "https://test.com/api"


@pytest.fixture()
def client() -> ReilaQuestClient:
    return ReilaQuestClient(
        url=TEST_URL,
        account_id="1234",
        username="test",
        password="test",
    )


class HttpRequestMock:

    LAST_EVENT_TIME_AND_NUM = None

    def __init__(self, num_of_events: int, num_of_alerts: int, num_of_incidents: int):
        self.num_of_events = num_of_events
        self.num_of_fetched_events = 0
        self.num_of_alerts = num_of_alerts
        self.num_of_fetched_alerts = 0
        self.num_of_incidents = num_of_incidents
        self.num_of_fetched_incidents = 0

    def http_request_side_effect(self, method: str, url_suffix: str, params: Dict | None = None, **kwargs):
        if url_suffix == "/triage-item-events":
            if self.num_of_fetched_events >= self.num_of_events:
                return create_mocked_response([])
            limit = params["limit"]
            event_num_after = params["event-num-after"]
            if event_num_after:
                event_num_after += 1
            response = create_triage_item_events(limit, start_event_num=event_num_after or 1)
            self.num_of_fetched_events += len(response)
            if self.num_of_fetched_events > self.num_of_events:
                response = response[:self.num_of_fetched_events - self.num_of_events]

        elif url_suffix == "/triage-items":
            triage_item_ids = params["id"]
            triage_item_alerts = triage_item_ids[:self.num_of_alerts - self.num_of_fetched_alerts]
            alerts_response = create_triage_items_from_events(triage_item_alerts, item_type="alert-id")
            triage_item_incidents = triage_item_ids[self.num_of_alerts - self.num_of_fetched_alerts:]
            incidents_response = create_triage_items_from_events(triage_item_incidents, item_type="incident-id")

            self.num_of_fetched_alerts += len(alerts_response)
            self.num_of_fetched_incidents += len(incidents_response)

            response = alerts_response + incidents_response

        elif url_suffix == "/alerts":
            response = create_incidents_and_alerts_from_triaged_items(params["id"], item_type="alert-id", amount_of_assets=1)

        elif url_suffix == "/incidents":
            response = create_incidents_and_alerts_from_triaged_items(params["id"], item_type="incident-id", amount_of_assets=1)

        elif url_suffix == "/assets":
            response = create_assets(params["id"])

        else:
            response = []

        return create_mocked_response(response)


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode('utf-8')
    mocked_response.status_code = status_code
    return mocked_response


def create_triage_item_events(num_of_events: int, start_event_num: int = 1) -> List[Dict]:
    return [
        {
            "event-num": event_num,
            "event-created": "2020-09-24T16:30:10.016Z",
            "triage-item-id": event_num,
        } for event_num in range(start_event_num, num_of_events + start_event_num)
    ]


def create_triage_items_from_events(triage_item_ids: List[str], item_type: str) -> List[Dict]:
    if item_type not in {"incident-id", "alert-id"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')

    return [
        {
            "id": triage_item_id,
            "title": "title",
            "source": {
                item_type: triage_item_id
            }
        } for triage_item_id in triage_item_ids
    ]


def create_incidents_and_alerts_from_triaged_items(_ids: List[str], item_type: str, amount_of_assets: int = 0) -> List[Dict]:
    if item_type not in {"incident-id", "alert-id"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')
    events = []
    for _id in _ids:
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

    return events


def create_assets(asset_ids: List[str]) -> List[Dict]:
    return [
        {
            "id": _id,
            "type": f"asset-{_id}"

        } for _id in asset_ids
    ]


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
        json=create_triage_item_events(num_of_events=1)
    )
    assert test_module(client) == "ok"


def test_http_request_rate_limit(mocker, client: ReilaQuestClient):
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
    ]
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=mocked_responses
    )
    with pytest.raises(RateLimitError):
        client.http_request("suffix")


def test_http_request_connection_errors(mocker, client: ReilaQuestClient):
    """
    Given:
     - connection error exceptions
     - request that succeeded after connection errors

    When:
     - running http_request

    Then:
     - make sure the retry mechanism is triggered and the response is returned properly
    """
    from requests.exceptions import ConnectionError, Timeout

    sleep_mocker = mocker.patch("CommonServerPython.time.sleep")
    mocked_responses = [
        Timeout, ConnectionError, create_mocked_response(response={"test": "test"})
    ]
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=mocked_responses
    )
    assert client.http_request("suffix") == {"test": "test"}
    assert sleep_mocker.called


@pytest.mark.parametrize(
    "limit, num_of_events",
    [
        (200, 1000),
        (1500, 1000),
        (100, 100),
        (10000, 15000)
    ],
)
def test_list_triage_item_events(client: ReilaQuestClient, mocker, limit: int, num_of_events: int):
    """
    Given:
     - maximum limit & actual number of events exist in the api

    When:
     - running list_triage_item_events

    Then:
     - make sure the right amount of events is returned
    """
    http_mocker = HttpRequestMock(num_of_events, num_of_alerts=0, num_of_incidents=0)

    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    fetched_events = []
    for events, latest_event in client.list_triage_item_events(limit=limit):
        fetched_events.extend(events)
        assert latest_event == len(fetched_events)

    assert len(fetched_events) == min(num_of_events, limit)


class TestFetchEvents:

    def test_fetch_events_no_last_run_single_iteration_sanity_test(self, mocker):
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

        http_mocker = HttpRequestMock(100, num_of_alerts=50, num_of_incidents=50)

        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=http_mocker.http_request_side_effect
        )

        ReliaQuestGreyMatterDRPEventCollector.main()
        assert send_events_mocker.call_count == 1
        events = send_events_mocker.call_args[0][0]
        assert len(events) == 100

        assert set_last_run_mocker.call_args[0][0][LAST_FETCHED_EVENT_NUM] == 100
        for event in events[0:50]:
            assert event["triage-item"]
            assert event["alert"]
            assert event["assets"]

        for event in events[50:100]:
            assert event["triage-item"]
            assert event["incident"]
            assert event["assets"]

    def test_fetch_events_sanity_rate_limit_error(self, mocker):
        """
        Given:
         - api rate limit error

        When:
         - running the entire fetch-events flow

        Then:
         - make sure all the last run saves the retry-after
        """
        import ReliaQuestGreyMatterDRPEventCollector

        send_events_mocker = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', return_value={})
        mocker.patch.object(demisto, "error")
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
        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=[
                create_mocked_response(response={"retry-after": "2024-01-18T10:22:00Z"}, status_code=429),
            ]
        )
        ReliaQuestGreyMatterDRPEventCollector.main()
        assert send_events_mocker.call_count == 0
        assert set_last_run_mocker.call_args[0][0][RATE_LIMIT_LAST_RUN] == "2024-01-18T10:22:00Z"

    def test_fetch_events_no_events(self, mocker):
        """
        Given:
         - flow where there is no last run or no events

        When:
         - running the entire fetch-events flow

        Then:
         - make sure that there aren't any events fetched
        """
        import ReliaQuestGreyMatterDRPEventCollector

        send_events_mocker = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
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
        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=[
                create_mocked_response(response=[]),
            ]
        )

        ReliaQuestGreyMatterDRPEventCollector.main()
        assert send_events_mocker.call_count == 0

    def test_fetch_events_no_events_with_last_run(self, mocker):
        """
        Given:
         - flow where there is last run from previous fetch, but no more events in the api

        When:
         - running the entire fetch-events flow

        Then:
         - make sure that there aren't any events fetched and the last run is kept the same
        """
        import ReliaQuestGreyMatterDRPEventCollector

        send_events_mocker = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun')
        mocker.patch.object(demisto, "error")
        mocker.patch.object(
            demisto, 'getLastRun', return_value={LAST_FETCHED_EVENT_NUM: 1}
        )
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
        http_mocker = HttpRequestMock(0, num_of_alerts=0, num_of_incidents=0)
        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=http_mocker.http_request_side_effect
        )

        ReliaQuestGreyMatterDRPEventCollector.main()
        assert send_events_mocker.call_count == 0
        assert set_last_run_mocker.call_args[0][0] == {LAST_FETCHED_EVENT_NUM: 1}

    def test_fetch_events_multiple_events_no_rate_limits_no_last_run(self, mocker):
        """
        Given:
         - flow where there are multiple events and no last run

        When:
         - running the entire fetch-events flow

        Then:
         - make sure that all events are enriched and fetched, make sure the send_events_to_xsiam is called multiple times
         - make sure last run saves the largest event number
        """
        import ReliaQuestGreyMatterDRPEventCollector
        from unittest.mock import MagicMock

        send_events_mocker: MagicMock = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
        set_last_run_mocker: MagicMock = mocker.patch.object(demisto, 'setLastRun', return_value={})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        mocker.patch.object(
            demisto, 'params',
            return_value={
                "url": TEST_URL,
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch_events": 4000
            }
        )
        mocker.patch.object(demisto, 'command', return_value='fetch-events')

        http_mocker = HttpRequestMock(3500, num_of_alerts=1750, num_of_incidents=1750)

        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=http_mocker.http_request_side_effect
        )

        ReliaQuestGreyMatterDRPEventCollector.main()

        assert send_events_mocker.call_count == 4
        fetched_events = []
        for call in send_events_mocker.call_args_list:
            fetched_events.extend(call.args[0])

        assert len(fetched_events) == 3500

        assert set_last_run_mocker.call_args[0][0][LAST_FETCHED_EVENT_NUM] == 3500
        for event in fetched_events[0:1750]:
            assert event["triage-item"]
            assert event["alert"]
            assert event["assets"]

        for event in fetched_events[1750:3500]:
            assert event["triage-item"]
            assert event["incident"]
            assert event["assets"]

    def test_fetch_events_multiple_events_no_rate_limits_with_last_run(self, mocker):
        """
        Given:
         - flow where there are multiple events and last run indicates on latest event

        When:
         - running the entire fetch-events flow

        Then:
         - make sure that all events are enriched and fetched, make sure the send_events_to_xsiam is called multiple times
         - make sure that the latest event-num is now larger = 10000
        """
        import ReliaQuestGreyMatterDRPEventCollector
        from unittest.mock import MagicMock

        send_events_mocker: MagicMock = mocker.patch.object(ReliaQuestGreyMatterDRPEventCollector, 'send_events_to_xsiam')
        set_last_run_mocker: MagicMock = mocker.patch.object(demisto, 'setLastRun', return_value={})
        mocker.patch.object(demisto, 'getLastRun', return_value={LAST_FETCHED_EVENT_NUM: 5000})
        mocker.patch.object(
            demisto, 'params',
            return_value={
                "url": TEST_URL,
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch_events": 10000
            }
        )
        mocker.patch.object(demisto, 'command', return_value='fetch-events')

        http_mocker = HttpRequestMock(5000, num_of_alerts=2500, num_of_incidents=2500)

        mocker.patch.object(
            ReliaQuestGreyMatterDRPEventCollector.ReilaQuestClient,
            "_http_request",
            side_effect=http_mocker.http_request_side_effect
        )

        ReliaQuestGreyMatterDRPEventCollector.main()

        assert send_events_mocker.call_count == 5
        fetched_events = []
        for call in send_events_mocker.call_args_list:
            fetched_events.extend(call.args[0])

        assert len(fetched_events) == 5000

        assert set_last_run_mocker.call_args[0][0][LAST_FETCHED_EVENT_NUM] == 10000
        for event in fetched_events[0:2500]:
            assert event["triage-item"]
            assert event["alert"]
            assert event["assets"]

        for event in fetched_events[2500:5000]:
            assert event["triage-item"]
            assert event["incident"]
            assert event["assets"]


def test_get_events_command(mocker, client: ReilaQuestClient):
    """
    Given:
     - 5000 events

    When:
     - running the get_events_command

    Then:
     - make sure that all events are enriched and fetched (5000)
    """
    from ReliaQuestGreyMatterDRPEventCollector import get_events_command
    http_mocker = HttpRequestMock(5000, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )

    command_results = get_events_command(client, args={"limit": 10000})
    events = command_results.outputs
    assert len(events) == 5000

    for event in events[0:2500]:
        assert event["triage-item"]
        assert event["alert"]
        assert event["assets"]

    for event in events[2500:5000]:
        assert event["triage-item"]
        assert event["incident"]
        assert event["assets"]

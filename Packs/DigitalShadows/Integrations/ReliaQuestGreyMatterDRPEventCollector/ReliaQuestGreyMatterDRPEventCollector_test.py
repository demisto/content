from CommonServerPython import *

import json
import pytest
from ReliaQuestGreyMatterDRPEventCollector import DATE_FORMAT, ReilaQuestClient


TEST_URL = "https://test.com/api"


@pytest.fixture()
def client() -> ReilaQuestClient:
    return ReilaQuestClient(
        url=TEST_URL,
        account_id="1234",
        username="test",
        password="test",
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def create_triage_items_events(num_of_events: int, start_time: str, offset: int = 3):
    start_datetime = dateparser.parse(start_time)
    events = []

    for event_num in range(1, num_of_events + 1):
        seconds_offset = (event_num - 1) // offset
        event_created = start_datetime + timedelta(seconds=seconds_offset)
        event_created_str = event_created.strftime(DATE_FORMAT)

        events.append(
            {
                "event-num": event_num,
                "event-created": event_created_str,
                "triage-item-id": "3ca266d3-4eb6-4852-a46a-9f42545fc412",
            }
        )
    return events


def create_triage_items_from_events(events: List[Dict], item_type: str):
    if item_type not in {"incident-id", "alert-d"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')
    triaged_items = []
    for item_type_id, event in enumerate(events):
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


def create_incidents_and_alerts_from_triaged_items(triaged_alert_ids: List[Dict], item_type: str, amount_of_assets: int = 0):
    if item_type not in {"incident-id", "alert-d"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')
    alerts = []
    for triaged_alert in triaged_alert_ids:
        _id = triaged_alert.get("source", {}).get(item_type)
        alerts.append(
            {
                "id": _id,
                "title": f'{item_type}-{_id}',
                "assets": [{"id": i} for i in amount_of_assets]
            }
        )
    return alerts


def test_the_test_module(requests_mock, client: ReilaQuestClient):
    from ReliaQuestGreyMatterDRPEventCollector import test_module
    requests_mock.get(
        f"{TEST_URL}/triage-item-events?limit=1",
        json=create_triage_items_events(num_of_events=1, start_time="2020-09-24T16:30:10.016Z")
    )
    assert test_module(client) == "ok"


class TestFetchEvents:

    def test_fetch_events_no_last_run_single_iteration(self, client: ReilaQuestClient, mocker, requests_mock):
        from ReliaQuestGreyMatterDRPEventCollector import fetch_events
        events = create_triage_items_events(100, start_time="020-09-24T16:30:10.016Z")
        triaged_alerts = create_triage_items_from_events(events[0:50], item_type="alert-id")
        triaged_incidents = create_triage_items_from_events(events[50:100], item_type="incident-id")
        mocker.patch.object(client, "_http_request", side_effect=[events, triaged_alerts, triaged_incidents])
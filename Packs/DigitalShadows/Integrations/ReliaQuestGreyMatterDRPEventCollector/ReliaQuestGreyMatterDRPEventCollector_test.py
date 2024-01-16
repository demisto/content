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


def create_triage_items_events(num_of_events: int, start_time: str):
    start_datetime = dateparser.parse(start_time)
    events = []

    for event_num in range(1, num_of_events + 1):
        seconds_offset = (event_num - 1) // 3
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


def test_the_test_module(requests_mock, client: ReilaQuestClient):
    from ReliaQuestGreyMatterDRPEventCollector import test_module
    requests_mock.get(
        f"{TEST_URL}/triage-item-events?limit=1",
        json=create_triage_items_events(num_of_events=1, start_time="2020-09-24T16:30:10.016Z")
    )
    assert test_module(client) == "ok"

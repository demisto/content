from __future__ import annotations
import re
import uuid


import pytest

from CommonServerPython import *
from ReliaquestTakedown import \
    Client

from Packs.DigitalShadows.Integrations.ReliaquestTakedown.ReliaquestTakedown import create_comment, list_brands, create_takedown

UUID_REGEX = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

TEST_URL = "https://test.com/api"


@pytest.fixture
def client() -> Client:
    return Client(
        base_url=TEST_URL,
        account_id="1234",
        access_key="HHHQW",
        secret_key="saddsadsajhhjksa",
        verify=False,
        proxy=False
    )


def create_comments_post(takedown_id):
    return {
        "content": "test comment",
        "created": "2025-03-12T06:21:36.986Z",
        "id": "c3894680-6d53-40c7-8129-fe896d48ce86",
        "takedown-id": takedown_id,
        "user": {
            "id": "71ddec65-2bc9-4051-92ed-5d9788d18e2f",
            "name": "API 'UAQJLB'"
        }
    }


def create_comments_get(takedown_id):
    return [{
        "content": "test comment",
        "created": "2025-03-12T06:21:36.986Z",
        "id": "c3894680-6d53-40c7-8129-fe896d48ce86",
        "takedown-id": takedown_id,
        "user": {
            "id": "71ddec65-2bc9-4051-92ed-5d9788d18e2f",
            "name": "API 'UAQJLB'"
        }
    }]


def create_brand_list():
    return [
        {
            "id": "83d44b8c-fd65-48af-adbd-8163d53ab501",
            "name": "Digital Shadows - Sandbox Testing",
            "domain-name": "www.digitalshadows.com",
            "created": "2024-08-07T09:58:25.308Z",
            "updated": "2024-08-07T09:58:25.308Z",
            "status": "pending"
        },
        {
            "id": "ef2abd0c-6199-403d-b9bf-0b4cc2538dd1",
            "name": "JS Brand",
            "domain-name": "www.jaydeep.com",
            "created": "2025-02-21T10:11:12.953Z",
            "updated": "2025-02-21T10:11:12.953Z",
            "status": "pending"
        },
        {
            "id": "d5e868ec-bfc9-4744-8c0e-1d0c991c5085",
            "name": "Reliaquest",
            "domain-name": "www.rq.com",
            "created": "2024-08-09T12:40:51.888Z",
            "updated": "2024-08-09T12:40:51.888Z",
            "status": "pending"
        }
    ]


def create_takedown_get(limit):
    return [{
        "id": str(uuid.uuid4()),
        "created": "2025-03-11T14:38:07.450Z",
        "updated": "2025-03-11T14:38:07.530Z",
        "type": "malware",
        "status": "submitted",
        "brand": {
            "id": "d5e868ec-bfc9-4744-8c0e-1d0c991c5085",
            "name": "Reliaquest",
            "domain-name": "www.rq.com",
            "created": "2024-08-09T12:40:51.888Z",
            "updated": "2024-08-09T12:40:51.888Z",
            "status": "pending"
        },
        "targets": [
            {
                "id": "1b30e52a-f7f0-4cab-aeb5-ec3bfca270ae",
                "url": "hellotech.com"
            }
        ]
    }
        for _ in range(limit)]


def create_takedown_post(kwags):
    return {
        "id": str(uuid.uuid4()),
        "created": "2025-03-11T14:38:07.450Z",
        "updated": "2025-03-11T14:38:07.530Z",
        "type": kwags["type"],
        "status": "submitted",
        "brand": {
            "id": kwags["brand"],
            "name": "Reliaquest",
            "domain-name": "www.rq.com",
            "created": "2024-08-09T12:40:51.888Z",
            "updated": "2024-08-09T12:40:51.888Z",
            "status": "pending"
        },
        "targets": [
            {
                "id": "1b30e52a-f7f0-4cab-aeb5-ec3bfca270ae",
                "url": kwags["target"]['url']
            }
        ]
    }


class ClientMock:
    LAST_EVENT_TIME_AND_NUM = None

    def __init__(self, num_of_events: int, num_of_alerts: int, num_of_incidents: int):
        self.num_of_events = num_of_events
        self.num_of_fetched_events = 0
        self.num_of_alerts = num_of_alerts
        self.num_of_fetched_alerts = 0
        self.num_of_incidents = num_of_incidents
        self.num_of_fetched_incidents = 0

    def http_request_side_effect(self, method: str, url_suffix: str, params: Dict | None = None, **kwargs):
        if url_suffix == "/v1/triage-item-events":
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
        elif url_suffix == '/api/search/find':
            response = create_comments_post()
        elif re.match(r'/v1/takedowns/%s/comments' % UUID_REGEX, url_suffix) and method == 'GET':
            takedownid = url_suffix.split('/')[3]
            response = create_comments_get(takedownid)

        elif re.match(r'/v1/takedowns/%s/comments' % UUID_REGEX, url_suffix) and method == 'POST':
            takedownid = url_suffix.split('/')[3]
            response = create_comments_post(takedownid)
        elif url_suffix == '/v1/takedown-brands':
            response = create_brand_list()
        elif url_suffix == '/v1/takedowns' and method == "GET":
            limit = params['limit']
            response = create_takedown_get(limit)
        elif url_suffix == '/v1/takedowns' and method == "POST":
            response = create_takedown_post(kwargs['json_data'])
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
            "event-action": "create",
            "risk-level": "high",
            "risk-type": "test",
            "classification": "test",
            "state": "unread"
        } for event_num in range(start_event_num, num_of_events + start_event_num)
    ]


def test_fetch_takedown_command(mocker, client: Client):
    """
    Given:
     - 100 events

    When:
     - running the fetch_incidents_command

    Then:
     - make sure that all events are enriched and fetched (5000)
    """
    from ReliaquestTakedown import fetch_takedowns
    http_mocker = ClientMock(100, num_of_alerts=100, num_of_incidents=100)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )

    last_run = {"takedown": {"last_fetch": 0}}
    next_run, events = fetch_takedowns(10, last_run, client)
    assert len(events) == 10


def test_create_comment_command(mocker, client: Client):
    http_mocker = ClientMock(5000, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    takedown_id = "e796945e-943c-4b44-a5d2-4f897d04f81f"
    res = create_comment(client, {"takedownId": takedown_id, "comment": "test comment"})
    assert len(res) is not None
    assert res['takedown-id'] == takedown_id


def test_list_brands_command(mocker, client: Client):
    http_mocker = ClientMock(5000, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    res = list_brands(client, {})
    assert len(res) is not None


def test_create_takedown_command(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    res = create_takedown(client, {"brandId": "14718933-7fdf-484b-bd45-a873c8ac2fba", "type": "impersonation",
                                   "target": "https://www.digitalshadowsresearch13.com/adobe"})
    assert len(res) is not None

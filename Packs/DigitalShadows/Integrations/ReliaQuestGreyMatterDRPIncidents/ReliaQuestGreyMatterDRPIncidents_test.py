from __future__ import annotations
import hashlib
import random

from Packs.DigitalShadows.Integrations.ReliaQuestGreyMatterDRPIncidents.ReliaQuestGreyMatterDRPIncidents import search_find

import pytest

from CommonServerPython import *
from ReliaQuestGreyMatterDRPIncidents import \
    Client

TEST_URL = "https://test.com/api"

RISK_TYPES = ['exposed-credential', 'impersonating-domain',
              'impersonating-subdomain', 'unauthorized-code-commit', 'exposed-access-key']


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


def create_alert_with_risk_type(id, risk_type):
    return [
        {
            "id": _id,
            "portal-id": "BFM9J",
            "risk-type": risk_type,
            "classification": "exposed-credential-alert",
            "risk-assessment": {
                "risk-level": "low"
            },
            "risk-factors": [
                "Exposed on open source",
                "Plain text password",
                "More than a year old when raised"
            ],
            "title": "The alert title",
            "description": "A description of this alert",
            "assets": [
                {
                    "id": "1de8c226-16ef-4c44-a2b4-11a769e6b377"
                }
            ],
            "raised": "2020-04-01T08:30:00Z",
            "updated": "2020-04-01T08:30:00Z",
            "email": "username@example.org",
            "password": "P@ssw0rd",
            "inferred-password-type": "scrypt",
            "first-seen": "2020-04-01T08:30:00Z"
        } for _id in id]


def create_search_find_response():
    return {
        "content": [],
        "total": 0
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

        elif url_suffix == "/v1/triage-items":
            triage_item_ids = params["id"]
            triage_item_alerts = triage_item_ids[:self.num_of_alerts - self.num_of_fetched_alerts]
            alerts_response = create_triage_items_from_events(triage_item_alerts, item_type="alert-id")
            triage_item_incidents = triage_item_ids[self.num_of_alerts - self.num_of_fetched_alerts:]
            incidents_response = create_triage_items_from_events(triage_item_incidents, item_type="incident-id")

            self.num_of_fetched_alerts += len(alerts_response)
            self.num_of_fetched_incidents += len(incidents_response)

            response = alerts_response + incidents_response

        elif url_suffix == "/v1/alerts":
            response = create_incidents_and_alerts_from_triaged_items(params["id"], item_type="alert-id", amount_of_assets=1)
        elif url_suffix == "/v1/incidents":
            response = create_incidents_and_alerts_from_triaged_items(params["id"], item_type="incident-id", amount_of_assets=1)
        elif url_suffix == "/v1/assets":
            response = create_assets(params["id"])
        elif url_suffix == '/v1/triage-item-comments':
            response = create_comments(params["id"])
        elif url_suffix in ['/v1/exposed-credential-alerts', '/v1/impersonating-domain-alerts',
                            '/v1/impersonating-subdomain-alerts', '/v1/unauthorized-code-commit-alerts',
                            '/v1/exposed-access-key-alerts']:
            response = create_alert_with_risk_type(params["id"], url_suffix.split('/')[-1])
        elif url_suffix == '/api/search/find':
            response = create_search_find_response()
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


def create_triage_items_from_events(triage_item_ids: List[str], item_type: str) -> List[Dict]:
    if item_type not in {"incident-id", "alert-id"}:
        raise ValueError(f'item-type {item_type} must be one of incident-id/alert-id')

    return [
        {
            "id": triage_item_id,
            "title": "title",
            "state": "unread",
            "raised": "date",
            "source": {
                item_type: triage_item_id
            },
            "risk-type": random.choice(RISK_TYPES)
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
            "type": f"asset-{_id}",
            "approval-state": "accepted",
            "display-value": "test"

        } for _id in asset_ids
    ]


def create_comments(comment_ids):
    return [
        {
            "id": _id,
            "triage-item-id": _id,
            "content": f"test content-{_id}",
            "updated": "2020-04-01T08:30:00Z",
            "created": "2020-04-01T08:30:00Z",
            "user": None
        } for _id in comment_ids
    ]


def test_fetch_incidents_command(mocker, client: Client):
    """
    Given:
     - 100 events

    When:
     - running the fetch_incidents_command

    Then:
     - make sure that all events are enriched and fetched (5000)
    """
    from ReliaQuestGreyMatterDRPIncidents import fetch_incidents
    http_mocker = ClientMock(100, num_of_alerts=100, num_of_incidents=100)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )

    sinceDate = "2009-01-20T00:00:00Z"
    sinceDate = arg_to_datetime(sinceDate)
    last_run = {"incidents": {"last_fetch": 0}}
    next_run, events = fetch_incidents(100, last_run, True, ["high"], [], client, sinceDate)
    assert len(events) == 100


def test_search_find_command(mocker, client: Client):
    http_mocker = ClientMock(5000, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    res = search_find(client, {"query": "md5"})
    assert len(res) is not None

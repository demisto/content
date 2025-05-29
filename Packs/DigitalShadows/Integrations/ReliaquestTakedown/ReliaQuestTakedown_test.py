from __future__ import annotations

import random
import re
import uuid

import pytest

from CommonServerPython import *
from ReliaquestTakedown import \
    Client

from Packs.DigitalShadows.Integrations.ReliaquestTakedown.ReliaquestTakedown import create_comment, list_brands, create_takedown, \
    download_attachment, test_module, upload_attachment, get_modified_remote_data_command

UUID_REGEX = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
NUMBER_REGEX = r'[0-9]{1,}'
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
        if url_suffix == '/v1/test':
            response = test_response()
        elif re.match(r"/v1/takedowns/attachments/%s/download" % UUID_REGEX, url_suffix) and method == 'GET':
            return download_attachment_get()
        elif re.match(r"/v1/takedowns/%s/attachments" % UUID_REGEX, url_suffix) and method == 'POST':
            response = {}
        elif url_suffix == '/api/search/find':
            response = create_comments_post()
        elif re.match(r'/v1/takedowns/%s/comments' % UUID_REGEX, url_suffix) and method == 'GET':
            takedownid = url_suffix.split('/')[3]
            response = create_comments_get(takedownid)
        elif re.match(r'/v1/takedowns/%s/comments' % UUID_REGEX, url_suffix) and method == 'POST':
            takedownid = url_suffix.split('/')[3]
            response = create_comments_post(takedownid)

        elif re.match(r'^/v1/takedown-events\?limit=[^&]+&event-num-after=[^&]+$', url_suffix) and method == 'GET':
            response = get_takedown_events()
        elif url_suffix == '/v1/takedown-brands':
            response = create_brand_list()
        elif url_suffix == '/v1/takedowns' and method == "GET":
            limit = params['limit']
            response = create_takedown_get(limit)
        elif url_suffix == '/v1/takedowns' and method == "POST" and kwargs['json_data']['brand'] == 'rate_limit':
            return create_takedown_rate_limit()
        elif url_suffix == '/v1/takedowns' and method == "POST":
            response = create_takedown_post(kwargs['json_data'])
        else:
            response = []

        return create_mocked_response(response)


def create_takedown_rate_limit():
    response = requests.Response()
    response.headers = {"ratelimit-limit": "10",
                        'ratelimit-remaining': '3',
                        'ratelimit-reset': '1'}
    response.status_code = 403
    return response


def test_response():
    data = [
        {"message": "accountId' is invalid"},
        {"api-key-valid": "accountId' is invalid"},
        {"access-account-enabled": "accountId' is invalid"},
        {"account-api-enabled": "accountId' is invalid"},
        {"account-id-valid": "accountId' is invalid"},
        {},
    ]
    random.shuffle(data)
    return data[1]


def get_takedown_events():
    get_incidents_list_response = load_test_data('./test_data/get_events.json')
    return get_incidents_list_response


def download_attachment_get():
    path = 'test_data/file-sample.pdf'
    try:
        with open(path, 'rb') as file:
            file_data = file.read()
        response = requests.Response()
        response.status_code = 200
        response._content = file_data
        response.headers = {"Content-Type": "application/octet-stream",
                            'Content-Disposition': 'attachment; filename="test_data/file-sample1.pdf"'}

        return response
    except FileNotFoundError:
        return requests.Response("File not found.", status_code=404)


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


def test_download_attachment_command(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    try:
        download_attachment(client, {"attachmentId": "14718933-7fdf-484b-bd45-a873c8ac2fba"})
    except Exception:
        pass


def test_upload_download_attachment_command(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    upload_attachment(client, {"fileId": "test_data/file-sample.pdf", 'takedownId': "14718933-7fdf-484b-bd45-a873c8ac2fba"})


def test_test_module_command(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    for i in range(20):
        test_module(client)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_get_modified_remote_data(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    modified_ids, last_num = get_modified_remote_data_command(client, '0')
    assert len(modified_ids.modified_incident_ids) == 10
    assert modified_ids.modified_incident_ids == ['1f1fe26c-b310-415d-9c02-6212a692cbd7', '59df3261-a5fd-4353-8f7b-32f64d2c5016',
                                                  '9c4a5e44-5c64-46b8-ae9f-72a5316ae07c', '18a9e57c-39c8-4799-b1e8-75f582bad994',
                                                  '04fc661f-e940-4acf-bbc3-8ba44c39270d', 'e0837d78-9b88-47c8-8f13-fc4474243867',
                                                  'e796945e-943c-4b44-a5d2-4f897d04f81f', 'ba269067-1b08-46ce-99af-c6fff088d0e7',
                                                  '93a41e46-185b-4ed1-a9a2-1999234a6fb8', '1f1fe26c-b310-415d-9c02-6212a692cbd7']


def test_create_takedown_command_ratelimit(mocker, client: Client):
    http_mocker = ClientMock(100, num_of_alerts=2500, num_of_incidents=2500)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=http_mocker.http_request_side_effect
    )
    try:
        create_takedown(client, {"brandId": "rate_limit", "type": "impersonation",
                                 "target": "https://www.digitalshadowsresearch13.com/adobe"})
    except Exception:
        pass

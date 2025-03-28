import json
from urllib.parse import urlencode

import pytest
from ZeroFox_Key_Incidents import KeyIncident, ZeroFox

BASE_URL = "https://api.zerofox.com"
OK_CODES = (200,)
TOKEN = "token"

KEY_INCIDENTS_ENDPOINT = "/cti/key-incidents/"
KEY_INCIDENT_ATTACHMENTS_ENDPOINT = "/cti/key-incident-attachments"
CTI_TOKEN_ENDPOINT = "/auth/token/"


@pytest.fixture
def zerofox() -> ZeroFox:
    return ZeroFox(
        base_url=BASE_URL,
        ok_codes=OK_CODES,
        username='',
        token=TOKEN,
    )


def load_json(file: str):
    with open(file) as f:
        return json.load(f)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_key_incidents(requests_mock, zerofox, mocker):
    requests_mock.post("/auth/token/", json={"access": "token"})
    start_time = "2022-05-24"
    end_time = "2022-05-25"
    first_page_response = load_json(
        "test_data/key_incidents/key_incidents_response_first_page.json",
    )
    first_url_params = urlencode(
        {
            'Tags': 'Key Incident',
            'updated_after': start_time,
            'updated_before': end_time,
            'ordering': 'updated'
        }
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{first_url_params}",
        json=first_page_response,
    )
    second_page_response = load_json(
        "test_data/key_incidents/key_incidents_response_second_page.json"
    )
    second_url_params = urlencode(
        {
            'Tags': 'Key Incident',
            'updated_after': start_time,
            'updated_before': end_time,
            'ordering': 'updated',
            'cursor': 'nextPageCursor'
        }
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{second_url_params}",
        json=second_page_response,
    )

    expected = [
        KeyIncident.from_dict(ki)
        for ki in load_json("test_data/key_incidents/parsed_key_incidents.json").get("key_incidents")
    ]
    ki = zerofox.get_key_incidents(
        start_time=start_time, end_time=end_time)

    assert len(ki) == len(expected)
    assert (
        sorted(ki, key=lambda x: x.incident_id)
        == sorted(expected, key=lambda x: x.incident_id)
    )

def test_get_key_incident_attachment(requests_mock, zerofox, mocker):
    ATTACHMENT_ID = 123
    expected = load_json("test_data/key_incident_attachments/parsed_ki_attachment.json")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get(
        f"{KEY_INCIDENT_ATTACHMENTS_ENDPOINT}/{ATTACHMENT_ID}/",
        json=load_json("test_data/key_incident_attachments/ki_attachment.json"),
    )
    attachment = zerofox.get_key_incident_attachment(ATTACHMENT_ID)

    assert expected == attachment.to_dict()

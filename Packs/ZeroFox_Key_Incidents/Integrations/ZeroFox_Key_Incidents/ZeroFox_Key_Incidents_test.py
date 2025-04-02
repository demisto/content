import json
from pathlib import Path
from urllib.parse import urlencode

import freezegun
import pytest
from ZeroFox_Key_Incidents import (
    KeyIncident,
    ZeroFox,
    ZeroFoxKIAttachmentNotFoundException,
    demisto,
    fetch_incidents,
    get_key_incident_attachment_command,
    map_key_incident_to_xsoar,
)

BASE_URL = "https://api.zerofox.com"
OK_CODES = (200,)
TOKEN = "token"

KEY_INCIDENTS_ENDPOINT = "/cti/key-incidents/"
KEY_INCIDENT_ATTACHMENTS_ENDPOINT = "/cti/key-incident-attachment"
CTI_TOKEN_ENDPOINT = "/auth/token/"


@pytest.fixture
def zerofox() -> ZeroFox:
    return ZeroFox(
        base_url=BASE_URL,
        ok_codes=OK_CODES,
        username="",
        token=TOKEN,
    )


def load_json(file: str):
    with open(file) as f:
        return json.load(f)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_key_incidents(requests_mock, zerofox):
    requests_mock.post(CTI_TOKEN_ENDPOINT, json={"access": "token"})
    start_time = "2022-05-24"
    end_time = "2022-05-25"
    first_page_response = load_json(
        "test_data/key_incidents/key_incidents_response_first_page.json",
    )
    first_url_params = urlencode(
        {"Tags": "Key Incident", "updated_after": start_time, "updated_before": end_time, "ordering": "updated"}
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{first_url_params}",
        json=first_page_response,
    )
    second_page_response = load_json("test_data/key_incidents/key_incidents_response_second_page.json")
    second_url_params = urlencode(
        {
            "Tags": "Key Incident",
            "updated_after": start_time,
            "updated_before": end_time,
            "ordering": "updated",
            "cursor": "nextPageCursor",
        }
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{second_url_params}",
        json=second_page_response,
    )

    expected = [
        KeyIncident.from_dict(ki) for ki in load_json("test_data/key_incidents/parsed_key_incidents.json").get("key_incidents")
    ]
    ki = zerofox.get_key_incidents(start_time=start_time, end_time=end_time)

    assert len(ki) == len(expected)
    assert sorted(ki, key=lambda x: x.incident_id) == sorted(expected, key=lambda x: x.incident_id)


def test_get_key_incident_attachment(requests_mock, zerofox, mocker):
    ATTACHMENT_ID = 123
    expected = load_json("test_data/key_incident_attachments/parsed_ki_attachment.json")
    requests_mock.post(CTI_TOKEN_ENDPOINT, json={"access": "token"})
    requests_mock.get(
        f"{KEY_INCIDENT_ATTACHMENTS_ENDPOINT}/{ATTACHMENT_ID}/",
        json=load_json("test_data/key_incident_attachments/ki_attachment.json"),
    )
    attachment = zerofox.get_key_incident_attachment(ATTACHMENT_ID)

    assert expected == attachment.to_dict()


def test_key_incident_attachment_not_found(requests_mock, zerofox):
    ATTACHMENT_ID = 123
    requests_mock.post(CTI_TOKEN_ENDPOINT, json={"access": "token"})
    requests_mock.get(
        f"{KEY_INCIDENT_ATTACHMENTS_ENDPOINT}/{ATTACHMENT_ID}/",
        status_code=404,
    )
    with pytest.raises(ZeroFoxKIAttachmentNotFoundException):
        zerofox.get_key_incident_attachment(ATTACHMENT_ID)


def test_create_xsoar_incidents():
    ki_list = [
        KeyIncident.from_dict(ki) for ki in load_json("test_data/key_incidents/parsed_key_incidents.json").get("key_incidents")
    ]

    xsoar_incidents = []
    for ki in ki_list:
        xsoar_incidents.append(map_key_incident_to_xsoar(ki))

    expected_names = [ki.incident_id + " " + ki.headline for ki in ki_list]
    actual_names = [incident.name for incident in xsoar_incidents]

    assert expected_names == actual_names
    assert len(xsoar_incidents) == 8


@freezegun.freeze_time("2022-05-25")
def test_fetch_incidents(requests_mock, zerofox):
    requests_mock.post("/auth/token/", json={"access": "token"})
    start_time = "2022-05-24T00:00:00"
    end_time = "2022-05-25T00:00:00"
    first_page_response = load_json(
        "test_data/key_incidents/key_incidents_response_first_page.json",
    )
    first_url_params = urlencode(
        {"Tags": "Key Incident", "updated_after": start_time, "updated_before": end_time, "ordering": "updated"}
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{first_url_params}",
        json=first_page_response,
    )
    second_page_response = load_json("test_data/key_incidents/key_incidents_response_second_page.json")
    second_url_params = urlencode(
        {
            "Tags": "Key Incident",
            "updated_after": start_time,
            "updated_before": end_time,
            "ordering": "updated",
            "cursor": "nextPageCursor",
        }
    )
    requests_mock.get(
        f"{KEY_INCIDENTS_ENDPOINT}?{second_url_params}",
        json=second_page_response,
    )

    last_run = {"time": start_time}
    first_fetch_time = ""

    expected_time = "2022-05-20T18:49:20.917000+00:00"

    last_run, incidents = fetch_incidents(zerofox, last_run, first_fetch_time)

    assert last_run == {"time": expected_time}

    expected_results = first_page_response.get("results", []) + second_page_response.get("results", [])
    for index, ki_expected in enumerate(expected_results):
        assert incidents[index].get("name") == f"{ki_expected.get('incident_id')} {ki_expected.get('headline')}"
        assert incidents[index].get("occurred") == ki_expected.get("created_at").replace("Z", "+00:00")
        assert incidents[index].get("dbotMirrorId") == ki_expected.get("incident_id")


@pytest.fixture
def mock_file_id(mocker):
    file_id = "dummyId"
    patcher = mocker.patch.object(demisto, "uniqueFile", return_value=file_id)

    yield file_id

    patcher.stop()
    try:
        file_path = Path(f"1_{file_id}")
        if file_path.exists():
            file_path.unlink()
    except Exception:
        pass


def test_get_key_incident_attachment_command(requests_mock, zerofox, mock_file_id):
    """
    Given
        A Key Incident Attachment Id
    When
        Calling get_key_incident_attachment_command
    Then
        It should return a file with attachment contents
    """
    attachment_id = 123
    ki_attachment = load_json("test_data/key_incident_attachments/ki_attachment.json")
    requests_mock.post(CTI_TOKEN_ENDPOINT, json={"access": "token"})
    requests_mock.get(
        f"/cti/key-incident-attachments/{attachment_id}/",
        json=ki_attachment,
    )
    args = {"attachment_id": attachment_id}

    results = get_key_incident_attachment_command(zerofox, args)

    expected = {
        "Contents": "",
        "ContentsFormat": "text",
        "File": ki_attachment.get("name"),
        "FileID": mock_file_id,
        "Type": 3,
    }

    assert results == expected

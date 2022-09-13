from requests_mock import Mocker
from accessdata.client import Client
from accessdata.api.extensions import status_check_ext, trigger_workflow_ext
from Exterro import _trigger_workflow

API_URL = "http://localhost:443/"
API_KEY = "API-TEST-KEY"


def generate_mock_client():
    """Creates a mock client using falsified
    information.

    :return: Client
    """

    with Mocker() as mocker:
        mocker.get(
            API_URL + status_check_ext[1],
            status_code=200,
            json="Ok"
        )
        client = Client(API_URL, API_KEY)

    return client


def test_mock_client():
    """Tests the client generator."""
    client = generate_mock_client()

    assert client.session.status_code == 200

    # assert client.session.headers == {
    #     "EnterpriseApiKey": API_KEY
    # }


def test_mock_trigger_workflow():
    """Tests the FTK Connect workflow trigger."""

    client = generate_mock_client()
    with Mocker() as mocker:
        mocker.post(API_URL + trigger_workflow_ext[1].format(workflowid="1"), json=True)

        workflow_params = {
            "automation_id": "1",
            "case_ids": "1",
            "evidence_path": "\\\\localhost\\Evidence",
            "search_tag_path": "\\\\localhost\\ScanAndTag",
            "export_path": "\\\\localhost\\Exports",
            "target_ips": "127.0.0.1"
        }
        result = _trigger_workflow(client, **workflow_params)
        outputs = result.outputs

        assert outputs["Status"] is True

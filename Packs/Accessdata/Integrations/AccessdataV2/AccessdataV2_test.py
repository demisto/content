from requests_mock import Mocker

from accessdata.client import Client
from accessdata.api.extensions import (
    attribute_list_ext,
    case_list_ext,
    server_setting_ext,
    status_check_ext
)

from AccessdataV2 import _get_case_by_name

API_URL = "http://randomurl.com/"
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

    assert client.session.headers == {
        "EnterpriseApiKey": API_KEY
    }


def test_mock_case_list():
    """Tests the case list getter."""
    client = generate_mock_client()

    with Mocker() as mocker:
        mocker.get(
            API_URL + case_list_ext[1],
            status_code=200,
            json=[
                {
                    "id": 1,
                    "name": "Test Case",
                    "casepath": "\\\\FTKC\\Cases\\Test Case"
                }
            ]
        )
        mocker.get(
            API_URL + attribute_list_ext[1],
            status_code=200,
            json=[]
        )
        mocker.get(
            API_URL + server_setting_ext[1].format(setting="FTKDefaultPath"),
            status_code=200,
            json="\\\\FTKC\\Cases"
        )

        cases = client.cases

        assert len(cases) == 1

        results = _get_case_by_name(client, "Test Case")
        outputs = results.outputs

        assert outputs.get("ID") == 1
        assert outputs.get("Name") == "Test Case"


test_mock_case_list()

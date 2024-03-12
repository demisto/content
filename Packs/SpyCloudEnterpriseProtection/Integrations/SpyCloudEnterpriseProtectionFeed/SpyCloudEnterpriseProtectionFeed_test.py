import pytest
import json
from SpyCloudEnterpriseProtectionFeed import (
    Client,
    fetch_incident,
    create_spycloud_args,
    remove_duplicate,
)
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


client = Client(
    base_url="http://test.com/", apikey="test_123", proxy=False, verify=False
)
WATCHLIST_DATA = util_load_json("test_data/breach_data_by_indicator.json")
INCIDENTS = util_load_json("test_data/incidents.json")
MODIFIED_RESPONSE = util_load_json("test_data/modified_response.json")


class MockResponse:
    def __init__(self, status_code, headers=None, json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.json_data = json_data or {}

    def json(self):
        return self.json_data


def test_spy_cloud_error_handler():
    # test case for 429 Limit Exceed
    response = MockResponse(
        status_code=429,
        headers={"x-amzn-ErrorType": "LimitExceededException"},
    )
    err_msg = "You have exceeded your monthly quota. Kindly contact SpyCloud support."
    with pytest.raises(DemistoException, match=err_msg):
        client.spy_cloud_error_handler(response)

    # test case for 403 Invalid IP
    response = MockResponse(status_code=403, headers={"SpyCloud-Error": "Invalid IP"})
    with pytest.raises(DemistoException):
        client.spy_cloud_error_handler(response)

    # test case for 403 Invalid API Key
    response = MockResponse(
        status_code=403, headers={"SpyCloud-Error": "Invalid API key"}
    )
    err_msg = (
        "Authorization Error:"
        " The provided API Key for SpyCloud is invalid."
        " Please provide a valid API Key."
    )
    with pytest.raises(DemistoException, match=err_msg):
        client.spy_cloud_error_handler(response)

    # test case for other errors
    response = MockResponse(
        status_code=500, json_data={"message": "Internal server error"}
    )
    with pytest.raises(DemistoException, match="Internal server error"):
        client.spy_cloud_error_handler(response)


def test_query_spy_cloud_api_success(requests_mock):
    endpoint = "watchlist"
    req_url = f"{client._base_url}{endpoint}"
    requests_mock.get(req_url, json=WATCHLIST_DATA)
    response = client.query_spy_cloud_api(endpoint, {})
    assert response == WATCHLIST_DATA


@pytest.mark.parametrize(
    "raw_response, expected",
    [
        (WATCHLIST_DATA, INCIDENTS),
    ],
)
def test_fetch_incident_command(mocker, raw_response, expected):
    mocker.patch.object(client, "query_spy_cloud_api", return_value=raw_response)
    mocker.patch.object(client, "get_last_run", return_value="2023-05-30")
    response = fetch_incident(client, {})
    assert response == expected


def test_create_spycloud_args():
    args = {"severity": "2, 1"}
    with pytest.raises(DemistoException):
        create_spycloud_args(args, client)


def test_remove_duplicate():
    result = remove_duplicate(WATCHLIST_DATA["results"], MODIFIED_RESPONSE["results"])
    assert MODIFIED_RESPONSE["results"] == result

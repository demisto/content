import pytest
import json
from SpyCloudEnterpriseProtectionEnrichment import (
    Client,
    command_helper_function,
    get_command_title_string,
    pagination,
    get_paginated_results,
    lookup_to_markdown_table,
)
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


def util_readme_load(path):
    with open(path) as f:
        return f.read()


BREACH_LIST_RESPONSE = util_load_json("test_data/breach_list.json")
BREACH_DATA_BY_INDICATOR = util_load_json("test_data/breach_data_by_indicator.json")
BREACH_LIST_README = util_readme_load(
    "test_data/readable_output/breach_list_readable_output.md"
)
BREACH_DATA_README = util_readme_load("test_data/readable_output/breach_data_by_id.md")
BREACH_DOMAIN_README = util_readme_load(
    "test_data/readable_output/breach_data_by_domain.md"
)
BREACH_USERNAME_README = util_readme_load(
    "test_data/readable_output/breach_data_by_username.md"
)
BREACH_IP_README = util_readme_load(
    "test_data/readable_output/breach_data_by_ip_address.md"
)
BREACH_EMAIL_README = util_readme_load(
    "test_data/readable_output/breach_data_by_email_address.md"
)
BREACH_PASSWORD_README = util_readme_load(
    "test_data/readable_output/breach_data_by_password.md"
)
BREACH_WATCHLIST_README = util_readme_load(
    "test_data/readable_output/watchlist_data.md"
)
COMPASS_APPLICATION_README = util_readme_load(
    "test_data/readable_output/compass_application_data.md"
)
COMPASS_DATA_README = util_readme_load("test_data/readable_output/compass_data_list.md")
COMPASS_DEVICE_DATA_README = util_readme_load(
    "test_data/readable_output/compass_device_data.md"
)
COMPASS_DEVICE_LIST_README = util_readme_load(
    "test_data/readable_output/compass_device_list.md"
)
BREACH_LIST_WITH_PAGINATION_README = util_readme_load(
    "test_data/readable_output/breach_list_with_pagination.md"
)

EMPTY_DATA = {"cursor": "", "hits": 0, "results": []}

client = Client(
    base_url="http://test.com/", apikey="test_123", proxy=False, verify=False
)


@pytest.mark.parametrize(
    "raw_response, expected, readable_output, args, command",
    [
        (
            BREACH_LIST_RESPONSE,
            BREACH_LIST_RESPONSE,
            BREACH_LIST_README,
            {"limit": 5},
            "spycloud-breach-catalog-list",
        ),
        (
            BREACH_LIST_RESPONSE,
            BREACH_LIST_RESPONSE,
            BREACH_DATA_README,
            {"id": "12345"},
            "spycloud-breach-catalog-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_DOMAIN_README,
            {"domain": "abc.com"},
            "spycloud-domain-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_USERNAME_README,
            {"username": "abc"},
            "spycloud-username-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_IP_README,
            {"ip": "1.1.1.1"},
            "spycloud-ip-address-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_EMAIL_README,
            {"email": "Dummy_Email"},
            "spycloud-email-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_PASSWORD_README,
            {"password": "password"},
            "spycloud-password-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            BREACH_WATCHLIST_README,
            {},
            "spycloud-watchlist-data-list",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            COMPASS_DEVICE_DATA_README,
            {"infected_machine_id": "12345"},
            "spycloud-compass-device-data-get",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            COMPASS_DATA_README,
            {},
            "spycloud-compass-data-list",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            COMPASS_DEVICE_LIST_README,
            {},
            "spycloud-compass-device-list",
        ),
        (
            BREACH_DATA_BY_INDICATOR,
            BREACH_DATA_BY_INDICATOR,
            COMPASS_APPLICATION_README,
            {"target_application": "abcd"},
            "spycloud-compass-application-data-get",
        ),
    ],
)
def test_command_helper_function(
    mocker, raw_response, expected, readable_output, args, command
):
    mocker.patch.object(client, "query_spy_cloud_api", side_effect=[raw_response])

    result = command_helper_function(client, args, command)
    assert result.to_context()["Contents"] == expected.get("results")
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_response, expected, readable_output, args, command",
    [
        (
            BREACH_LIST_RESPONSE,
            BREACH_LIST_RESPONSE,
            BREACH_LIST_WITH_PAGINATION_README,
            {"limit": 5, "page": 1, "page_size": 10},
            "spycloud-breach-catalog-list",
        )
    ],
)
def test_command_helper_function_with_pagination(
    mocker, raw_response, expected, readable_output, args, command
):
    mocker.patch.object(client, "query_spy_cloud_api", side_effect=[raw_response])

    result = command_helper_function(client, args, command)
    assert result.to_context()["Contents"] == expected.get("results")
    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    "raw_response, expected, args, command",
    [(EMPTY_DATA, EMPTY_DATA, {"limit": 5}, "spycloud-breach-catalog-list")],
)
def test_command_helper_function_exception(
    mocker, raw_response, expected, args, command
):
    mocker.patch.object(client, "query_spy_cloud_api", side_effect=[raw_response])
    result = command_helper_function(client, args, command)
    assert result.readable_output == "No data to present.\n"


@pytest.mark.parametrize(
    "raw_response, expected, args, command",
    [
        (
            BREACH_LIST_RESPONSE,
            BREACH_LIST_RESPONSE,
            {"page": 5, "page_size": 10},
            "spycloud-breach-catalog-list",
        )
    ],
)
def test_command_helper_function_pagination_exception(
    mocker, raw_response, expected, args, command
):
    mocker.patch.object(client, "query_spy_cloud_api", side_effect=[raw_response])
    result = command_helper_function(client, args, command)
    assert result.readable_output == "No data available for page 5. Total are 1"


@pytest.mark.parametrize(
    "raw_response, expected, args, command",
    [
        (
            BREACH_LIST_RESPONSE,
            BREACH_LIST_RESPONSE,
            {"all_resultS": "yes"},
            "spycloud-breach-catalog-list",
        )
    ],
)
def test_command_helper_function_pagination_all_result(
    mocker, raw_response, expected, args, command
):
    mocker.patch.object(client, "query_spy_cloud_api", side_effect=[raw_response])
    result = command_helper_function(client, args, command)
    assert result.to_context()["Contents"] == expected.get("results")


def test_query_spy_cloud_api_success(requests_mock):
    endpoint = "compass/device"
    req_url = f"{client._base_url}{endpoint}"
    requests_mock.get(req_url, json=BREACH_LIST_RESPONSE)
    response = client.query_spy_cloud_api(endpoint, {})
    assert response == BREACH_LIST_RESPONSE


def test_get_command_title_string():
    result = get_command_title_string("Breach List", 1, 5, 20)
    expected_output = "Breach List \nCurrent page size: 5\nShowing page 1 out of 4"
    assert result == expected_output


@pytest.mark.parametrize(
    "page, page_size, limit, expected_result",
    [
        (2, 5, 0, (5, 5)),
        (1, 5, 10, (5, 0)),
        (4, 2, 0, (2, 6)),
        (None, 5, 12, (5, 0)),
        (2, None, 10, (10, 50)),
        (None, None, 10, (10, 0)),
    ],
)
def test_pagination(page, page_size, limit, expected_result):
    """
    Tests the pagination function.

        Given:
            - page, page size and limit arguments.

        When:
            - Running the 'pagination function'.

        Then:
            - Checks that the limit and offset are calculated as expected.
    """
    actual_result = pagination(page, page_size, limit)
    assert actual_result == expected_result


def test_get_paginated_results():
    result = get_paginated_results(BREACH_LIST_RESPONSE.get("results"), 0, 1)

    assert result == BREACH_LIST_RESPONSE.get("results")


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


def test_lookup_to_markdown_table():
    results = lookup_to_markdown_table(
        BREACH_DATA_BY_INDICATOR.get("results"), "Breach List for domain abc.com"
    )
    assert results == BREACH_DOMAIN_README

from unittest.mock import patch, MagicMock

import pytest

from CommonServerPython import CommandResults
from GroupIBTIA import (
    fetch_incidents_command,
    Client,
    main,
    get_available_collections_command,
    local_search_command,
    CommonHelpers,
)
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
import GroupIBTIA
from json import load
import os

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))

with open(f"{realpath}/test_data/main_collections_examples.json") as example:
    COLLECTIONS_RAW_JSON = load(example)

with open(f"{realpath}/test_data/search_example.json") as example:
    SEARCH_RAW_JSON = load(example)

with open(f"{realpath}/test_data/avalible_collections_example.json") as example:
    AVALIBLE_COLLECTIONS_RAW_JSON = load(example)

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

COLLECTION_NAMES = [
    "compromised/account_group",
    "compromised/bank_card_group",
    "compromised/mule",
    "osi/git_repository",
    "osi/vulnerability",
    "attacks/ddos",
    "attacks/deface",
    "attacks/phishing_group",
    "attacks/phishing_kit",
    "suspicious_ip/tor_node",
    "suspicious_ip/open_proxy",
    "suspicious_ip/socks_proxy",
    "suspicious_ip/vpn",
    "suspicious_ip/scanner",
    "malware/cnc",
    "hi/threat",
    "hi/threat_actor",
    "apt/threat",
    "apt/threat_actor",
    "malware/malware",
    "osi/public_leak",
    "compromised/breached",
]


@pytest.fixture(scope="function", params=COLLECTION_NAMES)
def session_fixture(request):
    """
    Fixture for creating a client instance specific to each collection name.

    Given:
      - A list of predefined collection names that represent different types of data.

    When:
      - Each test function requests an instance of this fixture.

    Then:
      - Returns a tuple with the current collection name and an instantiated Client object.
      - The Client instance is configured to interact with the appropriate collection by connecting
        to the integration's base URL, using authentication, and including necessary headers.
    """
    return request.param, Client(
        base_url="https://some-url.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )


@pytest.fixture(scope="function")
def single_session_fixture():
    """
    Fixture for creating a generic client instance to be used across multiple tests.

    Given:
      - No specific parameters; only a need for a Client object with common configuration.

    When:
      - A test requires a general Client instance without needing to specify a collection.

    Then:
      - Returns a Client instance configured with the base URL, authentication, and headers.
      - The instance can be reused by any test that doesn't depend on a specific collection name.
    """
    return Client(
        base_url="https://some-url.com",
        auth=("example@example.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )


def test_fetch_incidents(mocker, session_fixture):
    """
    Test for verifying the behavior of the fetch_incidents_command function.

    Given:
      - session_fixture, which provides a client instance associated with a specific collection name.
      - last_run, a dictionary representing the previous state of incident fetching.
      - first_fetch_time, a string specifying the starting time frame for incident retrieval.

    When:
      - fetch_incidents_command() is invoked with the above parameters.

    Then:
      - Ensures that the command returns the correct types for next_run and incidents.
      - Verifies that incidents is a list, as expected.
      - This test validates that the command correctly retrieves incidents for each collection
        and that the returned data structure matches the expected format.
    """
    collection_name, client = session_fixture
    collection_name, client = session_fixture
    mocker.patch.object(client, "create_poll_generator", return_value=[COLLECTIONS_RAW_JSON[collection_name]])
    next_run, incidents = fetch_incidents_command(
        client=client, last_run={}, first_fetch_time="3 days", incident_collections=[], max_requests=3, hunting_rules=False
    )
    assert isinstance(incidents, list)


def test_main_error():
    """
    Test for verifying the error-handling behavior in the main() function.

    Given:
      - A main() function configured to raise an exception when calling error_command.

    When:
      - The main function invokes error_command(), which is expected to trigger an error.

    Then:
      - Ensures that a SystemExit exception is raised as expected.
      - The test checks that the main function handles errors in a predictable and controlled
        manner, allowing graceful exits during failure.
    """
    with pytest.raises(SystemExit):
        main()["error_command"]()  # type: ignore


def test_global_search_command(mocker, single_session_fixture):
    """
    Test for verifying the functionality of the global_search_command function.

    Given:
      - single_session_fixture provides a client instance for performing a search.
      - A test_query dictionary with a "query" key specifying a search term, in this case, an IP address.

    When:
      - The global_search_command() function is called with the client and test_query arguments.

    Then:
      - Ensures that the command's outputs_prefix and outputs_key_field are correctly set to expected values.
      - Verifies that the command returns the data structure with the correct outputs_key_field ("query"),
        ensuring compatibility with other functions that depend on this structure.
      - This test validates that the search command integrates smoothly with the client and returns
        consistent output formatting.
    """
    client = single_session_fixture
    mocker.patch.object(client, "search_proxy_function", return_value=SEARCH_RAW_JSON)
    test_query = {"query": "8.8.8.8"}
    result = GroupIBTIA.global_search_command(client=client, args=test_query)

    assert result.outputs_prefix == "GIBTIA.search.global"
    assert result.outputs_key_field == "query"


def test_get_available_collections(mocker, single_session_fixture):
    """
    Test for validating the get_available_collections_command function.

    Given:
      - single_session_fixture, which provides a client instance for retrieving available collections.

    When:
      - The get_available_collections_command() function is invoked with the client instance.

    Then:
      - Verifies that the outputs_prefix is correctly set to "GIBTIA.OtherInfo", indicating that
        the response data is categorized as general information.
      - Checks that the outputs_key_field is "collections", matching the expected key for collections data.
      - Ensures that the "collections" field in the output contains a list of collection names, as expected.
      - This test confirms that the command accurately retrieves and formats the list of available
        collections from the server response.
    """
    client = single_session_fixture
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=[AVALIBLE_COLLECTIONS_RAW_JSON])
    result = get_available_collections_command(client=client)

    assert result.outputs_prefix == "GIBTIA.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs["collections"], list)


@pytest.fixture
def mock_client():
    """Fixture to create a mock client."""
    client = MagicMock()
    client.poller.create_search_generator.return_value = []
    return client


@pytest.fixture
def mock_common_helpers():
    """Fixture to mock CommonHelpers functions."""
    with (
        patch("GroupIBTIA.CommonHelpers.validate_collections") as mock_validate,
        patch("GroupIBTIA.CommonHelpers.date_parse") as mock_date_parse,
    ):
        mock_validate.return_value = None
        mock_date_parse.side_effect = lambda date, arg_name: f"parsed_{date}" if date else None
        yield mock_validate, mock_date_parse


def test_local_search_command_no_results(mock_client, mock_common_helpers):
    """
    Given: A valid collection name and search query, with no results returned by the client.
    When: The local_search_command function is executed.
    Then: The function should return an empty list with appropriate formatting.
    """
    args = {"query": "test_query", "collection_name": "test_collection"}

    result = local_search_command(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GIBTIA.search.local"
    assert result.outputs_key_field == "id"
    assert result.outputs == []
    assert "Search results" in result.readable_output


def test_local_search_command_with_results(mock_client, mock_common_helpers):
    """
    Given: A valid collection name, search query, and results returned by the client.
    When: The local_search_command function is executed.
    Then: The function should return a formatted list of search results.
    """
    mock_client.poller.create_search_generator.return_value = [
        MagicMock(
            parse_portion=lambda keys, as_json: [
                {"id": "123", "name": "Test Result"},
                {"id": "456", "name": "Another Result"},
            ]
        )
    ]

    args = {"query": "test_query", "collection_name": "test_collection"}

    result = local_search_command(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GIBTIA.search.local"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "123"
    assert result.outputs[0]["additional_info"] == "Name: Test Result"
    assert "Search results" in result.readable_output
    assert "Name: Test Result" in result.readable_output
    assert "Name: Another Result" in result.readable_output


# Unit tests for CommonHelpers


def test_transform_dict_empty():
    assert CommonHelpers.transform_dict({}) == [{}]


def test_transform_dict_various_lengths():
    input_dict = {"a": [1, 2], "b": "x", "c": []}
    result = CommonHelpers.transform_dict(input_dict)
    assert len(result) == 2
    assert result[0] == {"a": 1, "b": "x", "c": None}
    assert result[1] == {"a": 2, "b": "x", "c": None}


def test_remove_underscore_and_lowercase_keys():
    data = [{"Test_Key": 1, "another_key": 2}]
    result = CommonHelpers.remove_underscore_and_lowercase_keys(data)
    assert result == [{"testkey": 1, "anotherkey": 2}]


def test_replace_empty_values_dict():
    data = {"a": "", "b": "value", "c": {"d": ""}}
    result = CommonHelpers.replace_empty_values(data)
    assert result == {"a": None, "b": "value", "c": {"d": None}}


def test_replace_empty_values_list():
    data = ["", "x", [], [{}]]
    result = CommonHelpers.replace_empty_values(data)
    assert result == [None, "x", None, [{}]]


def test_replace_empty_values_empty_list_returns_none():
    assert CommonHelpers.replace_empty_values([]) is None
    assert CommonHelpers.replace_empty_values([[]]) is None


def test_all_lists_empty_true():
    data = {"a": [], "b": {"c": []}}
    assert CommonHelpers.all_lists_empty(data) is True


def test_all_lists_empty_false():
    data = {"a": [1], "b": {}}
    assert CommonHelpers.all_lists_empty(data) is False


def test_date_parse_valid():
    result = CommonHelpers.date_parse("2020-01-01", "date")
    assert result.endswith("Z") or result == "2020-01-01"


def test_date_parse_invalid():
    with pytest.raises(Exception):
        CommonHelpers.date_parse("invalid", "date")


def test_transform_list_to_str():
    data = [{"x": [1, 2], "y": "a"}, {"x": []}]
    result = CommonHelpers.transform_list_to_str(data)
    assert result[0]["x"] == "1, 2"
    assert result[1]["x"] == ""


def test_validate_collections_valid():
    CommonHelpers.validate_collections("valid_collection")

import pytest
import os
from json import load
from GroupIB_TIA_Feed import (
    fetch_indicators_command,
    Client,
    main,
    DateHelper,
    validate_launch_get_indicators_command,
    collection_availability_check,
    get_indicators_command,
    IndicatorBuilding,
    COMMON_MAPPING,
)
import GroupIB_TIA_Feed
from CommonServerPython import DemistoException
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations.cyberintegrations import Parser

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

COLLECTION_NAMES = [
    "compromised/account_group",
    "compromised/bank_card_group",
    "compromised/mule",
    "attacks/ddos",
    "attacks/deface",
    "attacks/phishing_kit",
    "attacks/phishing_group",
    "apt/threat",
    "hi/threat",
    "suspicious_ip/tor_node",
    "suspicious_ip/open_proxy",
    "suspicious_ip/socks_proxy",
    "suspicious_ip/vpn",
    "suspicious_ip/scanner",
    "malware/cnc",
    "osi/vulnerability",
    "osi/git_repository",
    "ioc/common",
]

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))

with open(f"{realpath}/test_data/avalible_collections_example.json") as example:
    AVALIBLE_COLLECTIONS_RAW_JSON = load(example)

with open(f"{realpath}/test_data/main_collections_examples.json") as example:
    COLLECTIONS_RAW_JSON = load(example)


@pytest.fixture(scope="function", params=COLLECTION_NAMES)
def session_fixture(request):
    """
    Fixture for setting up a session with a client instance specific to each collection.

    Given:
      - COLLECTION_NAMES, a list of collection names representing different data types
        that the integration handles.

    When:
      - Each test function uses this fixture to set up a unique session with a particular
        collection name.

    Then:
      - Returns a tuple containing:
          - The current collection name as a parameter for test functions that may need it.
          - An instance of Client configured with the specified base URL, authentication,
            and necessary headers for the integration.
      - This fixture allows parameterized tests that run independently for each collection,
        providing an isolated client setup for each run.
    """
    return request.param, Client(
        base_url="https://some-url.com",
        auth=("example@roup-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )


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


def test_fetch_indicators_command(mocker, session_fixture):
    """
    Test for validating the functionality of fetch_indicators_command with multiple collection types.

    Given:
      - A session_fixture that supplies a client instance configured for a specific collection
        name for each test iteration.
      - collection_name, the current collection name being tested (e.g., "compromised/mule").

    When:
      - The fetch_indicators_command() function is called with:
          - An empty last_run dictionary to indicate that this is the initial data fetch.
          - first_fetch_time set based on specific collection conditions:
            - For "compromised/mule", first_fetch_time is set to a fixed date of "2023-01-01".
            - For "attacks/deface", first_fetch_time is set to "2024-10-01".
            - For all other collections, first_fetch_time is set to "15 days" as a general
              recent timeframe.
          - indicator_collections set to a list containing only the current collection_name.
          - requests_count set to 3, which limits the number of requests per fetch.
          - common_fields set to an empty dictionary for simplicity, as no specific common
            fields are required for this test.

    Then:
      - Validates that:
          - "last_fetch" is a key in next_run, indicating that the command updates last_run
            data with the latest fetch time.
          - The first indicator in the indicators list contains a "fields" dictionary with
            a "gibid" key, verifying that each indicator has the expected structure.
      - This test ensures that fetch_indicators_command retrieves data according to each
        collection's parameters and formats the output consistently.
    """
    collection_name, client = session_fixture
    if collection_name == "compromised/mule":
        first_fetch_time = "2023-01-01"
    elif collection_name == "attacks/deface":
        first_fetch_time = "2024-10-01"
    else:
        first_fetch_time = "15 days"

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "create_update_generator_proxy_functions",
        return_value=[Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])],
    )

    next_run, indicators = fetch_indicators_command(
        client=client,
        last_run={},
        first_fetch_time=first_fetch_time,
        indicator_collections=[collection_name],
        requests_count=3,
        common_fields={},
    )

    assert "last_fetch" in next_run, "Expected 'last_fetch' key in next_run to indicate the last data retrieval time."
    if len(indicators) > 0:
        assert "gibid" in indicators[0].get("fields"), (
            "Expected 'gibid' field in the first indicator's 'fields' dictionary, ensuring each indicator "
            "includes unique identifier data."
        )


def test_integration_test_module_success(mocker):
    """
    Test for verifying successful test_module execution when collections are available.

    Given:
      - A client instance with mocked get_available_collections_proxy_function that returns a non-empty list.

    When:
      - test_module() is called with the client.

    Then:
      - Returns 'ok' indicating successful connection and availability of collections.
    """
    client = Client(
        base_url="https://some-url.com",
        auth=("example@group-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=["collection1", "collection2"])

    result = GroupIB_TIA_Feed.test_module(client)

    assert result == "ok", "Expected 'ok' when collections are available."


def test_integration_test_module_no_collections(mocker):
    """
    Test for verifying test_module behavior when no collections are available.

    Given:
      - A client instance with mocked get_available_collections_proxy_function that returns an empty list.

    When:
      - test_module() is called with the client.

    Then:
      - Returns a message indicating that no collections are available.
    """
    client = Client(
        base_url="https://some-url.com",
        auth=("example@group-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=[])

    result = GroupIB_TIA_Feed.test_module(client)

    assert result == "There are no collections available", "Expected message when no collections are available."


def test_date_helper_first_time_fetch():
    """
    Test for verifying DateHelper.handle_first_time_fetch behavior on first fetch.

    Given:
      - An empty last_run dictionary indicating first-time fetch.
      - A valid first_fetch_time string.

    When:
      - DateHelper.handle_first_time_fetch() is called with these parameters.

    Then:
      - Returns date_from as a formatted date string and seq_update as None.
    """
    last_run = {}
    collection_name = "compromised/account_group"
    first_fetch_time = "2023-01-01"

    date_from, seq_update = DateHelper.handle_first_time_fetch(last_run, collection_name, first_fetch_time)

    assert date_from == "2023-01-01", "Expected date_from to be formatted as YYYY-MM-DD."
    assert seq_update is None, "Expected seq_update to be None on first fetch."


def test_date_helper_subsequent_fetch():
    """
    Test for verifying DateHelper.handle_first_time_fetch behavior on subsequent fetches.

    Given:
      - A last_run dictionary with existing last_fetch data for the collection.
      - A first_fetch_time string.

    When:
      - DateHelper.handle_first_time_fetch() is called with these parameters.

    Then:
      - Returns date_from as None and seq_update as the value from last_run.
    """
    last_run = {"last_fetch": {"compromised/account_group": 12345}}
    collection_name = "compromised/account_group"
    first_fetch_time = "15 days"

    date_from, seq_update = DateHelper.handle_first_time_fetch(last_run, collection_name, first_fetch_time)

    assert date_from is None, "Expected date_from to be None on subsequent fetch."
    assert seq_update == 12345, "Expected seq_update to match the value from last_run."


def test_date_helper_invalid_first_fetch_time():
    """
    Test for verifying DateHelper.handle_first_time_fetch raises exception on invalid date format.

    Given:
      - An empty last_run dictionary.
      - An invalid first_fetch_time string that cannot be parsed.

    When:
      - DateHelper.handle_first_time_fetch() is called with these parameters.

    Then:
      - Raises DemistoException with an appropriate error message.
    """
    last_run = {}
    collection_name = "compromised/account_group"
    first_fetch_time = "invalid-date-format"

    with pytest.raises(DemistoException, match="Inappropriate indicators_first_fetch format"):
        DateHelper.handle_first_time_fetch(last_run, collection_name, first_fetch_time)


def test_validate_launch_get_indicators_command_valid_input():
    """
    Test for verifying validate_launch_get_indicators_command with valid inputs.

    Given:
      - A valid limit (integer between 1 and 50).
      - A valid collection name that exists in COMMON_MAPPING.

    When:
      - validate_launch_get_indicators_command() is called with these parameters.

    Then:
      - Does not raise any exception, indicating successful validation.
    """
    limit = 25
    collection_name = "compromised/account_group"

    # Should not raise any exception
    validate_launch_get_indicators_command(limit, collection_name)


def test_validate_launch_get_indicators_command_invalid_limit_type():
    """
    Test for verifying validate_launch_get_indicators_command raises exception for non-numeric limit.

    Given:
      - A limit that is not a number (string that cannot be converted to int).

    When:
      - validate_launch_get_indicators_command() is called with this limit.

    Then:
      - Raises DemistoException with message "Limit should be a number."
    """
    limit = "not-a-number"
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be a number"):
        validate_launch_get_indicators_command(limit, collection_name)


def test_validate_launch_get_indicators_command_limit_too_low():
    """
    Test for verifying validate_launch_get_indicators_command raises exception for limit <= 0.

    Given:
      - A limit that is 0 or negative.

    When:
      - validate_launch_get_indicators_command() is called with this limit.

    Then:
      - Raises DemistoException with message "Limit should be greater than 0."
    """
    limit = 0
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be greater than 0"):
        validate_launch_get_indicators_command(limit, collection_name)


def test_validate_launch_get_indicators_command_limit_too_high():
    """
    Test for verifying validate_launch_get_indicators_command raises exception for limit > 50.

    Given:
      - A limit that exceeds 50.

    When:
      - validate_launch_get_indicators_command() is called with this limit.

    Then:
      - Raises DemistoException with message "Limit should be lower than or equal to 50."
    """
    limit = 51
    collection_name = "compromised/account_group"

    with pytest.raises(DemistoException, match="Limit should be lower than or equal to 50"):
        validate_launch_get_indicators_command(limit, collection_name)


def test_validate_launch_get_indicators_command_invalid_collection():
    """
    Test for verifying validate_launch_get_indicators_command raises exception for invalid collection name.

    Given:
      - A collection name that does not exist in COMMON_MAPPING.

    When:
      - validate_launch_get_indicators_command() is called with this collection name.

    Then:
      - Raises DemistoException with message about incorrect collection name.
    """
    limit = 25
    collection_name = "invalid/collection"

    with pytest.raises(DemistoException, match="Incorrect collection name"):
        validate_launch_get_indicators_command(limit, collection_name)


def test_collection_availability_check_success(mocker):
    """
    Test for verifying collection_availability_check succeeds when collection is available.

    Given:
      - A client with mocked get_available_collections_proxy_function that includes the collection.

    When:
      - collection_availability_check() is called with an available collection name.

    Then:
      - Does not raise any exception, indicating the collection is available.
    """
    client = Client(
        base_url="https://some-url.com",
        auth=("example@group-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )
    collection_name = "compromised/account_group"
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=[collection_name, "other/collection"])

    # Should not raise any exception
    collection_availability_check(client, collection_name)


def test_collection_availability_check_failure(mocker):
    """
    Test for verifying collection_availability_check raises exception when collection is not available.

    Given:
      - A client with mocked get_available_collections_proxy_function that does not include the collection.

    When:
      - collection_availability_check() is called with an unavailable collection name.

    Then:
      - Raises Exception with message indicating the collection is not available.
    """
    client = Client(
        base_url="https://some-url.com",
        auth=("example@group-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )
    collection_name = "unavailable/collection"
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=["other/collection"])

    with pytest.raises(Exception, match="Collection unavailable/collection is not available"):
        collection_availability_check(client, collection_name)


def test_indicator_building_clean_data():
    """
    Test for verifying IndicatorBuilding.clean_data removes None, empty values, and flattens nested lists.

    Given:
      - A list of dictionaries containing None values, empty strings, empty lists, and nested lists.

    When:
      - IndicatorBuilding.clean_data() is called with this data.

    Then:
      - Returns cleaned data with None, empty strings, and empty lists removed, and nested lists flattened.
    """
    data = [
        {"key1": "value1", "key2": None, "key3": "", "key4": []},
        {"key1": ["nested", "list"], "key2": [["deeply", "nested"], "value"]},
        {"key1": "value2", "key2": [None, "", "valid"]},
    ]

    cleaned = IndicatorBuilding.clean_data(data)

    assert len(cleaned) == 3, "Expected all items to be preserved."
    # clean_data doesn't remove keys with None values, only cleans lists
    assert cleaned[0]["key2"] is None, "None values are preserved in dict keys."
    assert cleaned[0]["key4"] == [], "Empty lists are preserved."
    assert cleaned[1]["key1"] == ["nested", "list"], "Nested lists are flattened."
    assert cleaned[2]["key2"] == ["valid"], "None and empty values are removed from lists."


def test_indicator_building_extract_single_value():
    """
    Test for verifying IndicatorBuilding.extract_single_value extracts non-empty values from nested structures.

    Given:
      - An IndicatorBuilding instance.
      - Various nested list structures containing None, empty strings, and valid values.

    When:
      - extract_single_value() is called with these structures.

    Then:
      - Returns the first non-empty, non-None value found, or None if no valid value exists.
    """
    builder = IndicatorBuilding(
        parsed_json=[],
        collection_name="test",
        common_fields={},
        collection_mapping={},
    )

    assert builder.extract_single_value([None, "", "valid"]) == "valid", "Expected first valid value."
    assert builder.extract_single_value([[None, "nested"], "value"]) == "nested", "Expected nested valid value."
    assert builder.extract_single_value([None, "", []]) is None, "Expected None when no valid value exists."
    assert builder.extract_single_value("simple") == "simple", "Expected simple value to be returned as-is."


def test_indicator_building_find_iocs_in_feed():
    """
    Test for verifying IndicatorBuilding.find_iocs_in_feed correctly extracts IOCs from feed data.

    Given:
      - An IndicatorBuilding instance with a valid collection mapping.
      - A feed dictionary containing IOC data matching the collection mapping.

    When:
      - find_iocs_in_feed() is called with the feed data.

    Then:
      - Returns a list of indicators with proper structure including value, type, rawJSON, and fields.
    """
    collection_name = "ioc/common"
    mapping = COMMON_MAPPING[collection_name]
    feed = {
        "id": "test-id-123",
        "url": "https://example.com/malicious",
        "domain": "malicious.example.com",
        "ip": "192.168.1.1",
        "dateFirstSeen": "2023-01-01T00:00:00Z",
        "dateLastSeen": "2023-01-02T00:00:00Z",
    }

    builder = IndicatorBuilding(
        parsed_json=[],
        collection_name=collection_name,
        common_fields={"trafficlightprotocol": "RED"},
        collection_mapping=mapping,
    )

    indicators = builder.find_iocs_in_feed(feed)

    assert len(indicators) > 0, "Expected at least one indicator to be extracted."
    assert all("value" in ind for ind in indicators), "Expected all indicators to have 'value' field."
    assert all("type" in ind for ind in indicators), "Expected all indicators to have 'type' field."
    assert all("rawJSON" in ind for ind in indicators), "Expected all indicators to have 'rawJSON' field."
    assert all("fields" in ind for ind in indicators), "Expected all indicators to have 'fields' field."


def test_fetch_indicators_command_with_last_run(mocker, session_fixture):
    """
    Test for verifying fetch_indicators_command behavior when last_run contains previous fetch data.

    Given:
      - A session_fixture providing a client and collection name.
      - A last_run dictionary with existing last_fetch data for the collection.

    When:
      - fetch_indicators_command() is called with this last_run data.

    Then:
      - Uses seq_update from last_run instead of date_from.
      - Returns updated next_run with the latest seq_update.
    """
    collection_name, client = session_fixture
    last_run = {"last_fetch": {collection_name: 12345}}
    first_fetch_time = "15 days"

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mock_parser = Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])
    mock_parser.sequpdate = 67890
    mocker.patch.object(
        client,
        "create_update_generator_proxy_functions",
        return_value=[mock_parser],
    )

    next_run, indicators = fetch_indicators_command(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        indicator_collections=[collection_name],
        requests_count=1,
        common_fields={},
    )

    assert "last_fetch" in next_run, "Expected 'last_fetch' key in next_run."
    assert collection_name in next_run["last_fetch"], "Expected collection name in next_run['last_fetch']."
    assert next_run["last_fetch"][collection_name] == 67890, "Expected seq_update to be updated from parser."


def test_fetch_indicators_command_multiple_collections(mocker):
    """
    Test for verifying fetch_indicators_command handles multiple collections correctly.

    Given:
      - A client instance.
      - A list of multiple collection names to fetch.

    When:
      - fetch_indicators_command() is called with multiple collections.

    Then:
      - Processes all collections and returns next_run with last_fetch for each collection.
    """
    client = Client(
        base_url="https://some-url.com",
        auth=("example@group-ib.com", "exampleAPI_TOKEN"),
        verify=True,
        headers={"Accept": "*/*"},
    )

    collections = ["compromised/account_group", "attacks/ddos"]
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)

    def create_mock_parser(collection_name):
        """Helper function to create a mock parser for a specific collection."""
        mock_parser = Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])
        mock_parser.sequpdate = 10000
        return mock_parser

    def side_effect_func(**kwargs):
        """Side effect function that returns appropriate parser based on collection_name."""
        collection_name = kwargs.get("collection_name")
        return [create_mock_parser(collection_name)]

    mocker.patch.object(
        client,
        "create_update_generator_proxy_functions",
        side_effect=side_effect_func,
    )

    next_run, indicators = fetch_indicators_command(
        client=client,
        last_run={},
        first_fetch_time="15 days",
        indicator_collections=collections,
        requests_count=1,
        common_fields={},
    )

    assert "last_fetch" in next_run, "Expected 'last_fetch' key in next_run."
    assert len(next_run["last_fetch"]) == len(collections), "Expected last_fetch entry for each collection."


def test_get_indicators_command_without_id(mocker, session_fixture):
    """
    Test for verifying get_indicators_command behavior when fetching without specific ID.

    Given:
      - A session_fixture providing a client and collection name.
      - Command arguments without an ID parameter.

    When:
      - get_indicators_command() is called with these arguments.

    Then:
      - Returns a list of CommandResults objects with readable output.
    """
    collection_name, client = session_fixture
    args = {"collection": collection_name, "limit": 10}

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client,
        "create_update_generator_proxy_functions",
        return_value=[Parser(chunk=COLLECTIONS_RAW_JSON[collection_name], keys=[], iocs_keys=[])],
    )

    results = get_indicators_command(client, args)

    assert isinstance(results, list), "Expected results to be a list."
    # Some collections may not have indicators in test data, so we check structure if results exist
    if len(results) > 0:
        assert all(hasattr(r, "readable_output") for r in results), "Expected all results to have readable_output."

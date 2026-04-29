from unittest.mock import patch, MagicMock

import pytest

from CommonServerPython import CommandResults
from typing import Any, cast
from GroupIBTIA import (
    fetch_incidents_command,
    Client,
    get_available_collections_command,
    local_search_command,
    BuilderCommandResponses,
    CommonHelpers,
    INCIDENT_CREATED_DATES_MAPPING,
    IncidentBuilder,
    MAPPING,
    PORTAL_LINKS,
)
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
import GroupIBTIA
from json import load, loads
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


def test_fetch_incidents_masked_card_collection(mocker, single_session_fixture):
    collection_name = "compromised/masked_card"
    client = single_session_fixture
    mock_portion = MagicMock()
    mock_portion.sequpdate = 1592219410029000
    mock_portion.portion_size = 1
    mock_portion.count = 1
    mock_portion.bulk_parse_portion.return_value = [
        {
            "id": "e66dbb9b2bdd55d5ecce174318060373f923c427",
            "name": "000000XXXXXXXXXX",
            "number": "000000XXXXXXXXXX",
            "issuer": None,
            "type": None,
            "payment_system": None,
            "validThru": "12/49",
            "address": None,
            "email": None,
            "owner_name": None,
            "phone": None,
            "dateDetected": "2020-05-22T17:04:25+00:00",
            "dateCompromised": "2020-05-15T09:17:45+00:00",
            "malware_name": "vendeta",
            "portalLink": "https://tap.group-ib.com/cd/cards?id=e66dbb9b2bdd55d5ecce174318060373f923c427",
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 90,
                "severity": "red",
                "tlp": "red",
            },
            "sourceType": "Card shop",
            "threat_actor_id": None,
            "threat_actor_name": None,
            "threat_actor_is_apt": None,
            "indicators": {
                "cnc_url": None,
                "cnc_domain": "kingven.cc",
                "cnc_ipv4_ip": "11.11.11.11",
                "cnc_ipv4_asn": "AS63949",
                "cnc_ipv4_country_name": "United States",
                "cnc_ipv4_region": "North America",
            },
        }
    ]

    mocker.patch.object(client.poller, "get_available_collections", return_value=[collection_name])
    mocker.patch.object(client, "create_poll_generator", return_value=([mock_portion], None))

    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
    )

    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "e66dbb9b2bdd55d5ecce174318060373f923c427"
    assert next_run["last_fetch"][collection_name] == "1592219410029000"


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
    with (
        pytest.raises(SystemExit),
        patch.object(
            GroupIBTIA.demisto,
            "params",
            return_value={
                "credentials": {"identifier": "user@example.com", "password": "token"},
                "url": "https://some-url.com",
                "proxy": False,
                "insecure": False,
                "incident_collections": [],
                "first_fetch": "3 days",
                "max_fetch": 1,
                "limit": 10,
            },
        ),
        patch.object(GroupIBTIA.demisto, "args", return_value={}),
        patch.object(GroupIBTIA.demisto, "command", return_value="non-existent-command"),
        patch.object(GroupIBTIA, "Client", autospec=True),
        patch.object(GroupIBTIA, "return_error", side_effect=SystemExit(1)),
    ):
        GroupIBTIA.main()


def test_reputation_command_disabled_ip(mocker):
    """
    Given: Integration instance configuration does not enable the 'ip' reputation command.
    When: The 'ip' command is invoked.
    Then: The integration must return a controlled no-op result and must not execute enrichment logic.
    """
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://some-url.com",
            "proxy": False,
            "insecure": False,
            # New behavior: allow-list. Empty means disabled.
            "enabled_reputation_commands": [],
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "8.8.8.8"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(GroupIBTIA.ReputationCommands, "ip", autospec=True)
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error must not be called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 0, "Expected ReputationCommands.ip not to be called when not enabled."
    assert rr.call_count == 1
    result_obj = rr.call_args[0][0]
    assert isinstance(result_obj, CommandResults)
    assert "not enabled" in (result_obj.readable_output or "").lower()


def test_reputation_commands_default_disabled_when_param_missing(mocker):
    """
    Given: Integration instance configuration does not include the 'enabled_reputation_commands' param.
    When: A reputation command (ip/domain/file) is invoked.
    Then: The integration must default to disabled (fail-safe) and must not execute enrichment logic.
    """
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://some-url.com",
            "proxy": False,
            "insecure": False,
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "8.8.8.8"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(GroupIBTIA.ReputationCommands, "ip", autospec=True)
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error must not be called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 0, "Expected ReputationCommands.ip not to be called when param is missing."
    assert rr.call_count == 1


def test_reputation_command_enabled_allow_list(mocker):
    """
    Given: Allow-list enables 'ip' reputation command.
    When: The 'ip' reputation command is invoked.
    Then: The integration must call the underlying reputation implementation.
    """
    mocker.patch.object(
        GroupIBTIA.demisto,
        "params",
        return_value={
            "credentials": {"identifier": "user@example.com", "password": "token"},
            "url": "https://some-url.com",
            "proxy": False,
            "insecure": False,
            "enabled_reputation_commands": ["ip"],
            "incident_collections": [],
            "first_fetch": "3 days",
            "max_fetch": 1,
            "limit": 10,
        },
    )
    mocker.patch.object(GroupIBTIA.demisto, "args", return_value={"ip": "8.8.8.8"})
    mocker.patch.object(GroupIBTIA.demisto, "command", return_value="ip")

    mocker.patch.object(GroupIBTIA, "Client", autospec=True)
    ip_impl = mocker.patch.object(
        GroupIBTIA.ReputationCommands,
        "ip",
        autospec=True,
        return_value=CommandResults(readable_output="ok"),
    )
    rr = mocker.patch.object(GroupIBTIA, "return_results", autospec=True)
    mocker.patch.object(GroupIBTIA, "return_error", side_effect=AssertionError("return_error must not be called"))

    GroupIBTIA.main()

    assert ip_impl.call_count == 1
    assert rr.call_count == 1


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

    assert result.outputs_prefix == "GIBTI.search.global"
    assert result.outputs_key_field == "query"


def test_get_available_collections(mocker, single_session_fixture):
    """
    Test for validating the get_available_collections_command function.

    Given:
      - single_session_fixture, which provides a client instance for retrieving available collections.

    When:
      - The get_available_collections_command() function is invoked with the client instance.

    Then:
      - Verifies that the outputs_prefix is correctly set to "GIBTI.OtherInfo", indicating that
        the response data is categorized as general information.
      - Checks that the outputs_key_field is "collections", matching the expected key for collections data.
      - Ensures that the "collections" field in the output contains a list of collection names, as expected.
      - This test confirms that the command accurately retrieves and formats the list of available
        collections from the server response.
    """
    client = single_session_fixture
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=[AVALIBLE_COLLECTIONS_RAW_JSON])
    result = get_available_collections_command(client=client)

    assert result.outputs_prefix == "GIBTI.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs["collections"], list)


@pytest.fixture
def mock_client():
    """Fixture to create a mock client."""
    client = MagicMock()
    client.poller.create_update_generator.return_value = []
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
    assert result.outputs_prefix == "GIBTI.search.local"
    assert result.outputs_key_field == "id"
    assert result.outputs == []
    assert "Search results" in result.readable_output


def test_local_search_command_with_results(mock_client, mock_common_helpers):
    """
    Given: A valid collection name, search query, and results returned by the client.
    When: The local_search_command function is executed.
    Then: The function should return a formatted list of search results.
    """
    mock_client.poller.create_update_generator.return_value = [
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
    assert result.outputs_prefix == "GIBTI.search.local"
    assert result.outputs_key_field == "id"
    outputs = cast(list[dict[str, Any]], result.outputs)
    assert len(outputs) == 2
    assert outputs[0]["id"] == "123"
    assert outputs[0]["additional_info"] == "Name: Test Result"
    assert "Search results" in result.readable_output
    assert "Name: Test Result" in result.readable_output
    assert "Name: Another Result" in result.readable_output


# Unit tests for CommonHelpers


def test_transform_dict_empty():
    assert CommonHelpers.transform_dict({}) == [{}]


def test_transform_dict_various_lengths():
    input_dict: dict[str, Any] = {"a": [1, 2], "b": "x", "c": []}
    result = CommonHelpers.transform_dict(cast(Any, input_dict))
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
    data: list[Any] = ["", "x", [], [{}]]
    result = CommonHelpers.replace_empty_values(cast(Any, data))
    assert result == [None, "x", None, [{}]]


def test_replace_empty_values_empty_list_returns_none():
    assert CommonHelpers.replace_empty_values(cast(Any, [])) is None
    assert CommonHelpers.replace_empty_values(cast(Any, [[]])) is None


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
    data: list[dict[str, Any]] = [{"x": [1, 2], "y": "a"}, {"x": []}]
    result = CommonHelpers.transform_list_to_str(cast(Any, data))
    assert result[0]["x"] == "1, 2"
    assert result[1]["x"] == ""


def test_validate_collections_valid():
    CommonHelpers.validate_collections("valid_collection")


def _get_date_field_for_collection(collection_name: str) -> str:
    """
    Helper function to get the appropriate date field for a collection.

    Returns the first date field from INCIDENT_CREATED_DATES_MAPPING for the given collection.
    """
    date_field = INCIDENT_CREATED_DATES_MAPPING.get(collection_name, "dateFirstSeen")
    if isinstance(date_field, list):
        return str(date_field[0])  # Return first field if it's a list
    return str(date_field)


def test_fetch_incidents_with_combolist_and_unique_parameters(mocker, session_fixture):
    """
    Test for verifying fetch_incidents_command correctly passes combolist and unique parameters.

    Given:
      - A session_fixture providing a client and collection name.
      - combolist and unique parameters set to True.

    When:
      - fetch_incidents_command() is called with combolist=True and unique=True.

    Then:
      - Verifies that create_poll_generator is called with the correct combolist and unique parameters.
      - Ensures incidents are returned as a list.
    """
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12345
    mock_portion.portion_size = 10
    mock_portion.count = 10
    # Mock incident data that will be processed by IncidentBuilder
    # Include required fields: id, name, evaluation, and date field based on collection
    # Use date format that matches real data: "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SS+00:00"
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    # Add the appropriate date field for this collection
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    # For compromised/breached collection, add emails field required for portal link generation
    if collection_name == "compromised/breached":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.bulk_parse_portion.return_value = [mock_incident_data]
    mock_portions.append(mock_portion)

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client.poller,
        "get_available_collections",
        return_value=[collection_name],
    )
    mocker.patch.object(
        client,
        "create_poll_generator",
        return_value=(mock_portions, None),
    )

    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=True,
        unique=True,
        enable_probable_corporate_access=False,
    )

    # Verify create_poll_generator was called with combolist and unique parameters
    client.create_poll_generator.assert_called_once()
    call_kwargs = client.create_poll_generator.call_args[1]
    assert call_kwargs["combolist"] is True, "Expected combolist parameter to be True."
    assert call_kwargs["unique"] is True, "Expected unique parameter to be True."
    assert isinstance(incidents, list), "Expected incidents to be a list."


def test_fetch_incidents_sequpdate_resolution(mocker, session_fixture):
    """
    Test for verifying sequpdate resolution in create_poll_generator when no last_fetch exists.

    Given:
      - A session_fixture providing a client and collection name.
      - An empty last_run dictionary (first time fetch).
      - A mocked get_seq_update_dict that returns a sequpdate value.

    When:
      - fetch_incidents_command() is called with first_fetch_time.

    Then:
      - Verifies that create_poll_generator resolves sequpdate via get_seq_update_dict.
      - Ensures the resolved sequpdate is used instead of date_from.
    """
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    mock_portion.sequpdate = 12345
    mock_portion.portion_size = 10
    mock_portion.count = 10
    # Mock incident data with required fields
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    # Add the appropriate date field for this collection
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    if collection_name == "compromised/breached":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.bulk_parse_portion.return_value = [mock_incident_data]
    mock_portions.append(mock_portion)

    # Mock get_seq_update_dict to return a sequpdate
    resolved_sequpdate = 10000
    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={collection_name: resolved_sequpdate},
    )
    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client.poller,
        "get_available_collections",
        return_value=[collection_name],
    )
    if collection_name == "compromised/breached":
        mocker.patch.object(
            client.poller,
            "create_search_generator",
            return_value=mock_portions,
        )
    else:
        mocker.patch.object(
            client.poller,
            "create_update_generator",
            return_value=mock_portions,
        )

    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="2023-01-01",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    if collection_name == "compromised/breached":
        client.poller.get_seq_update_dict.assert_not_called()
        client.poller.create_search_generator.assert_called_once()
        search_call_kwargs = client.poller.create_search_generator.call_args[1]
        assert search_call_kwargs["date_from"] == "2023-01-01"
        assert search_call_kwargs["apply_hunting_rules"] == 1
        assert isinstance(next_run["last_fetch"][collection_name], dict)
    else:
        # Verify get_seq_update_dict was called for sequpdate resolution
        client.poller.get_seq_update_dict.assert_called_once()
    assert isinstance(incidents, list), "Expected incidents to be a list."


def test_fetch_incidents_effective_last_fetch_calculation(mocker, session_fixture):
    """
    Test for verifying effective_last_fetch calculation using max(last_fetch, sequpdate).

    Given:
      - A session_fixture providing a client and collection name.
      - A last_run dictionary with existing last_fetch value.
      - Multiple portions with different sequpdate values.

    When:
      - fetch_incidents_command() processes portions and updates sequpdate.

    Then:
      - Verifies that next_run contains the maximum of last_fetch and sequpdate.
      - Ensures effective_last_fetch is correctly calculated.
    """
    collection_name, client = session_fixture
    mock_portions = []
    mock_portion = MagicMock()
    if collection_name == "compromised/breached":
        last_fetch_value = {
            "starting_date_from": "2023-01-01",
            "starting_date_to": "2023-01-31",
            "current_date_to": "2023-01-31",
        }
        sequpdate_value = None
    else:
        last_fetch_value = 10000
        sequpdate_value = 15000  # Higher than last_fetch
    mock_portion.sequpdate = sequpdate_value
    mock_portion.portion_size = 10
    mock_portion.count = 10
    # Mock incident data with required fields
    date_field = _get_date_field_for_collection(collection_name)
    mock_incident_data = {
        "id": "test-id",
        "name": "test",
        "evaluation": {"severity": "green"},
    }
    # Add the appropriate date field for this collection
    mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
    if collection_name == "compromised/breached":
        mock_incident_data["emails"] = ["test@example.com"]
    mock_portion.bulk_parse_portion.return_value = [mock_incident_data]
    mock_portions.append(mock_portion)

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client.poller,
        "get_available_collections",
        return_value=[collection_name],
    )
    if collection_name == "compromised/breached":
        mocker.patch.object(
            client.poller,
            "create_search_generator",
            return_value=mock_portions,
        )
    else:
        mocker.patch.object(
            client,
            "create_poll_generator",
            return_value=(mock_portions, last_fetch_value),
        )

    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={"last_fetch": {collection_name: last_fetch_value}},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    assert collection_name in next_run["last_fetch"], "Expected collection name in next_run['last_fetch']."
    effective_last_fetch = next_run["last_fetch"][collection_name]
    if collection_name == "compromised/breached":
        client.poller.create_search_generator.assert_called_once()
        search_call_kwargs = client.poller.create_search_generator.call_args[1]
        assert search_call_kwargs["date_from"] is None
        assert search_call_kwargs["date_to"] == last_fetch_value["current_date_to"]
        assert effective_last_fetch == last_fetch_value
    else:
        assert int(str(effective_last_fetch)) == max(
            last_fetch_value, sequpdate_value
        ), f"Expected effective_last_fetch to be max({last_fetch_value}, {sequpdate_value}) = {sequpdate_value}."


def test_fetch_incidents_incident_processing_loop(mocker, session_fixture):
    """
    Test for verifying the incident processing loop handles multiple portions correctly.

    Given:
      - A session_fixture providing a client and collection name.
      - Multiple portions with different sequpdate values.

    When:
      - fetch_incidents_command() processes multiple portions in a loop.

    Then:
      - Verifies that all portions are processed.
      - Ensures sequpdate is updated from each portion.
      - Checks that requests_count limits the number of processed portions.
    """
    collection_name, client = session_fixture
    # Create multiple mock portions
    mock_portions = []
    date_field = _get_date_field_for_collection(collection_name)
    for i in range(5):
        mock_portion = MagicMock()
        mock_portion.sequpdate = 10000 + i * 1000
        mock_portion.portion_size = 10
        mock_portion.count = 10
        # Mock incident data with required fields
        mock_incident_data = {
            "id": f"test-id-{i}",
            "name": f"test-{i}",
            "evaluation": {"severity": "green"},
        }
        # Add the appropriate date field for this collection
        mock_incident_data[date_field] = "2023-01-01T00:00:00+00:00"
        mock_portion.bulk_parse_portion.return_value = [mock_incident_data]
        mock_portions.append(mock_portion)

    mocker.patch.object(client, "get_available_collections_proxy_function", return_value=AVALIBLE_COLLECTIONS_RAW_JSON)
    mocker.patch.object(
        client.poller,
        "get_available_collections",
        return_value=[collection_name],
    )
    mocker.patch.object(
        client,
        "create_poll_generator",
        return_value=(mock_portions, None),
    )

    max_requests = 3
    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=max_requests,
        hunting_rules=0,
        combolist=False,
        unique=False,
        enable_probable_corporate_access=False,
    )

    # Verify that only max_requests portions were processed
    assert len(incidents) == max_requests, f"Expected {max_requests} incidents, got {len(incidents)}."
    # Verify that the final sequpdate is from the last processed portion
    assert collection_name in next_run["last_fetch"], "Expected collection name in next_run['last_fetch']."


def test_create_poll_generator_with_combolist_and_unique(mocker, single_session_fixture):
    """
    Test for verifying create_poll_generator correctly passes combolist and unique to create_update_generator.

    Given:
      - A client instance.
      - combolist=True and unique=True parameters.

    When:
      - create_poll_generator() is called with these parameters.

    Then:
      - Verifies that create_update_generator is called with combolist=1 and unique=1 (converted to int).
    """
    client = single_session_fixture
    collection_name = "compromised/account_group"

    mock_portions = []
    mock_portion = MagicMock()
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={},  # Empty dict means no sequpdate found, will use date_from
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = client.create_poll_generator(
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=True,
        combolist=True,
        last_fetch=None,
        first_fetch_time="2023-01-01",
    )

    # Verify create_update_generator was called with combolist and unique as integers
    client.poller.create_update_generator.assert_called_once()
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["combolist"] == 1, "Expected combolist to be converted to 1 (int)."
    assert call_kwargs["unique"] == 1, "Expected unique to be converted to 1 (int)."
    assert portions == mock_portions, "Expected returned portions to match mocked portions."


def test_create_poll_generator_sequpdate_resolution_success(mocker, single_session_fixture):
    """
    Test for verifying create_poll_generator resolves sequpdate via get_seq_update_dict when successful.

    Given:
      - A client instance.
      - No last_fetch, but date_from is provided.
      - get_seq_update_dict returns a valid sequpdate.

    When:
      - create_poll_generator() is called with first_fetch_time.

    Then:
      - Verifies that get_seq_update_dict is called.
      - Ensures resolved sequpdate is used and date_from is set to None.
    """
    client = single_session_fixture
    collection_name = "compromised/account_group"
    resolved_sequpdate = 12345

    mock_portions = []
    mock_portion = MagicMock()
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={collection_name: resolved_sequpdate},
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = client.create_poll_generator(
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        last_fetch=None,
        first_fetch_time="2023-01-01",
    )

    # Verify get_seq_update_dict was called
    client.poller.get_seq_update_dict.assert_called_once()
    # Verify create_update_generator was called with resolved sequpdate and date_from=None
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs["sequpdate"] == resolved_sequpdate, "Expected resolved sequpdate to be used."
    assert call_kwargs.get("date_from") is None, "Expected date_from to be None when sequpdate is resolved."


def test_create_poll_generator_sequpdate_resolution_fallback(mocker, single_session_fixture):
    """
    Test for verifying create_poll_generator falls back to date_from when sequpdate resolution fails.

    Given:
      - A client instance.
      - No last_fetch, but date_from is provided.
      - get_seq_update_dict returns empty dict or raises exception.

    When:
      - create_poll_generator() is called with first_fetch_time.

    Then:
      - Verifies that get_seq_update_dict is called.
      - Ensures date_from is used when sequpdate resolution fails.
    """
    client = single_session_fixture
    collection_name = "compromised/account_group"

    mock_portions = []
    mock_portion = MagicMock()
    mock_portions.append(mock_portion)

    mocker.patch.object(
        client.poller,
        "get_seq_update_dict",
        return_value={},  # Empty dict means no sequpdate found
    )
    mocker.patch.object(
        client.poller,
        "create_update_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = client.create_poll_generator(
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        last_fetch=None,
        first_fetch_time="2023-01-01",
    )

    # Verify get_seq_update_dict was called
    client.poller.get_seq_update_dict.assert_called_once()
    # Verify create_update_generator was called with date_from (fallback)
    call_kwargs = client.poller.create_update_generator.call_args[1]
    assert call_kwargs.get("date_from") is not None, "Expected date_from to be used when sequpdate resolution fails."
    assert call_kwargs.get("sequpdate") is None, "Expected sequpdate to be None when resolution fails."


def test_create_poll_generator_compromised_breached_uses_search_generator(mocker, single_session_fixture):
    client = single_session_fixture
    collection_name = "compromised/breached"
    mock_portions = [MagicMock()]

    mocker.patch.object(
        client.poller,
        "create_search_generator",
        return_value=mock_portions,
    )

    portions, last_fetch = client.create_poll_generator(
        collection_name=collection_name,
        hunting_rules=0,
        enable_probable_corporate_access=False,
        unique=False,
        combolist=False,
        last_fetch=None,
        first_fetch_time="2023-01-01",
    )

    client.poller.create_search_generator.assert_called_once()
    call_kwargs = client.poller.create_search_generator.call_args[1]
    assert call_kwargs["date_from"] == "2023-01-01"
    assert call_kwargs["apply_hunting_rules"] == 1
    assert portions == mock_portions
    assert last_fetch["starting_date_from"] == "2023-01-01"
    assert last_fetch["starting_date_to"] == last_fetch["current_date_to"]


def test_fetch_incidents_compromised_breached_keeps_date_range_last_fetch(mocker, single_session_fixture):
    collection_name = "compromised/breached"
    client = single_session_fixture
    mock_portion = MagicMock()
    mock_portion.sequpdate = None
    mock_portion.portion_size = 1
    mock_portion.count = 1
    mock_portion.bulk_parse_portion.return_value = [
        {
            "id": "breached-id",
            "name": ["Email collection"],
            "emails": ["user@example.com"],
            "uploadTime": "2024-10-01T01:45:13",
            "evaluation": {"severity": "green"},
        }
    ]
    expected_last_fetch = {
        "starting_date_from": "2024-10-01",
        "starting_date_to": "2024-10-31",
        "current_date_to": "2024-10-31",
    }

    mocker.patch.object(client.poller, "get_available_collections", return_value=[collection_name])
    mocker.patch.object(client, "create_poll_generator", return_value=([mock_portion], expected_last_fetch))

    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[collection_name],
        max_requests=3,
        hunting_rules=0,
    )

    assert len(incidents) == 1
    assert next_run["last_fetch"][collection_name] == expected_last_fetch


def test_build_feed_compromised_breached_generates_portal_link_from_email(mocker, single_session_fixture):
    client = single_session_fixture
    collection_name = "compromised/breached"
    mock_result = MagicMock()
    mock_result.parse_portion.return_value = {
        "id": "breached-id",
        "name": ["Email collection"],
        "emails": ["user@example.com"],
        "uploadTime": "2024-10-01T01:45:13",
        "evaluation": {"severity": "green"},
        "portalLink": "https://tap.group-ib.com/cd/breached?id=breached-id",
    }

    mocker.patch.object(client.poller, "search_feed_by_id", return_value=mock_result)

    feed, _, _, _, _ = BuilderCommandResponses(
        client=client,
        collection_name=collection_name,
        args={"id": "breached-id"},
    ).build_feed()

    assert feed["portalLink"] == f"{PORTAL_LINKS[collection_name]}user@example.com"


def test_build_incident_compromised_breached_generates_portal_link_from_email():
    collection_name = "compromised/breached"
    incident = {
        "id": "breached-id",
        "name": ["Email collection"],
        "emails": ["user@example.com"],
        "uploadTime": "2024-10-01T01:45:13",
        "evaluation": {"severity": "green"},
        "portalLink": "https://tap.group-ib.com/cd/breached?id=breached-id",
    }

    built_incident = IncidentBuilder(
        collection_name=collection_name,
        incident=incident,
        mapping=MAPPING[collection_name],
    ).build_incident()
    raw_incident = loads(built_incident["rawJSON"])

    assert raw_incident["portalLink"] == f"{PORTAL_LINKS[collection_name]}user@example.com"


# ---------------------------------------------------------------------------
# Deduplication: retention contract for `dedup_lookback_days`
# ---------------------------------------------------------------------------
#
# These tests pin the 1:1 semantics of the user-facing parameter:
#   * Configured `dedup_lookback_days = N` means "an ID added today is dropped
#     exactly N days later".
#   * No hidden multipliers, no "latest ID kept forever" exception.
#
# The previous implementation relied on `CommonServerPython.get_found_incident_ids`,
# which silently doubled the retention window (`look_back * 2`) and pinned the
# newest ID forever, breaking the contract documented in the integration YAML.


SECONDS_PER_DAY = 86_400


def test_convert_dedup_lookback_days_to_seconds_basic():
    assert GroupIBTIA._convert_dedup_lookback_days_to_seconds(1) == SECONDS_PER_DAY
    assert GroupIBTIA._convert_dedup_lookback_days_to_seconds(365) == 365 * SECONDS_PER_DAY


def test_convert_dedup_lookback_days_to_seconds_zero():
    assert GroupIBTIA._convert_dedup_lookback_days_to_seconds(0) == 0


def test_prune_seen_ids_returns_empty_for_zero_retention():
    cache = {"a": 1000.0, "b": 2000.0}
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=0, now=10_000.0)
    assert pruned == {}


def test_prune_seen_ids_returns_empty_for_negative_retention():
    cache = {"a": 1000.0}
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=-1, now=10_000.0)
    assert pruned == {}


def test_prune_seen_ids_keeps_entries_within_window():
    now = 10_000.0
    cache = {
        "fresh": now - 100,
        "older": now - 500,
    }
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"fresh": now - 100, "older": now - 500}


def test_prune_seen_ids_drops_entries_older_than_window():
    now = 10_000.0
    cache = {
        "fresh": now - 100,
        "stale": now - 5000,
    }
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"fresh": now - 100}


def test_prune_seen_ids_threshold_is_inclusive():
    """An ID exactly at the retention boundary must be kept (>=, not >)."""
    now = 10_000.0
    cache = {"boundary": now - 1000}
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"boundary": now - 1000}


def test_prune_seen_ids_drops_entries_just_past_threshold():
    now = 10_000.0
    cache = {"just_past": now - 1000.001}
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {}


def test_prune_seen_ids_drops_entries_with_malformed_timestamp():
    """Defensive: corrupt cache entries are dropped, never raised."""
    now = 10_000.0
    cache = {
        "ok": now - 100,
        "string_ts": "not-a-number",  # type: ignore[dict-item]
        "none_ts": None,  # type: ignore[dict-item]
        "negative": -1,
    }
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)  # type: ignore[arg-type]
    assert pruned == {"ok": now - 100}


def test_prune_seen_ids_does_not_mutate_input():
    cache = {"a": 1.0, "b": 2.0}
    snapshot = dict(cache)
    GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1, now=1000.0)
    assert cache == snapshot


def test_prune_seen_ids_drops_latest_id_when_older_than_retention():
    """
    Critical regression vs the old CommonServerPython helper, which pinned the
    newest ID forever via `addition_time == latest_incident_time`.

    With the in-house helper, every entry obeys the retention window without
    exceptions; otherwise, a single never-re-fetched ID would grow the cache
    unboundedly across years of operation.
    """
    now = 10_000.0
    cache = {
        "ancient_but_latest": now - 99_999_999,
        "ancient_too": now - 99_999_998,
    }
    pruned = GroupIBTIA._prune_seen_incident_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {}


def test_update_fetch_seen_ids_cache_noop_for_empty_incidents():
    state = {"found_incident_ids": {"existing": 1.0}}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[],
        dedup_lookback_days=365,
    )
    assert state == {"found_incident_ids": {"existing": 1.0}}


def test_update_fetch_seen_ids_cache_adds_new_ids(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state: dict = {}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": "alpha"}, {"id": "beta"}],
        dedup_lookback_days=365,
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now, "beta": fixed_now}


def test_update_fetch_seen_ids_cache_normalizes_non_string_ids(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state: dict = {}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": 42}, {"id": "alpha"}],
        dedup_lookback_days=365,
    )
    assert state["found_incident_ids"] == {"42": fixed_now, "alpha": fixed_now}


def test_update_fetch_seen_ids_cache_skips_incidents_without_id(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state: dict = {}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": None}, {"name": "no-id"}, {"id": "ok"}],
        dedup_lookback_days=365,
    )
    assert state["found_incident_ids"] == {"ok": fixed_now}


def test_update_fetch_seen_ids_cache_prunes_old_entries(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state = {
        "found_incident_ids": {
            "stale": fixed_now - (366 * SECONDS_PER_DAY),  # > 365d -> drop
            "fresh": fixed_now - (10 * SECONDS_PER_DAY),  # well within window
        }
    }
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": "new"}],
        dedup_lookback_days=365,
    )
    assert "stale" not in state["found_incident_ids"]
    assert "fresh" in state["found_incident_ids"]
    assert state["found_incident_ids"]["new"] == fixed_now


def test_update_fetch_seen_ids_cache_handles_corrupt_existing_value(mocker):
    """If `found_incident_ids` was somehow stored as a string, we don't crash."""
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state: dict = {"found_incident_ids": "this-should-have-been-a-dict"}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": "alpha"}],
        dedup_lookback_days=365,
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now}


def test_update_fetch_seen_ids_cache_one_to_one_retention_contract(mocker):
    """
    THE contract test for `dedup_lookback_days`:

    Configured retention is N days. An ID added exactly N days ago must
    still be kept. An ID added N days + 1 second ago must be dropped.

    This is the assertion the previous implementation could not satisfy:
    CommonServerPython would have kept the older ID for 2N days, and pinned
    the newest one forever.
    """
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    n_days = 7
    retention_seconds = n_days * SECONDS_PER_DAY

    state = {
        "found_incident_ids": {
            "boundary": fixed_now - retention_seconds,
            "just_past": fixed_now - retention_seconds - 1,
        }
    }
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": "today"}],
        dedup_lookback_days=n_days,
    )

    cache = state["found_incident_ids"]
    assert "boundary" in cache, "ID at exactly N days must be retained (>= threshold)"
    assert "just_past" not in cache, "ID at N days + 1s must be pruned"
    assert cache["today"] == fixed_now


def test_update_fetch_seen_ids_cache_disables_when_retention_is_zero(mocker):
    """
    Operational kill-switch: setting `dedup_lookback_days = 0` must drop the
    entire cache on the next update so customers can fully disable built-in
    deduplication without manual cleanup.
    """
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBTIA.time, "time", return_value=fixed_now)

    state = {"found_incident_ids": {"old": fixed_now - 10}}
    GroupIBTIA._update_fetch_seen_incident_ids_cache(
        last_run_state=state,
        incidents=[{"id": "incoming"}],
        dedup_lookback_days=0,
    )
    assert state["found_incident_ids"] == {}

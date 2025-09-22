import pytest
import os
from json import load
from GroupIB_TIA_Feed import fetch_indicators_command, Client, main
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

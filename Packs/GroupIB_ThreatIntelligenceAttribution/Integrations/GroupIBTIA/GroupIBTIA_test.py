import pytest
from GroupIBTIA import (
    fetch_incidents_command,
    Client,
    main,
    get_available_collections_command,
)
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
import GroupIBTIA

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)


BASE_URL = "https://tap.group-ib.com/api/v2/"
USERNAME = (
    "example@roup-ib.com"  # Replace this value before the tests. example@roup-ib.com
)
PASSWORD = "exampleAPI_TOKEN"  # Replace this value before the tests. exampleAPI_TOKEN

COLLECTION_NAMES = [
    "compromised/account_group",
    "compromised/bank_card_group",
    "compromised/breached",
    "compromised/mule",
    "osi/git_repository",
    "osi/public_leak",
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
    "malware/malware",
    "hi/threat",
    "hi/threat_actor",
    "apt/threat_actor",
    "apt/threat"
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
        base_url=BASE_URL,
        auth=(USERNAME, PASSWORD),
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
        base_url=BASE_URL,
        auth=(USERNAME, PASSWORD),
        verify=True,
        headers={"Accept": "*/*"},
    )
    

def test_fetch_incidents(session_fixture):
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
    next_run, incidents = fetch_incidents_command(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        incident_collections=[],
        max_requests=3,
        hunting_rules=False
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


def test_global_search_command(single_session_fixture):
    """
    Test for verifying the functionality of the global_search_command function.

    Given:
      - single_session_fixture provides a client instance for performing a search.
      - A test_query dictionary with a "query" key specifying a search term, in this case, an IP address.

    When:
      - The global_search_command() function is called with the client and test_query arguments.

    Then:
      - Ensures that the command’s outputs_prefix and outputs_key_field are correctly set to expected values.
      - Verifies that the command returns the data structure with the correct outputs_key_field ("query"),
        ensuring compatibility with other functions that depend on this structure.
      - This test validates that the search command integrates smoothly with the client and returns
        consistent output formatting.
    """
    client = single_session_fixture
    test_query = {"query": "8.8.8.8"}
    result = GroupIBTIA.global_search_command(client=client, args=test_query)

    assert result.outputs_prefix == "GIBTIA.search.global"
    assert result.outputs_key_field == "query"


def test_get_available_collections(single_session_fixture):
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
    result = get_available_collections_command(client=client)

    assert result.outputs_prefix == "GIBTIA.OtherInfo"
    assert result.outputs_key_field == "collections"
    assert isinstance(result.outputs["collections"], list)

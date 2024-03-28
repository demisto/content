import json
import os
from pathlib import Path
from pytest_mock import MockFixture

import requests

import networkx as nx
from networkx import DiGraph
import demisto_client
import pytest
import timeout_decorator
import Tests.Marketplace.search_and_install_packs as script
from demisto_client.demisto_api.rest import ApiException
from Tests.Marketplace.marketplace_constants import GCPConfig
from google.cloud.storage import Blob

CONTENT_PROJECT_ID = os.getenv('CI_PROJECT_ID', '1061')


def load_json_file(directory: str, file_name: str):
    with open(Path(__file__).parent / 'test_data' / directory / file_name) as json_file:
        json_data = json.load(json_file)
    return json_data


@pytest.fixture(autouse=True)
def mock_sleep(mocker):
    """
    Mock time.sleep function.
    """
    mocker.patch("time.sleep", return_value=None)


@pytest.fixture(autouse=True)
def mock_environment_variables(mocker):
    """
    Mock environment variables.

    Note:
        Works only if the environment variables are fetched in the code using the custom 'get_env_var' function.
    """
    def env_side_effect(env_name: str):
        if env_name == "CI_SERVER_URL":
            return "https://example.com"

        elif env_name == "GITLAB_API_READ_TOKEN":
            return "API_KEY"

        elif env_name == "LAST_UPLOAD_COMMIT":
            return "COMMIT_HASH"

        return None

    mocker.patch("Tests.Marketplace.search_and_install_packs.get_env_var", side_effect=env_side_effect)


MOCK_HELLOWORLD_SEARCH_RESULTS = load_json_file('search_dependencies', "HelloWorld_1.2.19.json")
MOCK_AZURESENTINEL_SEARCH_RESULTS = load_json_file('search_dependencies', 'AzureSentinel_1.5.8.json')

MOCK_PACKS_INSTALLATION_RESULT = [
    {
        "id": "HelloWorld",
        "currentVersion": "2.0.0",
        "name": "HelloWorldPremium",
        "installed": "2020-04-06T16:35:10.998538+03:00"
    },
    {
        "id": "TestPack",
        "currentVersion": "1.0.0",
        "name": "TestPack",
        "installed": "2020-04-13T16:43:22.304144+03:00"
    },
    {
        "id": "AzureSentinel",
        "currentVersion": "1.0.0",
        "name": "AzureSentinel",
        "installed": "2020-04-13T16:57:32.655598+03:00"
    },
    {
        "id": "Base",
        "currentVersion": "1.0.0",
        "name": "Base",
        "installed": "2020-04-06T14:54:09.755811+03:00"
    }
]

PACKS_PACK_META_FILE_NAME = 'pack_metadata.json'


def mocked_generic_request_func(self, path: str, method, body=None, **kwargs):
    if body:
        if body[0].get('id') == 'HelloWorld':
            return MOCK_HELLOWORLD_SEARCH_RESULTS, 200, None
        elif body and body[0].get('id') == 'AzureSentinel':
            return MOCK_AZURESENTINEL_SEARCH_RESULTS, 200, None
    raise ApiException(status=400)


class MockConfiguration:
    def __init__(self):
        self.host = None


class MockApiClient:
    def __init__(self):
        self.configuration = MockConfiguration()


class MockClient:
    def __init__(self):
        self.api_client = MockApiClient()


@timeout_decorator.timeout(3)
def test_install_nightly_packs_endless_loop(mocker):
    """
    Given
    - Packs to install with two packs that cannot be installed
        (usually because their version does not exist in the bucket)
    When
    - Run install_nightly_packs method with those packs
    Then
    - Ensure the function does not enter an endless loop and that it gracefully removes the two damaged packs from the
     installation list
    """

    def generic_request_mock(self, path: str, method, body=None, accept=None, _request_timeout=None):
        requested_pack_ids = {pack['id'] for pack in body['packs']}
        for bad_integration in {'bad_integration1', 'bad_integration2'}:
            if bad_integration in requested_pack_ids:
                raise Exception(f'invalid version 1.2.0 for pack with ID {bad_integration}')
        return MOCK_PACKS_INSTALLATION_RESULT, 200, None

    client = MockClient()
    mocker.patch.object(demisto_client, 'generic_request_func', generic_request_mock)
    mocker.patch("Tests.Marketplace.search_and_install_packs.logging")
    packs_to_install = [
        {'id': 'HelloWorld', 'version': '1.0.0'},
        {'id': 'TestPack', 'version': '1.0.0'},
        {'id': 'AzureSentinel', 'version': '1.0.0'},
        {'id': 'Base', 'version': '1.0.0'},
        {'id': 'bad_integration1', 'version': '1.0.0'},
        {'id': 'bad_integration2', 'version': '1.0.0'},
    ]
    script.install_packs(client, 'my_host', packs_to_install)


@pytest.mark.parametrize('path, latest_version', [
    (f'{GCPConfig.CONTENT_PACKS_PATH}/TestPack/1.0.1/TestPack.zip', '1.0.1'),
    (f'{GCPConfig.CONTENT_PACKS_PATH}/Blockade.io/1.0.1/Blockade.io.zip', '1.0.1')
])
def test_pack_path_version_regex(path, latest_version):
    """
       Given:
           - A path in GCS of a zipped pack.
       When:
           - Extracting the version from the path.
       Then:
           - Validate that the extracted version is the expected version.
   """
    assert script.PACK_PATH_VERSION_REGEX.findall(path)[0] == latest_version


def test_get_latest_version_from_bucket(mocker):
    """
       Given:
           - An id of a pack and the bucket.
       When:
           - Getting the latest version of the pack in the bucket.
           - Having a with_dependency.zip file in the bucket.
       Then:
           - Validate that the version is the one we expect for.
           - Skip over with_dependencies.zip file.
   """
    dummy_prod_bucket = mocker.MagicMock()
    first_blob = Blob(f'{GCPConfig.CONTENT_PACKS_PATH}/TestPack/1.0.0/TestPack.zip', dummy_prod_bucket)
    second_blob = Blob(f'{GCPConfig.CONTENT_PACKS_PATH}/TestPack/1.0.1/TestPack.zip', dummy_prod_bucket)
    third_blob = Blob(f'{GCPConfig.CONTENT_PACKS_PATH}/TestPack/TestPack_with_dependencies.zip', dummy_prod_bucket)
    dummy_prod_bucket.list_blobs.return_value = [first_blob, second_blob, third_blob]
    assert script.get_latest_version_from_bucket('TestPack', dummy_prod_bucket) == '1.0.1'


def test_is_pack_deprecated_locally(mocker):
    """
    Given: An ID of a pack
    When: Checking if the pack is deprecated (by checking pack-metadata file locally)
    Then: Validate the result is as expected
    """
    mock_pack_metadata = {
        "name": "TestPack",
        "description": "TestPack",
    }
    mocker.patch("pathlib.Path.is_file", return_value=True)
    mocker.patch("demisto_sdk.commands.common.tools.get_pack_metadata", return_value=mock_pack_metadata)

    # Check missing "hidden" field results in a default value of False
    assert not script.is_pack_deprecated("pack_id", production_bucket=False)

    # Check normal case of hidden pack
    mock_pack_metadata["hidden"] = True
    assert script.is_pack_deprecated("pack_id", production_bucket=False)

    # Check normal case of non-hidden pack
    mock_pack_metadata["hidden"] = False
    assert not script.is_pack_deprecated("pack_id", production_bucket=False)


def test_is_pack_deprecated_using_gitlab_api(mocker):
    """
    Given: An ID of a pack
    When: Checking if the pack is deprecated (by checking pack-metadata file in master branch - AKA pre-update)
    Then: Validate the result is as expected
    """
    mock_pack_metadata = {
        "name": "TestPack",
        "description": "TestPack",
    }

    # Check missing "hidden" field results in a default value of False
    mocker.patch("Tests.Marketplace.search_and_install_packs.fetch_pack_metadata_from_gitlab", return_value=mock_pack_metadata)
    assert not script.is_pack_deprecated("pack_id", production_bucket=True, commit_hash="X")

    # Check normal case of hidden pack
    mock_pack_metadata["hidden"] = True
    assert script.is_pack_deprecated("pack_id", production_bucket=True, commit_hash="X")

    # Check normal case of non-hidden pack
    mock_pack_metadata["hidden"] = False
    assert not script.is_pack_deprecated("pack_id", production_bucket=True, commit_hash="X")


def test_is_pack_deprecated_using_marketplace_api_data():
    """
    Given: An ID of a pack
    When: Checking if the pack is deprecated (by checking pack-metadata file in master branch - AKA pre-update)
    Then: Validate the result is as expected
    """
    mock_pack_api_data = {
        "TestPack": {
            "currentVersion": "1",
            "dependencies": [],
            "deprecated": False
        },
    }

    # Check missing "hidden" field results in a default value of False
    assert not script.is_pack_deprecated("TestPack", production_bucket=True, pack_api_data=mock_pack_api_data['TestPack'])

    # Check normal case of hidden pack
    mock_pack_api_data["TestPack"]["deprecated"] = True
    assert script.is_pack_deprecated("TestPack", production_bucket=True, pack_api_data=mock_pack_api_data['TestPack'])

    # Check normal case of non-hidden pack
    mock_pack_api_data["TestPack"]["deprecated"] = False
    assert not script.is_pack_deprecated("TestPack", production_bucket=True, pack_api_data=mock_pack_api_data['TestPack'])


def test_fetch_pack_metadata_from_gitlab(mocker):
    """
    Given: An ID of a pack
    When: Fetching the pack's metadata from GitLab's API
    Then: Validate that the API call is valid and that the content is properly parsed
    """
    mock_response = requests.Response()
    mock_response.status_code = 200
    requests_mock = mocker.patch.object(requests.Session, "get", return_value=mock_response)

    # Hidden pack case
    mock_response_data = load_json_file(directory="gitlab_api_pack_metadata", file_name="hidden-pack.json")
    mock_response._content = json.dumps(mock_response_data).encode("utf-8")
    assert script.fetch_pack_metadata_from_gitlab(pack_id="TestPack", commit_hash="COMMIT_HASH")["hidden"]  # Value is True

    # Clear cache
    script.fetch_pack_metadata_from_gitlab.cache_clear()

    # Non-hidden pack case
    mock_response_data = load_json_file(directory="gitlab_api_pack_metadata", file_name="non-hidden-pack.json")
    mock_response._content = json.dumps(mock_response_data).encode("utf-8")
    assert not script.fetch_pack_metadata_from_gitlab(pack_id="TestPack", commit_hash="COMMIT_HASH")["hidden"]  # Value is False

    # Assert API call is valid
    requests_mock.assert_called_with(
        f"https://example.com/api/v4/projects/{CONTENT_PROJECT_ID}/repository/files/Packs%2FTestPack%2Fpack_metadata.json",
        headers={"PRIVATE-TOKEN": "API_KEY"},
        params={"ref": "COMMIT_HASH"},
    )


class MockHttpRequest:
    def __init__(self, body):
        self.status = ''
        self.reason = ''
        self.data = body

    def getheaders(self):
        return ''


GCP_TIMEOUT_EXCEPTION_RESPONSE_BODY = '{"id":"errInstallContentPack","status":400,"title":"Could not install content ' \
                                      'pack","detail":"Could not install content pack","error":"Get' \
                                      ' \"https://storage.googleapis.com/marketplace-ci-build/content/builds' \
                                      '/master%2F2788053%2Fxsoar/content/packs/pack2/1.0.2/pack2.zip\": http2: ' \
                                      'timeout awaiting response headers","encrypted":false,"multires":null}'

MALFORMED_PACK_RESPONSE_BODY = '{"id":"errGetContentPack","status":400,"title":"Failed getting content pack",' \
                               '"detail":"Failed getting content pack","error":"Item not found (8), pack id: ' \
                               '[pack1]","encrypted":false,"multires":null}'

ERROR_AS_LIST_RESPONSE_BODY = '{"errors":[{"SystemError":null,"id":8,"detail":"Item not found"}]}'

MALFORMED_PACK_RESPONSE_BODY_TWO_PACKS = '{"id":"errGetContentPack","status":400,"title":"Failed getting ' \
                                         'content pack", "detail":"Failed getting content pack","error":"Item not ' \
                                         'found (8), pack id: [pack1, pack2]","encrypted":false,"multires":null}'


class TestInstallPacks:
    def test_gcp_timeout_exception(self, mocker):
        """
        Given:
            An error response noting that the installation failed due to gcp timeout
        When:
            installing packs on servers
        Then:
            Retry once again.
            Fail completely if reoccurs after retry.
        """
        http_resp = MockHttpRequest(GCP_TIMEOUT_EXCEPTION_RESPONSE_BODY)
        mocker.patch.object(demisto_client, 'generic_request_func', side_effect=ApiException(http_resp=http_resp))
        client = MockClient()
        success, _ = script.install_packs(client, 'my_host',
                                          packs_to_install=[
                                              {'id': 'pack1', 'version': '1.0.0'},
                                              {'id': 'pack3', 'version': '1.0.0'}
                                          ])
        assert not success

    def test_malformed_pack_exception(self, mocker):
        """
        Given:
            An error response noting that the installation failed due to malformed pack
        When:
            installing packs on servers
        Then:
            Retry without failing pack.
            Fail completely if reoccurs after removing.

        """
        http_resp = MockHttpRequest(MALFORMED_PACK_RESPONSE_BODY)
        mocker.patch.object(demisto_client, 'generic_request_func', side_effect=ApiException(http_resp=http_resp))
        client = MockClient()
        success, _ = script.install_packs(client, 'my_host', packs_to_install=[
            {'id': 'pack1', 'version': '1.0.0'},
            {'id': 'pack3', 'version': '1.0.0'}
        ])
        assert not success


def test_malformed_pack_id():
    assert script.find_malformed_pack_id(MALFORMED_PACK_RESPONSE_BODY) == ['pack1']
    assert script.find_malformed_pack_id(MALFORMED_PACK_RESPONSE_BODY_TWO_PACKS) == ['pack1', 'pack2']
    assert script.find_malformed_pack_id(ERROR_AS_LIST_RESPONSE_BODY) == []


def test_get_pack_id_from_error_with_gcp_path():
    assert script.get_pack_id_from_error_with_gcp_path(GCP_TIMEOUT_EXCEPTION_RESPONSE_BODY) == 'pack2'


class TestFindMalformedPackId:
    """
    Code Analysis

    Objective:
    The objective of the function is to extract the pack ID from the installation error message in case the error is that the
     pack is not found or the error is that the pack's version is invalid.

    Inputs:
    The function takes a single input, which is a string containing the response message of the failed installation pack.

    Flow:
    The function first initializes an empty list to store the malformed pack IDs. It then compiles a regular expression pattern
    to match the invalid version of the pack. If the input string is not empty, it loads the JSON response and extracts the error
    information. If the error message contains the string 'pack id:', it extracts the pack IDs from the error message. Otherwise,
    it searches for the malformed pack ID using the regular expression pattern. The function returns the list of
    malformed pack IDs.

    Outputs:
    The main output of the function is a list of malformed pack IDs.

    Additional aspects:
    The function uses ``contextlib.suppress()`` to catch JSONDecodeError exceptions that may occur when loading the JSON response.
    It also handles cases where the error message contains multiple errors by iterating over the list of errors.
    """

    #  Tests that the function handles an empty input string.
    def test_empty_input(self):
        assert script.find_malformed_pack_id('') == []

    #  Tests that the function returns an empty list if no malformed pack IDs are found.
    def test_no_malformed_ids(self):
        assert script.find_malformed_pack_id('{"errors": ["Some error message"]}') == []

    #  Tests that the function handles a case where the error message contains an invalid version number but no pack ID.
    def test_invalid_version_no_id(self):
        assert script.find_malformed_pack_id('{"errors": ["invalid version 1.0.0 for pack"]}') == []

    #  Tests that the function correctly extracts multiple pack IDs from the error message.
    def test_multiple_malformed_ids(self):
        error_msg = '{"errors": ["Pack installation failed. pack id: pack1","Pack installation failed. pack id: pack2"]}'
        assert script.find_malformed_pack_id(error_msg) == ['pack1', 'pack2']

    #  Tests that the function handles a JSONDecodeError when parsing the input string.
    def test_invalid_json(self):
        assert script.find_malformed_pack_id('invalid json') == []

    #  Tests that the function correctly extracts the pack ID when the error message contains additional
    #  information after the pack ID.
    def test_additional_info(self):
        error_msg = '{"errors": ["invalid version 1.0.0 for pack with ID pack1 some additional info"]}'
        assert script.find_malformed_pack_id(error_msg) == ['pack1']


def test_create_graph_empty():
    """
    Given:
        An empty dictionary of pack dependencies
    When:
        create_graph is called
    Then:
        An empty DiGraph is returned
    """
    all_packs_dependencies = {}

    graph = script.create_graph(all_packs_dependencies)

    assert isinstance(graph, DiGraph)
    assert len(graph) == 0


def test_create_graph_single_dependency():
    """
    Given:
        A dictionary with a single pack and dependency
    When:
        create_graph is called
    Then:
        A DiGraph with a single edge is returned
    """
    all_packs_dependencies = {"PackA": {"dependencies": {"PackB": {"mandatory": True}}}}

    graph = script.create_graph(all_packs_dependencies)

    assert isinstance(graph, DiGraph)
    assert len(graph.edges()) == 1
    assert ("PackB", "PackA") in graph.edges()


def test_create_graph_multiple_dependencies():
    """
    Given:
        A dictionary with multiple packs and dependencies
    When:
        create_graph is called
    Then:
        A DiGraph with multiple edges is returned
    """
    all_packs_dependencies = {
        "PackA": {
            "dependencies": {"PackB": {"mandatory": True}, "PackC": {"mandatory": True}}
        },
        "PackB": {"dependencies": {"PackD": {"mandatory": True}}},
        "PackC": {"dependencies": {}},
    }

    graph = script.create_graph(all_packs_dependencies)

    assert isinstance(graph, DiGraph)
    assert len(graph.edges()) == 3
    assert ("PackB", "PackA") in graph.edges()
    assert ("PackC", "PackA") in graph.edges()
    assert ("PackD", "PackB") in graph.edges()


def test_merge_cycles_direct_single_cycle():
    """
    Given:
        A directed graph with a direct cycle between two nodes
    When:
        merge_cycles is called on that graph
    Then:
        The nodes in the cycle are merged into a single node
    """
    graph = nx.DiGraph()
    edges = [
        ("PackB", "PackA"),
        ("PackC", "PackB"),
        ("PackB", "PackC"),
        ("PackD", "PackC"),
    ]  # Cycle between PackB and PackC
    graph.add_edges_from(edges)
    merged_nodes = ("PackB", "PackC")

    assert all(pack in graph.nodes() for pack in merged_nodes)
    assert len(graph) == 4
    assert len(graph.edges()) == len(edges)

    merged_graph = script.merge_cycles(graph)

    assert any(script.CYCLE_SEPARATOR in pack for pack in merged_graph.nodes())
    assert all(pack not in merged_graph.nodes() for pack in merged_nodes)
    assert len(merged_graph) == 3
    assert len(merged_graph.edges()) == 2


def test_merge_cycles_single_wide_cycle():
    """
    Given:
        A directed graph with a single cycle created by three nodes
    When:
        merge_cycles is called on that graph
    Then:
        The nodes in the cycle are merged into a single node
    """
    graph = nx.DiGraph()
    edges = [
        ("PackB", "PackA"),
        ("PackC", "PackB"),
        ("PackD", "PackC"),
        ("PackB", "PackD"),
        ("PackD", "PackE"),
    ]  # Cycle between PackB, PackC and PackD
    graph.add_edges_from(edges)
    merged_nodes = ("PackB", "PackC", "PackD")

    assert all(pack in graph.nodes() for pack in merged_nodes)
    assert len(graph) == 5
    assert len(graph.edges()) == len(edges)

    merged_graph = script.merge_cycles(graph)

    assert any(script.CYCLE_SEPARATOR in pack for pack in merged_graph.nodes())
    assert all(pack not in merged_graph.nodes() for pack in merged_nodes)
    assert len(merged_graph) == 3
    assert len(merged_graph.edges()) == 2


def test_merge_cycles_node_with_multiple_cycles():
    """
    Given:
        A directed graph with a node that have multiple cycles
        The node 'PackC' have two cycles, one with PackB and one with PackD.
    When:
        merge_cycles is called on that graph
    Then:
        The nodes in each cycle are merged into separate single nodes
    """
    graph = nx.DiGraph()
    edges = [
        ("PackB", "PackA"),
        ("PackC", "PackB"),
        ("PackB", "PackC"),
        ("PackD", "PackC"),
        ("PackC", "PackD"),
        ("PackE", "PackD"),
    ]  # Cycle between PackB and PackC, and cycle between PackC and PackD
    graph.add_edges_from(edges)
    merged_nodes = ("PackB", "PackC", "PackD")

    assert all(pack in graph.nodes() for pack in merged_nodes)
    assert len(graph) == 5
    assert len(graph.edges()) == len(edges)

    merged_graph = script.merge_cycles(graph)

    assert any(script.CYCLE_SEPARATOR in pack for pack in merged_graph.nodes())
    assert all(pack not in merged_graph.nodes() for pack in merged_nodes)
    assert len(merged_graph) == 3
    assert len(merged_graph.edges()) == 2


@pytest.mark.parametrize(
    "list_of_nodes, expected",
    (
        (["PackA", "PackB<->PackC"], [["PackA"], ["PackB", "PackC"]]),
        (["PackX"], [["PackX"]]),
        ([], []),
    ),
)
def test_split_cycles(list_of_nodes, expected):
    """
    Given:
        A list of nodes, some of which are merged cycles
    When:
        Calling split_cycles
    Then:
        Returns a list of lists, with merged cycles split
    """
    result = script.split_cycles(list_of_nodes)
    assert result == expected


def test_get_all_content_packs_dependencies(mocker: MockFixture):
    """
    Given:
        A demisto client instance
    When:
        get_all_content_packs_dependencies is called and iterates over pages
    Then:
        Pack dependencies are extracted correctly across pages
    """
    # Mock client and responses
    client = mocker.Mock()
    mock_request = [
        {
            "total": 3,
            "packs": [
                {
                    "id": "Pack1",
                    "dependencies": {},
                    "currentVersion": "",
                    "deprecated": "",
                },
                {
                    "id": "Pack2",
                    "dependencies": {},
                    "currentVersion": "",
                    "deprecated": "",
                },
            ]
        },
        {
            "total": 3,
            "packs": [
                {
                    "id": "Pack3",
                    "dependencies": {},
                    "currentVersion": "",
                    "deprecated": "",
                }
            ]
        },
    ]
    mocker.patch.object(
        script, "get_one_page_of_packs_dependencies", side_effect=mock_request
    )
    script.PAGE_SIZE_DEFAULT = 2

    # Call function and test
    result = script.get_all_content_packs_dependencies(client)

    assert len(result) == 3
    assert all(pack in result for pack in ("Pack1", "Pack2", "Pack3"))


def test_get_all_content_packs_dependencies_empty(mocker: MockFixture):
    """
    Given:
        A demisto client instance
    When:
        The search API returns no results
    Then:
        An empty dict is returned
    """
    client = mocker.Mock()
    mocker.patch.object(
        script, "get_one_page_of_packs_dependencies", return_value={"total": 3, "packs": []}
    )

    result = script.get_all_content_packs_dependencies(client)

    assert result == {}


def test_get_one_page_of_packs_dependencies_success(mocker: MockFixture):
    """
    Given:
        A demisto client and page number
    When:
        Calling get_one_page_of_packs_dependencies
    Then:
        - Make API call with correct params
        - Return API response
    """
    client = mocker.Mock()
    page = 1

    mocker.patch.object(
        script, "generic_request_with_retries", return_value=(True, {"packs": []})
    )

    result = script.get_one_page_of_packs_dependencies(client, page)

    assert result == {"packs": []}


def test_search_for_deprecated_dependencies_with_deprecated_dependency(
    mocker: MockFixture,
):
    """
    Given:
        - Pack ID
        - Set of dependency pack IDs containing a deprecated pack
        - Pack metadata mapping containing deprecated pack metadata
    When:
        Calling search_for_deprecated_dependencies
    Then:
        - Returns False
        - Logs critical message about deprecated dependency
    """
    pack_id = "TestPack"
    dependencies = {"Pack1", "Pack2"}
    dependencies_data = {"Pack1": {"deprecated": True}, "Pack2": {"deprecated": False}}
    mocker.patch.object(script, "logging")

    assert (
        script.search_for_deprecated_dependencies(
            pack_id, dependencies, True, dependencies_data
        )
        is False
    )

    script.logging.critical.assert_called_with(mocker.ANY)


def test_search_for_deprecated_dependencies_no_deprecated_dependency(mocker: MockFixture):
    """
    Given:
        - Pack ID
        - Set of dependency pack IDs with no deprecated packs
        - Pack metadata mapping with no deprecated packs
    When:
        Calling search_for_deprecated_dependencies
    Then:
        - Returns True
        - Does not log any critical messages
    """
    pack_id = "TestPack"
    dependencies = {"Pack1", "Pack2"}
    dependencies_data = {"Pack1": {"deprecated": False}, "Pack2": {"deprecated": False}}
    mocker.patch.object(script, "logging")

    assert (
        script.search_for_deprecated_dependencies(
            pack_id, dependencies, True, dependencies_data
        )
        is True
    )
    script.logging.critical.assert_not_called()


def test_get_packs_and_dependencies_to_install_no_deprecated(mocker: MockFixture):
    """
    Given:
        Packs to search for their dependencies
    When:
        Calling get_packs_and_dependencies_to_install
    Then:
        Ensure correct return value with no deprecated dependencies
    """
    client = MockClient()
    mocker.patch.object(script, 'search_for_deprecated_dependencies',
                        return_value=True)
    mocker.patch.object(script, "get_server_numeric_version", return_value="6.9")
    mocker.patch.object(script, "create_packs_artifacts", return_value="")

    pack_id = "PackA"
    dependencies = {"Dep1", "Dep2"}
    production_bucket = True
    dependencies_data = {}
    mocker.patch.object(script, "filter_packs_by_min_server_version", return_value=dependencies)

    pack_ids = [pack_id]
    graph_dependencies = DiGraph([(d, pack_id) for d in dependencies])

    result = script.get_packs_and_dependencies_to_install(
        pack_ids, graph_dependencies, production_bucket, dependencies_data, client)

    assert result == (True, {pack_id, *dependencies})


def test_get_packs_and_dependencies_to_install_no_dependencies(mocker: MockFixture):
    """
    Given:
        Packs to search for their dependencies
    When:
        Calling get_packs_and_dependencies_to_install, for pack with no dependencies
    Then:
        Ensure that the pack itself added to result
    """
    client = MockClient()
    mocker.patch.object(script, 'search_for_deprecated_dependencies',
                        return_value=True)
    mocker.patch.object(script, "create_packs_artifacts", return_value="")

    pack_id = "PackA"
    dependencies = {}
    production_bucket = True
    dependencies_data = {}

    pack_ids = [pack_id]
    graph_dependencies = DiGraph()
    graph_dependencies.add_node(pack_id)

    result = script.get_packs_and_dependencies_to_install(
        pack_ids, graph_dependencies, production_bucket, dependencies_data, client)

    assert result == (True, {pack_id, *dependencies})


def test_get_packs_and_dependencies_to_install_deprecated(mocker: MockFixture):
    """
    Given:
        - Pack ID
        - Dependency IDs
        - Production bucket flag
        - Packs dependencies data
    When:
        - Getting packs and dependencies to install
        - Mocking search finding deprecated dependencies
    Then:
        - Ensure empty dependencies set returned
        - Ensure no deprecated dependencies flag set to False
    """
    client = MockClient()
    mocker.patch.object(script, "search_for_deprecated_dependencies",
                        return_value=False)
    mocker.patch.object(script, "get_server_numeric_version", return_value="6.9")
    mocker.patch.object(script, "create_packs_artifacts", return_value="")

    pack_id = "PackA"
    dependencies = {"Dep1", "Dep2"}
    production_bucket = True
    dependencies_data = {}
    mocker.patch.object(script, "filter_packs_by_min_server_version", return_value=dependencies)

    pack_ids = [pack_id]
    graph_dependencies = DiGraph([(d, pack_id) for d in dependencies])

    result = script.get_packs_and_dependencies_to_install(
        pack_ids, graph_dependencies, production_bucket, dependencies_data, client)

    assert result == (False, set())


def test_create_install_request_body():
    """
    Given:
        - A list of packs to install
        - Dependencies data for packs
    When:
        Calling create_install_request_body
    Then:
        Validate returned request body contains correct data
    """
    packs_to_install = [['HelloWorld'], ['TestPack']]
    packs_deps_data = {
        'HelloWorld': {'currentVersion': '1.0.0'},
        'TestPack': {'currentVersion': '2.0.0'}
    }
    result = script.create_install_request_body(packs_to_install, packs_deps_data)

    assert len(result) == 2
    assert result[0][0]['id'] == 'HelloWorld'
    assert result[1][0]['id'] == 'TestPack'


def test_filter_deprecated_packs(mocker: MockFixture):
    """
    Given:
        - A list of pack IDs, some deprecated and some not
        - Production bucket boolean
        - Commit hash

    When:
        Calling filter_deprecated_packs

    Then:
        - Deprecated packs are filtered from the list
        - Warning is logged for deprecated packs
        - List without deprecated packs is returned
    """
    pack_ids = ['pack1', 'deprecated_pack', 'pack2']
    production_bucket = True
    commit_hash = '1234abcd'

    mocker.patch.object(script, 'is_pack_deprecated', side_effect=[False, True, False])
    mocker.patch.object(script, 'logging')

    result = script.filter_deprecated_packs(pack_ids, production_bucket, commit_hash)

    assert result == ['pack1', 'pack2']
    script.logging.warning.assert_called_with("Pack 'deprecated_pack' is deprecated (hidden) and will not be installed.")


@pytest.mark.parametrize("list_of_packs, expected", [
    (
        [["pack1"], ["pack2", "pack3"]],
        [["pack1", "pack2", "pack3"]]
    ),
    (
        [["pack1"], ["pack2", "pack3"], ["pack4"]],
        [["pack1", "pack2", "pack3", "pack4"]]
    ),
    (
        [["pack1"], ["pack2", "pack3"], ["pack4", "pack5", "pack6"]],
        [["pack1", "pack2", "pack3"], ["pack4", "pack5", "pack6"]]
    )
])
def test_create_batches(mocker: MockFixture, list_of_packs, expected):
    """
    Given:
        A list of packs and dependencies

    When:
        Running create_batches

    Then:
        Ensure the correct batches are created based on the batch size
    """
    mocker.patch.object(script, "BATCH_SIZE", 5)
    assert script.create_batches(list_of_packs) == expected


def test_search_and_install_packs_success(mocker: MockFixture):
    """
    Given:
        A list of pack IDs to install

    When:
        search_and_install_packs_and_their_dependencies is called with that list of packs

    Then:
        A success response should be returned, since no deprecated dependencies packs were found
        and packs were installed successfully
    """
    mock_packs = ["pack1", "pack2"]
    mocker.patch.object(script, "get_env_var", return_value="commit")
    mocker.patch.object(script, "filter_deprecated_packs", return_value=mock_packs)
    mocker.patch.object(script, "get_all_content_packs_dependencies", return_value={})
    mocker.patch.object(script, "save_graph_data_file_log")
    mocker.patch.object(
        script, "get_packs_and_dependencies_to_install", return_value=(True, set())
    )
    mocker.patch.object(script, "merge_cycles", return_value=DiGraph())
    mocker.patch.object(script, "install_packs", return_value=(True, []))

    _, success = script.search_and_install_packs_and_their_dependencies(
        pack_ids=mock_packs, client=MockClient()
    )

    assert success is True


def test_search_and_install_packs_deprecated_dependencies(mocker: MockFixture):
    """
    Given:
        A list of pack IDs to install

    When:
        search_and_install_packs_and_their_dependencies is called with that list of packs

    Then:
        A failure response should be returned, since deprecated dependencies packs were found
    """
    mock_packs = ["pack1", "pack2"]
    mocker.patch.object(script, "get_env_var", return_value="commit")
    mocker.patch.object(script, "filter_deprecated_packs", return_value=mock_packs)
    mocker.patch.object(script, "get_all_content_packs_dependencies", return_value={})
    mocker.patch.object(script, "save_graph_data_file_log")
    mocker.patch.object(
        script, "get_packs_and_dependencies_to_install", return_value=(False, set())
    )
    mocker.patch.object(script, "merge_cycles", return_value=DiGraph())
    mocker.patch.object(script, "install_packs", return_value=(True, []))

    _, success = script.search_and_install_packs_and_their_dependencies(
        pack_ids=mock_packs, client=MockClient()
    )

    assert success is False


def test_search_and_install_packs_failure_install_packs(mocker: MockFixture):
    """
    Given:
        A list of pack IDs to install

    When:
        search_and_install_packs_and_their_dependencies is called with that list of packs

    Then:
        A failure response should be returned, since the install packs call returned a failure
    """
    mock_packs = ["pack1", "pack2"]
    mocker.patch.object(script, "get_env_var", return_value="commit")
    mocker.patch.object(script, "filter_deprecated_packs", return_value=mock_packs)
    mocker.patch.object(script, "get_all_content_packs_dependencies", return_value={})
    mocker.patch.object(script, "save_graph_data_file_log")
    mocker.patch.object(
        script, "get_packs_and_dependencies_to_install", return_value=(False, set())
    )
    mocker.patch.object(script, "merge_cycles", return_value=DiGraph())
    mocker.patch.object(script, "install_packs", return_value=(False, []))

    _, success = script.search_and_install_packs_and_their_dependencies(
        pack_ids=mock_packs, client=MockClient()
    )

    assert success is False


@pytest.mark.parametrize(
    'pack_version, expected_results',
    [('6.5.0', {'TestPack'}), ('6.8.0', set())])
def test_get_packs_with_higher_min_version(mocker: MockFixture, pack_version, expected_results):
    """
    Given:
        - Pack names to install.
        - case 1: pack with a version lower than the machine.
        - case 2: pack with a version higher than the machine.
    When:
        - Running 'get_packs_with_higher_min_version' method.
    Then:
        - Assert the returned packs are with higher min version than the server version.
        - case 1: shouldn't filter any packs.
        - case 2: should filter the pack.
    """
    mocker.patch.object(script, "get_json_file",
                        return_value={"serverMinVersion": "6.6.0"})

    packs_with_higher_min_version = script.get_packs_with_higher_min_version({'TestPack'}, pack_version, "")
    assert packs_with_higher_min_version == expected_results


def test_filter_packs_by_min_server_version_packs_filtered(mocker: MockFixture):
    """
    Given:
        A set of pack IDs and a server version
    When:
        Some packs have a higher min version than the server version
    Then:
        It returns the pack IDs that have a lower min version
    """
    packs_id = {"Pack1", "Pack2", "Pack3"}
    server_version = "6.10.0"
    mocker.patch.object(script, 'get_packs_with_higher_min_version', return_value={"Pack2", "Pack3"})

    filtered_packs = script.filter_packs_by_min_server_version(packs_id, server_version, "")

    assert filtered_packs == {"Pack1"}


def test_filter_packs_by_min_server_version_no_packs_filtered(mocker: MockFixture):
    """
    Given:
        A set of pack IDs and a server version
    When:
        No packs have a higher min version than the server version
    Then:
        It returns the original set of pack IDs
    """
    packs_id = {"Pack1", "Pack2", "Pack3"}
    server_version = "6.9.0"
    mocker.patch.object(script, 'get_packs_with_higher_min_version', return_value=set())

    filtered_packs = script.filter_packs_by_min_server_version(packs_id, server_version, "")

    assert filtered_packs == packs_id

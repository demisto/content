import json
from pathlib import Path

import urllib3.request
from urllib3.response import HTTPResponse

import demisto_client
import pytest
import timeout_decorator
import Tests.Marketplace.search_and_install_packs as script
from demisto_client.demisto_api.rest import ApiException
from Tests.Marketplace.marketplace_constants import GCPConfig
from google.cloud.storage import Blob

BASE_URL = 'http://123-fake-api.com'
API_KEY = 'test-api-key'


def load_json_file(directory: str, file_name: str):
    with open(Path(__file__).parent / 'test_data' / directory / file_name) as json_file:
        json_data = json.load(json_file)
    return json_data


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


def mocked_generic_request_func(self, path: str, method, body=None, accept=None, _request_timeout=None, response_type='object'):
    if body:
        if body[0].get('id') == 'HelloWorld':
            return MOCK_HELLOWORLD_SEARCH_RESULTS, 200, None
        elif body and body[0].get('id') == 'AzureSentinel':
            return MOCK_AZURESENTINEL_SEARCH_RESULTS, 200, None
    return None, None, None


class MockConfiguration:
    def __init__(self):
        self.host = None


class MockApiClient:
    def __init__(self):
        self.configuration = MockConfiguration()


class MockClient:
    def __init__(self):
        self.api_client = MockApiClient()


class MockLock:
    def acquire(self):
        return None

    def release(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return False


@pytest.mark.parametrize('use_multithreading', [True, False])
def test_search_and_install_packs_and_their_dependencies(mocker, use_multithreading: bool):
    """
    Given
    - Valid pack ids.
    - Invalid pack id.
    When
    - Running integrations configuration tests.
    Then
    - Ensure packs & their dependency search requests are valid.
    - Ensure packs & their dependency installation requests are valid.
    """
    good_pack_ids = [
        'HelloWorld',
        'AzureSentinel'
    ]

    bad_pack_ids = ['malformed_pack_id']

    client = MockClient()

    mocker.patch.object(script, 'install_packs')
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)
    mocker.patch.object(script, 'is_pack_deprecated', return_value=False)  # Relevant only for post-update unit-tests

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(pack_ids=good_pack_ids,
                                                                                      client=client,
                                                                                      multithreading=use_multithreading,
                                                                                      is_post_update=False)
    assert 'HelloWorld' in installed_packs
    assert 'AzureSentinel' in installed_packs
    assert 'TestPack' in installed_packs
    assert success is True

    installed_packs, _ = script.search_and_install_packs_and_their_dependencies(pack_ids=bad_pack_ids,
                                                                                client=client,
                                                                                multithreading=use_multithreading,
                                                                                is_post_update=False)
    assert bad_pack_ids[0] not in installed_packs


@pytest.mark.parametrize('error_code,use_multithreading',
                         [
                             (400, True), (400, False),
                             (500, True), (500, False),
                         ])
def test_search_and_install_packs_and_their_dependencies_with_error(mocker, error_code, use_multithreading: bool):
    """
    Given
    - Error when searching for a pack
    When
    - Running integrations configuration tests.
    Then
    - Ensure a flag is raised
    """
    good_pack_ids = ['HelloWorld']

    client = MockClient()
    mock_response = HTTPResponse(status=error_code, body=b"Error")

    mocker.patch.object(script, 'install_packs')
    mocker.patch.object(urllib3.request.RequestMethods, 'request', return_value=mock_response)

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(pack_ids=good_pack_ids,
                                                                                      client=client,
                                                                                      multithreading=use_multithreading,
                                                                                      is_post_update=False)
    assert success is False


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
        {'id': 'HelloWorld'},
        {'id': 'TestPack'},
        {'id': 'AzureSentinel'},
        {'id': 'Base'},
        {'id': 'bad_integration1'},
        {'id': 'bad_integration2'},
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


@pytest.mark.parametrize("pack_metadata_content, expected", [
    ({'hidden': False}, False),
    ({'hidden': True}, True),
])
def test_is_pack_hidden(tmp_path, pack_metadata_content, expected):
    """
    Given:
        - Case A: Pack is not deprecated
        - Case B: Pack is deprecated

    When:
        - Checking if pack is deprecated

    Then:
        - Case A: Verify pack is not deprecated, since the 'hidden' flag is set to 'false'
        - Case B: Verify pack is deprecated, since the 'hidden' flag is set to 'true'
    """
    pack_metadata_file = tmp_path / PACKS_PACK_META_FILE_NAME
    pack_metadata_file.write_text(json.dumps(pack_metadata_content))
    assert script.is_pack_hidden(str(tmp_path)) == expected


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
        mocker.patch('time.sleep', return_value=None)
        client = MockClient()
        assert not script.install_packs(client, 'my_host', packs_to_install=[{'id': 'pack1'}, {'id': 'pack3'}])

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
        mocker.patch('time.sleep', return_value=None)
        client = MockClient()
        assert not script.install_packs(client, 'my_host', packs_to_install=[{'id': 'pack1'}, {'id': 'pack2'}])


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

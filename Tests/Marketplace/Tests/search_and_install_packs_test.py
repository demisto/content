import demisto_client
import Tests.Marketplace.search_and_install_packs as script
from Tests.test_content import ParallelPrintsManager

BASE_URL = 'http://123-fake-api.com'
API_KEY = 'test-api-key'

MOCK_HELLOWORLD_SEARCH_RESULTS = """{
    "id": "HelloWorld",
    "currentVersion": "1.1.10"
}"""
MOCK_AZURESENTINEL_SEARCH_RESULTS = """{
    "id": "AzureSentinel",
    "currentVersion": "1.0.2"
}"""
MOCK_PACKS_INSTALLATION_RESULT = """[
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
]"""

MOCK_PACKS_DEPENDENCIES_RESULT = """{
    "dependencies": [
        {
            "id": "TestPack",
            "currentVersion": "",
            "dependants": {
                "HelloWorld": {
                    "level": "required"
                }
            },
            "extras": {
                "pack": {
                    "currentVersion": "1.0.0"
                }
            }
        }
    ]
}"""


def mocked_generic_request_func(self, path: str, method, body=None, accept=None, _request_timeout=None):
    if path == '/contentpacks/marketplace/HelloWorld':
        return MOCK_HELLOWORLD_SEARCH_RESULTS, 200, None
    if path == '/contentpacks/marketplace/AzureSentinel':
        return MOCK_AZURESENTINEL_SEARCH_RESULTS, 200, None
    elif path == '/contentpacks/marketplace/install':
        return MOCK_PACKS_INSTALLATION_RESULT, 200, None
    elif path == '/contentpacks/marketplace/search/dependencies':
        return MOCK_PACKS_DEPENDENCIES_RESULT, 200, None
    return None, None, None


def mocked_get_pack_display_name(pack_id):
    if pack_id == 'HelloWorld':
        return 'HelloWorld'
    elif pack_id == 'AzureSentinel':
        return 'AzureSentinel'
    return ''


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


def test_search_and_install_packs_and_their_dependencies(mocker):
    """
    Given
    - Valid pack ids.
    - Invalid pack id.
    When
    - Running integrations configuration tests.
    Then
    - Ensure packs & their dependencies' search requests are valid.
    - Ensure packs & their dependencies' installation requests are valid.
    """
    good_pack_ids = [
        'HelloWorld',
        'AzureSentinel'
    ]

    bad_pack_ids = ['malformed_pack_id']

    client = MockClient()

    mocker.patch.object(script, 'install_packs')
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)
    mocker.patch.object(script, 'get_pack_display_name', side_effect=mocked_get_pack_display_name)
    prints_manager = ParallelPrintsManager(1)

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(good_pack_ids,
                                                                                      client,
                                                                                      prints_manager)
    assert 'HelloWorld' in installed_packs
    assert 'AzureSentinel' in installed_packs
    assert 'TestPack' in installed_packs
    assert success is True

    installed_packs, _ = script.search_and_install_packs_and_their_dependencies(bad_pack_ids,
                                                                                client,
                                                                                prints_manager)
    assert bad_pack_ids[0] not in installed_packs


def test_search_and_install_packs_and_their_dependencies_with_error(mocker):
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

    mocker.patch.object(script, 'install_packs')
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('', 500, None))
    mocker.patch.object(script, 'get_pack_display_name', side_effect=mocked_get_pack_display_name)
    prints_manager = ParallelPrintsManager(1)

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(good_pack_ids,
                                                                                      client,
                                                                                      prints_manager)
    assert success is False


def test_search_pack_with_id(mocker):
    """
   Given
   - Pack with a new name (different from its ID)
   When
   - Searching the pack in the Demsito instance.
   Then
   - Ensure the pack is found using its ID
   """
    client = MockClient()
    prints_manager = ParallelPrintsManager(1)
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)
    expected_response = {
        'id': 'HelloWorld',
        'version': '1.1.10'
    }
    assert expected_response == script.search_pack(client, prints_manager, "New Hello World", 'HelloWorld', 0, None)


def test_search_pack_with_failure(mocker):
    """
   Given
   - Error when searching for pack
   - Response with missing data
   When
   - Searching the pack in the Demsito instance for installation.
   Then
   - Ensure error is raised.
   """
    client = MockClient()
    prints_manager = ParallelPrintsManager(1)
    lock = MockLock()

    # Error when searching for pack
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('', 500, None))
    script.search_pack(client, prints_manager, "New Hello World", 'HelloWorld', 0, lock)
    assert not script.SUCCESS_FLAG

    # Response with missing data
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('{"id": "HelloWorld"}', 200, None))
    script.search_pack(client, prints_manager, "New Hello World", 'HelloWorld', 0, lock)
    assert not script.SUCCESS_FLAG

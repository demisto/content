import demisto_client
import Tests.Marketplace.search_and_install_packs as script
from Tests.test_content import ParallelPrintsManager

BASE_URL = 'http://123-fake-api.com'
API_KEY = 'test-api-key'

MOCK_PACKS_SEARCH_RESULTS = """{
    "packs": [
        {
            "id": "HelloWorld",
            "currentVersion": "2.0.0",
            "name": "HelloWorld",
            "dependencies": {"Base": {}, "TestPack": {}}
        },
        {
            "id": "TestPack",
            "currentVersion": "1.0.0",
            "name": "TestPack",
            "dependencies": {"Base": {}}
        },
        {
            "id": "AzureSentinel",
            "currentVersion": "1.0.0",
            "name": "AzureSentinel",
            "dependencies": {"Base": {}}
        },
        {
            "id": "Base",
            "currentVersion": "1.0.0",
            "name": "Base",
            "dependencies": {}
        }
    ]
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


def mocked_generic_request_func(self, path, method, body, accept, _request_timeout):
    if path == '/contentpacks/marketplace/search':
        return MOCK_PACKS_SEARCH_RESULTS, 200, None
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


def test_search_and_install_packs_and_their_dependencies(mocker):
    """
    Given
    - Valid and invalid integrations paths.
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

    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('', 500, None))
    mocker.patch.object(script, 'get_pack_display_name', side_effect=mocked_get_pack_display_name)
    prints_manager = ParallelPrintsManager(1)

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(good_pack_ids,
                                                                                      client,
                                                                                      prints_manager)
    assert success is False

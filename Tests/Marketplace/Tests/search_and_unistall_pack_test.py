import demisto_client
import pytest
import Tests.Marketplace.search_and_uninstall_pack as script

BASE_URL = 'http://123-fake-api.com'
API_KEY = 'test-api-key'

MOCK_BASE_SEARCH_RESULTS = """{
    "id": "Base",
    "currentVersion": "1.0.2"
}"""
MOCK_PACKS_INSTALLATED_RESULT = """[
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
        "id": "Base",
        "currentVersion": "1.0.0",
        "name": "Base",
        "installed": "2020-04-06T14:54:09.755811+03:00"
    }
]"""
MOCK_PACKS_ID_TO_UNINSTALL = ['HelloWorld', 'TestPack', 'Base']


def mocked_generic_request_func(self, path: str, method, body=None, accept=None, _request_timeout=None):
    if path == '/contentpacks/marketplace/Base':
        return MOCK_BASE_SEARCH_RESULTS, 200, None
    elif path == '/contentpacks/metadata/installed':
        return MOCK_PACKS_INSTALLATED_RESULT, 200, None
    elif path == '/contentpacks/installed/delete':
        return None, 200, None
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


def test_get_installed_packs(mocker):
    """
    Given
    - Instance with packs to uninstall.
    When
    - Cleaning up xsiam instance between builds.
    Then
    - Ensure all packs beside Base pack listed to be uninstalled.
    """

    client = MockClient()

    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)

    installed_packs = script.get_all_installed_packs(client)
    assert 'HelloWorld' in installed_packs
    assert 'TestPack' in installed_packs
    assert 'Base' not in installed_packs


def test_uninstall_all_packs(mocker):
    """
    Given
    - Packs ids list to uninstall.
    When
    - Uninstalling all packs.
    Then
    - Ensure all packs uninstalled.
    """

    client = MockClient()

    mocker.patch.object(script, 'get_all_installed_packs', return_value=MOCK_PACKS_ID_TO_UNINSTALL)
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)

    success = script.uninstall_all_packs(client, 'hostname')

    assert success is True


def test_reset_base_pack_version(mocker):
    """
   Given
   - Base pack with different version than production.
   When
   - Updating Base pack to prod version.
   Then
   - Ensure the pack version gets reset.
   """
    client = MockClient()
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)
    mocker.patch('Tests.Marketplace.search_and_uninstall_pack.install_packs', return_value=True)
    success = script.reset_base_pack_version(client)

    assert success is True


@pytest.mark.parametrize('def_call, return_val', [
    (script.get_all_installed_packs, None),
    (script.reset_base_pack_version, False)
])
def test_exception_reset_base_pack(def_call, return_val, mocker):
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
    ret_val_from_call = def_call(client)
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('', 500, None))

    assert ret_val_from_call == return_val

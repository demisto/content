import demisto_client
import pytest

import Tests.Marketplace.search_and_install_packs as script

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

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(good_pack_ids,
                                                                                      client)
    assert 'HelloWorld' in installed_packs
    assert 'AzureSentinel' in installed_packs
    assert 'TestPack' in installed_packs
    assert success is True

    installed_packs, _ = script.search_and_install_packs_and_their_dependencies(bad_pack_ids,
                                                                                client)
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

    installed_packs, success = script.search_and_install_packs_and_their_dependencies(good_pack_ids,
                                                                                      client)
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
    mocker.patch.object(demisto_client, 'generic_request_func', side_effect=mocked_generic_request_func)
    expected_response = {
        'id': 'HelloWorld',
        'version': '1.1.10'
    }
    assert expected_response == script.search_pack(client, "New Hello World", 'HelloWorld', None)


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
    lock = MockLock()

    # Error when searching for pack
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('', 500, None))
    script.search_pack(client, "New Hello World", 'HelloWorld', lock)
    assert not script.SUCCESS_FLAG

    # Response with missing data
    mocker.patch.object(demisto_client, 'generic_request_func', return_value=('{"id": "HelloWorld"}', 200, None))
    script.search_pack(client, "New Hello World", 'HelloWorld', lock)
    assert not script.SUCCESS_FLAG


ERROR_MESSAGE = """
(400)
Reason: Bad Request
HTTP response headers: HTTPHeaderDict({'Content-Type': 'application/json',
'Set-Cookie': 'S=A4Nj75P0P3UcPLb2eJByVpv311AEzeVsjIjLpKyFjNRJHjBHcJaj3LHskUp9Sdceu5BFhw38bX5+xs//0s/JL8/mig6kkm5/
atpS7Rt5gyd3PKaVz0Mh9tvFuZ4JdhA3tIeq5gy9O+8ADlMT0JjLuCl7jqJmlH7ENX9JEJ6chadow3ah78loM3roczVSPiZPLg9hHDtwiq8tB5SNis5K;
Path=/; Expires=Mon, 02 Nov 2020 11:23:10 GMT; Max-Age=3600; HttpOnly; Secure; SameSite=Lax,
S-Expiration=MDIgTm92IDIwIDExOjIzICswMDAw; Path=/; Expires=Mon, 02 Nov 2020 11:23:10 GMT; Max-Age=3600;
Secure; SameSite=Lax', 'Strict-Transport-Security': 'max-age=10886400000000000; includeSubDomains',
'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'X-Xss-Protection': '1; mode=block',
'Date': 'Mon, 02 Nov 2020 10:23:10 GMT', 'Content-Length': '218'})
HTTP response body: {"id":"bad_request","status":400,"title":"Bad request","detail":"Request body is not well-formed.
It must be JSON.","error":"invalid version 1.2.0 for pack with ID AutoFocus (35000)","encrypted":false,"multires":null}
"""


def test_find_malformed_pack_id():
    """
    Given
    - Error message.
    When
    - Run find_malformed_pack_id command.
    Then
    - Ensure the pack ID is caught.
   """
    malformed_pack_id = script.find_malformed_pack_id(ERROR_MESSAGE)
    assert 'AutoFocus' in malformed_pack_id


def test_not_find_malformed_pack_id():
    """
    Given
    - Error message without any pack ID.
    When
    - Run find_malformed_pack_id command.
    Then
    - Ensure Exception is returned with the error message.
    """
    with pytest.raises(Exception, match='The request to install packs has failed. '
                                        'Reason: This is an error message without pack ID'):
        script.find_malformed_pack_id('This is an error message without pack ID')

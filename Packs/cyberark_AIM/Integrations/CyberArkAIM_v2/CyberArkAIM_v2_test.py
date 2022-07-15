import pytest
import copy
import demistomock as demisto
from CyberArkAIM_v2 import Client, list_credentials_command, fetch_credentials
from test_data.context import LIST_CREDENTIALS_CONTEXT
from test_data.get_credentials_res import LIST_CREDENTIALS_RAW


@pytest.mark.parametrize('command, get_credentials_res, context', [
    (list_credentials_command, copy.deepcopy(LIST_CREDENTIALS_RAW), LIST_CREDENTIALS_CONTEXT)
])
def test_cyberark_aim_commands(command, get_credentials_res, context, mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - mock the http request result
    Then
    - create the context
    - validate the expected_result and the created context
    - make sure the key "Content" that contains the password doesn't appear in content or raw_response
    """
    client = Client(server_url="https://api.cyberark.com/", use_ssl=False, proxy=False, app_id="app", folder="Root",
                    safe="safe1", credentials_object="name1,name2", username="", password="", cert_text="", key_text="")
    mocker.patch.object(Client, 'get_credentials', side_effect=lambda name: get_credentials_res[name])

    outputs = command(client)
    results = outputs.to_context()
    assert results.get("EntryContext") == context
    assert not results.get("EntryContext")['CyberArkAIM(val.Name && val.Name == obj.Name)'][0].get("Content")
    assert not results.get("Contents")[0].get("Content")


@pytest.mark.parametrize('creds_name_to_fetch, expected_res', [
    ('name1', [{
        "user": 'username1',
        "password": 'password1',
        "name": 'name1',
    }]),
    (None, [{
        "user": 'username1',
        "password": 'password1',
        "name": 'name1',
    }, {
        "user": 'username2',
        "password": 'password2',
        "name": 'name2',
    }
    ])
])
def test_cyberark_fetch_credentials(creds_name_to_fetch, expected_res, mocker):
    """
    Given
    - Case A: Creds name to fetch credentials is 'name1'
    - Case B: No specific creds were asked in fetch credentials
    When
    - Running fetch-credentials process
    Then
    - Ensure that the credentials returned to demisto are: [(username1,password1,name1)]
    - Ensure that all credentials were returned to demisto: [(username1,password1,name1),(username2,password2,name2)]
    """
    client = Client(server_url="https://api.cyberark.com/", use_ssl=False, proxy=False, app_id="app", folder="Root",
                    safe="safe1", credentials_object="name1,name2", username="", password="", cert_text="", key_text="")
    mocker.patch.object(Client, 'get_credentials', side_effect=lambda name: LIST_CREDENTIALS_RAW[name])
    mocker.patch.object(demisto, 'credentials')
    fetch_credentials(client, {'identifier': creds_name_to_fetch})
    demisto.credentials.assert_called_with(expected_res)


@pytest.mark.parametrize('creds_name_to_fetch, get_call_num, expected_res', [
    ('name1, name2', 2, 'ok'),
    ('', 1, 'ok')
])
def test_test_module_passes(creds_name_to_fetch, get_call_num, expected_res, mocker):
    """
        Given
        - Case A: Creds name to fetch credentials is 'name1, name2'
        - Case B: No specific creds were asked in fetch credentials
        When
        - Running fetch-credentials process
        Then
        - Ensure that the credentials returned to demisto are: [(username1,password1,name1)]
        - Ensure that all credentials were returned to demisto: [(username1,password1,name1),(username2,password2,name2)]
        """
    from CyberArkAIM_v2 import test_module
    client = Client(server_url="https://api.example.com/", use_ssl=False, proxy=False, app_id="app", folder="Root",
                    safe="safe1", credentials_object=creds_name_to_fetch, username="", password="", cert_text="", key_text="")
    get_mock = mocker.patch.object(Client, 'get_credentials')
    res = test_module(client)
    assert get_mock.call_count == get_call_num
    assert res == expected_res

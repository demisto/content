import io
import json
import requests

import pytest

from AzureStorage import (ASClient, storage_account_list, storage_account_create_update,
                          storage_blob_service_properties_get, storage_blob_service_properties_set,
                          storage_blob_containers_create, storage_blob_containers_update, storage_blob_containers_list)

app_id = 'app_id'
subscription_id = 'subscription_id'
resource_group_name = 'resource_group_name'


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureStorage.MicrosoftClient.get_access_token', return_value='token')
    return ASClient(app_id, subscription_id, resource_group_name, False, False, 'Device Code')


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_storage_account_list(client, mocker):
    """
    Given:
        - AS Client
        - An API response for storage account list

    When:
        - Running storage_account_list

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('./test_data/storage_account_list_response.json')
    mocker.patch.object(ASClient, "storage_account_list_request", return_value=api_response)
    result = storage_account_list(client=client, args={}, params={'subscription_id': subscription_id,
                                                                  'resource_group_name': resource_group_name})
    expected_hr = '### Azure Storage Account List\n' \
                  '|Account Name|Subscription ID|Resource Group|Kind|Status Primary|Status Secondary|Location|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| account_name_1 | subscription_id_1 | resource_group_name_1 | Storage | available |  | location1 ' \
                  '|\n| account_name_2 | subscription_id_2 | resource_group_name_2 | Storage | available | available ' \
                  '| location_2 |\n'
    assert result.outputs == api_response.get('value')
    assert result.readable_output == expected_hr


def test_storage_account_single(client, mocker):
    """
    Given:
        - AS Client
        - An API response for single storage account

    When:
        - Running storage_account_list with a given account_name argument

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('test_data/storage_account_single_response.json')
    mocker.patch.object(ASClient, "storage_account_list_request", return_value=api_response)
    result = storage_account_list(client=client, args={'account_name': 'account_name'},
                                  params={'subscription_id': subscription_id,
                                          'resource_group_name': resource_group_name})
    expected_hr = '### Azure Storage Account List\n' \
                  '|Account Name|Subscription ID|Resource Group|Kind|Status Primary|Status Secondary|Location|\n' \
                  '|---|---|---|---|---|---|---|\n| ' \
                  'account_name | subscription_id | resource_group_name | Storage | available | available | eastus |\n'
    assert result.outputs[0] == api_response
    assert result.readable_output == expected_hr


def test_storage_account_create_update(client, mocker):
    """
    Given:
        - AS Client
        - An API response for storage account create/update

    When:
        - Running storage_account_create_update with the required arguments

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('test_data/storage_account_single_response.json')
    response = requests.models.Response()
    response._content = json.dumps(api_response).encode('utf-8')
    mocker.patch.object(ASClient, "storage_account_create_update_request", return_value=response)
    result = storage_account_create_update(client=client, args={'account_name': 'account_name', "sku": "Standard_GRS",
                                                                "kind": "Storage", "location": "eastus"},
                                           params={'subscription_id': subscription_id,
                                                   'resource_group_name': resource_group_name})
    expected_hr = '### Azure Storage Account\n' \
                  '|Account Name|Subscription ID|Resource Group|Kind|Status Primary|Status Secondary|Location|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| account_name | subscription_id | resource_group_name | Storage | available | available | eastus ' \
                  '|\n'
    assert result.outputs == api_response
    assert result.readable_output == expected_hr


def test_storage_blob_service_properties_get(client, mocker):
    """
    Given:
        - AS Client
        - An API response for get blob service properties

    When:
        - Running storage_blob_service_properties_get with a given account_name argument

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('test_data/blob_service_properties_get_response.json')
    mocker.patch.object(ASClient, "storage_blob_service_properties_get_request", return_value=api_response)
    result = storage_blob_service_properties_get(client=client, args={'account_name': 'account_name'},
                                                 params={'subscription_id': subscription_id,
                                                         'resource_group_name': resource_group_name})
    expected_hr = '### Azure Storage Blob Service Properties\n' \
                  '|Name|Account Name|Subscription ID|Resource Group|Change Feed|Delete Retention Policy|Versioning|\n'\
                  '|---|---|---|---|---|---|---|\n' \
                  '| default | account_name | subscription_id | resource_group_name |  | false ' \
                  '|  |\n'
    assert result.outputs == api_response
    assert result.readable_output == expected_hr


def test_storage_blob_service_properties_set(client, mocker):
    """
    Given:
        - AS Client
        - An API response for set blob service properties

    When:
        - Running storage_blob_service_properties_set with a given account_name argument

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('test_data/blob_service_properties_set_response.json')
    mocker.patch.object(ASClient, "storage_blob_service_properties_set_request", return_value=api_response)
    result = storage_blob_service_properties_set(client=client, args={'account_name': 'account_name'},
                                                 params={'subscription_id': subscription_id,
                                                         'resource_group_name': resource_group_name})
    expected_hr = '### Azure Storage Blob Service Properties\n' \
                  '|Name|Account Name|Subscription ID|Resource Group|Change Feed|Delete Retention Policy|Versioning|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| default | account_name | subscription_id | resource_group_name |  |  |  ' \
                  '|\n'
    assert result.outputs == api_response
    assert result.readable_output == expected_hr


def test_storage_blob_containers_create(client, mocker):
    """
        Given:
            - AS Client
            - An API response for create blob container

        When:
            - Running storage_blob_containers_create with the given account_name and container_name arguments

        Then:
            - Verify result outputs
            - Verify result readable outputs
    """
    api_response = util_load_json('test_data/blob_containers_create_update_response.json')

    mocker.patch.object(ASClient, "storage_blob_containers_create_update_request", return_value=api_response)

    result = storage_blob_containers_create(client=client, args={'account_name': 'account_name',
                                                                 'container_name': 'test'},
                                            params={'subscription_id': subscription_id,
                                                    'resource_group_name': resource_group_name})

    expected_hr = '### Azure Storage Blob Containers Properties\n' \
                  '|Name|Account Name|Subscription ID|Resource Group|\n' \
                  '|---|---|---|---|\n' \
                  '| test | account_name | subscription_id | resource_groups |\n'

    assert result.outputs == api_response
    assert result.readable_output == expected_hr


def test_storage_blob_containers_update(client, mocker):
    """
        Given:
            - AS Client
            - An API response for update blob container

        When:
            - Running storage_blob_containers_update with the given account_name and container_name arguments

        Then:
            - Verify result outputs
            - Verify result readable outputs
    """
    api_response = util_load_json('test_data/blob_containers_create_update_response.json')

    mocker.patch.object(ASClient, "storage_blob_containers_create_update_request", return_value=api_response)

    result = storage_blob_containers_update(client=client, args={'account_name': 'account_name',
                                                                 'container_name': 'test'},
                                            params={'subscription_id': subscription_id,
                                                    'resource_group_name': resource_group_name})

    expected_hr = '### Azure Storage Blob Containers Properties\n' \
                  '|Name|Account Name|Subscription ID|Resource Group|Public Access|\n' \
                  '|---|---|---|---|---|\n' \
                  '| test | account_name | subscription_id | resource_groups |  |\n'

    assert result.outputs == api_response
    assert result.readable_output == expected_hr


def test_storage_blob_containers_list(client, mocker):
    """
    Given:
        - AS Client
        - An API response for blob containers list

    When:
        - Running storage_blob_containers_list

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('./test_data/blob_containers_list_response.json')

    mocker.patch.object(ASClient, "storage_blob_containers_list_request", return_value=api_response)

    result = storage_blob_containers_list(client=client, args={'account_name': 'account_name'},
                                          params={'subscription_id': subscription_id,
                                                  'resource_group_name': resource_group_name})

    expected_hr = '### Azure Storage Blob Containers list\n' \
                  '|Container Name|Account Name|Subscription ID|Resource Group|Public ' \
                  'Access|Lease State|Last Modified Time|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| test | account_name | subscription_id | resource_groups | None | Available ' \
                  '| 2020-02-20T20:20:20.0000000Z |\n' \
                  '| test2 | account_name | subscription_id | resource_groups | None | ' \
                  'Available | 2020-02-20T20:20:20.0000000Z |\n'

    assert result.outputs == api_response.get('value')
    assert result.readable_output == expected_hr


def test_storage_blob_containers_single(client, mocker):
    """
    Given:
        - AS Client
        - An API response for single blob container

    When:
        - Running storage_blob_containers_list with the given account_name and container_name arguments

    Then:
        - Verify result outputs
        - Verify result readable outputs
    """
    api_response = util_load_json('test_data/blob_containers_single_response.json')

    mocker.patch.object(ASClient, "storage_blob_containers_list_request", return_value=api_response)

    result = storage_blob_containers_list(client=client, args={'account_name': 'account_name',
                                                               'container_name': 'test'},
                                          params={'subscription_id': subscription_id,
                                                  'resource_group_name': resource_group_name})

    expected_hr = '### Azure Storage Blob Containers list\n' \
                  '|Container Name|Account Name|Subscription ID|Resource Group|Public ' \
                  'Access|Lease State|Last Modified Time|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| test | account_name | subscription_id | resource_groups | None | Available ' \
                  '| 2020-02-20T20:20:20.0000000Z |\n'

    assert result.outputs[0] == api_response
    assert result.readable_output == expected_hr


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from AzureStorage import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import AzureStorage

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'auth_type': 'Azure Managed Identities',
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureStorage, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureStorage.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-storage-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureStorage import main
    import AzureStorage

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'tenant_id': tenant_id,
        'app_id': client_id,
        'credentials': {
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-storage-generate-login-url')
    mocker.patch.object(AzureStorage, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://management.azure.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureStorage.return_results.call_args[0][0].readable_output
    assert expected_url in res

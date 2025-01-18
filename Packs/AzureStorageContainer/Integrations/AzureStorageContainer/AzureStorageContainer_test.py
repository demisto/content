import pytest
import defusedxml.ElementTree as defused_ET

from CommonServerPython import *

ACCOUNT_NAME = "test"
BASE_URL = f'https://{ACCOUNT_NAME}.blob.core.windows.net/'
SAS_TOKEN = "XXXX"
API_VERSION = "2020-10-02"
SHARED_KEY = "XXXX"


def load_mock_response(file_name: str, file_type: str = "json"):
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response XML file to return.
        file_type (str): Mock file type.

    """
    file_path = f'test_data/{file_name}'

    if file_type == "xml":
        top = defused_ET.parse(file_path)
        return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")

    else:
        with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
            return mock_file.read()


def test_azure_storage_list_containers_command(requests_mock):
    """
    Scenario: List Containers.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageContainer import Client, list_containers_command
    mock_response = load_mock_response('containers.xml', "xml")

    url = f'{BASE_URL}?{SAS_TOKEN}&maxresults=50&comp=list'
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_containers_command(client, {})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageContainer.Container'
    assert result.outputs[0].get('name') == 'xsoar'
    assert result.outputs[1].get('name') == 'test'


def test_azure_storage_create_container_command(requests_mock):
    """
    Scenario: Create Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-create called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    - Ensure validation of the container name.
    """
    from AzureStorageContainer import Client, create_container_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}?{SAS_TOKEN}&restype=container'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_container_command(client, {'container_name': container_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Container {container_name} successfully created.'

    invalid_container_name = 'test--1'

    with pytest.raises(Exception):
        create_container_command(client, {'container_name': invalid_container_name})


def test_azure_storage_create_blob_command_content_length_header(mocker):
    """
    Given:
     - User has provided valid credentials.

    When:
     - azure-storage-container-blob-create called.

    Then:
     - Ensure the content length header is being sent with the correct file size.
    """
    from AzureStorageContainer import Client, create_blob_command

    def mock_file(_id):
        return {
            'path': 'test_data/blob.txt',
            'name': 'blob.txt',
        }

    client = Client(
        server_url=BASE_URL, verify=False, proxy=False,
        account_sas_token=SAS_TOKEN, storage_account_name=ACCOUNT_NAME, api_version=API_VERSION
    )

    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_file)
    http_mocker = mocker.patch.object(client.ms_client, 'http_request', return_value='worked')

    create_blob_command(client, {'container_name': 'container-test', 'file_entry_id': '1'})

    assert http_mocker.call_args.kwargs.get('headers', {}) == {'x-ms-blob-type': 'BlockBlob'}


def test_azure_storage_get_container_properties_command(requests_mock):
    """
    Scenario: Retrieve properties for the specified Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-property-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageContainer import Client, get_container_properties_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}?{SAS_TOKEN}&restype=container'
    headers_response = json.loads(load_mock_response('container_properties.json'))

    requests_mock.get(url, headers=headers_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_container_properties_command(client, {'container_name': container_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Property')) == 14
    assert result.outputs_prefix == 'AzureStorageContainer.Container'
    assert result.outputs.get('Property').get('lease_status') == 'unlocked'
    assert result.outputs.get('name') == container_name


def test_azure_storage_delete_container_command(requests_mock):
    """
    Scenario: Delete Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageContainer import Client, delete_container_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}?{SAS_TOKEN}&restype=container'

    requests_mock.delete(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_container_command(client, {'container_name': container_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Container {container_name} successfully deleted.'


def test_azure_storage_list_blobs_command(requests_mock):
    """
    Scenario: List Blobs under the specified container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageContainer import Client, list_blobs_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}?{SAS_TOKEN}&container_name={container_name}&maxresults=50&restype=container&comp=list'
    response = load_mock_response('blobs.xml', 'xml')

    requests_mock.get(url, text=response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_blobs_command(client, {'container_name': container_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Blob')) == 2
    assert result.outputs_prefix == 'AzureStorageContainer.Container'
    assert result.outputs.get('Blob')[0].get('name') == 'xsoar.txt'
    assert result.outputs.get('Blob')[1].get('name') == 'test.pdf'
    assert result.outputs.get('name') == container_name


def test_azure_storage_get_blob_command(requests_mock):
    """
    Scenario: Retrieve Blob from Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-get called.
    Then:
     - Ensure XSOAR File output.
    """
    from AzureStorageContainer import Client, get_blob_command

    container_name = "test"
    blob_name = "blob.txt"
    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}'

    with open('test_data/blob.txt', 'rb') as text_file_mock:
        requests_mock.get(url, content=text_file_mock.read())

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_blob_command(client, {'container_name': container_name,
                                       'blob_name': blob_name})

    assert result['ContentsFormat'] == 'text'
    assert result['Type'] == EntryType.FILE
    assert result['File'] == blob_name
    assert len(result) == 5


def test_azure_storage_get_blob_tags_command(requests_mock):
    """
    Scenario: Retrieve the tags of the specified Blob.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-tag-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageContainer import Client, get_blob_tags_command

    container_name = "test"
    blob_name = "blob.txt"

    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}&comp=tags'
    mock_response = load_mock_response('tags.xml', "xml")

    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_blob_tags_command(client, {'container_name': container_name,
                                            'blob_name': blob_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Blob')) == 2
    assert len(result.outputs.get('Blob').get('Tag')) == 1
    assert result.outputs_prefix == 'AzureStorageContainer.Container'
    assert result.outputs.get('Blob').get('Tag')[0].get('Key') == 'Name'
    assert result.outputs.get('Blob').get('Tag')[0].get('Value') == 'Azure'


def test_azure_storage_block_public_access_command(mocker, requests_mock):
    """
    Scenario: Block public access for the specified container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-block-public-access called.
    Then:
     - Ensure readable output message content.
    """
    from AzureStorageContainer import Client, block_public_access_command
    params = {
        'shared_key': {'password': SHARED_KEY},
        'credentials': {'identifier': ACCOUNT_NAME}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    container_name = "test"
    url = f"https://{ACCOUNT_NAME}.blob.core.windows.net/{container_name}?restype=container&comp=acl"
    requests_mock.put(url, status_code=200, text="")
    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = block_public_access_command(client, {
        'container_name': container_name
    })

    expected_response = f"Public access to container '{container_name}' has been successfully blocked"
    assert result.readable_output == expected_response

    # Test for invalid shared key
    with pytest.raises(ValueError, match="Incorrect shared key provided"):
        # Here we need to set params to have an invalid key
        invalid_shared_key_params = {
            'shared_key': {'password': "invalid-key"},
            'credentials': {'identifier': ACCOUNT_NAME}
        }
        mocker.patch.object(demisto, 'params', return_value=invalid_shared_key_params)
        block_public_access_command(client, {'container_name': container_name})

    # Test for missing shared key
    with pytest.raises(KeyError, match="The 'shared_key' parameter must be provided."):
        missing_shared_key_params = {
            'shared_key': {'password': ""},
            'credentials': {'identifier': ACCOUNT_NAME}
        }
        mocker.patch.object(demisto, 'params', return_value=missing_shared_key_params)
        block_public_access_command(client, {'container_name': container_name})


def test_azure_storage_set_blob_tags_command(requests_mock):
    """
    Scenario: Set the tags for the specified Blob.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-tag-set called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageContainer import Client, set_blob_tags_command

    container_name = "test"
    blob_name = "blob.txt"
    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}&comp=tags'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = set_blob_tags_command(client, {'container_name': container_name,
                                            'blob_name': blob_name,
                                            'tags': "{}"})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'{blob_name} Tags successfully updated.'


def test_azure_storage_delete_blob_command(requests_mock):
    """
    Scenario: Delete Blob from Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageContainer import Client, delete_blob_command

    container_name = "test"
    blob_name = "blob.txt"
    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}'

    requests_mock.delete(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_blob_command(client, {'container_name': container_name,
                                          'blob_name': blob_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Blob {blob_name} successfully deleted.'


def test_azure_storage_get_blob_properties_command(requests_mock):
    """
    Scenario: Retrieve Blob properties.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-property-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageContainer import Client, get_blob_properties_command

    container_name = "test"
    blob_name = "blob.txt"

    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}'
    headers_response = json.loads(load_mock_response('blob_properties.json'))

    requests_mock.head(url, headers=headers_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_blob_properties_command(client, {'container_name': container_name,
                                                  'blob_name': blob_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Blob')) == 2
    assert len(result.outputs.get('Blob').get('Property')) == 18
    assert result.outputs_prefix == 'AzureStorageContainer.Container'
    assert result.outputs.get('Blob').get('Property').get('blob_type') == 'BlockBlob'
    assert result.outputs.get('Blob').get('name') == blob_name
    assert result.outputs.get('name') == container_name


def test_azure_storage_set_blob_properties_command(requests_mock):
    """
    Scenario: Set Blob properties.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-property-set called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageContainer import Client, set_blob_properties_command

    container_name = "test"
    blob_name = "blob.txt"
    url = f'{BASE_URL}{container_name}/{blob_name}?{SAS_TOKEN}&comp=properties'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = set_blob_properties_command(client, {'container_name': container_name,
                                                  'blob_name': blob_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Blob {blob_name} properties successfully updated.'


def test_create_set_tags_request_body():
    """
    Scenario: Create valid request body for set blob tags.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-container-blob-tag-set called.
    Then:
     - Ensure command request body.
    """
    from AzureStorageContainer import create_set_tags_request_body

    tags = {"tag-name-1": "tag-value-1", "tag-name-2": "tag-value-2-yehuda"}

    result = create_set_tags_request_body(tags)
    expected = "<Tags><TagSet><Tag><Key>tag-name-1</Key><Value>tag-value-1</Value></Tag><Tag><Key>tag-name-2</Key>" \
               "<Value>tag-value-2-yehuda</Value></Tag></TagSet></Tags>"

    assert result == expected


def test_generate_sas_signature():
    from AzureStorageContainer import generate_sas_signature
    assert generate_sas_signature('test', 'test', 'test', 'test', 'test', 'test', 'test',
                                  'test', ) == 'sp=test&st=test&se=test&sip=test&spr=https&sv=test&sr=test&sig=pyUQ25%2BIijJ2TstI5Q6Sre3jJWI0b4qwvRg2LtD9uhc%3D'  # noqa


def test_generate_sas_signature_no_key(mocker):
    """
    Given:
     - User hasn't provided an account key to create the SAS token.
    When:
     - azure-storage-container-sas-create called.
    Then:
     - Ensure command raises an exception.
    """
    from AzureStorageContainer import generate_sas_token_command, Client
    mocker.patch.object(demisto, "params", return_value={})
    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    with pytest.raises(DemistoException):
        generate_sas_token_command(client, {"signed_permissions": "c"})


def test_check_valid_permission():
    from AzureStorageContainer import check_valid_permission
    assert check_valid_permission('cr', 'c')
    assert not check_valid_permission('cr', 'crw')


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

    from AzureStorageContainer import main, MANAGED_IDENTITIES_TOKEN_URL
    import demistomock as demisto
    import AzureStorageContainer
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile('blob.core.windows.net/.*'))

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'credentials': {'identifier': 'test_storage_account_name'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureStorageContainer, 'return_results', return_value=params)

    main()

    assert 'ok' in AzureStorageContainer.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs

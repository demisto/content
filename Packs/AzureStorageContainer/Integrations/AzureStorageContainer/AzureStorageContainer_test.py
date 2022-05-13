import pytest

from CommonServerPython import *

ACCOUNT_NAME = "test"
BASE_URL = f'https://{ACCOUNT_NAME}.blob.core.windows.net/'
SAS_TOKEN = "XXXX"
API_VERSION = "2020-10-02"


def load_mock_response(file_name: str, file_type: str = "json"):
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response XML file to return.
        file_type (str): Mock file type.

    """
    file_path = f'test_data/{file_name}'

    if file_type == "xml":
        top = ET.parse(file_path)
        return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")

    else:
        with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
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

    url = f'{BASE_URL}{SAS_TOKEN}&maxresults=50&comp=list'
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
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'

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
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'
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
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'

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
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&container_name={container_name}&maxresults=50&restype=container&comp=list'
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
    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}'

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

    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}&comp=tags'
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
    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}&comp=tags'

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
    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}'

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

    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}'
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
    url = f'{BASE_URL}{container_name}/{blob_name}{SAS_TOKEN}&comp=properties'

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

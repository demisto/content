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
     - azure-storage-blob-container-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, list_containers_command
    mock_response = load_mock_response('containers.xml', "xml")

    url = f'{BASE_URL}{SAS_TOKEN}&maxresults=50&comp=list'
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_containers_command(client, {})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageBlob.Container'
    assert result.outputs[0].get('container_name') == 'xsoar'


def test_azure_storage_create_container_command(requests_mock):
    """
    Scenario: Create Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-container-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, create_container_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_container_command(client, {'container_name': container_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_get_container_properties_command(requests_mock):
    """
    Scenario: Retrieve properties for the specified Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-container-properties-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, get_container_properties_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'
    headers_response = json.loads(load_mock_response('container_properties.json'))

    requests_mock.get(url, headers=headers_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_container_properties_command(client, {'container_name': container_name})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageBlob.Container'
    assert result.outputs.get('Properties').get('lease_status') == 'unlocked'
    assert result.outputs.get('container_name') == container_name


def test_azure_storage_delete_container_command(requests_mock):
    """
    Scenario: Delete Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-container-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, delete_container_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&restype=container'

    requests_mock.delete(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_container_command(client, {'container_name': container_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_list_blobs_command(requests_mock):
    """
    Scenario: List Blobs under the specified container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, list_blobs_command

    container_name = "test"
    url = f'{BASE_URL}{container_name}{SAS_TOKEN}&container_name={container_name}&maxresults=50&restype=container&comp=list'
    response = load_mock_response('blobs.xml', 'xml')

    requests_mock.get(url, text=response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_blobs_command(client, {'container_name': container_name})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageBlob.Blob'
    assert result.outputs[0].get('blob_name') == 'xsoar.txt'
    assert result.outputs[1].get('blob_name') == 'test.pdf'
    assert result.outputs[0].get('container_name') == container_name
    assert result.outputs[1].get('container_name') == container_name


def test_azure_storage_get_blob_command(requests_mock):
    """
    Scenario: Retrieve Blob from Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, get_blob_command

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


def test_azure_storage_get_blob_tags_command(requests_mock):
    """
    Scenario: Retrieve the tags of the specified Blob.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-tags-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, get_blob_tags_command

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

    assert len(result.outputs) == 3
    assert len(result.outputs.get('Tag')) == 1
    assert result.outputs_prefix == 'AzureStorageBlob.Blob'
    assert result.outputs.get('Tag')[0].get('Key') == 'Name'
    assert result.outputs.get('Tag')[0].get('Value') == 'Azure'
    assert result.outputs.get('blob_name') == blob_name
    assert result.outputs.get('container_name') == container_name


def test_azure_storage_set_blob_tags_command(requests_mock):
    """
    Scenario: Set the tags for the specified Blob.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-tags-set called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, set_blob_tags_command

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


def test_azure_storage_delete_blob_command(requests_mock):
    """
    Scenario: Delete Blob from Container.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, delete_blob_command

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


def test_azure_storage_get_blob_properties_command(requests_mock):
    """
    Scenario: Retrieve Blob properties.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-properties-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, get_blob_properties_command

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

    assert len(result.outputs) == 3
    assert len(result.outputs.get('Properties')) == 18
    assert result.outputs_prefix == 'AzureStorageBlob.Blob'
    assert result.outputs.get('Properties').get('blob_type') == 'BlockBlob'
    assert result.outputs.get('blob_name') == blob_name
    assert result.outputs.get('container_name') == container_name


def test_azure_storage_set_blob_properties_command(requests_mock):
    """
    Scenario: Set Blob properties.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-blob-blob-properties-set called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageBlob import Client, set_blob_properties_command

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

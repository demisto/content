from CommonServerPython import *

ACCOUNT_NAME = "test"
BASE_URL = f'https://{ACCOUNT_NAME}.file.core.windows.net/'
SAS_TOKEN = "XXXX"
API_VERSION = "2020-10-02"


def load_xml_mock_response(file_name: str) -> str:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response XML file to return.
    """
    file_path = f'test_data/{file_name}'

    top = ET.parse(file_path)
    return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")


def test_azure_storage_create_share_command(requests_mock):
    """
    Scenario: Create new Share.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-share-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, create_share_command
    share_name = 'test'
    url = f'{BASE_URL}{share_name}{SAS_TOKEN}&restype=share'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_share_command(client, {'share_name': share_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_delete_share_command(requests_mock):
    """
    Scenario: Delete Share.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-share-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, delete_share_command
    share_name = 'test'
    url = f'{BASE_URL}{share_name}{SAS_TOKEN}&restype=share'

    requests_mock.delete(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_share_command(client, {'share_name': share_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_list_shares_command(requests_mock):
    """
    Scenario: List Shares.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-share-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, list_shares_command
    url = f'{BASE_URL}{SAS_TOKEN}&comp=list&maxresults=50'
    mock_response = load_xml_mock_response('shares.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_shares_command(client, {})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageFileShares.Share'
    assert result.outputs[0].get('Name') == 'my-file-share'


def test_azure_storage_list_directories_and_files_command(requests_mock):
    """
    Scenario: List directories and files.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-directory-file-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, list_directories_and_files_command
    share_name = "test"
    url = f'{BASE_URL}{share_name}{SAS_TOKEN}&restype=directory&comp=list&include=Timestamps&maxresults=50'
    mock_response = load_xml_mock_response('files.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_directories_and_files_command(client, {'share_name': share_name})

    assert len(result.outputs) == 5
    assert len(result.outputs['Directory']) == 1
    assert len(result.outputs['File']) == 1
    assert result.outputs_prefix == 'AzureStorageFileShares.Directory'
    assert result.outputs['File'][0].get('Name') == 'AzureStorage_image.png'
    assert result.outputs.get('share_name') == share_name


def test_azure_storage_create_directory_command(requests_mock):
    """
    Scenario: Create directory.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-directory-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, create_directory_command
    share_name = "test"
    directory_name = "test_new_directory"
    url = f'{BASE_URL}{share_name}/{directory_name}{SAS_TOKEN}&restype=directory'

    requests_mock.put(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_directory_command(client, {'share_name': share_name,
                                               'directory_name': directory_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_delete_directory_command(requests_mock):
    """
    Scenario: Delete directory.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-directory-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, delete_directory_command
    share_name = "test"
    directory_name = "test_new_directory"
    url = f'{BASE_URL}{share_name}/{directory_name}{SAS_TOKEN}&restype=directory'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_directory_command(client, {'share_name': share_name,
                                               'directory_name': directory_name})

    assert result.outputs is None
    assert result.outputs_prefix is None


def test_azure_storage_get_file_command(requests_mock):
    """
    Scenario: Get file
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-file-get called.
    Then:
         - Ensure that the return ContentsFormat of the file is 'text'.
         - Ensure that the return Type is file.
         - Ensure the name of the file.
    """
    from AzureStorageFileShares import Client, get_file_command
    share_name = "test"
    file_name = "test_file.txt"
    url = f'{BASE_URL}{share_name}/{file_name}{SAS_TOKEN}'

    with open('test_data/test_file.txt', 'rb') as text_file_mock:
        requests_mock.get(url, content=text_file_mock.read())

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_file_command(client, {'share_name': share_name,
                                       'file_name': file_name})

    assert result['ContentsFormat'] == 'text'
    assert result['Type'] == EntryType.FILE
    assert result['File'] == file_name


def test_azure_storage_delete_file_command(requests_mock):
    """
    Scenario: Delete file
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshares-file-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShares import Client, delete_file_command
    share_name = "test"
    file_name = "test_file.txt"
    url = f'{BASE_URL}{share_name}/{file_name}{SAS_TOKEN}'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_file_command(client, {'share_name': share_name,
                                          'file_name': file_name})

    assert result.outputs is None
    assert result.outputs_prefix is None

import pytest
import defusedxml.ElementTree as defused_ET

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

    top = defused_ET.parse(file_path)
    return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")


def test_azure_storage_create_share_command(requests_mock):
    """
    Scenario: Create new Share.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-create called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
     - Ensure validation of the share name.
    """
    from AzureStorageFileShare import Client, create_share_command
    share_name = 'test'
    url = f'{BASE_URL}{share_name}?{SAS_TOKEN}&restype=share'

    requests_mock.put(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_share_command(client, {'share_name': share_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Share {share_name} successfully created.'

    invalid_share_name = 'test--1'

    with pytest.raises(Exception):
        create_share_command(client, {'share_name': invalid_share_name})


def test_azure_storage_delete_share_command(requests_mock):
    """
    Scenario: Delete Share.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageFileShare import Client, delete_share_command
    share_name = 'test'
    url = f'{BASE_URL}{share_name}?{SAS_TOKEN}&restype=share'

    requests_mock.delete(url, text="")

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_share_command(client, {'share_name': share_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Share {share_name} successfully deleted.'


def test_azure_storage_list_shares_command(requests_mock):
    """
    Scenario: List Shares.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShare import Client, list_shares_command
    url = f'{BASE_URL}?{SAS_TOKEN}&comp=list&maxresults=50'
    mock_response = load_xml_mock_response('shares.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_shares_command(client, {})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageFileShare.Share'
    assert result.outputs[0].get('Name') == 'my-file-share'
    assert result.outputs[1].get('Name') == 'my-share'


def test_azure_storage_list_directories_and_files_command(requests_mock):
    """
    Scenario: List directories and files.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-content-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageFileShare import Client, list_directories_and_files_command
    share_name = "test"
    url = f'{BASE_URL}{share_name}?{SAS_TOKEN}&restype=directory&comp=list&include=Timestamps&maxresults=50'
    mock_response = load_xml_mock_response('files.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_directories_and_files_command(client, {'share_name': share_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Content')) == 4
    assert len(result.outputs.get('Content').get('Directory')) == 1
    assert len(result.outputs.get('Content').get('File')) == 1
    assert result.outputs_prefix == 'AzureStorageFileShare.Share'
    assert result.outputs.get('Content')['File'][0].get('Name') == 'AzureStorage_image.png'
    assert result.outputs.get('Name') == share_name


def test_azure_storage_create_directory_command(requests_mock):
    """
    Scenario: Create directory.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-directory-create called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
     - Ensure validation of the directory name.
    """
    from AzureStorageFileShare import Client, create_directory_command
    share_name = "test"
    directory_name = "test_new_directory"
    url = f'{BASE_URL}{share_name}/{directory_name}?{SAS_TOKEN}&restype=directory'

    requests_mock.put(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_directory_command(client, {'share_name': share_name,
                                               'directory_name': directory_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'{directory_name} Directory successfully created in {share_name}.'

    invalid_directory_name = 'test<1'

    with pytest.raises(Exception):
        create_directory_command(client, {'share_name': share_name,
                                          'directory_name': invalid_directory_name})


def test_azure_storage_delete_directory_command(requests_mock):
    """
    Scenario: Delete directory.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-directory-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageFileShare import Client, delete_directory_command
    share_name = "test"
    directory_name = "test_new_directory"
    url = f'{BASE_URL}{share_name}/{directory_name}?{SAS_TOKEN}&restype=directory'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_directory_command(client, {'share_name': share_name,
                                               'directory_name': directory_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'{directory_name} Directory successfully deleted from {share_name}.'


def test_azure_storage_get_file_command(requests_mock):
    """
    Scenario: Get file.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-file-get called.
    Then:
     - Ensure XSOAR File output.
    """
    from AzureStorageFileShare import Client, get_file_command
    share_name = "test"
    file_name = "test_file.txt"
    url = f'{BASE_URL}{share_name}/{file_name}?{SAS_TOKEN}'

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
    assert len(result) == 5


def test_azure_storage_delete_file_command(requests_mock):
    """
    Scenario: Delete file
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-file-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageFileShare import Client, delete_file_command
    share_name = "test"
    file_name = "test_file.txt"
    url = f'{BASE_URL}{share_name}/{file_name}?{SAS_TOKEN}'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_file_command(client, {'share_name': share_name,
                                          'file_name': file_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'File {file_name} successfully deleted from {share_name}.'


def test_validate_characters():
    """
    Test validate_characters function.
    Scenarios:
        - Send valid string to function.
        - Send invalid string to function.
    Then:
     - Ensure that the output is correct (True / False).

    """
    from AzureStorageFileShare import validate_characters
    valida_string = "my-valid-test"
    invalid_string = "my-invalid|test"

    assert validate_characters(valida_string, "\"\/:|<>*?")
    assert not validate_characters(invalid_string, "\"\/:|<>*?")


def test_create_file_command(requests_mock, mocker):
    """
    Scenario: Create a file in Share from War room file Entry ID.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-fileshare-file-create called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    mocker.patch('shutil.copy')
    mocker.patch('shutil.rmtree')
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'my_local_path', 'name': 'my_file_name'})

    mock_read = mocker.mock_open(read_data="XSOAR-TEST")
    mocker.patch('AzureStorageFileShare.open', mock_read)

    from AzureStorageFileShare import Client, create_file_command
    share_name = "test"
    file_entry_id = "12345"
    directory_path = "xsoar/path"
    file_name = "test_file.txt"

    command_arguments = {"share_name": share_name, "file_entry_id": file_entry_id,
                         "directory_path": directory_path, "file_name": file_name}
    url = f'{BASE_URL}{share_name}/{directory_path}/{file_name}?{SAS_TOKEN}'

    requests_mock.put(url, text='', status_code=201)
    url = f'{BASE_URL}{share_name}/{directory_path}/{file_name}?{SAS_TOKEN}&comp=range'

    requests_mock.put(url, text='', status_code=201)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_file_command(client, command_arguments)

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'File successfully created in {share_name}.'

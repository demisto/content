import pytest
from CommonServerPython import *

ACCOUNT_NAME = "test"
BASE_URL = f'https://{ACCOUNT_NAME}.table.core.windows.net/'
SAS_TOKEN = "XXXX"
API_VERSION = "2020-10-02"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
        return mock_file.read()


def test_azure_storage_create_table_command(requests_mock):
    """
    Scenario: Create Table.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure validation of the table name.
    """
    from AzureStorageTable import Client, create_table_command

    mock_response = json.loads(load_mock_response('create_table.json'))
    url = f'{BASE_URL}Tables?{SAS_TOKEN}'
    table_name = 'test'

    requests_mock.post(url, json=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    result = create_table_command(client, {'table_name': table_name})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureStorageTable.Table'
    assert result.outputs.get('name') == 'xsoar'

    invalid_table_name = 'test--1'

    with pytest.raises(Exception):
        create_table_command(client, {'table_name': invalid_table_name})


def test_azure_storage_delete_table_command(requests_mock):
    """
    Scenario: Delete Table.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table--delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageTable import Client, delete_table_command

    table_name = 'test'
    url = f'{BASE_URL}Tables(\'{table_name}\')?{SAS_TOKEN}'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    result = delete_table_command(client, {'table_name': table_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Table {table_name} successfully deleted.'


def test_azure_storage_query_tables_command(requests_mock):
    """
    Scenario: Query Tables.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-query called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageTable import Client, query_tables_command

    mock_response = json.loads(load_mock_response('query_table.json'))
    url = f'{BASE_URL}Tables?{SAS_TOKEN}&$top=50'

    requests_mock.get(url, json=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    result = query_tables_command(client, {})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageTable.Table'
    assert result.outputs[0].get('name') == 'xsoar1'
    assert result.outputs[1].get('name') == 'xsoar2'


def test_azure_storage_insert_entity_command(requests_mock):
    """
    Scenario: Insert Entity.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-entity-insert called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageTable import Client, insert_entity_command

    mock_response = json.loads(load_mock_response('insert_entity.json'))
    table_name = 'test'
    url = f'{BASE_URL}{table_name}?{SAS_TOKEN}'

    requests_mock.post(url, json=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    command_arguments = {'entity_fields': '{"Age":20}', 'partition_key': 'xsoar-partition',
                         'row_key': 'xsoar-row', 'table_name': table_name}
    result = insert_entity_command(client, command_arguments)

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageTable.Table'
    assert len(result.outputs.get('Entity')) == 1
    assert len(result.outputs.get('Entity')[0]) == 4
    assert result.outputs.get('Entity')[0].get('PartitionKey') == 'xsoar-partition'
    assert result.outputs.get('Entity')[0].get('RowKey') == 'xsoar-row'
    assert result.outputs.get('name') == table_name


#
def test_azure_storage_update_entity_command(requests_mock):
    """
    Scenario: Update Entity.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-entity-update called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageTable import Client, update_entity_command

    table_name = 'test'
    partition_key = 'xsoar-partition'
    row_key = 'xsoar-row'
    url = f'{BASE_URL}{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')?{SAS_TOKEN}'

    requests_mock.register_uri('MERGE', url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    command_arguments = {'entity_fields': '{"Address":"New York"}', 'partition_key': partition_key,
                         'row_key': row_key, 'table_name': table_name}
    result = update_entity_command(client, command_arguments)

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Entity in {table_name} table successfully updated.'


def test_azure_storage_replace_entity_command(requests_mock):
    """
    Scenario: Replace Entity.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-entity-replace called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageTable import Client, replace_entity_command

    table_name = 'test'
    partition_key = 'xsoar-partition'
    row_key = 'xsoar-row'
    url = f'{BASE_URL}{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')?{SAS_TOKEN}'

    requests_mock.put(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    command_arguments = {'entity_fields': '{"Address":"New York"}', 'partition_key': partition_key,
                         'row_key': row_key, 'table_name': table_name}
    result = replace_entity_command(client, command_arguments)

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Entity in {table_name} table successfully replaced.'


def test_azure_storage_query_entity_command(requests_mock):
    """
    Scenario: Query Entity.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-entity-query called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageTable import Client, query_entity_command

    mock_response = json.loads(load_mock_response('query_entity.json'))
    table_name = 'test'
    url = f'{BASE_URL}{table_name}()?{SAS_TOKEN}&$top=1'

    requests_mock.get(url, json=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    result = query_entity_command(client, {'table_name': table_name, 'limit': '1'})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Entity')) == 1
    assert len(result.outputs.get('Entity')[0]) == 4
    assert result.outputs_prefix == 'AzureStorageTable.Table'
    assert result.outputs.get('Entity')[0].get('PartitionKey') == 'xsoar-partition'
    assert result.outputs.get('Entity')[0].get('RowKey') == 'xsoar-row'
    assert result.outputs.get('Entity')[0].get('Address') == 'New York'
    assert result.outputs.get('name') == table_name


def test_azure_storage_delete_entity_command(requests_mock):
    """
    Scenario: Delete Entity.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-table-entity-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageTable import Client, delete_entity_command

    table_name = 'test'
    partition_key = 'xsoar-partition'
    row_key = 'xsoar-row'
    url = f'{BASE_URL}{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')?{SAS_TOKEN}'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)

    command_arguments = {'partition_key': partition_key,
                         'row_key': row_key, 'table_name': table_name}

    result = delete_entity_command(client, command_arguments)

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Entity in {table_name} table successfully deleted.'


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

    from AzureStorageTable import main, MANAGED_IDENTITIES_TOKEN_URL
    import demistomock as demisto
    import AzureStorageTable
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile('.table.core.windows.net/.*'))

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'credentials': {'identifier': 'test_storage_account_name'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureStorageTable, 'return_results', return_value=params)

    main()

    assert 'ok' in AzureStorageTable.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs

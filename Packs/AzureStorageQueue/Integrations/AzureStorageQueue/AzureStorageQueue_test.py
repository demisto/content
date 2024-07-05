import pytest
import defusedxml.ElementTree as defused_ET

from CommonServerPython import *

ACCOUNT_NAME = "test"
BASE_URL = f'https://{ACCOUNT_NAME}.queue.core.windows.net'
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


def test_azure_storage_queue_list_queues_command(requests_mock):
    """
    Scenario: List queues.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageQueue import Client, list_queues_command
    url = f'{BASE_URL}/?{SAS_TOKEN}&comp=list&maxresults=50'

    mock_response = load_xml_mock_response('queues.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = list_queues_command(client, {})

    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'AzureStorageQueue.Queue'
    assert result.outputs[0].get('name') == 'my-queue'
    assert result.outputs[1].get('name') == 'test'
    assert result.outputs[2].get('name') == 'xsoar-test'


def test_azure_storage_queue_create_queue_command(requests_mock):
    """
    Scenario: Create queue.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-queue-create called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure validation of the queue name.
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, create_queue_command
    queue_name = "test-queue"
    url = f'{BASE_URL}/{queue_name}?{SAS_TOKEN}'

    requests_mock.put(url, text='', status_code=201)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_queue_command(client, {"queue_name": queue_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Queue {queue_name} successfully created.'

    invalid_queue_name = 'test--1'

    with pytest.raises(Exception):
        create_queue_command(client, {'queue_name': invalid_queue_name})


def test_azure_storage_queue_delete_queue_command(requests_mock):
    """
    Scenario: Delete queue.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, delete_queue_command
    queue_name = "test-queue"
    url = f'{BASE_URL}/{queue_name}?{SAS_TOKEN}'

    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_queue_command(client, {"queue_name": queue_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Queue {queue_name} successfully deleted.'


def test_azure_storage_queue_create_message_command(requests_mock):
    """
    Scenario: Create message.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageQueue import Client, create_message_command
    queue_name = "test-queue"
    url = f'{BASE_URL}/{queue_name}/messages?{SAS_TOKEN}'

    mock_response = load_xml_mock_response('create_message.xml')
    requests_mock.post(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = create_message_command(client, {'message_content': "test", 'queue_name': queue_name})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureStorageQueue.Queue'
    assert result.outputs.get('name') == queue_name
    assert len(result.outputs.get('Message')) == 5
    assert result.outputs.get('Message').get('MessageId') == '111111111'
    assert result.outputs.get('Message').get('InsertionTime') == '2021-08-10T13:42:46'


def test_azure_storage_queue_get_messages_command(requests_mock):
    """
    Scenario: Get messages.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageQueue import Client, get_messages_command
    queue_name = "test-queue"
    url = f'{BASE_URL}/{queue_name}/messages?{SAS_TOKEN}&numofmessages=1'

    mock_response = load_xml_mock_response('get_message.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = get_messages_command(client, {'queue_name': queue_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Message')) == 1
    assert len(result.outputs.get('Message')[0]) == 7
    assert result.outputs_prefix == 'AzureStorageQueue.Queue'
    assert result.outputs.get('Message')[0].get('MessageId') == '1111111111111'
    assert result.outputs.get('Message')[0].get('InsertionTime') == '2021-08-22T13:00:49'
    assert result.outputs.get('name') == queue_name


def test_azure_storage_queue_peek_messages_command(requests_mock):
    """
    Scenario: Peek message.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-peek called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureStorageQueue import Client, peek_messages_command
    queue_name = "test-queue"
    url = f'{BASE_URL}/{queue_name}/messages?{SAS_TOKEN}&numofmessages=1&peekonly=true'

    mock_response = load_xml_mock_response('peek_message.xml')
    requests_mock.get(url, text=mock_response)

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = peek_messages_command(client, {'queue_name': queue_name})

    assert len(result.outputs) == 2
    assert len(result.outputs.get('Message')) == 1
    assert len(result.outputs.get('Message')[0]) == 5
    assert result.outputs_prefix == 'AzureStorageQueue.Queue'
    assert result.outputs.get('Message')[0].get('MessageId') == '222222222'
    assert result.outputs.get('Message')[0].get('InsertionTime') == '2021-08-22T13:00:49'
    assert result.outputs.get('Message')[0].get('TimeNextVisible') is None
    assert result.outputs.get('name') == queue_name


def test_azure_storage_queue_dequeue_messages_command(requests_mock):
    """
    Scenario: Dequeue message.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-dequeue called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, dequeue_message_command
    queue_name = "test-queue"
    get_url = f'{BASE_URL}/{queue_name}/messages?{SAS_TOKEN}&numofmessages=1&visibilitytimeout=30'

    mock_response = load_xml_mock_response('get_message.xml')
    requests_mock.get(get_url, text=mock_response)

    message_id = '1111111111111'
    pop_receipt = 'AgAAAAMAAAAAAAAAsIN/0VWX1wE='

    delete_url = f'{BASE_URL}/{queue_name}/messages/{message_id}?{SAS_TOKEN}&popreceipt={pop_receipt}'
    requests_mock.delete(delete_url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = dequeue_message_command(client, {'queue_name': queue_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Message in {queue_name} successfully deleted.'


def test_azure_storage_queue_update_messages_command(requests_mock):
    """
    Scenario: Update message.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-update called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, update_message_command
    queue_name = "test-queue"

    message_id = '1111111111111'
    pop_receipt = 'AgAAAAMAAAAAAAAAsIN/0VWX1wE='
    visibility_time_out = '30'

    url = f'{BASE_URL}/{queue_name}/messages/{message_id}?{SAS_TOKEN}' \
          f'&popreceipt={pop_receipt}&visibilitytimeout={visibility_time_out}'

    requests_mock.put(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = update_message_command(client, {'queue_name': queue_name,
                                             'message_id': message_id,
                                             'pop_receipt': pop_receipt,
                                             'message_content': 'update test',
                                             'visibility_time_out': visibility_time_out})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'The message in {queue_name} successfully updated.'


def test_azure_storage_queue_delete_messages_command(requests_mock):
    """
    Scenario: Delete message.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, delete_message_command
    queue_name = "test-queue"

    message_id = '1111111111111'
    pop_receipt = 'AgAAAAMAAAAAAAAAsIN/0VWX1wE='

    delete_url = f'{BASE_URL}/{queue_name}/messages/{message_id}?{SAS_TOKEN}&popreceipt={pop_receipt}'
    requests_mock.delete(delete_url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = delete_message_command(client, {'queue_name': queue_name,
                                             'message_id': message_id,
                                             'pop_receipt': pop_receipt})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'Message in {queue_name} successfully deleted.'


def test_azure_storage_queue_clear_queue_command(requests_mock):
    """
    Scenario: Clear queue messages command.
    Given:
     - User has provided valid credentials.
    When:
     - azure-storage-queue-message-clear called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
    """
    from AzureStorageQueue import Client, clear_messages_command
    queue_name = "test-queue"

    url = f'/{queue_name}/messages?{SAS_TOKEN}'
    requests_mock.delete(url, text='')

    client = Client(server_url=BASE_URL, verify=False, proxy=False,
                    account_sas_token=SAS_TOKEN,
                    storage_account_name=ACCOUNT_NAME, api_version=API_VERSION)
    result = clear_messages_command(client, {'queue_name': queue_name})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'{queue_name} was cleared of messages successfully.'


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

    from AzureStorageQueue import main, MANAGED_IDENTITIES_TOKEN_URL
    import demistomock as demisto
    import AzureStorageQueue
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile('.queue.core.windows.net/.*'))

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'credentials': {'identifier': 'test_storage_account_name'},
        'max_fetch': 20
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureStorageQueue, 'return_results', return_value=params)

    main()

    assert 'ok' in AzureStorageQueue.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs

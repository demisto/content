from unittest.mock import patch, MagicMock
import demistomock as demisto


from typing import Any
from WorkdaySignOnEventCollector import Client, fetch_sign_on_logs, get_sign_on_events_command, module_of_testing, main, fetch_sign_on_events_command

# Test Constants
TEST_BASE_URL = 'https://test.workday.com/'
TEST_VERIFY_CERTIFICATE = False
TEST_PROXY = False
TEST_TENANT_NAME = 'test_tenant'
TEST_TOKEN = 'test_token'
TEST_USERNAME = 'test_username'
TEST_PASSWORD = 'test_password'
TEST_MAX_FETCH = 100
TEST_FIRST_FETCH = '2023-07-01T00:00:00Z'
TEST_LAST_RUN = {'last_fetch_time': '2023-07-01T00:00:00Z', 'last_event': {}}


def create_mock_response(content: str, status: int = 200) -> MagicMock:
    mock_response = MagicMock()
    mock_response.status = status
    # Convert content to bytes before setting the return value
    content_bytes = content.encode('utf-8')
    content_str = content_bytes.decode('utf-8')
    mock_response.text = MagicMock(return_value=content_str)
    mock_response.content = content_bytes
    return mock_response


# Test the `retrieve_events` function
def test_retrieve_events():
    client = Client(TEST_BASE_URL, TEST_VERIFY_CERTIFICATE, TEST_PROXY, TEST_TENANT_NAME, TEST_TOKEN, TEST_USERNAME, TEST_PASSWORD)
    mock_response = create_mock_response('<some_response_content>')
    with patch.object(Client, '_http_request', return_value=mock_response) as mock_http_request:
        account_signon_data, total_pages = client.retrieve_events(page=1, count=100, from_time='2023-07-01T00:00:00Z', to_time='2023-07-31T00:00:00Z')
        assert account_signon_data == '<some_response_content>'
        assert total_pages == 10  # For example, if the response indicates there are 10 pages


# Test the `fetch_sign_on_logs` function
def test_fetch_sign_on_logs():
    client = Client(TEST_BASE_URL, TEST_VERIFY_CERTIFICATE, TEST_PROXY, TEST_TENANT_NAME, TEST_TOKEN, TEST_USERNAME, TEST_PASSWORD)
    # Assuming the retrieve_events method works correctly based on the previous test
    with patch.object(Client, 'retrieve_events', side_effect=[
        ('page1_data', 2),  # 2 pages in total
        ('page2_data', 2),
    ]) as mock_retrieve_events:
        sign_on_logs = fetch_sign_on_logs(client, limit_to_fetch=3, from_date='2023-07-01T00:00:00Z', to_date='2023-07-31T00:00:00Z')
        assert sign_on_logs == ['page1_data', 'page2_data']


# Test the `get_sign_on_events_command` function
def test_get_sign_on_events_command():
    client = Client(TEST_BASE_URL, TEST_VERIFY_CERTIFICATE, TEST_PROXY, TEST_TENANT_NAME, TEST_TOKEN, TEST_USERNAME, TEST_PASSWORD)
    with patch.object(Client, 'retrieve_events', return_value=('<some_response_content>', 1)) as mock_retrieve_events:
        sign_on_events, cmd_results = get_sign_on_events_command(client, from_date='2023-07-01T00:00:00Z', to_date='2023-07-31T00:00:00Z', limit=10)
        assert sign_on_events == '<some_response_content>'
        assert 'Sign On Events List:' in cmd_results.readable_output


# Test the `fetch_sign_on_events_command` function
def test_fetch_sign_on_events_command():
    client = Client(TEST_BASE_URL, TEST_VERIFY_CERTIFICATE, TEST_PROXY, TEST_TENANT_NAME, TEST_TOKEN, TEST_USERNAME, TEST_PASSWORD)
    # Assuming the fetch_sign_on_logs method works correctly based on the previous test
    with patch.object(Client, 'retrieve_events', return_value=('<some_response_content>', 1)) as mock_retrieve_events:
        sign_on_events, new_last_run = fetch_sign_on_events_command(client, max_fetch=100, first_fetch=TEST_FIRST_FETCH, last_run=TEST_LAST_RUN)
        assert sign_on_events == '<some_response_content>'
        assert 'last_fetch_time' in new_last_run


# Test the `module_of_testing` function
def test_module_of_testing():
    client = Client(TEST_BASE_URL, TEST_VERIFY_CERTIFICATE, TEST_PROXY, TEST_TENANT_NAME, TEST_TOKEN, TEST_USERNAME, TEST_PASSWORD)
    with patch.object(Client, '_http_request', return_value=create_mock_response('<some_response_content>')) as mock_http_request:
        assert module_of_testing(client) == 'ok'


# Test the `main` function (when command is 'test-module')
def test_main_test_module():
    with patch('demisto.command', return_value='test-module'), \
         patch('demisto.args', return_value={}), \
         patch('demisto.params', return_value={
             'base_url': TEST_BASE_URL,
             'insecure': TEST_VERIFY_CERTIFICATE,
             'proxy': TEST_PROXY,
             'tenant_name': TEST_TENANT_NAME,
             'token': {'password': TEST_TOKEN},
             'credentials': {'identifier': TEST_USERNAME, 'password': TEST_PASSWORD}
         }), \
         patch('arg_to_number', return_value=TEST_MAX_FETCH), \
         patch('arg_to_datetime', return_value=TEST_FIRST_FETCH), \
         patch('demisto.getLastRun', return_value=TEST_LAST_RUN), \
         patch('send_events_to_xsiam') as mock_send_events_to_xsiam:
        main()
        assert mock_send_events_to_xsiam.call_count == 0


# Test the `main` function (when command is 'workday-get-sign-on-events')
def test_main_workday_get_sign_on_events():
    with patch('demisto.command', return_value='workday-get-sign-on-events'), \
         patch('demisto.args', return_value={
             'from_date': '2023-07-01T00:00:00Z',
             'to_date': '2023-07-31T00:00:00Z',
             'limit': 10,
             'should_push_events': True,
         }), \
         patch('demisto.params', return_value={
             'base_url': TEST_BASE_URL,
             'insecure': TEST_VERIFY_CERTIFICATE,
             'proxy': TEST_PROXY,
             'tenant_name': TEST_TENANT_NAME,
             'token': {'password': TEST_TOKEN},
             'credentials': {'identifier': TEST_USERNAME, 'password': TEST_PASSWORD}
         }), \
         patch('arg_to_number', return_value=TEST_MAX_FETCH), \
         patch('arg_to_datetime', return_value=TEST_FIRST_FETCH), \
         patch('demisto.getLastRun', return_value=TEST_LAST_RUN), \
         patch('send_events_to_xsiam') as mock_send_events_to_xsiam, \
         patch.object(Client, 'retrieve_events', return_value=('<some_response_content>', 1)):
        main()
        assert mock_send_events_to_xsiam.call_count == 1

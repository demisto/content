import pytest

from Tests.test_integration import __print_investigation_error
import demisto_client


@pytest.mark.parametrize('command, output', [
    ('!create account name="User" mail="Test" password="123123!"',
     '  Command: !create account name="User" mail="Test" password=******'),
    ('!create account name="User" mail="Test" Password="123123!"',
     '  Command: !create account name="User" mail="Test" password=******'),
    ('!create account name="User" mail="Test" pass word="123123!"',
     '  Command: !create account name="User" mail="Test" pass word="123123!"'),
])
def test_print_investigation_error(command, output, mocker):
    """
    Given
    -  A failed playbook task command line.
    When
    - Extracting the task error reason from the server
    Then
    - Ensure message sent to print manager contains `password=******` instead of `password="123123!"`
    - Ensure message sent to print manager contains `password=******` instead of `Password="123123!"`
    - Ensure message sent to print manager contains "pass word="123123!""

    """
    body = {'entries': [{'type': 4, 'parentContent': command, 'taskId': '12', 'contents': '2'}]}
    mocker.patch.object(demisto_client, "generic_request_func", return_value=[str(body), '200'])
    logging_manager = mocker.MagicMock()
    client = demisto_client
    __print_investigation_error(client, '', '', logging_manager)
    logging_manager.error.assert_any_call(output)

import pytest
from Tests.test_integration import __print_investigation_error
from Tests.test_content import ParallelPrintsManager
import demisto_client

@pytest.mark.parametrize('command, output', [
    ('!create account name="User" mail="Test" password="123123!"', '  Command: !create account name="User" mail="Test" password=******'),
    ('!create account name="User" mail="Test" Password="123123!"', '  Command: !create account name="User" mail="Test" password=******'),
    ('!create account name="User" mail="Test" pass word="123123!"', '  Command: !create account name="User" mail="Test" pass word="123123!"'),
])
def test_print_investigation_error(command, output, mocker):
    """
    Given
    - Failed command line
    When
    - When a playbook test fails
    Then
    - Ensure that it replaces the password="123123!" with password=******
    - Ensure that it replaces the Password="123123!" with password=******
    - Ensure that it  not replaces the "pass word="123123!""

    """
    prints_manager = ParallelPrintsManager(1)
    body = {'entries': [{'type': 4, 'parentContent': command, 'taskId': '12', 'contents': '2'}]}
    handle_error_mock = mocker.patch.object(demisto_client, "generic_request_func", return_value=[str(body), '200'])

    client = demisto_client
    __print_investigation_error(client, '', '', prints_manager)
    prints_to_execute = prints_manager.threads_print_jobs[0]
    assert prints_to_execute[2].message_to_print == output


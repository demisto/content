import pytest
from PwnedV2 import pwned_domain_command, pwned_username_command
from test_data.context_data import username_context, domain_context
from test_data.http_responses import username_req, domain_req


args1 = {
    'username': "jondon",
    'domain': "adobe.com"
}


@pytest.mark.parametrize('command, args, response, expected_result', [
    (pwned_username_command, args1, username_req, username_context),
    (pwned_domain_command, args1, domain_req, domain_context)
])
def test_pwned_commands(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - command args - e.g username, mail
    - response of the database
    When
    - mock the website result
    Then
    - convert the result to human readable table
    - create the context
    validate the expected_result and the created context
    """
    mocker.patch('PwnedV2.http_request', return_value=response)
    for args in command(args):
        hr, outputs, raw = args
        assert expected_result == outputs  # entry context is found in the 2nd place in the result of the command

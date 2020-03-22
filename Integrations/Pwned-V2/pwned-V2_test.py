from Pwned-V2 import pwned_email_command, pwned_domain_command, pwned_username_command
from api_email_res import api_email_res
import pytest

args1 = {
    'email': "michaeljordan1@gmail.com",
    'domain': "johndon",
    'username': "user"
}


@pytest.mark.parametrize('command, args, response, expected_result', [
    (pwned_email_command, args1, "raw1", "expected_output"),
])
def test_pwned(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - select query
    - raw response of the database
    When
    - mock the database result
    Then
    - convert the result to human readable table
    - create the context
    validate the expected_result and the created context
    """
    email_suffix= "/breachedaccount/michaeljordan1@gmail.com?truncateResponse=false&includeUnverified=true"
    paste_suffix = "/ pasteaccount / michaeljordan1 @ gmail.com"
    mocker.patch.object(http_request,'GET', url_suffix=email_suffix, return_value = api_email_res)
    mocker.patch.object(http_request,'GET', url_suffix=paste_suffix, return_value = [])
    result = command()
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command

from CrowdStrikeFalconX import Client,\
    add_user_command, update_user_command, delete_user_command, get_users_command
from TestsInput.context import *
from TestsInput.http_responses import *
import pytest


def test_cs_falconx_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, concurrent_session=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    _, outputs, _ = command(client, **args)
    assert outputs == context

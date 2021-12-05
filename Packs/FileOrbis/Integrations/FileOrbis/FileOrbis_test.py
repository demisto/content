"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from FileOrbis import FileOrbisClient


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_change_user_status_success(mocker):
    from FileOrbis import change_user_status_command

    mock_change_user_status_success = util_load_json('test_data/test_change_user_status_success.json')
    mock_login_response = util_load_json('test_data/test_login_response_success.json')
    mock_logout_response = util_load_json('test_data/test_logout_response_success.json')

    client = FileOrbisClient("https://www.fileorbis.com/api/v2", False, False, "test-api-client", "test-api-secret")

    mocker.patch.object(client, 'change_user_status', return_value=mock_change_user_status_success)
    mocker.patch.object(client, 'login', return_value=mock_login_response)
    mocker.patch.object(client, 'logout', return_value=mock_logout_response)

    result = change_user_status_command(client, args={'user_id': 'test-user', 'status': 1})

    assert result.outputs == mock_change_user_status_success


def test_change_user_status_failure(mocker):
    from FileOrbis import change_user_status_command

    mock_change_user_status_failure = util_load_json('test_data/test_change_user_status_failure.json')
    mock_login_response = util_load_json('test_data/test_login_response_success.json')
    mock_logout_response = util_load_json('test_data/test_logout_response_success.json')

    client = FileOrbisClient("https://www.fileorbis.com/api/v2", False, False, "test-api-client", "test-api-secret")

    mocker.patch.object(client, 'change_user_status', return_value=mock_change_user_status_failure)
    mocker.patch.object(client, 'login', return_value=mock_login_response)
    mocker.patch.object(client, 'logout', return_value=mock_logout_response)

    result = change_user_status_command(client, args={'user_id': 'test-user', 'status': 1})

    assert result.outputs == mock_change_user_status_failure

"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import pytest
from McAfeeNSMv2 import Client


@pytest.fixture
def mcafeensmv2_client():
    return Client(url='url', auth=(), headers={}, proxy=False, verify=False)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_encode_to_base64():
    """
        Given:
            - A string to encode.
        When:
            - Before every command, to be used in the get_session_command.
        Then:
            - An encoded string in base64 is returned.
    """
    from McAfeeNSMv2 import encode_to_base64
    str_to_encode = 'username:password'
    expected = 'dXNlcm5hbWU6cGFzc3dvcmQ='
    result = encode_to_base64(str_to_encode)
    assert expected == result


def test_get_session(mocker, mcafeensmv2_client):
    """
        Given:
            - A string to encode.
        When:
            - Before every command, to be used in the get_session_command.
        Then:
            - An encoded session string in base64 is returned.
    """
    from McAfeeNSMv2 import get_session
    str_to_encode = 'username:password'
    mock_session_result = {
        "session": "ABC3AC9AB39EE322C261B733272FC49F",
        "userId": "1"
    }
    expected_session_id = 'QUJDM0FDOUFCMzlFRTMyMkMyNjFCNzMzMjcyRkM0OUY6MQ=='
    mocker.patch.object(mcafeensmv2_client, 'get_session_request', return_value=mock_session_result)
    result = get_session(mcafeensmv2_client, str_to_encode)
    assert expected_session_id == result

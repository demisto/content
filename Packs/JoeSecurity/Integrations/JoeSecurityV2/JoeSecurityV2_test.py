import pytest
from jbxapi import *


def mock_client():
    client = JoeSandbox(apiurl='https://test.com', apikey="mockkey")
    return client


@pytest.mark.parametrize('result,excepted', [({'online': True}, 'online'), ({'online': False}, 'offline')])
def test_is_online(mocker, result, excepted):
    """
    Given:
        - An app client object.
    When:
        - Is online method called.
    Then:
        - Ensure the human-readable correspond to the expcted server status.
    """
    from JoeSecurityV2 import is_online
    client = mock_client()
    mocker.patch.object(client, 'server_online', return_value=result)
    response = is_online(client)
    assert response.readable_output == f'Joe server is {excepted}'

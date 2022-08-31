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


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {
        'dummy': 'this is a dummy response'
    }
    response = baseintegration_dummy_command(client, args)

    mock_response = util_load_json('test_data/baseintegration-dummy.json')

    assert response.outputs == mock_response


# TODO: ADD HERE unit tests for every command


ARGS_CASES = [
    (-1, None, None, 'The limit value must be equal to 1 or bigger.'),
    (1, 0, None, 'The page value must be equal to 1 or bigger.'),
    (None, 2, -1, 'The page_size value must be equal to 1 or bigger.')
]


@pytest.mark.parametrize('limit, page, page_size, expected_results', ARGS_CASES)
def test_check_args(limit, page, page_size, expected_results):
    """
        Given:
            - A command's arguments

        When:
            - running commands that has pagination

        Then:
            - checking that if the parameters < 1 , exception is thrown

        """
    from Bitbucket import check_args

    with pytest.raises(Exception) as e:
        check_args(limit, page, page_size)
    assert e.value.args[0] == expected_results


def test_get_paged_results(mocker):
    """
        Given:
            - A http response

        When:
            - running a command with pagination

        Then:
            - return a list with all the results after pagination

        """
    from Bitbucket import get_paged_results, Client
    client = Client(workspace='workspace',
                    server_url='server_url',
                    auth=(),
                    proxy=False,
                    verify=False,
                    repository='repository')
    response1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response1')
    response2 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response2')
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    mocker.patch.object(Client, 'get_full_url', return_value=response2)
    results = get_paged_results(client, response1, 10)
    assert len(results) == 2
    assert results == res
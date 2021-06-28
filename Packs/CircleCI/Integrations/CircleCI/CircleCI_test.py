"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import io
import json

import pytest

from CircleCI import Client, circleci_pipelines_list_command
from CommonServerPython import CommandResults

fake_client = Client('', '', False, False, '', '', '')


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


test_data = util_load_json('test_data/circle_ci_commands_test_data.json')


@pytest.mark.parametrize('command_func, func_name',
                         [(circleci_pipelines_list_command, 'get_pipelines_list')])
def test_circleci_commands(mocker, command_func, func_name):
    """
    Given:
    - 'args': XSOAR arguments

    When:
    - Executing a CircleCI command.

    Then:
    - Ensure expected CommandResults object is returned.

    """
    command_test_data = test_data[func_name]
    mocker.patch.object(fake_client, func_name, return_value=command_test_data['raw_response'])
    result: CommandResults = command_func(fake_client, dict())
    assert result.outputs_prefix == command_test_data['outputs_prefix']
    assert result.outputs_key_field == command_test_data['outputs_key_field']
    assert result.outputs == command_test_data['raw_response']

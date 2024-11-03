import json

import pytest
from CircleCI import Client, circleci_workflows_list_command, circleci_artifacts_list_command, \
    circleci_workflow_jobs_list_command, circleci_workflow_last_runs_command, DEFAULT_LIMIT_VALUE
from CommonServerPython import CommandResults

fake_client = Client('', '', False, False, '', '', '')


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


test_data = util_load_json('test_data/circle_ci_commands_test_data.json')


@pytest.mark.parametrize('command_func, func_name',
                         [(circleci_workflows_list_command, 'get_workflows_list'),
                          (circleci_artifacts_list_command, 'get_job_artifacts'),
                          (circleci_workflow_jobs_list_command, 'get_workflow_jobs'),
                          (circleci_workflow_last_runs_command, 'get_last_workflow_runs')])
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
    mocker.patch.object(fake_client, func_name, return_value=command_test_data['response'])
    result: CommandResults = command_func(fake_client, dict())
    assert result.outputs_prefix == command_test_data['outputs_prefix']
    assert result.outputs_key_field == command_test_data['outputs_key_field']
    assert result.outputs == command_test_data['outputs']


GET_COMMON_ARGUMENTS_INPUTS = [(Client('', '', False, False, vc_type='a', organization='b', project='c'), dict(),
                                ('a', 'b', 'c', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x'}, ('x', 'b', 'c', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'organization': 'x'}, ('a', 'x', 'c', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'project': 'x'}, ('a', 'b', 'x', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'limit': 1}, ('a', 'b', 'c', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'limit': 1}, ('x', 'b', 'c', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'organization': 'x', 'limit': 1}, ('a', 'x', 'c', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'project': 'x', 'limit': 1}, ('a', 'b', 'x', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'organization': 'y'}, ('x', 'y', 'c', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'project': 'y'}, ('x', 'b', 'y', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'organization': 'x', 'project': 'y'}, ('a', 'x', 'y', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'organization': 'y', 'project': 'z'},
                                ('x', 'y', 'z', DEFAULT_LIMIT_VALUE)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'organization': 'y', 'limit': 1},
                                ('x', 'y', 'c', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'project': 'y', 'limit': 1},
                                ('x', 'b', 'y', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'organization': 'x', 'project': 'y', 'limit': 1},
                                ('a', 'x', 'y', 1)),
                               (Client('', '', False, False, vc_type='a', organization='b', project='c'),
                                {'vcs_type': 'x', 'organization': 'y', 'project': 'z', 'limit': 1},
                                ('x', 'y', 'z', 1)),
                               ]


@pytest.mark.parametrize('client, args, expected', GET_COMMON_ARGUMENTS_INPUTS)
def test_get_common_arguments(client: Client, args: dict, expected: tuple[str, str, str, int]):
    """
    Given:
    - XSOAR arguments

    When:
    - Extracting common used args for few commands.

    Then
    - Ensure the common commands are extracted as expected, and uses default value of instance parameter if not found.
    """
    from CircleCI import get_common_arguments
    assert get_common_arguments(client, args) == expected

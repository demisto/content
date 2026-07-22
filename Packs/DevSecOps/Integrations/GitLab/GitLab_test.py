import io
import json
from typing import Dict, Callable, Union, List, Any

import pytest

from CommonServerPython import CommandResults
from GitLab import Client, gitlab_pipelines_schedules_list_command, gitlab_pipelines_list_command, \
    gitlab_jobs_list_command, gitlab_artifact_get_command, gitlab_merge_requests_list_command, \
    gitlab_issues_list_command, gitlab_edit_issue_command, gitlab_group_projects_list_command, \
    gitlab_get_merge_request_command, gitlab_create_issue_command, gitlab_get_raw_file_command, \
    gitlab_trigger_build_command

BASE_URL = 'https://gitlab.com/api/v4'
mock_client = Client(BASE_URL, verify=False, proxy=False, headers=dict(), trigger_token='token')


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


command_test_data = util_load_json('test_data/commands_test_data.json')

TEST_GITLAB_COMMANDS_DATA = [(gitlab_pipelines_schedules_list_command, command_test_data['pipeline_schedule']),
                             (gitlab_pipelines_list_command, command_test_data['pipeline']),
                             (gitlab_jobs_list_command, command_test_data['jobs']),
                             (gitlab_artifact_get_command, command_test_data['artifact-get']),
                             (gitlab_merge_requests_list_command, command_test_data['merge-requests-list']),
                             (gitlab_get_merge_request_command, command_test_data['get-merge-request']),
                             (gitlab_issues_list_command, command_test_data['issues-list']),
                             (gitlab_edit_issue_command, command_test_data['edit-issue']),
                             (gitlab_create_issue_command, command_test_data['create-issue']),
                             (gitlab_get_raw_file_command, command_test_data['get-raw-file']),
                             (gitlab_group_projects_list_command, command_test_data['group-projects-list']),
                             (gitlab_trigger_build_command, command_test_data['trigger_pipeline'])]


@pytest.mark.parametrize('command_func, test_data', TEST_GITLAB_COMMANDS_DATA)
def test_gitlab_commands(requests_mock, command_func: Callable[[Client, Dict], CommandResults], test_data: Dict):
    """
    Given:
     - Command function.
     - XSOAR arguments.

    When:
     - Executing a command.

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    mock_response: Union[Dict, List[Dict]] = test_data['mock_response']
    expected_outputs: List[Dict] = test_data['expected_outputs']
    expected_prefix: str = test_data['expected_prefix']
    expected_url_mock_suffix: str = test_data['expected_url_mock_suffix']
    expected_key_field: str = test_data['expected_key_field']
    args: Dict[str, Any] = test_data['args']
    method: str = test_data.get('method', "GET")
    if method.upper() == "GET":
        requests_mock.get(f'{BASE_URL}/{expected_url_mock_suffix}', json=mock_response)
    elif method.upper() == "PUT":
        requests_mock.put(f'{BASE_URL}/{expected_url_mock_suffix}', json=mock_response)
    elif method.upper() == "POST":
        requests_mock.post(f'{BASE_URL}/{expected_url_mock_suffix}', json=mock_response)

    else:
        raise Exception
    command_result = command_func(mock_client, args)
    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs == expected_outputs
    assert command_result.outputs_key_field == expected_key_field

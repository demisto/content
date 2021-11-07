import json
import io

import pytest

from GsuiteAuditor import GSuiteClient, activities_list_command

MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'

with open('test_data/service_account_json.txt') as j:
    TEST_JSON = j.read()


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_activities_list_command(gsuite_client, mocker):
    """
        Scenario: gsuite-activities-list command is called with valid arguments.

        Given:
        - Command args.

        When:
        - Calling activities_list with command arguments.

        Then:
        - Ensure CommandResult should return data as expected. with and without results
        """

    arguments = {
        'user_key': 'all',
        'application_name': 'admin'
    }
    api_response = util_load_json('test_data/activities_list_response.json')
    expected_entry_context = util_load_json('test_data/activities_list_entry_context.json')

    mocker.patch.object(gsuite_client, 'http_request', return_value=api_response)

    command_result = activities_list_command(gsuite_client, arguments)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']

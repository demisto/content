import pytest
import io
from CommonServerPython import *
from HashiCorpTerraform import Client, runs_list_command, run_action_command, plan_get_command, policies_list_command, policy_set_list_command, policies_checks_list_command
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(
        url=SERVER_URL, token=None,
        default_organization_name=None, default_workspace_id=None,
        verify=None, proxy=None)


def test_runs_list_command(client, requests_mock):
    """
        When:
        Given:
        Then:
    """
    args = {'workspace_id': None, 'run_id': None, 'filter_status': None}
    mock_response_runs_list_request = util_load_json(
        './test_data/outputs/runs_list_request.json')
    mock_results = util_load_json('./test_data/outputs/runs_list_command.json')
    requests_mock.post(SERVER_URL, json=mock_response_runs_list_request)
    results = runs_list_command(client=client, args=args)
    assert results.outputs_prefix == 'Terraform.Run'
    assert results.outputs_key_field == 'data.id'
    assert results.outputs == mock_results.get('outputs')
    assert results.readable_output == mock_results.get('readable_output')


def test_run_action_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'run_id': 'run-Q2kS54r6pJjdyYfk', 'action': 'apply', 'comment':
            'comment'}
    mock_response_run_action = util_load_json(
        './test_data/outputs/run_action.json')
    mock_results = util_load_json('./test_data/outputs/run_action_command.json'
                                  )
    requests_mock.post(SERVER_URL, json=mock_response_run_action)
    results = run_action_command(client=client, args=args)


def test_plan_get_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'plan_id': 'plan-V4fvpvCzGQrsZikD', 'json_output': None}
    mock_response_get_plan = util_load_json('./test_data/outputs/get_plan.json'
                                            )
    mock_results = util_load_json('./test_data/outputs/plan_get_command.json')
    requests_mock.post(SERVER_URL, json=mock_response_get_plan)
    results = plan_get_command(client=client, args=args)


def test_policies_list_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'organization_name': None, 'policy_kind': None, 'policy_name':
            None, 'policy_id': None}
    mock_response_list_policies = util_load_json(
        './test_data/outputs/list_policies.json')
    mock_results = util_load_json(
        './test_data/outputs/policies_list_command.json')
    requests_mock.post(SERVER_URL, json=mock_response_list_policies)
    results = policies_list_command(client=client, args=args)
    assert results.outputs_prefix == 'Terraform.Policy'
    assert results.outputs_key_field == 'id'
    assert results.outputs == mock_results.get('outputs')
    assert results.raw_response == mock_response_list_policies
    assert results.readable_output == mock_results.get('readable_output')


def test_policy_set_list_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'organization_name': None, 'policy_set_id': None, 'versioned':
            None, 'policy_set_kind': None, 'include': None, 'policy_set_name':
            None, 'page_number': None, 'page_size': None}
    mock_response_list_policy_sets = util_load_json(
        './test_data/outputs/list_policy_sets.json')
    mock_results = util_load_json(
        './test_data/outputs/policy_set_list_command.json')
    requests_mock.post(SERVER_URL, json=mock_response_list_policy_sets)
    results = policy_set_list_command(client=client, args=args)
    assert results.outputs_prefix == 'Terraform.PolicySet'
    assert results.outputs_key_field == 'id'
    assert results.outputs == mock_results.get('outputs')
    assert results.raw_response == mock_response_list_policy_sets
    assert results.readable_output == mock_results.get('readable_output')


def test_policies_checks_list_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'run_id': 'run-Q2kS54r6pJjdyYfk', 'policy_check_id': None,
            'page_number': None, 'page_size': None}
    mock_response_list_policy_checks = util_load_json(
        './test_data/outputs/list_policy_checks.json')
    mock_results = util_load_json(
        './test_data/outputs/policies_checks_list_command.json')
    requests_mock.post(SERVER_URL, json=mock_response_list_policy_checks)
    results = policies_checks_list_command(client=client, args=args)
    assert results.outputs_prefix == 'Terraform.PolicyCheck'
    assert results.outputs_key_field == 'id'
    assert results.outputs == mock_results.get('outputs')
    assert results.raw_response == mock_response_list_policy_checks
    assert results.readable_output == mock_results.get('readable_output')

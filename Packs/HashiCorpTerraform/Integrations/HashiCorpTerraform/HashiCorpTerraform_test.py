import pytest
from pytest import raises
import io
from CommonServerPython import *
from HashiCorpTerraform import Client, runs_list_command, run_action_command, plan_get_command, policies_list_command, policy_set_list_command, policies_checks_list_command
import re
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
        Given:
            - Client object.
        When:
            - run the list runs command.
        Then:
            - validate the results are as expected. 
    """
    mock_response = util_load_json('./test_data/runs_list_request.json')['mock_response']
    requests_mock.get(re.compile(f'{SERVER_URL}.*'), json=mock_response)
    expected_results = util_load_json('./test_data/runs_list_request.json')['expected_results']
    
    results = runs_list_command(client=client, args={'workspace_id': 'workspace_id'})
    
    assert results.to_context() == expected_results


def test_run_action_command(client, requests_mock):
    """
        Given:
            - Client object.
        When:
            - run the run action command.
        Then:
            - validate the results are as expected. 
    """
    mock_response = util_load_json('./test_data/run_action_request.json')['mock_response']
    requests_mock.post(re.compile(f'{SERVER_URL}.*'), json=mock_response, status_code=409)
    expected_results = util_load_json('./test_data/run_action_request.json')['expected_results']
    
    with raises(DemistoException) as err:
        results = run_action_command(client=client, args={
            'run_id': 'run-ABCABCABCABCABCa',
            'action': 'apply', 'comment': 'comment'
        })
    assert err


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

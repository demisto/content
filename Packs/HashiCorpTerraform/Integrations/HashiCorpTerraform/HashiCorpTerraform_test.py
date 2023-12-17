import pytest
from CommonServerPython import *
from HashiCorpTerraform import Client, runs_list_command, \
    run_action_command, plan_get_command, policies_list_command, policy_set_list_command, policies_checks_list_command
import re
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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
            - error occurred when run the run action command.
        Then:
            - validate the exception raised as expected.
    """
    mock_response = util_load_json('./test_data/run_action_request.json')['mock_response']
    requests_mock.post(re.compile(f'{SERVER_URL}.*'), json=mock_response, status_code=409)

    run_id = 'run-ABCABCABCABCABCa'
    with pytest.raises(DemistoException) as err:
        run_action_command(client=client, args={
            'run_id': run_id,
            'action': 'apply', 'comment': 'comment'
        })
    assert f'Error occurred when queued an apply request for run id {run_id}' in str(err)


def test_plan_get_command(client, requests_mock):
    """
        Given:
            - Client object.
        When:
            - run the get plan command to get the plan meta data.
        Then:
            - validate the results are as expected.
    """
    args = {'plan_id': 'plan-Abcabcabcabcabc4'}

    mock_response = util_load_json('./test_data/plan_get_request.json')['mock_response']
    expected_results = util_load_json('./test_data/plan_get_request.json')['expected_results']

    requests_mock.get(re.compile(f'{SERVER_URL}.*'), json=mock_response)
    results = plan_get_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policies_list_command(client, requests_mock, mocker):
    """
        Given:
            - Client object.
        When:
            - run the get policies list command.
        Then:
            - validate the results are as expected.
    """
    organization_name = 'organization_name'
    args = {'organization_name': organization_name}

    mock_response = util_load_json('./test_data/policies_list_request.json')['mock_response']
    expected_results = util_load_json('./test_data/policies_list_request.json')['expected_results']

    requests_mock.get(f'{SERVER_URL}/organizations/{organization_name}/policies', json=mock_response)
    mocker.patch.object(demisto, 'dt', side_effect=lambda _, key: key)

    results = policies_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policy_set_list_command(client, requests_mock, mocker):
    """
        Given:
            - Client object.
        When:
            - run the get policy set list command.
        Then:
            - validate the results are as expected.
    """

    organization_name = 'organization_name'
    args = {'organization_name': organization_name}

    mock_response = util_load_json('./test_data/policy_set_list_request.json')['mock_response']
    expected_results = util_load_json('./test_data/policy_set_list_request.json')['expected_results']

    requests_mock.get(f'{SERVER_URL}/organizations/{organization_name}/policy-sets', json=mock_response)
    mocker.patch.object(demisto, 'dt', side_effect=lambda _, key: key)
    results = policy_set_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_policies_checks_list_command(client, requests_mock):
    """
        Given:
            - Client object.
        When:
            - run the get policies checks list command.
        Then:
            - validate the results are as expected.
    """
    run_id = 'run-abcabcabcabcabc1'
    args = {'run_id': run_id}

    mock_response = util_load_json('./test_data/policies_check_list_request.json')['mock_response']
    expected_results = util_load_json('./test_data/policies_check_list_request.json')['expected_results']

    requests_mock.get(f'{SERVER_URL}/runs/{run_id}/policy-checks', json=mock_response)
    results = policies_checks_list_command(client=client, args=args)
    assert results.to_context() == expected_results


def test_test_module_command(client, mocker):
    """
        Given:
            - Client object with error occurred in test_connection.
        When:
            - run the test module command.
        Then:
            - validate the expected exception.
    """
    import HashiCorpTerraform
    mocker.patch.object(client, 'test_connection', side_effect=Exception('Unauthorized'))

    with pytest.raises(DemistoException) as err:
        HashiCorpTerraform.test_module(client)

    assert 'Unauthorized: Please be sure you put a valid API Token' in str(err)

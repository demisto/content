import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_authenticate_user(requests_mock):
    from Integrations.FireMonSecurityManager.FireMonSecurityManager import Client, authenticate_command

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_authentication.json')
    requests_mock.post('https://192.168.21.98/securitymanager/api/authentication/login', json=mock_response)

    client = Client(
        base_url='https://192.168.21.98',
        verify=False,
        proxy=False)

    response = authenticate_command(client)
    assert response is not None
    assert response == mock_response.get('token')


def test_workflow_command(requests_mock):
    from Integrations.FireMonSecurityManager.FireMonSecurityManager import Client, workflow_command

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_authentication.json')
    requests_mock.post('https://192.168.21.98/securitymanager/api/authentication/login', json=mock_response)

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_workflows.json')
    requests_mock.get('https://192.168.21.98/policyplanner/api/domain/1/workflow/version/latest/all',
                      json=mock_response)

    client = Client(
        base_url='https://192.168.21.98',
        verify=False,
        proxy=False)
    args = {
        'domain_id': 1
    }
    response = workflow_command(client, args)
    assert response is not None
    assert response == 'Access Req WF,WorkflowForTest'


def test_create_pp_ticket_command(requests_mock):
    from Integrations.FireMonSecurityManager.FireMonSecurityManager import Client, create_pp_ticket_command

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_authentication.json')
    requests_mock.post('https://192.168.21.98/securitymanager/api/authentication/login', json=mock_response)

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_workflows.json')
    requests_mock.get('https://192.168.21.98/policyplanner/api/domain/1/workflow/version/latest/all',
                      json=mock_response)

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_pp_ticket.json')
    requests_mock.post('https://192.168.21.98/policyplanner/api/domain/1/workflow/3/packet',
                       json=mock_response)

    client = Client(
        base_url='https://192.168.21.98',
        verify=False,
        proxy=False)
    args = {'domain_id': 1,
            'workflow_name': 'Access Req WF',
            'requirement': [{"action": "ACCEPT",
                             "destinations": "2.2.2.2",
                             "services": "http",
                             "sources": "1.1.1.1"}],
            'priority': 'Low',
            'due_date': '2021-08-26T03:50:17-04:00'}
    response = create_pp_ticket_command(client, args)
    assert response is not None


def test_pca_new_command(requests_mock):
    from Integrations.FireMonSecurityManager.FireMonSecurityManager import Client, pca_new_command

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_authentication.json')
    requests_mock.post('https://192.168.21.98/securitymanager/api/authentication/login', json=mock_response)

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_rule_rec.json')
    requests_mock.post('https://192.168.21.98/orchestration/api/domain/1/change/rulerec', json=mock_response)

    mock_response = util_load_json('Integrations/FireMonSecurityManager/test_data/get_pca.json')
    requests_mock.post('https://192.168.21.98/orchestration/api/domain/1/change/device/9/pca', json=mock_response)

    client = Client(
        base_url='https://192.168.21.98',
        verify=False,
        proxy=False)
    args = {'sources': '10.1.1.1',
            'destinations': '192.168.202.1',
            'services': 'tcp/8090',
            'action': 'ACCEPT',
            'domain_id': 1,
            'device_group_id': 1}

    response = pca_new_command(client, args)
    assert response is not None

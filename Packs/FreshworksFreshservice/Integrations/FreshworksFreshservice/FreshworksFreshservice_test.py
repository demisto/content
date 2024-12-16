import pytest
from unittest import mock

import os
from CommonServerPython import *
from FreshworksFreshservice import Client

SERVER_URL = 'https://test_url.com/'
API_TOKEN = 'api_token'
FILE_ENTRY = {
    'name': 'freshservice_ticket_create_update.json',
    'path': 'test_data/freshservice_ticket_create_update.json'
}


def util_load_json(file_name):
    with open(os.path.join('test_data', file_name),
              encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL,
                  verify=False,
                  proxy=False,
                  api_token=API_TOKEN)


@pytest.mark.parametrize('url, args, entity_name, output_prefix', [
    (f'{SERVER_URL}api/v2/requesters/1', {
        'command_name': 'freshservice-requester-list',
        'requester_id': 1,
    }, 'requester_get', 'Requester'),
    (f'{SERVER_URL}api/v2/vendors/1', {
        'vendor_id': 1,
        'command_name': 'freshservice-vendor-list',
    }, 'vendor_get', 'Vendor'),
    (f'{SERVER_URL}api/v2/agents/1', {
        'agent_id': 1,
        'command_name': 'freshservice-agent-list',
    }, 'agent_get', 'Agent'),
    (f'{SERVER_URL}api/v2/roles/1', {
        'role_id': 1,
        'command_name': 'freshservice-role-list',
    }, 'role_get', 'Role'),
    (f'{SERVER_URL}api/v2/applications/1', {
        'software_id': 1,
        'command_name': 'freshservice-software-list',
    }, 'software_get', 'Software'),
    (f'{SERVER_URL}api/v2/departments/1', {
        'department_id': 1,
        'command_name': 'freshservice-department-list',
    }, 'department_get', 'Department'),
    (f'{SERVER_URL}api/v2/groups/1', {
        'agent_group_id': 1,
        'command_name': 'freshservice-agent-group-list',
    }, 'agent_group_get', 'AgentGroup'),
    (f'{SERVER_URL}api/v2/purchase_orders/1', {
        'purchase_order_id': 1,
        'command_name': 'freshservice-purchase-order-list',
    }, 'purchase_order_get', 'PurchaseOrder'),
    (f'{SERVER_URL}api/v2/assets/1', {
        'asset_id': 1,
        'command_name': 'freshservice-asset-list',
    }, 'asset_get', 'Asset'),
])
def test_get_freshservice_entities_command(
    client,
    requests_mock,
    url,
    args,
    entity_name,
    output_prefix,
):
    """
    Scenario: Returns a specific requester/ role/ agent/ vendor/ software/ asset/
        agent group/ purchase order by ID in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-asset-list called.
     - freshservice-agent-list called.
     - freshservice-agent-group-list called.
     - freshservice-vendor-list called.
     - freshservice-software-list called.
     - freshservice-role-list called.
     - freshservice-requester-list called.
     - freshservice-department-list called.
     - freshservice-purchase-order-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_entities_command
    mock_response_freshservice_entities_list = util_load_json(
        f'freshservice_{entity_name}.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_entities_command(client=client, args=args)

    assert results.outputs['id'] == 1
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args, entity_name, output_prefix', [
    (f'{SERVER_URL}api/v2/requesters', {
        'page': 1,
        'page_size': 4,
        'first_name': 'Jack',
        'command_name': 'freshservice-requester-list',
    }, 'requester_list', 'Requester'),
    (f'{SERVER_URL}api/v2/vendors', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-vendor-list',
    }, 'vendor_list', 'Vendor'),
    (f'{SERVER_URL}api/v2/agents', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-agent-list',
    }, 'agent_list', 'Agent'),
    (f'{SERVER_URL}api/v2/roles', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-role-list',
    }, 'role_list', 'Role'),
    (f'{SERVER_URL}api/v2/applications', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-software-list',
    }, 'software_list', 'Software'),
    (f'{SERVER_URL}api/v2/departments', {
        'page': 1,
        'page_size': 4,
        'first_name': 'Jack',
        'command_name': 'freshservice-department-list',
    }, 'department_list', 'Department'),
    (f'{SERVER_URL}api/v2/groups', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-agent-group-list',
    }, 'agent_group_list', 'AgentGroup'),
    (f'{SERVER_URL}api/v2/purchase_orders', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-purchase-order-list',
    }, 'purchase_order_list', 'PurchaseOrder'),
    (f'{SERVER_URL}api/v2/assets', {
        'first_name': 'Jack',
        'command_name': 'freshservice-asset-list',
    }, 'asset_list', 'Asset'),
    (f'{SERVER_URL}api/v2/requester_fields', {
        'command_name': 'freshservice-requester-field-list',
    }, 'requester_field_list', 'RequesterField'),
])
def test_list_freshservice_entities_command(
    client,
    requests_mock,
    url,
    args,
    entity_name,
    output_prefix,
):
    """
    Scenario: Returns a list of requesters/ roles/ agents/ vendors/ softwares/ assets/
        agent groups/ purchase orders in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-asset-list called.
     - freshservice-agent-list called.
     - freshservice-agent-group-list called.
     - freshservice-vendor-list called.
     - freshservice-software-list called.
     - freshservice-role-list called.
     - freshservice-requester-list called.
     - freshservice-department-list called.
     - freshservice-purchase-order-list called.
     - freshservice-requester-field-list called.


    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_entities_command
    mock_response_freshservice_entities_list = util_load_json(
        f'freshservice_{entity_name}.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_entities_command(client=client, args=args)

    assert results.outputs[0]['id'] == 1
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/tickets', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-ticket-list',
    }),
    (f'{SERVER_URL}api/v2/tickets/filter', {
        'query': "priority:>3 AND status:2",
        'command_name': 'freshservice-ticket-list',
    }),
])
def test_list_freshservice_ticket_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Returns a list of ticket in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client, args=args)

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0].get('source') == 'Portal'
    assert results.outputs[0]['status'] == 'Resolved'
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


def test_get_freshservice_ticket_command(
    client,
    requests_mock,
):
    """
    Scenario: Returns a specific ticket in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_get.json')

    requests_mock.get(f'{SERVER_URL}api/v2/tickets/1',
                      json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client,
                                               args={
                                                   'ticket_id':
                                                   1,
                                                   'command_name':
                                                   'freshservice-ticket-list'
                                               })

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['source'] == 'Portal'
    assert results.outputs[0]['status'] == 'Resolved'
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/problems', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-problem-list',
    }),
    (f'{SERVER_URL}api/v2/problems?page=1&per_page=2', {
        'limit': 2,
        'command_name': 'freshservice-problem-list',
    }),
])
def test_list_freshservice_problem_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Returns a list of problem in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-problem-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_problem_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client, args=args)

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['priority'] == 'High'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Problem'
    assert results.outputs_key_field == 'id'


def test_get_freshservice_problem_command(
    client,
    requests_mock,
):
    """
    Scenario: Returns a specific problem in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-problem-list called.


    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_problem_get.json')

    requests_mock.get(f'{SERVER_URL}api/v2/problems/1',
                      json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client,
                                               args={
                                                   'problem_id':
                                                   1,
                                                   'command_name':
                                                   'freshservice-problem-list'
                                               })

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['priority'] == 'High'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Problem'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/changes', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-change-list',
    }),
    (f'{SERVER_URL}api/v2/changes?page=1&per_page=2', {
        'limit': 2,
        'command_name': 'freshservice-change-list',
    }),
])
def test_list_freshservice_change_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Returns a list of change in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-change-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_change_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client, args=args)

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['risk'] == 'Low'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Change'
    assert results.outputs_key_field == 'id'


def test_get_freshservice_change_command(
    client,
    requests_mock,
):
    """
    Scenario: Returns a specific change in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-change-list called.


    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_change_get.json')

    requests_mock.get(f'{SERVER_URL}api/v2/changes/1',
                      json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client,
                                               args={
                                                   'change_id':
                                                   1,
                                                   'command_name':
                                                   'freshservice-change-list'
                                               })

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['risk'] == 'Low'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Change'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/releases', {
        'page': 1,
        'page_size': 4,
        'command_name': 'freshservice-release-list',
    }),
    (f'{SERVER_URL}api/v2/releases?page=1&per_page=2', {
        'limit': 2,
        'filter_name': 'all',
        'command_name': 'freshservice-release-list',
    }),
])
def test_list_freshservice_release_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Returns a list of release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-release-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_release_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client, args=args)

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['priority'] == 'Low'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Release'
    assert results.outputs_key_field == 'id'


def test_get_freshservice_release_command(
    client,
    requests_mock,
):
    """
    Scenario: Returns a specific release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-release-list called.


    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_release_get.json')

    requests_mock.get(f'{SERVER_URL}api/v2/releases/1',
                      json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_command(client=client,
                                               args={
                                                   'release_id':
                                                   1,
                                                   'command_name':
                                                   'freshservice-release-list'
                                               })

    assert results.outputs[0]['id'] == 1
    assert results.raw_response[0]['priority'] == 'Low'
    assert results.outputs[0]['status'] == 'Open'
    assert results.outputs_prefix == 'Freshservice.Release'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize(
    'url, method, args, entity_name, output_prefix, response_entity', [
        (f'{SERVER_URL}api/v2/tickets', 'POST', {
            'command_name': 'freshservice-ticket-create',
            "subject": 'subject',
            "status": 'Open',
            "priority": 'Low',
            "email": 'email',
            "description": 'description',
        }, 'ticket_create_update', 'Ticket', 'ticket'),
        (f'{SERVER_URL}api/v2/tickets', 'POST', {
            "subject": 'subject',
            "status": 'Open',
            "priority": 'Low',
            "email": 'email',
            "description": 'description',
            "assets": 1,
            'command_name': 'freshservice-ticket-create',
        }, 'ticket_create_update', 'Ticket', 'ticket'),
        (f'{SERVER_URL}api/v2/tickets/1', 'PUT', {
            'ticket_id': '1',
            "priority": 'Low',
            'command_name': 'freshservice-ticket-update',
        }, 'ticket_create_update', 'Ticket', 'ticket'),
        (f'{SERVER_URL}api/v2/tickets/1', 'PUT', {
            'ticket_id': '1',
            "attachments": 'attachments',
            'command_name': 'freshservice-ticket-update',
        }, 'ticket_create_update', 'Ticket', 'ticket'),
        (f'{SERVER_URL}api/v2/problems', 'POST', {
            'command_name': 'freshservice-problem-create',
            "subject": 'subject',
            "status": 'Open',
            "priority": 'Low',
            "impact": 'Low',
            "email": 'email',
            "description": 'description',
        }, 'problem_create_update', 'Problem', 'problem'),
        (f'{SERVER_URL}api/v2/problems/1', 'PUT', {
            'problem_id': '1',
            "priority": 'Low',
            'command_name': 'freshservice-problem-update',
        }, 'problem_create_update', 'Problem', 'problem'),
        (f'{SERVER_URL}api/v2/changes', 'POST', {
            'command_name': 'freshservice-change-create',
            "subject": 'subject',
            "status": 'Open',
            "priority": 'Low',
            "impact": 'Low',
            "risk": 'Low',
            "change_type": 'Minor',
            "email": 'email',
            "description": 'description',
            "planned_start_date": 'date',
            "planned_end_date": 'date',
        }, 'change_create_update', 'Change', 'change'),
        (f'{SERVER_URL}api/v2/changes/1', 'PUT', {
            'change_id': '1',
            "priority": 'Low',
            'command_name': 'freshservice-change-update',
        }, 'change_create_update', 'Change', 'change'),
        (f'{SERVER_URL}api/v2/releases', 'POST', {
            'command_name': 'freshservice-release-create',
            "category": 'category',
            "planned_end_date": 'planned_end_date',
            "planned_start_date": 'planned_start_date',
            "priority": 'Low',
            "release_type": 'Minor',
            "status": 'Open',
            "description": 'description',
            "subject": 'subject'
        }, 'release_create_update', 'Release', 'release'),
        (f'{SERVER_URL}api/v2/releases/1', 'PUT', {
            'release_id': '1',
            "priority": 'Low',
            'command_name': 'freshservice-release-update',
        }, 'release_create_update', 'Release', 'release'),
    ])
@mock.patch('FreshworksFreshservice.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_create_update_freshservice_ticket_command(
    client,
    url,
    method,
    args,
    entity_name,
    output_prefix,
    response_entity,
    requests_mock,
):
    """
    Scenario: Create/ Update a ticket/ change/ problem/
        release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-create called.
     - freshservice-ticket-update called.
     - freshservice-problem-create called.
     - freshservice-problem-update called.
     - freshservice-change-create called.
     - freshservice-change-update called.
     - freshservice-release-create called.
     - freshservice-release-update called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import create_update_freshservice_ticket_command
    mock_response_freshservice_entities_list = util_load_json(
        f'freshservice_{entity_name}.json')

    help_method = requests_mock.post if method == 'POST' else requests_mock.put
    help_method(url, json=mock_response_freshservice_entities_list)

    results = create_update_freshservice_ticket_command(client=client,
                                                        args=args)

    assert results.outputs[0].get('id') == 1
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'
    assert results.outputs[0].get('status') == 'Open'
    assert results.outputs[0].get('priority') == 'Low'


@pytest.mark.parametrize('url, args, response_entity', [
    (f'{SERVER_URL}api/v2/tickets/1', {
        'command_name': 'freshservice-ticket-delete',
        'ticket_id': 1,
    }, 'Ticket'),
    (f'{SERVER_URL}api/v2/problems/1', {
        'command_name': 'freshservice-problem-delete',
        'problem_id': 1,
    }, 'Problem'),
    (f'{SERVER_URL}api/v2/changes/1', {
        'command_name': 'freshservice-change-delete',
        'change_id': 1,
    }, 'Change'),
    (f'{SERVER_URL}api/v2/releases/1', {
        'command_name': 'freshservice-release-delete',
        'release_id': 1,
    }, 'Release'),
])
def test_delete_freshservice_ticket_command(
    client,
    requests_mock,
    url,
    args,
    response_entity,
):
    """
    Scenario: Delete ticket/ change/ problem/
        release by ID in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-delete called.

    Then:
     - Ensure readable_output is correct.
    """
    from FreshworksFreshservice import delete_freshservice_ticket_command

    requests_mock.delete(url, json='')

    results = delete_freshservice_ticket_command(client=client, args=args)

    assert results.readable_output == f'{response_entity} deleted successfully'


@pytest.mark.parametrize('url, args, output_prefix', [
    (f'{SERVER_URL}api/v2/tickets/1/tasks/1', {
        'command_name': 'freshservice-ticket-task-list',
        'ticket_id': 1,
        'task_id': 1,
    }, 'Ticket'),
    (f'{SERVER_URL}api/v2/problems/1/tasks/1', {
        'command_name': 'freshservice-problem-task-list',
        'problem_id': 1,
        'task_id': 1,
    }, 'Problem'),
    (f'{SERVER_URL}api/v2/changes/1/tasks/1', {
        'command_name': 'freshservice-change-task-list',
        'change_id': 1,
        'task_id': 1,
    }, 'Change'),
    (f'{SERVER_URL}api/v2/releases/1/tasks/1', {
        'command_name': 'freshservice-release-task-list',
        'release_id': 1,
        'task_id': 1,
    }, 'Release'),
])
def test_get_freshservice_ticket_task_command(
    client,
    requests_mock,
    url,
    args,
    output_prefix,
):
    """
    Scenario: Returns a specific task of ticket/ change/ problem/
        release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-task-list called.
     - freshservice-problem-task-list called.
     - freshservice-change-task-list called.
     - freshservice-release-task-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_task_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_task_get.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_task_command(client=client, args=args)

    assert results.outputs['Task'][0].get('id') == 1
    assert results.outputs['Task'][0].get('status') == 'Open'
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args, output_prefix', [
    (f'{SERVER_URL}api/v2/tickets/1/tasks', {
        'command_name': 'freshservice-ticket-task-list',
        'ticket_id': 1,
        'page': 1,
        'page_size': 4,
    }, 'Ticket'),
    (f'{SERVER_URL}api/v2/problems/1/tasks', {
        'command_name': 'freshservice-problem-task-list',
        'problem_id': 1,
        'page': 1,
        'page_size': 4,
    }, 'Problem'),
    (f'{SERVER_URL}api/v2/changes/1/tasks', {
        'command_name': 'freshservice-change-task-list',
        'change_id': 1,
        'page': 1,
        'page_size': 4,
    }, 'Change'),
    (f'{SERVER_URL}api/v2/releases/1/tasks', {
        'command_name': 'freshservice-release-task-list',
        'release_id': 1,
        'page': 1,
        'page_size': 4,
    }, 'Release'),
])
def test_list_freshservice_ticket_task_command(
    client,
    requests_mock,
    url,
    args,
    output_prefix,
):
    """
    Scenario: Returns a task list of ticket/ change/ problem/
        release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-task-list called.
     - freshservice-problem-task-list called.
     - freshservice-change-task-list called.
     - freshservice-release-task-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import list_freshservice_ticket_task_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_task_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_task_command(client=client, args=args)

    assert results.outputs['Task'][0].get('id') == 1
    assert results.outputs['Task'][0].get('status') == 'Open'
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, method, args,  output_prefix', [
    (f'{SERVER_URL}api/v2/tickets/1/tasks', 'POST', {
        'command_name': 'freshservice-ticket-task-create',
        "due_date": 'due_date',
        "notify_before": 800,
        "title": 'title',
        "description": 'description',
        "ticket_id": 1,
    }, 'Ticket'),
    (f'{SERVER_URL}api/v2/tickets/1/tasks/1', 'PUT', {
        'ticket_id': 1,
        'task_id': 1,
        "title": 'title',
        'command_name': 'freshservice-ticket-task-update',
    }, 'Ticket'),
    (f'{SERVER_URL}api/v2/problems/1/tasks', 'POST', {
        'command_name': 'freshservice-problem-task-create',
        "due_date": 'due_date',
        "notify_before": 1000,
        "title": 'title',
        "description": 'description',
        "problem_id": 1,
    }, 'Problem'),
    (f'{SERVER_URL}api/v2/problems/1/tasks/1', 'PUT', {
        'problem_id': 1,
        'task_id': 1,
        "title": 'title',
        'command_name': 'freshservice-problem-task-update',
    }, 'Problem'),
    (f'{SERVER_URL}api/v2/changes/1/tasks', 'POST', {
        'command_name': 'freshservice-change-task-create',
        "due_date": 'due_date',
        "notify_before": 2200,
        "title": 'title',
        "description": 'description',
        "change_id": 1,
    }, 'Change'),
    (f'{SERVER_URL}api/v2/changes/1/tasks/1', 'PUT', {
        'change_id': 1,
        'task_id': 1,
        "title": 'title',
        'command_name': 'freshservice-change-task-update',
    }, 'Change'),
    (f'{SERVER_URL}api/v2/releases/1/tasks', 'POST', {
        'command_name': 'freshservice-release-task-create',
        "due_date": 'due_date',
        "notify_before": 3600,
        "title": 'title',
        "description": 'description',
        "release_id": 1,
    }, 'Release'),
    (f'{SERVER_URL}api/v2/releases/1/tasks/1', 'PUT', {
        'release_id': 1,
        'task_id': 1,
        "title": 'title',
        'command_name': 'freshservice-release-task-update',
    }, 'Release'),
])
def test_create_update_freshservice_ticket_task_command(
    client,
    requests_mock,
    url,
    method,
    args,
    output_prefix,
):
    """
    Scenario: Create/ Update a ticket/ change/ problem/
        release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-task-create called.
     - freshservice-ticket-task-update called.
     - freshservice-problem-task-create called.
     - freshservice-problem-task-update called.
     - freshservice-change-task-create called.
     - freshservice-change-task-update called.
     - freshservice-release-task-create called.
     - freshservice-release-task-update called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import create_update_freshservice_ticket_task_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_task_create_update.json')

    help_method = requests_mock.post if method == 'POST' else requests_mock.put
    help_method(url, json=mock_response_freshservice_entities_list)

    results = create_update_freshservice_ticket_task_command(client=client,
                                                             args=args)

    assert results.outputs['Task'][0].get('id') == 3
    assert results.outputs_prefix == f'Freshservice.{output_prefix}'
    assert results.outputs_key_field == 'id'
    assert results.outputs['Task'][0].get('status') == 'Open'


@pytest.mark.parametrize('url, args, response_entity', [
    (f'{SERVER_URL}api/v2/tickets/1/tasks/1', {
        'command_name': 'freshservice-ticket-task-delete',
        'ticket_id': 1,
        'task_id': 1,
    }, 'Ticket Task'),
    (f'{SERVER_URL}api/v2/problems/1/tasks/1', {
        'command_name': 'freshservice-problem-task-delete',
        'problem_id': 1,
        'task_id': 1,
    }, 'Problem Task'),
    (f'{SERVER_URL}api/v2/changes/1/tasks/1', {
        'command_name': 'freshservice-change-task-delete',
        'change_id': 1,
        'task_id': 1,
    }, 'Change Task'),
    (f'{SERVER_URL}api/v2/releases/1/tasks/1', {
        'command_name': 'freshservice-release-task-delete',
        'release_id': 1,
        'task_id': 1,
    }, 'Release Task'),
])
def test_delete_freshservice_ticket_task_command(
    client,
    requests_mock,
    url,
    args,
    response_entity,
):
    """
    Scenario: Delete ticket/ change/ problem/
        release by ID in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-delete called.

    Then:
     - Ensure readable_output is correct.
    """
    from FreshworksFreshservice import delete_freshservice_ticket_task_command

    requests_mock.delete(url, json='')

    results = delete_freshservice_ticket_task_command(client=client, args=args)

    assert results.readable_output == f'{response_entity} deleted successfully'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/tickets/1/conversations', {
        'command_name': 'freshservice-ticket-conversation-list',
        'ticket_id': 1,
    }),
    (f'{SERVER_URL}api/v2/tickets/1/conversations', {
        'page': 1,
        'page_size': 4,
        'ticket_id': 1,
        'command_name': 'freshservice-ticket-conversation-list',
    }),
])
def test_list_freshservice_ticket_conversation_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Returns a conversation list of ticket/ change/ problem/
        release in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-conversation-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
    """
    from FreshworksFreshservice import list_freshservice_ticket_conversation_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_conversation_list.json')

    requests_mock.get(url, json=mock_response_freshservice_entities_list)
    results = list_freshservice_ticket_conversation_command(client=client,
                                                            args=args)

    assert results.outputs.get('id') == 1
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/tickets/1/reply', {
        'command_name': 'freshservice-ticket-conversation-reply-create',
        "ticket_id": 1,
        "body": 'body',
        "bcc_emails": 'email',
    }),
    (f'{SERVER_URL}api/v2/tickets/1/reply', {
        'ticket_id': 1,
        "body": 'body',
        "attachments": 'attachments',
        'command_name': 'freshservice-ticket-conversation-reply-create',
    }),
])
@mock.patch('FreshworksFreshservice.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_create_freshservice_ticket_conversation_reply_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Create ticket conversation reply in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-conversation-reply-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import create_freshservice_ticket_conversation_reply_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_conversation_reply_create.json')

    requests_mock.post(url, json=mock_response_freshservice_entities_list)

    results = create_freshservice_ticket_conversation_reply_command(
        client=client, args=args)

    assert results.outputs.get('id') == 1
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/tickets/1/notes', {
        'command_name': 'freshservice-ticket-conversation-note-create',
        "ticket_id": 1,
        "body": 'body',
        "notify_emails": 'email',
        "private": 'true',
    }),
    (f'{SERVER_URL}api/v2/tickets/1/notes', {
        'ticket_id': 1,
        "body": 'body',
        "attachments": 'attachments',
        'command_name': 'freshservice-ticket-conversation-note-create',
    }),
])
@mock.patch('FreshworksFreshservice.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_create_freshservice_ticket_conversation_note_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Create ticket conversation note in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-conversation-note-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import create_freshservice_ticket_conversation_note_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_conversation_note_create.json')

    requests_mock.post(url, json=mock_response_freshservice_entities_list)

    results = create_freshservice_ticket_conversation_note_command(
        client=client, args=args)

    assert results.outputs.get('id') == 1
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/conversations/6', {
        'command_name': 'freshservice-ticket-conversation-update',
        "conversation_id": 6,
        "body": 'body',
        "name": 'name',
    }),
    (f'{SERVER_URL}api/v2/conversations/6', {
        'conversation_id': 6,
        "body": 'body',
        "attachments": 'attachments',
        'command_name': 'freshservice-ticket-conversation-update',
    }),
])
@mock.patch('FreshworksFreshservice.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_update_freshservice_ticket_conversation_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Update ticket conversation in a Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-conversation-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import update_freshservice_ticket_conversation_command
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_conversation_update.json')

    requests_mock.put(url, json=mock_response_freshservice_entities_list)

    results = update_freshservice_ticket_conversation_command(client=client,
                                                              args=args)

    assert results.outputs.get('id') == 1
    assert results.outputs.get('Conversation').get('id') == 6
    assert results.outputs_prefix == 'Freshservice.Ticket'
    assert results.outputs_key_field == 'id'


@pytest.mark.parametrize('url, args', [
    (f'{SERVER_URL}api/v2/conversations/6', {
        'command_name': 'freshservice-ticket-conversation-delete',
        "conversation_id": 6,
    }),
])
def test_delete_freshservice_ticket_conversation_command(
    client,
    requests_mock,
    url,
    args,
):
    """
    Scenario: Delete ticket conversation from Freshservice account.
    Given:
     - User has provided valid credentials.
    When:
     - freshservice-ticket-conversation-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key field is correct.
     - Ensure outputs is correct.
     - Ensure raw response is correct.
     - Ensure a entity value from the API matches what is generated in the context.
    """
    from FreshworksFreshservice import delete_freshservice_ticket_conversation_command

    requests_mock.delete(url, json='')

    results = delete_freshservice_ticket_conversation_command(client=client,
                                                              args=args)
    assert results.readable_output == 'Conversation deleted successfully'


''' helper function test '''


@pytest.mark.parametrize('args, outputs', [
    ({
        'page': 1,
        'page_size': 2,
        'limit': 50,
    }, {
        'page': 1,
        'page_size': 2,
    }),
    ({
        'limit': 20,
    }, {
        'page': 1,
        'page_size': 20,
    }),
    ({
        'limit': 50,
    }, {
        'page': 1,
        'page_size': 50,
    }),
])
def test_pagination(args, outputs):
    """
    Scenario: Validate pagination arguments.

    Given:
     - Command pagination arguments.
    When:
     - Generic list commands are called.
    Then:
     - Ensure pagination arguments values are correct.
    """

    from FreshworksFreshservice import pagination
    new_page, new_page_size, _ = pagination(args)
    assert new_page == outputs['page']
    assert new_page_size == outputs['page_size']


@pytest.mark.parametrize('args, entity_name, outputs', [
    ({
        'first_name': 'Alice',
        'job_title': 'Developer',
    }, 'ticket', '"first_name:\'Alice\' AND job_title:\'Developer\'"'),
    ({
        'query': 'first_name:\'Alice\' OR first_name:\'Bob\'',
    }, 'ticket', '"first_name:\'Alice\' OR first_name:\'Bob\'"'),
])
def test_build_query(args, entity_name, outputs):
    """
    Scenario: Create a query for Freshservice according their template.

    Given:
     - Command arguments.
    When:
     - Generic list commands are called.
    Then:
     - Ensure query arguments values are correct.
    """

    from FreshworksFreshservice import build_query
    updated_query = build_query(args, entity_name)
    assert updated_query == outputs


@pytest.mark.parametrize(
    'args, command_response_key, command_arg_id, output', [
        ({
            'first_name': 'Alice',
        }, 'ticket', 1, {
            'page': None,
            'page_size': None,
            'updated_query': None,
            'command_response_key': 'ticket'
        }),
        ({
            'first_name': 'Alice',
            'job_title': 'Developer',
            'limit': 50,
        }, 'ticket', None, {
            'page': 1,
            'page_size': 50,
            'updated_query':
            '"first_name:\'Alice\' AND job_title:\'Developer\'"',
            'command_response_key': 'tickets'
        }),
        ({
            'first_name': 'Bob',
            'limit': 50,
        }, 'software', None, {
            'page': 1,
            'page_size': 50,
            'updated_query': '"first_name:\'Bob\'"',
            'command_response_key': 'applications'
        }),
    ])
def test_get_command_list_args(args, command_response_key, command_arg_id,
                               output):
    """
    Scenario: Get command arguments according to the
        command mode: list or get.

    Given:
     - Command arguments.
    When:
     - Generic list commands are called.
    Then:
     - Ensure arguments values are correct.
    """

    from FreshworksFreshservice import get_command_list_args
    command_args = get_command_list_args(args, command_response_key,
                                         command_arg_id)
    assert command_args.page == output['page']
    assert command_args.page_size == output['page_size']
    assert command_args.updated_query == output['updated_query']
    assert command_args.command_response_key == output['command_response_key']


@pytest.mark.parametrize('command_entity, command_request', [
    ('problem_task_update', 'freshservice_problem_task_update'),
    ('vendor', 'freshservice_vendor_list'),
    ('ticket_create', 'freshservice_ticket_create'),
    ('change_task_delete', 'freshservice_change_task_delete'),
    ('release_task', 'freshservice_release_task_list'),
])
def test_get_command_request(client, command_entity, command_request):
    """
    Scenario: Get command request by entity name.

    Given:
     - command request function name.
    When:
     - Generic commands functions are called.
    Then:
     - Ensure command request function name is correct.
    """

    from FreshworksFreshservice import get_command_request
    command_request_function = get_command_request(client, command_entity)
    assert command_request_function.__name__ == command_request


@pytest.mark.parametrize('args, ticket_type, output', [
    ({
        'status': 'Open',
        'priority': 'Low',
    }, 'ticket', {
        'status': 2,
        'priority': 1,
    }),
    ({
        'status': 'Open',
        'priority': 'Low',
    }, 'problem', {
        'status': 1,
        'priority': 1,
    }),
    ({
        'status': 'Open',
        'priority': 'Low',
        'risk': 'Low',
        'change_type': 'Minor',
    }, 'change', {
        'status': 1,
        'priority': 1,
        'change_type': 1,
        'risk': 1,
    }),
    ({
        'status': 'Open',
        'priority': 'Low',
        'release_type': 'Minor',
    }, 'release', {
        'status': 1,
        'priority': 1,
        'release_type': 1,
    }),
])
def test_convert_command_properties(args, ticket_type, output):
    """
    Scenario: Convert command properties from
        string to number for the Freshservice request.

    Given:
     - command arguments & entity type.
    When:
     - Fields type in string.
    Then:
     - Ensure fields values are correct.
    """

    from FreshworksFreshservice import convert_command_properties
    urgency, status, source, priority, impact, risk, change_type, release_type = convert_command_properties(
        args, ticket_type)
    assert status == output.get('status')
    assert urgency == output.get('urgency')
    assert source == output.get('source')
    assert priority == output.get('priority')
    assert impact == output.get('impact')
    assert risk == output.get('risk')
    assert change_type == output.get('change_type')
    assert release_type == output.get('release_type')


@mock.patch('FreshworksFreshservice.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_get_file():
    """
    Scenario: Open file to send data to API.

    Given:
     - File ID in XSOAR.
    When:
     - Command that has attachments is called.
    Then:
     - Ensure attachment and file name values are correct.
    """

    from FreshworksFreshservice import get_file
    file = get_file('file_id')
    attachments, file_data = file
    file_name, file_content, file_type = file_data
    assert attachments == 'attachments[]'
    assert file_name == FILE_ENTRY['name']


@pytest.mark.parametrize('seconds,  output', [
    (400, 0),
    (750, 900),
    (1800, 1800),
    (2000, 1800),
    (10000, 7200),
])
def test_get_default_seconds(seconds, output):
    """
    Scenario: Get the closest Freshservice predefined seconds to the specified seconds.

    Given:
     - Seconds argument.
    When:
     - freshservice-ticket-task-create called.
     - freshservice-ticket-task-update called.
     - freshservice-problem-task-create called.
     - freshservice-problem-task-update called.
     - freshservice-change-task-create called.
     - freshservice-change-task-update called.
     - freshservice-release-task-create called.
     - freshservice-release-task-update called.
    Then:
     - Ensure updated seconds value is correct.
    """

    from FreshworksFreshservice import get_default_seconds
    default_time_in_seconds = get_default_seconds(seconds)

    assert default_time_in_seconds == output


@pytest.mark.parametrize('args,  output', [
    (
        {
            'command_name': 'freshservice-vendor-list',
        },
        {
            'entity_id_value': None,
            'entity_name': 'vendor',
            'output_prefix': 'Vendor',
            'command_operator': 'list',
        },
    ),
    (
        {
            'command_name': 'freshservice-problem-task-create',
        },
        {
            'entity_id_value': None,
            'entity_name': 'problem',
            'output_prefix': 'Problem',
            'command_operator': 'create',
        },
    ),
    (
        {
            'command_name': 'freshservice-change-update',
            'change_id': 2,
        },
        {
            'entity_id_value': 2,
            'entity_name': 'change',
            'output_prefix': 'Change',
            'command_operator': 'update',
        },
    ),
])
def test_get_args_by_command_name(args, output):
    """
    Scenario: Return the default command args by the command name.

    Given:
     - Command arguments.
    When:
     - commands are called.
    Then:
     - Ensure argument values are correct.
    """

    from FreshworksFreshservice import get_args_by_command_name
    entity_id_value, entity_name, output_prefix, command_operator = get_args_by_command_name(
        args)

    assert entity_id_value == output.get('entity_id_value')
    assert entity_name == output.get('entity_name')
    assert output_prefix == output.get('output_prefix')
    assert command_operator == output.get('command_operator')


def test_reverse_dict():
    """
    Scenario: Reverse dictionary.

    Given:
     - Some dictionary.
    When:
     - Response include fields type in numbers.
    Then:
     - Ensure value string is correct.
    """

    from FreshworksFreshservice import reverse_dict
    reversed_dict = reverse_dict({
        'a': 1,
        'b': 2,
        'c': 3,
    })

    assert reversed_dict == {
        1: 'a',
        2: 'b',
        3: 'c',
    }


def test_convert_response_properties():
    """
    Scenario: Convert command properties from number to string for
        the XSOAR output.
    Given:
     - Response from Freshservice.
    When:
     - Response include fields type in numbers.
    Then:
     - Ensure value string is correct.
    """

    from FreshworksFreshservice import convert_response_properties, TICKET_PROPERTIES_BY_TYPE
    updated_response = util_load_json('freshservice_ticket_get.json')
    converted_response = convert_response_properties(
        updated_response,
        TICKET_PROPERTIES_BY_TYPE.get('ticket'),
    )

    assert converted_response[0]['ticket'].get(
        'status') == updated_response['ticket'].get('status')
    assert converted_response[0]['ticket'].get(
        'priority') == updated_response['ticket'].get('priority')
    assert converted_response[0]['ticket'].get(
        'source') == updated_response['ticket'].get('source')


def test_get_request_arguments_per_ticket_type():
    """
    Scenario: Get the arguments for each ticket type.
    Given:
     -XSOAR arguments.
    When:
     - freshservice-ticket-task-create called.
     - freshservice-ticket-task-update called.
     - freshservice-problem-task-create called.
     - freshservice-problem-task-update called.
     - freshservice-change-task-create called.
     - freshservice-change-task-update called.
     - freshservice-release-task-create called.
     - freshservice-release-task-update called.
    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import get_request_arguments_per_ticket_type, TICKET_PROPERTIES_BY_TYPE

    response = get_request_arguments_per_ticket_type('ticket', {
        'status': 'Open',
        'priority': 'Low',
        'source': 'Email'
    }, 11)

    assert response.get(
        'status') == TICKET_PROPERTIES_BY_TYPE['ticket']['status']['Open']
    assert response.get(
        'priority') == TICKET_PROPERTIES_BY_TYPE['ticket']['priority']['Low']
    assert response.get(
        'source') == TICKET_PROPERTIES_BY_TYPE['ticket']['source']['Email']


def test_get_arg_template():
    """
    Scenario: Get the arguments template.
    Given:
     -XSOAR arguments.
    When:
     - freshservice-ticket-create called.
     - freshservice-ticket-update called.
     - freshservice-problem-create called.
     - freshservice-problem-update called.
     - freshservice-change-create called.
     - freshservice-change-update called.
     - freshservice-release-create called.
     - freshservice-release-update called.
    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import get_arg_template

    response = get_arg_template({5}, 'assets')

    assert response == [{'display_id': 5}]


@pytest.mark.parametrize(
    'custom_fields_arg, expected_output',
    [
        (
            "key=value",
            {'key': 'value'},
        ),
        (
            "building_location=Student Center, suiteroom_location=140",
            {"building_location": "Student Center", "suiteroom_location": "140"},
        ),
    ],
)
def test_update_custom_fields(custom_fields_arg: str, expected_output: dict):
    """
    Scenario: Update custom_fields arguments according to template.
    Given:
     -XSOAR arguments.
    When:
     - freshservice-ticket-create called.
     - freshservice-ticket-update called.
     - freshservice-problem-create called.
     - freshservice-problem-update called.
     - freshservice-change-create called.
     - freshservice-change-update called.
     - freshservice-release-create called.
     - freshservice-release-update called.
    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import update_custom_fields

    response = update_custom_fields({'custom_fields': custom_fields_arg})

    assert response == expected_output


def test_validate_mandatory_ticket_requester_fields():
    """
    Scenario: Validate mandatory requester fields.
    Given:
     -XSOAR arguments.
    When:
     - freshservice-ticket-create called.
     - freshservice-ticket-update called.
     - freshservice-problem-create called.
     - freshservice-problem-update called.
     - freshservice-change-create called.
     - freshservice-change-update called.
     - freshservice-release-create called.
     - freshservice-release-update called.
    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import validate_mandatory_ticket_requester_fields
    with pytest.raises(ValueError) as error_info:
        validate_mandatory_ticket_requester_fields('ticket', {
            'a': 1,
            'b': 2,
            'c': 3,
        })
        assert str(
            error_info.value) == 'One of the following is mandatory: requester_id, phone, email'


def test_fetch_incidents(client, requests_mock):
    """
    Scenario: Fetch incidents.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import fetch_incidents

    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_ticket_list.json')
    requests_mock.get(
        f'{SERVER_URL}api/v2/tickets?updated_since=2023-01-01T00%3A00%3A00Z&order_type=asc',
        json=mock_response_freshservice_entities_list)
    mock_response_freshservice_entities_list = util_load_json(
        'freshservice_problem_list.json')
    requests_mock.get(
        f'{SERVER_URL}api/v2/problems?updated_since=2023-01-01T00%3A00%3A00Z&order_type=asc',
        json=mock_response_freshservice_entities_list)

    fetch_incidents(
        client, {
            'max_fetch': 10,
            'fetch_ticket_task': 'false',
            'first_fetch': '2023-01-01',
            'mirror_direction': 'Incoming',
            'ticket_type': ['Incident/Service Request', 'Problem Request'],
            'ticket_status': 'Open',
            'ticket_priority': 'Low',
            'ticket_impact': 'Low'
        })

    assert demisto.getLastRun() == {'lastRun': '2018-10-24T14:13:20+00:00'}


def test_parse_incident():
    """
    Scenario: parse incident to XSOAR.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure value is correct.
    """

    from FreshworksFreshservice import parse_incident
    mock_response = util_load_json('freshservice_ticket_get.json')
    alert = mock_response['ticket']
    response = parse_incident(alert, 'ticket', 'Incoming')

    assert response['name'] == 'ticket ID: 1'


def test_get_alert_properties():
    """
    Scenario: Get the arguments for each ticket type.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure value is correct.
    """
    from FreshworksFreshservice import get_alert_properties
    response = get_alert_properties({
        'ticket_type': ['Incident/Service Request', 'Problem Request'],
        'ticket_status':
        'Open',
        'ticket_priority': ['Low', 'High'],
        'ticket_impact': ['Low', 'Medium']
    })

    assert response == (['Incident/Service Request',
                         'Problem Request'], [('impact', ['Low', 'Medium']),
                                              ('status', ['Open']),
                                              ('risk', []), ('urgency', []),
                                              ('priority', ['Low', 'High'])])


def test_convert_datetime_to_iso():
    """
    Scenario: Convert datetime to ISO.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure value is correct.
    """
    from FreshworksFreshservice import convert_datetime_to_iso
    response = convert_datetime_to_iso('2023-01-04T14:22:43Z')
    assert response == '2023-01-04T14:22:43Z'

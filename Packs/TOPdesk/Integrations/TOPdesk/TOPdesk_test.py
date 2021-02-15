import pytest
import json
import io
from TOPdesk import Client, INTEGRATION_NAME, \
    fetch_incidents, entry_types_command, call_types_command, categories_command, subcategories_command, \
    list_persons_command, list_operators_command, branches_command, get_incidents_list_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('command, command_api_url, mock_response, expected_results', [
    (entry_types_command,
     'https://test.com/api/v1/incidents/entry_types',
     [{"id": "1st-id", "name": "entry-type-1"}, {"id": "2st-id", "name": "entry-type-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.entryType',
         'outputs_key_field': 'id'
     }),
    (call_types_command,
     'https://test.com/api/v1/incidents/call_types',
     [{"id": "1st-id", "name": "call-type-1"}, {"id": "2st-id", "name": "call-type-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.callType',
         'outputs_key_field': 'id'
     }),
    (categories_command,
     'https://test.com/api/v1/incidents/categories',
     [{"id": "1st-id", "name": "category-1"}, {"id": "2st-id", "name": "category-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.category',
         'outputs_key_field': 'id'
     }),
    (subcategories_command,
     'https://test.com/api/v1/incidents/subcategories',
     [{"id": "1st-id-sub", "name": "subcategory-1", "category": {"id": "1st-id", "name": "category-1"}},
      {"id": "2st-id-sub", "name": "subcategory-2", "category": {"id": "2st-id", "name": "category-2"}}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.subcategories',
         'outputs_key_field': 'id'
     }),
])
def test_list_command(requests_mock, command, command_api_url, mock_response, expected_results):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    requests_mock.get(
        command_api_url, json=mock_response)
    command_results = command(client)
    assert command_results.outputs_prefix == expected_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_results['outputs_key_field']
    assert command_results.outputs == mock_response


@pytest.mark.parametrize('command, command_api_url, mock_response_file, override_nodes, expected_results', [
    (list_persons_command,
     'https://test.com/api/v1/persons',
     'test_data/topdesk_person.json',
     [{'id': '1st-person-id'}, {'id': '2nd-person-id'}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.person',
         'outputs_key_field': 'id'
     }),
    (list_operators_command,
     'https://test.com/api/v1/operators',
     'test_data/topdesk_operator.json',
     [{'id': '1st-operator-id'}, {'id': '2nd-operator-id'}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.operator',
         'outputs_key_field': 'id'
     }),
    (branches_command,
     'https://test.com/api/v1/branches',
     'test_data/topdesk_branch.json',
     [{"id": "1st-branch-id"}, {"id": "2nd-branch-id"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.branch',
         'outputs_key_field': 'id'
     }),
    (get_incidents_list_command,
     'https://test.com/api/v1/incidents',
     'test_data/topdesk_incident.json',
     [{"id": "1st-incident-id"}, {"id": "2nd-incident-id"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.incident',
         'outputs_key_field': 'id'
     })
])
def test_large_output_list_command(requests_mock,
                                   command,
                                   command_api_url,
                                   mock_response_file,
                                   override_nodes,
                                   expected_results):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    mock_topdesk_node = util_load_json(mock_response_file)
    mock_topdesk_response = []
    for node_override in override_nodes:
        response_node = mock_topdesk_node.copy()
        response_node['id'] = node_override['id']
        mock_topdesk_response.append(response_node)

    requests_mock.get(
        command_api_url, json=mock_topdesk_response)
    command_results = command(client, {})
    assert command_results.outputs_prefix == expected_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_results['outputs_key_field']
    assert command_results.outputs == mock_topdesk_response


@pytest.mark.parametrize('command, command_args, command_api_request', [
    (branches_command,
     {'page_size': 2},
     ('https://test.com/api/v1/branches?page_size=2', {})),
    (branches_command,
     {'start': 2},
     ('https://test.com/api/v1/branches?start=2', {})),
    (branches_command,
     {'query': 'id==1st-branch-id'},
     ('https://test.com/api/v1/branches?query=id==1st-branch-id', {})),
    (branches_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-branch-id'},
     ('https://test.com/api/v1/branches?start=2&page_size=2&query=id==1st-branch-id', {})),
    (branches_command,
     {'page_size': 2, 'query': 'id==1st-branch-id'},
     ('https://test.com/api/v1/branches?page_size=2&query=id==1st-branch-id', {})),
    (list_operators_command,
     {'page_size': 2},
     ('https://test.com/api/v1/operators?page_size=2', {})),
    (list_operators_command,
     {'start': 2},
     ('https://test.com/api/v1/operators?start=2', {})),
    (list_operators_command,
     {'query': 'id==1st-operator-id'},
     ('https://test.com/api/v1/operators?query=id==1st-operator-id', {})),
    (list_operators_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-operator-id'},
     ('https://test.com/api/v1/operators?start=2&page_size=2&query=id==1st-operator-id', {})),
    (list_operators_command,
     {'page_size': 2, 'query': 'id==1st-operator-id'},
     ('https://test.com/api/v1/operators?page_size=2&query=id==1st-operator-id', {})),
    (list_persons_command,
     {'page_size': 2},
     ('https://test.com/api/v1/persons?page_size=2', {})),
    (list_persons_command,
     {'start': 2},
     ('https://test.com/api/v1/persons?start=2', {})),
    (list_persons_command,
     {'query': 'id==1st-person-id'},
     ('https://test.com/api/v1/persons?query=id==1st-person-id', {})),
    (list_persons_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-person-id'},
     ('https://test.com/api/v1/persons?start=2&page_size=2&query=id==1st-person-id', {})),
    (list_persons_command,
     {'page_size': 2, 'query': 'id==1st-person-id'},
     ('https://test.com/api/v1/persons?page_size=2&query=id==1st-person-id', {})),
    (get_incidents_list_command,
     {'page_size': 2},
     ('https://test.com/api/v1/incidents?page_size=2', {})),
    (get_incidents_list_command,
     {'start': 2},
     ('https://test.com/api/v1/incidents?start=2', {})),
    (get_incidents_list_command,
     {'query': 'id==1st-incident-id'},
     ('https://test.com/api/v1/incidents?query=id==1st-incident-id', {})),
    (get_incidents_list_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-incident-id'},
     ('https://test.com/api/v1/incidents?start=2&page_size=2&query=id==1st-incident-id', {})),
    (get_incidents_list_command,
     {'page_size': 2, 'query': 'id==1st-incident-id'},
     ('https://test.com/api/v1/incidents?page_size=2&query=id==1st-incident-id', {})),
])
def test_list_command_with_args(requests_mock,
                                command,
                                command_args,
                                command_api_request):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    requests_mock.get(
        command_api_request[0], json=[{}])
    command(client, command_args)

    assert requests_mock.called
    assert requests_mock.last_request.json() == command_api_request[1]


# TODO: add test for pagination for fetch_incidents
# TODO: add tests for incident_do commands
# TODO: add tests for attachment upload command


@pytest.mark.parametrize('topdesk_incidents_override, last_fetch_time, updated_fetch_time', [
    ([{
        'number': 'TEST-1',
        'creationDate': '2020-02-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-01-11T06:32:36.303+0000',
        '2020-02-10T06:32:36Z'),  # Last fetch is before incident creation
    ([{
        'number': 'TEST-1',
        'creationDate': '2020-01-10T06:32:36Z',
        'will_be_fetched': False
    }, {
        'number': 'TEST-2',
        'creationDate': '2020-03-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-02-11T06:32:36.303+0000',
        '2020-03-10T06:32:36Z'),  # Last fetch is after one incident creation and before other.
    ([{
        'number': 'TEST-1',
        'creationDate': '2020-02-10T06:32:36.303+0000',
        'will_be_fetched': False
    }], '2020-02-10T06:32:36Z',
        '2020-02-10T06:32:36Z'),  # Last fetch is at incident creation
])
def test_fetch_incidents(requests_mock, topdesk_incidents_override, last_fetch_time, updated_fetch_time):
    """
    """

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    mock_topdesk_incident = util_load_json('test_data/topdesk_incident.json')
    mock_topdesk_response = []
    expected_incidents = []
    for incident_override in topdesk_incidents_override:
        response_incident = mock_topdesk_incident.copy()
        response_incident['number'] = incident_override['number']
        response_incident['creationDate'] = incident_override['creationDate']
        mock_topdesk_response.append(response_incident)
        if incident_override['will_be_fetched']:
            expected_incidents.append({
                'name': f"TOPdesk incident {incident_override['number']}",
                'details': json.dumps(response_incident),
                'occurred': incident_override['creationDate'],
                'rawJSON': json.dumps(response_incident),
            })

    requests_mock.get(
        'https://test.com/api/v1/incidents', json=mock_topdesk_response)

    last_run = {
        'last_fetch': last_fetch_time
    }
    last_fetch, incidents = fetch_incidents(client=client,
                                            last_run=last_run,
                                            demisto_params={})

    assert len(incidents) == len(expected_incidents)
    for incident, expected_incident in zip(incidents, expected_incidents):
        assert incident['name'] == expected_incident['name']
        assert incident['details'] == expected_incident['details']
        assert incident['occurred'] == expected_incident['occurred']
        assert incident['rawJSON'] == expected_incident['rawJSON']
    assert last_fetch == {'last_fetch': updated_fetch_time}

import pytest
import json
import io
from TOPdesk import Client, INTEGRATION_NAME, MAX_API_PAGE_SIZE, XSOAR_ENTRY_TYPE, \
    fetch_incidents, entry_types_command, call_types_command, categories_command, subcategories_command, \
    list_persons_command, list_operators_command, branches_command, get_incidents_list_command, \
    get_incidents_with_pagination, incident_do_command, incident_touch_command


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


@pytest.mark.parametrize('action, command_args, command_api_url, mock_response_file, override_node', [
    ("escalate",
     {"id": "incident_id", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/escalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("deescalate",
     {"id": "incident_id", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/deescalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("archive",
     {"id": "incident_id", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/archive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("unarchive",
     {"id": "incident_id"},
     'https://test.com/api/v1/incidents/id/incident_id/unarchive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("escalate",
     {"number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/number/incident_number/escalate',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("deescalate",
     {"number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/number/incident_number/deescalate',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("archive",
     {"number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/number/incident_number/archive',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("unarchive",
     {"number": "incident_number"},
     'https://test.com/api/v1/incidents/number/incident_number/unarchive',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("escalate",
     {"id": "incident_id", "number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/escalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("deescalate",
     {"id": "incident_id", "number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/deescalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("archive",
     {"id": "incident_id", "number": "incident_number", "reason_id": "some_reason"},
     'https://test.com/api/v1/incidents/id/incident_id/archive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("unarchive",
     {"id": "incident_id", "number": "incident_number"},
     'https://test.com/api/v1/incidents/id/incident_id/unarchive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'})
])
def test_incident_do_commands(requests_mock,
                              action,
                              command_args,
                              command_api_url,
                              mock_response_file,
                              override_node):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    mock_topdesk_node = util_load_json(mock_response_file)
    response_incident = mock_topdesk_node.copy()
    if override_node.get('id', None):
        response_incident['id'] = override_node['id']
    elif override_node.get('number', None):
        response_incident['number'] = override_node['number']

    requests_mock.put(
        command_api_url, json=response_incident)

    command_results = incident_do_command(client=client,
                                          args=command_args,
                                          action=action)
    assert requests_mock.called
    if command_args.get("reason_id", None):
        assert requests_mock.last_request.json() == {'id': command_args.get("reason_id", None)}
    else:
        assert requests_mock.last_request.json() == {}

    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.incident'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs == [response_incident]


@pytest.mark.parametrize('create_func, command_args, command_api_url, caller_lookup, mock_response_file,'
                         ' expected_last_request_body, expected_call_count', [
                             (True,
                              {"caller": "some_caller"},
                              'https://test.com/api/v1/incidents/',
                              True,
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'}, 'entryType': {'name': XSOAR_ENTRY_TYPE}},
                              1),
                             (True,
                              {"caller": "some_caller"},
                              'https://test.com/api/v1/incidents/',
                              False,
                              'test_data/topdesk_incident.json',
                              {'caller': {'dynamicName': 'some_caller'}, 'entryType': {'name': XSOAR_ENTRY_TYPE}},
                              2),
                             (False,
                              {"caller": "some_caller", "id": "incident_id"},
                              'https://test.com/api/v1/incidents/id/incident_id',
                              True,
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'}, 'entryType': {'name': XSOAR_ENTRY_TYPE}},
                              1),
                             (False,
                              {"caller": "some_caller", "id": "incident_id"},
                              'https://test.com/api/v1/incidents/id/incident_id',
                              False,
                              'test_data/topdesk_incident.json',
                              {'caller': {'dynamicName': 'some_caller'}, 'entryType': {'name': XSOAR_ENTRY_TYPE}},
                              1)
                         ])
def test_incident_touch_commands(requests_mock,
                                 create_func,
                                 command_args,
                                 command_api_url,
                                 caller_lookup,
                                 mock_response_file,
                                 expected_last_request_body,
                                 expected_call_count):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    client_func = client.update_incident
    request_method = "put"
    action = "updating"
    if create_func:
        client_func = client.create_incident
        request_method = "post"
        action = "creating"
    mock_topdesk_node = util_load_json(mock_response_file)
    response_incident = mock_topdesk_node.copy()
    request_command = getattr(requests_mock, request_method)

    request_command(command_api_url, json=response_incident)  # Fix multiple returns

    command_results = incident_touch_command(client=client,
                                             args=command_args,
                                             client_func=client_func,
                                             action=action)
    assert requests_mock.call_count == expected_call_count
    assert requests_mock.last_request.json() == expected_last_request_body
    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.incident'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs == [response_incident]


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


@pytest.mark.parametrize('command_args, command_api_request, call_count', [
    ({'max_fetch': 2,
      'modification_date_start': '2020-02-10T06:32:36Z',
      'modification_date_end': '2020-03-10T06:32:36Z',
      'query': 'id==1st-incident-id'},
     [('https://test.com/api/v1/incidents?page_size=2&query=id==1st-incident-id',
       {'modification_date_start': '2020-02-10T06:32:36Z',
        'modification_date_end': '2020-03-10T06:32:36Z'})], 1),
    ({'max_fetch': 2 * MAX_API_PAGE_SIZE,
      'modification_date_start': '2020-02-10T06:32:36Z',
      'modification_date_end': '2020-03-10T06:32:36Z',
      'query': 'id==1st-incident-id'},
     [(f'https://test.com/api/v1/incidents?page_size={MAX_API_PAGE_SIZE}&query=id==1st-incident-id',
       {'modification_date_start': '2020-02-10T06:32:36Z',
        'modification_date_end': '2020-03-10T06:32:36Z'}),
      (f'https://test.com/api/v1/incidents'
       f'?start={MAX_API_PAGE_SIZE}&page_size={MAX_API_PAGE_SIZE}&query=id==1st-incident-id',
       {'modification_date_start': '2020-02-10T06:32:36Z',
        'modification_date_end': '2020-03-10T06:32:36Z'})], 2)
])
def test_get_incidents_with_pagination(requests_mock,
                                       command_args,
                                       command_api_request,
                                       call_count):
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Basic some_encoded_credentials'
        }
    )
    for request in command_api_request:
        requests_mock.get(
            request[0], json=[{}])
    get_incidents_with_pagination(client=client,
                                  max_fetch=command_args.get('max_fetch', None),
                                  query=command_args.get('query', None),
                                  modification_date_start=command_args.get('modification_date_start', None),
                                  modification_date_end=command_args.get('modification_date_end', None))

    for called_request, mocked_request in zip(requests_mock._adapter.request_history, command_api_request):
        assert called_request._request.url == mocked_request[0]
        assert called_request.json() == mocked_request[1]
    assert requests_mock.call_count == call_count


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

import pytest
import demistomock as demisto
import json
from TOPdesk import Client, INTEGRATION_NAME, MAX_API_PAGE_SIZE, \
    fetch_incidents, entry_types_command, call_types_command, categories_command, subcategories_command, \
    list_persons_command, list_operators_command, branches_command, get_incidents_list_command, \
    get_incidents_with_pagination, incident_do_command, incident_touch_command, attachment_upload_command, \
    escalation_reasons_command, deescalation_reasons_command, archiving_reasons_command, capitalize_for_outputs, \
    list_attachments_command, list_actions_command, get_mapping_fields_command, get_remote_data_command, \
    get_modified_remote_data_command, update_remote_system_command


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client(requests_mock):
    """Client fixture for tests using the default client settings."""
    requests_mock.get(
        'https://test.com/api/version', json={"version": "3.1.4"})
    return Client(
        base_url='https://test.com/api/',
        verify=False,
        auth=('some_username', 'some_password')
    )


@pytest.mark.parametrize('outputs, expected_capitalized_output', [
    ([{"hiThere": "hi"}], [{"HiThere": "hi"}]),
    ([{"hi": "hi"}], [{"Hi": "hi"}]),
    ([{"hiThere": {"wellHello": "hi"}}], [{"HiThere": {"WellHello": "hi"}}]),
    ([{"hiThere": {"wellHello": {"hiyaThere": "hi"}}}], [{"HiThere": {"WellHello": {"HiyaThere": "hi"}}}]),
])
def test_capitalize_outputs(outputs, expected_capitalized_output):
    """Unit test
    Given
        - output of API command
    When
        - returning output to XSOAR
    Then
        - validate the output is capitalized.
    """
    assert capitalize_for_outputs(outputs) == expected_capitalized_output


@pytest.mark.parametrize('command, command_api_url, mock_response, expected_results', [
    (entry_types_command,
     'https://test.com/api/incidents/entry_types',
     [{"id": "1st-id", "name": "entry-type-1"}, {"id": "2st-id", "name": "entry-type-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.EntryType',
         'outputs_key_field': 'Id'
     }),
    (call_types_command,
     'https://test.com/api/incidents/call_types',
     [{"id": "1st-id", "name": "call-type-1"}, {"id": "2st-id", "name": "call-type-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.CallType',
         'outputs_key_field': 'Id'
     }),
    (categories_command,
     'https://test.com/api/incidents/categories',
     [{"id": "1st-id", "name": "category-1"}, {"id": "2st-id", "name": "category-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Category',
         'outputs_key_field': 'Id'
     }),
    (subcategories_command,
     'https://test.com/api/incidents/subcategories',
     [{"id": "1st-id-sub", "name": "subcategory-1", "category": {"id": "1st-id", "name": "category-1"}},
      {"id": "2st-id-sub", "name": "subcategory-2", "category": {"id": "2st-id", "name": "category-2"}}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Subcategory',
         'outputs_key_field': 'Id'
     }),
    (escalation_reasons_command,
     'https://test.com/api/incidents/escalation-reasons',
     [{"id": "1st-id", "name": "escalation-name-1"}, {"id": "2st-id", "name": "escalation-name-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.EscalationReason',
         'outputs_key_field': 'Id'
     }),
    (deescalation_reasons_command,
     'https://test.com/api/incidents/deescalation-reasons',
     [{"id": "1st-id", "name": "deescalation-name-1"}, {"id": "2st-id", "name": "deescalation-name-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.DeescalationReason',
         'outputs_key_field': 'Id'
     }),
    (archiving_reasons_command,
     'https://test.com/api/archiving-reasons',
     [{"id": "1st-id", "name": "archiving-reason-1"}, {"id": "2st-id", "name": "archiving-reason-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.ArchiveReason',
         'outputs_key_field': 'Id'
     }),
])
def test_list_command(client, requests_mock, command, command_api_url, mock_response, expected_results):
    """Unit test
    Given
        - A command that returns a list
    When
        - running the command
    Then
        - validate the entry context
    """
    requests_mock.get(
        command_api_url, json=mock_response)
    command_results = command(client, {})
    assert command_results.outputs_prefix == expected_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_results['outputs_key_field']
    assert command_results.outputs == capitalize_for_outputs(mock_response)


@pytest.mark.parametrize('command, args, command_api_url, mock_response, expected_results', [
    (entry_types_command, {'limit': '1'},
     'https://test.com/api/incidents/entry_types',
     [{"id": "1st-id", "name": "entry-type-1"}, {"id": "2st-id", "name": "entry-type-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.EntryType',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "entry-type-1"}]}),
    (call_types_command, {'limit': '2'},
     'https://test.com/api/incidents/call_types',
     [{"id": "1st-id", "name": "call-type-1"}, {"id": "2st-id", "name": "call-type-2"},
      {"id": "3rd-id", "name": "call-type-3"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.CallType',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "call-type-1"}, {"id": "2st-id", "name": "call-type-2"}]}),
    (categories_command, {'limit': '-1'},
     'https://test.com/api/incidents/categories',
     [{"id": "1st-id", "name": "category-1"}, {"id": "2st-id", "name": "category-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Category',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "category-1"}, {"id": "2st-id", "name": "category-2"}]}),
    (subcategories_command, {'limit': '1'},
     'https://test.com/api/incidents/subcategories',
     [{"id": "1st-id-sub", "name": "subcategory-1", "category": {"id": "1st-id", "name": "category-1"}},
      {"id": "2st-id-sub", "name": "subcategory-2", "category": {"id": "2st-id", "name": "category-2"}}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Subcategory',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id-sub", "name": "subcategory-1",
                      "category": {"id": "1st-id", "name": "category-1"}}]}),
    (escalation_reasons_command, {'limit': '2'},
     'https://test.com/api/incidents/escalation-reasons',
     [{"id": "1st-id", "name": "escalation-name-1"}, {"id": "2st-id", "name": "escalation-name-2"},
      {"id": "3rd", "name": "escalation-name-3"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.EscalationReason',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "escalation-name-1"}, {"id": "2st-id", "name": "escalation-name-2"}]}),
    (deescalation_reasons_command, {'limit': '-1'},
     'https://test.com/api/incidents/deescalation-reasons',
     [{"id": "1st-id", "name": "deescalation-name-1"}, {"id": "2st-id", "name": "deescalation-name-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.DeescalationReason',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "deescalation-name-1"},
                     {"id": "2st-id", "name": "deescalation-name-2"}]}),
    (archiving_reasons_command, {'limit': '1'},
     'https://test.com/api/archiving-reasons',
     [{"id": "1st-id", "name": "archiving-reason-1"}, {"id": "2st-id", "name": "archiving-reason-2"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.ArchiveReason',
         'outputs_key_field': 'Id',
         'outputs': [{"id": "1st-id", "name": "archiving-reason-1"}]})
])
def test_list_command_with_limit_arg(client, requests_mock, command, args, command_api_url, mock_response,
                                     expected_results):
    """Unit test
    Given
        - A command that returns a list
    When
        - running the command
    Then
        - validate the entry context
    """
    requests_mock.get(
        command_api_url, json=mock_response)
    command_results = command(client, args)
    assert command_results.outputs_prefix == expected_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_results['outputs_key_field']
    assert command_results.outputs == capitalize_for_outputs(expected_results['outputs'])


@pytest.mark.parametrize('command, command_api_url, mock_response_file, override_nodes, expected_results', [
    (list_persons_command,
     'https://test.com/api/persons',
     'test_data/topdesk_person.json',
     [{'id': '1st-person-id'}, {'id': '2nd-person-id'}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Person',
         'outputs_key_field': 'Id'
     }),
    (list_operators_command,
     'https://test.com/api/operators',
     'test_data/topdesk_operator.json',
     [{'id': '1st-operator-id'}, {'id': '2nd-operator-id'}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Operator',
         'outputs_key_field': 'Id'
     }),
    (branches_command,
     'https://test.com/api/branches',
     'test_data/topdesk_branch.json',
     [{"id": "1st-branch-id"}, {"id": "2nd-branch-id"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Branch',
         'outputs_key_field': 'Id'
     }),
    (get_incidents_list_command,
     'https://test.com/api/incidents',
     'test_data/topdesk_incident.json',
     [{"id": "1st-incident-id"}, {"id": "2nd-incident-id"}],
     {
         'outputs_prefix': f'{INTEGRATION_NAME}.Incident',
         'outputs_key_field': 'Id'
     })
])
def test_large_output_list_command(client,
                                   requests_mock,
                                   command,
                                   command_api_url,
                                   mock_response_file,
                                   override_nodes,
                                   expected_results):
    """Unit test
    Given
        - a command that returns a list
        - file path of mocked response
    When
        - running the command
    Then
        - validate the entry context
    """
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
    assert command_results.outputs == capitalize_for_outputs(mock_topdesk_response)


@pytest.mark.parametrize('action, command_args, command_api_url, mock_response_file, override_node', [
    ("escalate",
     {"id": "incident_id", "escalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/escalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("deescalate",
     {"id": "incident_id", "deescalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/deescalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("archive",
     {"id": "incident_id", "archive_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/archive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("unarchive",
     {"id": "incident_id"},
     'https://test.com/api/incidents/id/incident_id/unarchive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("escalate",
     {"number": "incident_number", "escalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/number/incident_number/escalate',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("deescalate",
     {"number": "incident_number", "deescalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/number/incident_number/deescalate',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("archive",
     {"number": "incident_number", "archive_reason_id": "some_reason"},
     'https://test.com/api/incidents/number/incident_number/archive',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("unarchive",
     {"number": "incident_number"},
     'https://test.com/api/incidents/number/incident_number/unarchive',
     'test_data/topdesk_incident.json',
     {'number': 'incident_number'}),
    ("escalate",
     {"id": "incident_id", "number": "incident_number", "escalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/escalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("deescalate",
     {"id": "incident_id", "number": "incident_number", "deescalate_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/deescalate',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("archive",
     {"id": "incident_id", "number": "incident_number", "archive_reason_id": "some_reason"},
     'https://test.com/api/incidents/id/incident_id/archive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'}),
    ("unarchive",
     {"id": "incident_id", "number": "incident_number"},
     'https://test.com/api/incidents/id/incident_id/unarchive',
     'test_data/topdesk_incident.json',
     {'id': 'incident_id'})
])
def test_incident_do_commands(client,
                              requests_mock,
                              action,
                              command_args,
                              command_api_url,
                              mock_response_file,
                              override_node):
    """Unit test
    Given
        - action: archive, unarchive, escalate, deescalate
        - command args: id, number, reason_id
    When
        - running incident_do_command with the action and args
    Then
        - validate the correct request was called.
        - validate the entry context.
    """
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
    if command_args.get(f"{action}_reason_id", None):
        assert requests_mock.last_request.json() == {'id': command_args.get(f"{action}_reason_id", None)}
    else:
        assert requests_mock.last_request.json() == {}

    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.Incident'
    assert command_results.outputs_key_field == 'Id'
    assert command_results.outputs == capitalize_for_outputs([response_incident])


@pytest.mark.parametrize('command_args, command_api_url, command_api_body', [
    ({"id": "incident_id", "file": "some_entry_id", "invisible_for_caller": "false"},
     'https://test.com/api/incidents/id/incident_id/attachments',
     {"invisible_for_caller": "false"}),
    ({"id": "incident_id", "file": "some_entry_id", "description": "some description"},
     'https://test.com/api/incidents/id/incident_id/attachments',
     {"description": "some description"}),
    ({"id": "incident_id", "file": "some_entry_id", "description": "some description", "invisible_for_caller": "false"},
     'https://test.com/api/incidents/id/incident_id/attachments',
     {"description": "some description", "invisible_for_caller": "false"}),
    ({"id": "incident_id", "file": "some_entry_id"},
     'https://test.com/api/incidents/id/incident_id/attachments',
     {})
])
def test_attachment_upload_command(client,
                                   mocker,
                                   requests_mock,
                                   command_args,
                                   command_api_url,
                                   command_api_body):
    """Unit test
    Given
        - command args: id, file, description, invisible_for_caller
    When
        - running attachment_upload_command with the command args
    Then
        - validate the correct request was called.
        - validate the file is in the request.
        - validate the entry context.
    """

    mock_topdesk_node = util_load_json('test_data/topdesk_attachment.json')
    response_attachment = mock_topdesk_node.copy()

    requests_mock.post(
        command_api_url, json=response_attachment)

    mocker.patch.object(demisto, 'dt', return_value="made_up_file.txt")
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/mock_upload_file.txt'})

    command_results = attachment_upload_command(client=client,
                                                args=command_args)

    output_attachment = response_attachment
    output_attachment['downloadUrl'] = 'https://test.com/api/incidents/id/incident_id/attachments/some-id/download'

    assert requests_mock.called
    assert b'mock text file for attachment up' in requests_mock.last_request._request.body
    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.Attachment'
    assert command_results.outputs_key_field == 'Id'
    assert command_results.outputs == capitalize_for_outputs([output_attachment])


@pytest.mark.parametrize('command_args, command_api_url, response_override', [
    ({"incident_id": "incident_id"},
     'https://test.com/api/incidents/id/incident_id/attachments',
     [{"id": "attachment-id-1", "downloadUrl": "/api/incidents/id/incident_id/attachments/attachment-id-1",
       "expected": True}]),
    ({"incident_id": "incident_id", 'limit': '1'},
     'https://test.com/api/incidents/id/incident_id/attachments',
     [{"id": "attachment-id-1", "downloadUrl": "/api/incidents/id/incident_id/attachments/attachment-id-1",
       "expected": True},
      {"id": "attachment-id-2", "downloadUrl": "/api/incidents/id/incident_id/attachments/attachment-id-2",
       "expected": False}]),
    ({"incident_number": "incident_number"},
     'https://test.com/api/incidents/number/incident_number/attachments',
     [{"id": "attachment-id-1", "downloadUrl": "/api/incidents/id/incident_id/attachments/attachment-id-1",
       "expected": True}])
])
def test_attachment_list_command(client,
                                 requests_mock,
                                 command_args,
                                 command_api_url,
                                 response_override):
    """Unit test
    Given
        - command args: id, file, description, invisible_for_caller
    When
        - running attachment_upload_command with the command args
    Then
        - validate the correct request was called.
        - validate the file is in the request.
        - validate the entry context.
    """

    mock_topdesk_node = util_load_json('test_data/topdesk_attachment.json')

    response = []
    expected = []
    for attachment_override in response_override:
        response_attachment = mock_topdesk_node.copy()
        response_attachment["id"] = attachment_override["id"]
        response_attachment["downloadUrl"] = attachment_override["downloadUrl"]
        response.append(response_attachment)
        if attachment_override["expected"]:
            expected_attachment = mock_topdesk_node.copy()
            expected_attachment["id"] = attachment_override["id"]
            expected_attachment["downloadUrl"] = f'https://test.com{attachment_override["downloadUrl"]}'
            expected.append(expected_attachment)

    requests_mock.get(command_api_url, json=response)

    command_results = list_attachments_command(client=client,
                                               args=command_args)

    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.Attachment'
    assert command_results.outputs_key_field == 'Id'
    assert command_results.outputs == capitalize_for_outputs(expected)


@pytest.mark.parametrize('create_func, command_args, command_api_url, mock_response_file,'
                         ' expected_last_request_body', [
                             (True,  # Create
                              {"caller": "some_caller"},
                              'https://test.com/api/incidents/',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'}}),
                             (True,  # Create
                              {"caller": "some_caller", "description": "some_change"},
                              'https://test.com/api/incidents/',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'},
                               'briefDescription': 'some_change'}),
                             (True,  # Create
                              {"caller": "some_caller", "description": "some_change", "category": "some_category_id"},
                              'https://test.com/api/incidents/',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'},
                               'briefDescription': 'some_change', 'category': {'name': 'some_category_id'}}),
                             (False,  # Update
                              {"caller": "some_caller", "id": "incident_id"},
                              'https://test.com/api/incidents/id/incident_id',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'}}),
                             (False,  # Update
                              {"caller": "some_caller", "number": "incident_number"},
                              'https://test.com/api/incidents/number/incident_number',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'}}),
                             (False,  # Update
                              {"caller": "some_caller", "number": "incident_number", "description": "some_change"},
                              'https://test.com/api/incidents/number/incident_number',
                              'test_data/topdesk_incident.json',
                              {'callerLookup': {'id': 'some_caller'},
                               'briefDescription': 'some_change'})
                         ])
def test_caller_lookup_incident_touch_commands(client,
                                               requests_mock,
                                               create_func,
                                               command_args,
                                               command_api_url,
                                               mock_response_file,
                                               expected_last_request_body):
    """Unit test
    Given
        - whether the command is Create or Update
        - command args
    When
        - running the command with a caller as a registered caller.
    Then
        - validate 1 request was called.
        - validate the correct request was called.
        - validate the entry context.
    """
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

    request_command(command_api_url, json=response_incident)

    command_results = incident_touch_command(client=client,
                                             args=command_args,
                                             client_func=client_func,
                                             action=action)
    assert requests_mock.call_count == 2
    assert requests_mock.last_request.json() == expected_last_request_body
    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.Incident'
    assert command_results.outputs_key_field == 'Id'
    assert command_results.outputs == capitalize_for_outputs([response_incident])


@pytest.mark.parametrize('create_func, command_args, command_api_url, mock_response_file,'
                         ' expected_last_request_body', [
                             (True,  # Create
                              {"caller": "some_caller"},
                              'https://test.com/api/incidents/',
                              'test_data/topdesk_incident.json',
                              {'caller': {'dynamicName': 'some_caller'}}),
                             (False,  # Update
                              {"caller": "some_caller", "id": "incident_id"},
                              'https://test.com/api/incidents/id/incident_id',
                              'test_data/topdesk_incident.json',
                              {'caller': {'dynamicName': 'some_caller'}}),
                             (False,  # Update
                              {"caller": "some_caller", "number": "incident_number"},
                              'https://test.com/api/incidents/number/incident_number',
                              'test_data/topdesk_incident.json',
                              {'caller': {'dynamicName': 'some_caller'}}),
                         ])
def test_non_registered_caller_incident_touch_commands(client,
                                                       requests_mock,
                                                       create_func,
                                                       command_args,
                                                       command_api_url,
                                                       mock_response_file,
                                                       expected_last_request_body):
    """Unit test
    Given
        - whether the command is Create or Update
        - command args
    When
        - running the command with a caller as a non registered caller.
    Then
        - validate 2 requests were called.
        - validate the entry context.
    """
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

    def callback_func(request, _):
        if 'callerLookup' in request.json():
            return {"message": "The value for the field 'callerLookup.id' cannot be parsed."}
        else:
            return response_incident

    request_command(command_api_url, json=callback_func)

    command_results = incident_touch_command(client=client,
                                             args=command_args,
                                             client_func=client_func,
                                             action=action)
    assert requests_mock.call_count == 3
    assert requests_mock.last_request.json() == expected_last_request_body
    assert command_results.outputs_prefix == f'{INTEGRATION_NAME}.Incident'
    assert command_results.outputs_key_field == 'Id'
    assert command_results.outputs == capitalize_for_outputs([response_incident])


@pytest.mark.parametrize('command, command_args, command_api_request', [
    (branches_command,
     {'page_size': 2},
     'https://test.com/api/branches?page_size=2'),
    (branches_command,
     {'start': 2},
     'https://test.com/api/branches?start=2'),
    (branches_command,
     {'query': 'id==1st-branch-id'},
     'https://test.com/api/branches?query=id==1st-branch-id'),
    (branches_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-branch-id'},
     'https://test.com/api/branches?start=2&page_size=2&query=id==1st-branch-id'),
    (branches_command,
     {'page_size': 2, 'query': 'id==1st-branch-id'},
     'https://test.com/api/branches?page_size=2&query=id==1st-branch-id'),
    (branches_command,
     {'fields': 'id,name'},
     'https://test.com/api/branches?$fields=id,name'),
    (list_operators_command,
     {'page_size': 2},
     'https://test.com/api/operators?page_size=2'),
    (list_operators_command,
     {'start': 2},
     'https://test.com/api/operators?start=2'),
    (list_operators_command,
     {'query': 'id==1st-operator-id'},
     'https://test.com/api/operators?query=id==1st-operator-id'),
    (list_operators_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-operator-id'},
     'https://test.com/api/operators?start=2&page_size=2&query=id==1st-operator-id'),
    (list_operators_command,
     {'page_size': 2, 'query': 'id==1st-operator-id'},
     'https://test.com/api/operators?page_size=2&query=id==1st-operator-id'),
    (list_persons_command,
     {'page_size': 2},
     'https://test.com/api/persons?page_size=2'),
    (list_persons_command,
     {'start': 2},
     'https://test.com/api/persons?start=2'),
    (list_persons_command,
     {'query': 'id==1st-person-id'},
     'https://test.com/api/persons?query=id==1st-person-id'),
    (list_persons_command,
     {'page_size': 2, 'start': 2, 'query': 'id==1st-person-id'},
     'https://test.com/api/persons?start=2&page_size=2&query=id==1st-person-id'),
    (list_persons_command,
     {'page_size': 2, 'query': 'id==1st-person-id'},
     'https://test.com/api/persons?page_size=2&query=id==1st-person-id'),
    (list_persons_command,
     {'fields': 'id,status'},
     'https://test.com/api/persons?$fields=id,status'),
    (get_incidents_list_command,
     {'page_size': 2},
     'https://test.com/api/incidents?page_size=2'),
    (get_incidents_list_command,
     {'start': 2},
     'https://test.com/api/incidents?start=2'),
    (get_incidents_list_command,
     {'query': 'id=1st-incident-id'},
     'https://test.com/api/incidents?id=1st-incident-id'),
    (get_incidents_list_command,
     {'page_size': 2, 'start': 2, 'query': 'id=1st-incident-id'},
     'https://test.com/api/incidents?start=2&page_size=2&id=1st-incident-id'),
    (get_incidents_list_command,
     {'page_size': 2, 'query': 'id=1st-incident-id'},
     'https://test.com/api/incidents?page_size=2&id=1st-incident-id'),
    (get_incidents_list_command,
     {'fields': 'id,number'},
     'https://test.com/api/incidents?fields=id,number')
])
def test_large_output_list_command_with_args(client,
                                             requests_mock,
                                             command,
                                             command_args,
                                             command_api_request):
    """Unit test
    Given
        - command that returns a list
        - command args: page_size, start, query
    When
        - running the command with given args
    Then
        - validate the correct request was called
        - validate the request body is as expected
    """
    requests_mock.get(
        command_api_request, json=[{}])
    command(client, command_args)

    assert requests_mock.called
    assert requests_mock.last_request.json() == {}


@pytest.mark.parametrize('command_args, command_api_request, call_count', [
    ({'max_fetch': 2,
      'creation_date_start': '2020-02-10T06:32:36Z',
      'creation_date_end': '2020-03-10T06:32:36Z',
      'query': 'id=1st-incident-id'},
     [('https://test.com/api/incidents?page_size=2&id=1st-incident-id',
       {'creation_date_start': '2020-02-10T06:32:36Z',
        'creation_date_end': '2020-03-10T06:32:36Z'})], 1),
    ({'max_fetch': 2 * MAX_API_PAGE_SIZE,
      'creation_date_start': '2020-02-10T06:32:36Z',
      'creation_date_end': '2020-03-10T06:32:36Z',
      'query': 'id=1st-incident-id'},
     [(f'https://test.com/api/incidents?page_size={MAX_API_PAGE_SIZE}&id=1st-incident-id',
       {'creation_date_start': '2020-02-10T06:32:36Z',
        'creation_date_end': '2020-03-10T06:32:36Z'}),
      (f'https://test.com/api/incidents'
       f'?start={MAX_API_PAGE_SIZE}&page_size={MAX_API_PAGE_SIZE}&id=1st-incident-id',
       {'creation_date_start': '2020-02-10T06:32:36Z',
        'creation_date_end': '2020-03-10T06:32:36Z'})], 2)
])
def test_get_incidents_with_pagination(client,
                                       requests_mock,
                                       command_args,
                                       command_api_request,
                                       call_count):
    """Unit test
    Given
        - start, modification_date_start, modification_date_end and query arguments.
    When
        - running get_incidents_with_pagination function with arguments.
    Then
        validate the pagination logic is implemented correctly:
        - validate the correct parameters in the request.
        - validate the number of requests preformed.
    """
    for request in command_api_request:
        requests_mock.get(
            request[0], json=[{}])
    get_incidents_with_pagination(client=client,
                                  max_fetch=command_args.get('max_fetch', None),
                                  query=command_args.get('query', None),
                                  creation_date_start=command_args.get('creation_date_start', None),
                                  creation_date_end=command_args.get('creation_date_end', None))

    for called_request, mocked_request in zip(requests_mock._adapter.request_history[1:], command_api_request):
        assert called_request._request.url == mocked_request[0]
        assert called_request.json() == mocked_request[1]
    assert requests_mock.call_count == call_count + 1


@pytest.mark.parametrize('command, new_query, command_args, command_api_request', [
    (list_persons_command,
     False,  # Rest old query
     {"query": "status=firstLine&id=5"},
     'https://test.com/api/persons?query=status==firstLine&id==5'),
    (list_persons_command,
     False,  # Rest old query
     {"query": "status=firstLine"},
     'https://test.com/api/persons?query=status==firstLine'),
    (list_persons_command,
     False,  # Rest old query
     {"fields": "id,status"},
     'https://test.com/api/persons?$fields=id,status'),
    (list_operators_command,
     False,  # Old query
     {"query": "status=firstLine"},
     'https://test.com/api/operators?query=status==firstLine'),
    (list_operators_command,
     False,  # Old query
     {"query": "status==firstLine"},
     'https://test.com/api/operators?query=status==firstLine'),
    (branches_command,
     False,  # Old query
     {"query": "status=firstLine"},
     'https://test.com/api/branches?query=status==firstLine'),
    (branches_command,
     False,  # Old query
     {"query": "status==firstLine"},
     'https://test.com/api/branches?query=status==firstLine'),
    (branches_command,
     False,  # Old query
     {"fields": "id,name"},
     'https://test.com/api/branches?$fields=id,name'),
    (get_incidents_list_command,
     False,  # Old query
     {"query": "status=firstLine"},
     'https://test.com/api/incidents?status=firstLine'),
    (get_incidents_list_command,
     False,  # Old query
     {"status": "firstLine"},
     'https://test.com/api/incidents?status=firstLine'),
    (get_incidents_list_command,
     False,  # Old query
     {"query": 'caller_id=some_caller', "status": "firstLine"},
     'https://test.com/api/incidents?caller_id=some_caller&status=firstLine'),
    (get_incidents_list_command,
     False,  # Old query
     {"query": 'caller_id==some_caller', "status": "firstLine"},
     'https://test.com/api/incidents?caller_id=some_caller&status=firstLine'),
    (get_incidents_list_command,
     False,  # Old query
     {"query": 'caller_id=some_caller', "status": "firstLine", "branch_id": "some_branch"},
     'https://test.com/api/incidents?caller_id=some_caller&status=firstLine&branch=some_branch'),
    (get_incidents_list_command,
     False,  # Old query
     {"fields": "id,number"},
     'https://test.com/api/incidents?fields=id,number'),
    (get_incidents_list_command,
     True,  # New query
     {"query": "status==firstLine"},
     'https://test.com/api/incidents?query=status==firstLine'),
    (get_incidents_list_command,
     True,  # New query
     {"status": "firstLine"},
     'https://test.com/api/incidents?query=status==firstLine'),
    (get_incidents_list_command,
     True,  # New query
     {"query": 'caller_id==some_caller', "status": "firstLine"},
     'https://test.com/api/incidents?query=caller_id==some_caller&status==firstLine'),
    (get_incidents_list_command,
     True,  # New query
     {"query": 'status==firstLine', "caller_id": "some_caller_id", "branch_id": "some_branch"},
     'https://test.com/api/incidents?query=status==firstLine&caller==some_caller_id&branch==some_branch')
])
def test_old_new_query(requests_mock,
                       command,
                       new_query,
                       command_args,
                       command_api_request):
    """Unit test
    Given
        - command args
        - which type of query is supported
    When
        - running the command
    Then
        - validate the correct request url was called.
    """
    version = "3.1.4"
    if new_query:
        version = "3.4.0"

    requests_mock.get(
        'https://test.com/api/version', json={"version": version})
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        auth=('some_username', 'some_password')
    )
    requests_mock.get(command_api_request, json=[{}])
    command(client=client, args=command_args)

    assert requests_mock.called


@pytest.mark.parametrize('command_args', [
    ({"category": "blah"}), ({"subcategory": "blah"}), ({"call_type": "blah"}), ({"entry_type": "blah"})
])
def test_unsupported_old_query_param(client, command_args):
    """Unit test
    Given
        - client with old query setting. The old query does not support all args that the new query supports.
        - unsupported command args of get_incidents_list_command.
    When
        - running get_incidents_list_command with the unsupported param.
    Then
        - validate KeyError is raised.
    """
    with pytest.raises(KeyError, match=" is not supported in older TOPdeskRestApi versions."):
        get_incidents_list_command(client=client, args=command_args)


@pytest.mark.parametrize('topdesk_incidents_override, last_fetch_time, updated_fetch_time', [
    ([{  # Last fetch is before incident creation
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-02-10T06:32:36.303000+0000',
        'occurred': '2020-02-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-01-11T06:32:36.303000+0000', '2020-02-10T06:32:36.303000+0000'),
    ([{  # Last fetch is after one incident creation and before other.
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-01-10T06:32:36.303000+0000',
        'occurred': '2020-01-10T06:32:36Z',
        'will_be_fetched': False
    }, {
        'number': 'TEST-2',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-02-11T06:32:36.303000+0000', '2020-03-10T06:32:36.303000+0000'),
    ([{  # Last fetch is at incident creation
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-02-10T06:32:36.303+0000',
        'occurred': '2020-02-10T06:32:36Z',
        'will_be_fetched': False
    }], '2020-02-10T06:32:36.303000+0000', '2020-02-10T06:32:36.303000+0000'),
    ([{  # Same incident returned twice.
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': True
    }, {
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': False
    }], '2020-02-11T06:32:36.303000+0000', '2020-03-10T06:32:36.303000+0000'),
])
def test_fetch_incidents(client, requests_mock, topdesk_incidents_override, last_fetch_time, updated_fetch_time):
    """Unit test
    Given
        - fetch incidents args
    When
        - running fetch incidents command
    Then
        - validate The length of the results.
        - validate the entry context.
        - validate last_fetch is updated.
    """
    mock_topdesk_incident = util_load_json('test_data/topdesk_incident.json')
    mock_topdesk_response = []
    mock_actions = util_load_json('test_data/topdesk_actions.json')
    requests_mock.get(
        'https://test.com/api/incidents/id/some-test-id-1/actions',
        json=mock_actions)

    expected_incidents = []
    for incident_override in topdesk_incidents_override:
        response_incident = mock_topdesk_incident.copy()
        response_incident['number'] = incident_override['number']
        response_incident['creationDate'] = incident_override['creationDate']
        response_incident['mirror_direction'] = None
        response_incident['mirror_tags'] = ["comments", "ForTOPdesk", "work_notes"]
        response_incident['mirror_instance'] = ""
        mock_topdesk_response.append(response_incident)
        if incident_override['will_be_fetched']:
            expected_incidents.append({
                'name': f"{incident_override['briefDescription']}",
                'details': json.dumps(response_incident),
                'occurred': incident_override['occurred'],
                'rawJSON': json.dumps(response_incident),
            })

    requests_mock.get(
        'https://test.com/api/incidents', json=mock_topdesk_response)

    last_run = {
        'last_fetch': last_fetch_time
    }
    last_fetch, incidents = fetch_incidents(client=client,
                                            last_run=last_run,
                                            demisto_params={
                                                'mirror_direction': 'both'
                                            })

    assert len(incidents) == len(expected_incidents)
    for incident, expected_incident in zip(incidents, expected_incidents):
        assert incident['name'] == expected_incident['name']
        assert incident['details'] == expected_incident['details']
        assert incident['occurred'] == expected_incident['occurred']
        assert incident['rawJSON'] == expected_incident['rawJSON']
    assert last_fetch == {'last_fetch': updated_fetch_time}


@pytest.mark.parametrize('topdesk_incidents_override, last_fetch_time, updated_fetch_time', [
    ([{  # Last fetch is before incident creation
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-02-10T06:32:36.303000+0000',
        'occurred': '2020-02-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-01-11T06:32:36.303000+0000', '2020-02-10T06:32:36.303000+0000'),
    ([{  # Last fetch is after one incident creation and before other.
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-01-10T06:32:36.303000+0000',
        'occurred': '2020-01-10T06:32:36Z',
        'will_be_fetched': False
    }, {
        'number': 'TEST-2',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': True
    }], '2020-02-11T06:32:36.303000+0000', '2020-03-10T06:32:36.303000+0000'),
    ([{  # Last fetch is at incident creation
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-02-10T06:32:36.303+0000',
        'occurred': '2020-02-10T06:32:36Z',
        'will_be_fetched': False
    }], '2020-02-10T06:32:36.303000+0000', '2020-02-10T06:32:36.303000+0000'),
    ([{  # Same incident returned twice.
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': True
    }, {
        'number': 'TEST-1',
        'briefDescription': 'some_brief_description',
        'creationDate': '2020-03-10T06:32:36.303000+0000',
        'occurred': '2020-03-10T06:32:36Z',
        'will_be_fetched': False
    }], '2020-02-11T06:32:36.303000+0000', '2020-03-10T06:32:36.303000+0000'),
])
def test_fetch_incidents_with_no_actions(client, requests_mock, topdesk_incidents_override, last_fetch_time, updated_fetch_time):
    """Unit test
    Given
        - fetch incidents args
        - empty response of actions from the api
    When
        - running fetch incidents command
    Then
        - validate The length of the results.
        - validate the entry context.
        - validate last_fetch is updated.
    """
    mock_topdesk_incident = util_load_json('test_data/topdesk_incident.json')
    mock_topdesk_response = []
    requests_mock.get(
        'https://test.com/api/incidents/id/some-test-id-1/actions',
        text='')

    expected_incidents = []
    for incident_override in topdesk_incidents_override:
        response_incident = mock_topdesk_incident.copy()
        response_incident['number'] = incident_override['number']
        response_incident['creationDate'] = incident_override['creationDate']
        response_incident['mirror_direction'] = None
        response_incident['mirror_tags'] = ["comments", "ForTOPdesk", "work_notes"]
        response_incident['mirror_instance'] = ""
        mock_topdesk_response.append(response_incident)
        if incident_override['will_be_fetched']:
            expected_incidents.append({
                'name': f"{incident_override['briefDescription']}",
                'details': json.dumps(response_incident),
                'occurred': incident_override['occurred'],
                'rawJSON': json.dumps(response_incident),
            })

    requests_mock.get(
        'https://test.com/api/incidents', json=mock_topdesk_response)

    last_run = {
        'last_fetch': last_fetch_time
    }
    last_fetch, incidents = fetch_incidents(client=client,
                                            last_run=last_run,
                                            demisto_params={
                                                'mirror_direction': 'both'
                                            })

    assert len(incidents) == len(expected_incidents)
    for incident, expected_incident in zip(incidents, expected_incidents):
        assert incident['name'] == expected_incident['name']
        assert incident['details'] == expected_incident['details']
        assert incident['occurred'] == expected_incident['occurred']
        assert incident['rawJSON'] == expected_incident['rawJSON']
    assert last_fetch == {'last_fetch': updated_fetch_time}


def test_get_mapping_fields(client):
    """
    Given:
        -  TOPdesk client
        -  TOPdesk mapping fields
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping.
    """
    # client = Client(base_url='https://server_url.com/', verify=False, auth=("username","password"))
    res = get_mapping_fields_command(client)
    expected_mapping = {
        "TOPdesk Incident": {
            'processingStatus': "",
            'priority': "",
            'urgency': "",
            'impact': ""
        }
    }
    assert expected_mapping == res.extract_mapping()


@pytest.mark.parametrize('command_args', [
    ({"incident_id": "some-id", "incident_number": None}),
    ({"incident_id": None, "incident_number": "some-number"})
])
def test_incident_actions_list(client, requests_mock, command_args):
    """
    Given:
        - TOPdesk client
        - Arguments (incident_id, incident_number, limit)
    When
        - running list_actions_command
    Then
        - The result fits the expected mapping
    """

    mock_incident_actions = util_load_json('test_data/topdesk_actions.json')
    if command_args['incident_id']:
        requests_mock.get(
            'https://test.com/api/incidents/id/some-id/actions',
            json=mock_incident_actions)
    elif command_args['incident_number']:
        requests_mock.get(
            'https://test.com/api/incidents/number/some-number/actions',
            json=mock_incident_actions)

    list_actions_command(client, command_args)
    assert requests_mock.called


@pytest.mark.parametrize('args', [
    ({"id": "some-id", "lastUpdate": "2022-04-26T08:21:48.520Z"})
])
def test_get_remote_data_command(client, requests_mock, args):
    """
    Given:
        - TOPdesk client
        - Arguments (incident_id, last_update)
    When
        - running get_remote_command
    Then
        - The result fits the expected mapping
    """
    mock_incident = util_load_json('test_data/topdesk_incident.json')
    mock_actions = util_load_json('test_data/topdesk_actions.json')
    requests_mock.get(
        'https://test.com/api/incidents/id/some-id',
        json=mock_incident)
    requests_mock.get(
        'https://test.com/api/incidents/id/some-id/actions',
        json=mock_actions)

    get_remote_data_command(client, args, None)


@pytest.mark.parametrize('args,params', [
    ({"lastUpdate": "2022-04-26T08:21:48.520Z"}, {"max_fetch": 10}),
    ({"lastUpdate": "2022-04-26T08:21:48.520Z"}, {"max_fetch": 1})
])
def test_get_modified_remote_data_command(client, requests_mock, args, params):
    client.rest_api_new_query = True
    get_modified_remote_data_command(client, args, params)


@pytest.mark.parametrize('args,params', [
    ({"remote_incident_id": "some-id"}, {"close_ticket": False})
])
def test_update_remote_system_command(client, args, params):
    update_remote_system_command(client, args, params)

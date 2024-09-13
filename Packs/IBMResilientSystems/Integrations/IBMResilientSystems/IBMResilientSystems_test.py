import json
from io import BytesIO

import pytest
import requests
from requests import Session

from pytest import raises

import demistomock as demisto
from CommonServerPython import DemistoException

DEFAULT_MAX_FETCH = 1000
TAG_TO_IBM = "FROM XSOAR"


def dict_to_response(data, status=200):
    response = requests.Response()
    response.status_code = status
    # Convert dictionary to bytes and set as content
    response.raw = BytesIO(json.dumps(data).encode('utf-8'))

    response.headers['Content-Type'] = 'application/json'
    return response


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


class MockClient:
    @staticmethod
    def get(incident_id):
        return {
            'name': 'The old name',
            'description': {'format': 'html', 'content': 'The old description'},
            'owner_id': 1,
            'discovered_date': 1624782898000,
            'confirmed': 'true'
        }

    @staticmethod
    def post(url, body):
        return url, body

    @staticmethod
    def patch(url, body):
        return url, body


def test_update_incident_command_with_invalid_json(mocker):
    """
    Given:
     - An incident should be updated.

    When:
     - Running update_incident_command function with other-fields argument, the other-field is an invalid json.

    Then:
     - Ensure the parsing before the request fails and returns a JSONDecodeError.
    """
    mocker.patch.object(demisto, 'params', return_value={'server': 'example.com:80', 'org': 'example', 'proxy': True})
    args = {
        "incident-id": "1234",
        "other-fields": 'Invalid json'
    }
    from IBMResilientSystems import update_incident_command

    with raises(Exception) as exception:
        update_incident_command(MockClient, args)
    assert 'The other_fields argument is not a valid json.' in exception.value.args[0]


def test_add_note(mocker):
    """
    Given:
     - An incident that should be updated with a note.

    When:
     - Running add_note_command function.

    Then:
     - Ensure the function runs as expected.
    """
    mocker.patch.object(demisto, 'params', return_value={'server': 'example.com:80', 'org': 'example', 'proxy': True})
    mock_result = mocker.patch.object(MockClient, 'post')
    expected_result = ('/incidents/1234/comments', {'text': {'format': 'text', 'content': f'This is a new note\n{TAG_TO_IBM}'}})
    from IBMResilientSystems import add_note_command

    output = add_note_command(MockClient, "1234", "This is a new note", tag_to_ibm=TAG_TO_IBM)

    assert mock_result.call_args.args == expected_result
    assert '1234' in output.readable_output


def test_add_incident_artifact(mocker):
    """
    Given:
     - An incident should be updated with an artifact.

    When:
     - Running add_artifact_command function.

    Then:
     - Ensure the function runs as expected.
    """
    mocker.patch.object(demisto, 'params', return_value={'server': 'example.com:80', 'org': 'example', 'proxy': True})
    mock_result = mocker.patch.object(MockClient, 'post')
    expected_result = ('/incidents/1234/artifacts', {'type': 'IP Address', 'value': '1.1.1.1',
                                                     'description': {'format': 'text',
                                                                     'content': 'This is the artifact description'}})
    from IBMResilientSystems import add_artifact_command

    output = add_artifact_command(MockClient, "1234", "IP Address", "1.1.1.1", "This is the artifact description")

    assert mock_result.call_args.args == expected_result
    assert '1234' in output.get('HumanReadable')


def test_test_module(mocker):
    """
    Tests whether the test module returns expected result for default http response.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import test_module, SimpleClient
    client = SimpleClient()
    mocker.patch.object(client, 'get', return_value={})
    assert test_module(client, '2024-01-01T00:00:00Z') == "ok"


@pytest.mark.parametrize('fetch_time, expected_result', [
    ('2024-01-01T00:00:00Z', 'ok'),
    ('2024-01-01T00:00:00', 'ok'),
    ('', 'fail'),
    ('2024/01/01 00:00:00', 'fail'),
    ('invalid-date', 'fail'),
])
def test_test_module_fetch_time(fetch_time, expected_result, mocker):
    """
    Tests whether the test module returns expected result for valid and invalid responses.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import test_module, SimpleClient, validate_iso_time_format
    client = SimpleClient()
    mocker.patch.object(client, 'get', return_value={})
    fetch_time = validate_iso_time_format(fetch_time)
    if expected_result == 'fail':
        with raises(DemistoException):
            test_module(client, fetch_time)
    else:
        assert test_module(client, fetch_time) == expected_result


@pytest.mark.parametrize("args, expected", [
    ({}, {
        'filters': [{'conditions': []}],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'length': DEFAULT_MAX_FETCH}),  # Test without any filters or pagination params

    ({'severity': 'Low'}, {
        'filters': [{
            'conditions': [{'field_name': 'severity_code', 'method': 'in', 'value': [50]}]
        }],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'length': DEFAULT_MAX_FETCH
    }),

    ({'date-created-before': '2022-01-01T10:00:00Z'}, {
        'filters': [{
            'conditions': [{'field_name': 'create_date', 'method': 'lte', 'value': 1641024000000}]
        }],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'length': DEFAULT_MAX_FETCH
    }),

    ({'page': 1, 'page_size': 10, 'last-modified-after': '2022-01-01T10:00:00Z'}, {
        'filters': [{'conditions': [{
            'field_name': 'inc_last_modified_date',
            'method': 'gte',
            'value': 1641024000000
        }]}],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'start': 0,
        'length': 10
    })
], ids=['no-filters-query', 'args-1-query', 'args-2-query', 'pagination-params-query']
                         )
def test_prepare_search_query_data(mocker, args, expected):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import prepare_search_query_data
    assert prepare_search_query_data(args) == expected


@pytest.mark.parametrize(
    "input_notes, expected_output",
    [
        (
            [{
                "type": "incident",
                "id": 0,
                "parent_id": None,
                "user_id": 0,
                "user_fname": "Demisto",
                "user_lname": "Resilient",
                "text": "insecure?",
                "create_date": 1722424268280,
                "modify_date": 1722424268280,
                "children": [],
                "mentioned_users": [],
                "is_deleted": False,
                "modify_user": {
                    "id": 0,
                    "first_name": "Demisto",
                    "last_name": "Resilient"
                },
                "actions": [],
                "inc_id": 2222,
                "inc_name": "inci-11",
                "task_id": None,
                "task_name": None,
                "task_custom": None,
                "task_members": None,
                "task_at_id": None,
                "inc_owner": 0,
                "user_name": "Demisto Resilient",
                "modify_principal": {
                    "id": 0,
                    "type": "user",
                    "name": "demist",
                    "display_name": "Demisto Resilient"
                },
                "comment_perms": {
                    "update": True,
                    "delete": True
                }
            }],
            [{'create_date': '2024-07-31T14:11:08Z',
              'created_by': 'Demisto Resilient',
              'id': 0,
              'modify_date': 1722424268280,
              'text': 'insecure?'}]
        ),
        (
            [{"id": 2, "text": " ", "create_date": 1722424253387}],
            [{'create_date': '2024-07-31T14:10:53Z',
              'created_by': ' ',
              'id': 2,
              'modify_date': None,
              'text': ' '}]
        )

    ]
)
def test_prettify_incident_notes(mocker, input_notes, expected_output):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import prettify_incident_notes
    assert prettify_incident_notes(input_notes) == expected_output


@pytest.mark.parametrize('incidents, expected_output', [
    ([], 'No results found.'),
])
def test_search_incidents_command(mocker, incidents, expected_output):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, search_incidents_command
    client = SimpleClient()
    mocker.patch('IBMResilientSystems.search_incidents', return_value=incidents)

    assert search_incidents_command(client=client, args={}) == expected_output


@pytest.mark.parametrize(
    "args", [
        (
            {'date-created-after': 1577865600000, 'limit': '1000', 'page': '1', 'page_size': '10'}
        ),
    ]
)
def test_search_incidents(mocker, args):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import SimpleClient, search_incidents, DEFAULT_RETURN_LEVEL
    test_dict_response = load_test_data('./test_data/test_search_incidents_response.json')
    test_response = dict_to_response(test_dict_response)
    request = mocker.patch.object(Session, "post", return_value=test_response)
    client = SimpleClient()
    client.org_id = 0
    search_incidents(client=client, args=args)

    request_url = request.call_args.args[0]
    request_headers = request.call_args.kwargs['headers']
    request_data = request.call_args.kwargs['data']

    assert request_url.endswith(
        f"/rest/orgs/0/incidents/query_paged?text_content_output_format=objects_convert_text&return_level={args.get('return_level', DEFAULT_RETURN_LEVEL)}"
    )
    assert request_headers['content-type'] == 'application/json'
    assert request_data == (
        '{"filters": [{"conditions": [{"field_name": "create_date", "method": "gte", "value": 1577865600000}]}], "sorts": [{"field_name": "create_date", "type": "asc"}], "length": 10, "start": 0}')


@pytest.mark.parametrize('args, processed_payload', [
    ({
         'incident-id': 0000,
         'severity': 'Low',
         'incident-type': "Malware",
         'nist': "Attrition",
         "resolution": "NotAnIssue",
         "resolution-summary": "This is a test incident.",
         "description": "Test incident",
         "name": "incident-0000",
     },
     {"changes": [{"field": "severity_code", "old_value": {"id": 6}, "new_value": {"id": 4}},
                  {"field": "incident_type_ids", "old_value": {"ids": [21, 19, 17, 6]},
                   "new_value": {"ids": [21, 19, 17, 6, 19]}},
                  {"field": "nist_attack_vectors", "old_value": {"ids": [4, 2]}, "new_value": {"ids": [4, 2, 2]}},
                  {"field": "resolution_id", "old_value": {"id": 9}, "new_value": {"id": 9}},
                  {"field": "resolution_summary",
                   "old_value": {
                       "textarea": {
                           "format": "html",
                           "content": "This is a test incident."
                       }},
                   "new_value": {
                       "textarea": {
                           "format": "html",
                           "content": "This is a test incident."
                       }}
                   },
                  {"field": "description",
                   "old_value": {
                       "textarea": {
                           "format": "html",
                           "content": "1111 2222 3333"
                       }
                   },
                   "new_value": {
                       "textarea": {"format": "html", "content": "Test incident"}}},
                  {"field": "name", "old_value": {"text": "incident_name"}, "new_value": {"text": "incident-0000"}}]}
    ),
])
def test_update_incident_command(mocker, args, processed_payload):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, update_incident_command
    client = SimpleClient()
    client.org_id = 0
    mocker.patch.object(Session, 'get', return_value=dict_to_response(
        load_test_data('./test_data/test_get_incident_response.json')))

    request = mocker.patch.object(Session, 'patch', return_value=dict_to_response({
        "success": True, "title": None, "message": None, "hints": []
    }))
    update_incident_command(client, args)
    assert request.call_args.args[0].endswith(f"/rest/orgs/{client.org_id}/incidents/{args['incident-id']}")
    assert json.loads(request.call_args[1]['data']) == processed_payload


def test_update_incident(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })

    from IBMResilientSystems import SimpleClient, update_incident

    request = mocker.patch.object(Session, 'patch', return_value=dict_to_response({
        "success": True, "title": None, "message": None, "hints": []
    }))

    client = SimpleClient()
    client.org_id = 0

    update_incident(client, incident_id='0000', data={})
    assert request.call_args.args[0].endswith('/rest/orgs/0/incidents/0000')
    assert request.call_args[1]['data'] == '{}'


@pytest.mark.parametrize('incident_id, expected_human_readable', [
    ('1000',
     '### IBM QRadar SOAR incident ID 1000\n|Id|Name|Description|NistAttackVectors|Phase|Resolution|ResolutionSummary|Owner'
     '|CreatedDate|DateOccurred|DiscoveredDate|DueDate|NegativePr|Confirmed|ExposureType|Severity|Reporter|\n'
     '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1000 | incident_name | 1111 2222 3333 | '
     'E-mail<br>Attrition<br> |  | Not an Issue | This is a test incident. |  | 2024-07-29T14:32:36Z |  | 2024-07-29T14:31:57Z '
     '|  | true | true | ExternalParty | 6 |  |'),
])
def test_get_incident_command(mocker, incident_id, expected_human_readable):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })

    from IBMResilientSystems import SimpleClient, get_incident_command

    client = SimpleClient()
    client.org_id = 0
    mocker.patch('IBMResilientSystems.get_users', return_value=[])
    mocker.patch('IBMResilientSystems.get_phases', return_value={})
    mocker.patch.object(Session, 'get', return_value=dict_to_response(
        load_test_data('./test_data/test_get_incident_response.json')))

    context_entry = get_incident_command(client, incident_id)
    assert context_entry['HumanReadable'].strip() == expected_human_readable


@pytest.mark.parametrize('script_id, expected_outputs, expected_readable_output', [
    ('1', [{'id': 1, 'name': 'Sample script: process inbound email (v35)',
            'description': 'This script processes inbound emails.',
            'language': 'python', 'object_type': 13, 'uuid': '0000-0000-0000-0000-0000',
            'actions': [], 'tags': [], 'script_text': '...',
            'creator_id': 0, 'last_modified_by': 0, 'last_modified_time': 1600698818789}],
     """### example Scripts
|id|name|description|language|
|---|---|---|---|
| 1 | Sample script: process inbound email (v35) | This script processes inbound emails. | python |
"""),
    ('', [{'id': 1, 'name': 'Sample script: process inbound email (v35)',
           'description': 'This script processes inbound emails.',
           'language': 'python', 'object_type': 13, 'uuid': '0000-0000-0000-0000-0000',
           'actions': [], 'tags': []}, {'id': 3, 'name': 'test-script',
                                        'description': 'Testing', 'language': 'python', 'object_type': 0,
                                        'uuid': '0000-0000-0000-0000-0000', 'actions': [], 'tags': []},
          {'id': 4, 'name': 'test-script-2', 'description': 'Testing 2',
           'language': 'python', 'object_type': 13, 'uuid': '0000-0000-0000-0000-0000',
           'actions': [], 'tags': []}],
     """### example Scripts
|id|name|description|language|
|---|---|---|---|
| 1 | Sample script: process inbound email (v35) | This script processes inbound emails. | python |
| 3 | test-script | Testing | python |
| 4 | test-script-2 | Testing 2 | python |
"""),
    ('2', [{'error_code': 'generic',
            'hints': [], 'message': 'Unable to find object with ID 2', 'success': False, 'title': None}],
     """### example Scripts
|id|name|description|language|
|---|---|---|---|
|  |  |  |  |
""")
])
def test_list_scripts_command(mocker, script_id: str, expected_outputs: list, expected_readable_output: str):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, list_scripts_command
    from os import path

    def side_effect(url: str):
        _script_id = url.split('/')[-1]
        if _script_id:  # Return enriched script data for a specific script ID
            response_path = f'./test_data/test_get_script_{_script_id}_response.json'
            if not path.exists(response_path):
                response_path = './test_data/test_get_script_fail_response.json'
        else:
            response_path = './test_data/test_get_all_scripts_response.json'

        return load_test_data(response_path)

    client = SimpleClient()
    client.org_id = 0
    args = {'script_id': script_id}

    mocker.patch.object(SimpleClient, 'get', side_effect=side_effect)

    command_result = list_scripts_command(client, args)
    assert command_result.readable_output == expected_readable_output
    assert command_result.outputs == expected_outputs


@pytest.mark.parametrize('file_entry_id', ['ENTRY_ID'])
def test_upload_incident_attachment(mocker, file_entry_id: str):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, upload_incident_attachment_command
    client = SimpleClient()
    client.org_id = 0
    response = {'status_code': 200}
    expected_output = "File was uploaded successfully to 1000."

    def mock_get_file_path(entry_id):  # noqa: F811
        if entry_id == 'ENTRY_ID':
            return {'path': '/path/to/file', 'name': 'filename.txt'}

    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_get_file_path)
    post_attachment_request = mocker.patch.object(SimpleClient, 'post_attachment', return_value=response)

    args = {'entry_id': file_entry_id, 'incident_id': 1000}
    result = upload_incident_attachment_command(SimpleClient(), args, tag_to_ibm="FROM XSOAR")

    assert result.readable_output == expected_output
    post_attachment_request.assert_called_once_with(
        uri=f"/incidents/{args['incident_id']}/attachments",
        filepath='/path/to/file',
        filename=f'filename_{TAG_TO_IBM}.txt'
    )


def test_delete_incidents_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, delete_incidents_command
    client = SimpleClient()
    client.org_id = 0

    delete_incident_request = mocker.patch.object(SimpleClient, 'put', return_value={
        "success": True, "title": None, "message": None, "hints": []
    })

    incident_ids = ['1001', '1002']
    delete_incidents_command(client, args={"incident_ids": ','.join(incident_ids)})

    delete_incident_request.assert_called_once_with("/incidents/delete", payload=incident_ids)


def test_list_incident_notes_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, list_incident_notes_command

    client = SimpleClient()
    client.org_id = 0

    get_incident_notes_request = mocker.patch.object(
        SimpleClient,
        'get',
        return_value=load_test_data('./test_data/test_get_incident_notes_reponse.json')
    )
    list_incident_notes_command(client, {"incident_id": "2000"})

    get_incident_notes_request.assert_called_once_with(
        f"/incidents/2000/comments?text_content_output_format=objects_convert_text"
    )


def test_update_incident_note(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, update_incident_note_command

    client = SimpleClient()
    client.org_id = 0

    update_incident_note_request = mocker.patch.object(
        SimpleClient,
        'put',
        return_value={}
    )
    update_incident_note_command(client, args={
        'incident_id': 2000,
        'note_id': 1,
        'note': "NOTE_BODY"
    })

    update_incident_note_request.assert_called_once_with(f"/incidents/2000/comments/1", payload={
        'text': {
            'format': 'text',
            'content': 'NOTE_BODY'
        }
    })


@pytest.mark.parametrize("args, expected_task_dto", [
    (
        {
            'incident_id': '2000',
            'name': 'TASK-1',
            'owner_id': '0',
            'description': 'TASK',
            'instructions': 'INSTRUCTIONS',
            'phase': 'Initial',
            'due_date': '2023-04-01T12:00:00.000Z'
        },
        {
            "name": 'TASK-1',
            "phase_id": {"name": 'Initial'},
            "description": 'TASK',
            "due_date": 1680339600000,
            "instructions": 'INSTRUCTIONS',
            "owner_id": 0
        }
    ),
    (  # Task without Instructions
        {
            'incident_id': '2001',
            'name': 'TASK-2',
            'owner_id': '1',
            'description': 'TASK 2',
            'instructions': '',
            'phase': 'Custom',
            'due_date': '2023-05-01T12:00:00.000Z'
        },
        {
            "name": 'TASK-2',
            "phase_id": {"name": 'Custom'},
            "description": 'TASK 2',
            "due_date": 1682931600000,
            "owner_id": 1
        }
    ),
    (  # Invalid Owner ID
        {
            'incident_id': '2003',
            'name': 'TASK-3',
            'owner_id': 'abcd',
            'description': 'TASK 3',
            'instructions': 'TASK 3 Instructions',
            'phase': 'Initial',
            'due_date': '2023-07-01T12:00:00.000Z'
        },
        DemistoException("Owner ID must be an integer number.")
    ),
    (  # Task without Due Date
        {
            'incident_id': '2004',
            'name': 'TASK-4',
            'owner_id': '3',
            'description': 'TASK 4',
            'instructions': 'TASK 4 Instructions',
            'phase': 'Initial',
            'due_date': ''
        },
        {
            "name": 'TASK-4',
            "phase_id": {"name": 'Initial'},
            "description": 'TASK 4',
            "instructions": 'TASK 4 Instructions',
            "owner_id": 3
        }
    ),
])
def test_add_custom_task_command(mocker, args, expected_task_dto):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, add_custom_task_command
    client = SimpleClient()
    client.org_id = 0

    def post_side_effect(uri, payload):
        if isinstance(expected_task_dto, Exception):
            raise expected_task_dto
        assert uri == f"/incidents/{args['incident_id']}/tasks"
        assert payload == expected_task_dto
        return {"id": "1234"}

    add_custom_task_request = mocker.patch.object(
        SimpleClient,
        'post',
        side_effect=post_side_effect
    )

    if isinstance(expected_task_dto, Exception):
        with pytest.raises(DemistoException, match="Owner ID must be an integer number."):
            add_custom_task_command(client, args=args)
    else:
        result = add_custom_task_command(client, args=args)
        add_custom_task_request.assert_called_once_with(uri=f"/incidents/{args['incident_id']}/tasks", payload=expected_task_dto)
        assert result.readable_output == f"Successfully created new task for incident with ID {args['incident_id']}. Task ID: 1234"


def test_list_tasks_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, list_tasks_command
    client = SimpleClient()
    client.org_id = 0

    get_tasks_request = mocker.patch.object(
        SimpleClient,
        'get',
        return_value={}
    )
    list_tasks_command(client)
    get_tasks_request.assert_called_with(f"/tasks")


def test_get_task_members_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, get_task_members_command
    client = SimpleClient()
    client.org_id = 0
    task_id = "1234"
    get_task_members_request = mocker.patch.object(
        SimpleClient,
        'get',
        return_value={}
    )
    get_task_members_command(client, args={'task_id': task_id})

    get_task_members_request.assert_called_with(f"/tasks/{task_id}/members")


@pytest.mark.parametrize("task_ids, should_raise_exception", [
    ("1000", False),
    ("2000,3000", False),
    ("", True)
])
def test_delete_tasks_command(mocker, task_ids, should_raise_exception):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, delete_tasks_command
    client = SimpleClient()
    client.org_id = 0

    delete_tasks_request = mocker.patch.object(SimpleClient, 'put', return_value={
        "success": True, "title": None, "message": None, "hints": []
    })

    if should_raise_exception:
        with pytest.raises(DemistoException):
            delete_tasks_command(client, args={"task_ids": task_ids})
    else:
        result = delete_tasks_command(client, args={"task_ids": task_ids})
        task_id_list = task_ids.split(',')
        delete_tasks_request.assert_called_once_with("/tasks/delete", payload=task_id_list)
        assert result.readable_output == f"Tasks with IDs {task_id_list} were deleted successfully."


def test_delete_task_members_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, delete_task_members_command
    client = SimpleClient()
    client.org_id = 0

    task_id = '1234'
    mock_response = {"content": "Members deleted successfully"}

    delete_task_members_request = mocker.patch.object(
        SimpleClient,
        'delete',
        return_value=mock_response
    )
    delete_task_members_command(client, args={'task_id': task_id})

    delete_task_members_request.assert_called_once_with(f"/tasks/{task_id}/members")


def test_list_task_instructions_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, list_task_instructions_command
    client = SimpleClient()
    client.org_id = 0

    task_id = "5678"
    mock_response = {
        "text": {
            "content": "These are the instructions for the task.",
            "format": "text"
        }
    }

    get_task_instructions_request = mocker.patch.object(
        SimpleClient,
        'get',
        return_value=mock_response
    )

    list_task_instructions_command(client, args={'task_id': task_id})

    get_task_instructions_request.assert_called_once_with(
        f"/tasks/{task_id}/instructions_ex?text_content_output_format=objects_convert_text"
    )


def test_get_attachment_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, get_attachment_command
    from requests import Response
    client = SimpleClient()
    client.org_id = 0

    def side_effect(url: str, get_response_object=False):
        if url.endswith('/contents'):  # File content request
            response = Response()
            response.__setattr__('_content', b"test file content")  # Note: Bytes for content
            response.status_code = 200
            return response
        # File metadata response
        else:
            return {
                "type": "incident",
                "id": 1,
                "uuid": "0000-0000-0000-0000",
                "name": "test-test-test.txt",
                "content_type": "text/plain",
                "created": 1725880565507,
                "creator_id": 1,
                "size": 6,
                "actions": [],
                "playbooks": [],
                "task_id": None,
                "task_name": None,
                "task_custom": None,
                "task_members": None,
                "task_at_id": None,
                "reconciliation_status": "matched",
                "vers": 8,
                "inc_id": 2000,
                "inc_name": "INCIDENT-1",
                "inc_owner": 0
            }

    get_attachment_request = mocker.patch.object(SimpleClient, 'get', side_effect=side_effect)

    args = {'incident_id': '1000', 'attachment_id': '1'}
    get_attachment_command(client, args)

    get_attachment_endpoint = f'/incidents/{args.get("incident_id")}/attachments/{args.get("attachment_id")}'
    get_attachment_contents_endpoint = get_attachment_endpoint + '/contents'

    # Check the calls made to the mock
    get_attachment_request.assert_has_calls([
        mocker.call(get_attachment_endpoint),
        mocker.call(get_attachment_contents_endpoint, get_response_object=True)
    ])


def test_get_modified_remote_data_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, get_modified_remote_data_command
    from CommonServerPython import GetModifiedRemoteDataResponse

    client = SimpleClient()
    client.org_id = 0

    mock_search_incidents = mocker.patch('IBMResilientSystems.search_incidents', return_value=[
        {'id': 1000, 'last_modified_time': '2023-09-01T12:01:00Z'},
        {'id': 1001, 'last_modified_time': '2023-09-01T12:02:00Z'}
    ])
    expected_output = GetModifiedRemoteDataResponse(['1000', '1001'])

    last_update = '2023-09-01T12:00:00Z'
    args = {'lastUpdate': last_update}
    result = get_modified_remote_data_command(client, args)

    mock_search_incidents.assert_called_once_with(client, args={'last-modified-after': last_update})
    assert result.modified_incident_ids == expected_output.modified_incident_ids


def test_get_remote_data_command(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, get_remote_data_command

    # Mock client and its methods
    client = SimpleClient()
    client.org_id = 0

    incident_id = "1000"
    last_update = "2024-01-01T00:00:00Z"

    # Mock incoming arguments
    args = {
        'id': incident_id,
        'lastUpdate': last_update
    }

    # Mock the get_incident and process_raw_incident function behavior
    mock_incident_data = {
        'plan_status': 'A',  # 'A' stands for Active
        'end_date': None,
        'notes': [{
            'modify_date': 1725880565507,
            'text': {'content': 'Note content'},
            'created_by': 'User 1'
        }],
        'attachments': [{
            'ID': '1',
            'Create Time': 1725880565507,
            'Name': 'Attachment1'
        }]
    }

    mocker.patch('IBMResilientSystems.get_incident', return_value=mock_incident_data)
    mocker.patch('IBMResilientSystems.process_raw_incident', return_value=mock_incident_data)

    # Mock get_attachment and handle_incoming_incident_resolution
    mocker.patch('IBMResilientSystems.get_attachment', return_value=("filename.txt", b"file content"))
    mocker.patch('IBMResilientSystems.handle_incoming_incident_resolution', return_value={'Contents': 'Incident resolved'})
    # Call the command and capture the result
    result = get_remote_data_command(client, args, tag_to_ibm="FROM ", tag_from_ibm="TO ")

    # Check if the result contains the expected mirrored data and entries
    assert len(result.entries) == 3  # A note, a file, and a reopen entry.
    assert "Note content" in result.entries[0].get('Contents')
    assert "filename.txt" in result.entries[1].get('File')
    assert result.mirrored_object


def test_update_remote_system(mocker):
    pass


def test_get_mapping_fields_command(mocker):
    pass


def test_validate_iso_time_format():
    # TODO
    pass


def test_fetch_incidents(mocker):
    # TODO
    pass

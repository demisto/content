import json
from io import BytesIO

import pytest
import requests
from requests import Session

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


@pytest.fixture
def _mocker(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'close_ibm_incident': True
    })
    return mocker


def test_update_incident_command_with_invalid_json(_mocker):
    """
    Given:
     - An incident should be updated.

    When:
     - Running update_incident_command function with other-fields argument, the other-field is an invalid json.

    Then:
     - Ensure the parsing before the request fails and returns a JSONDecodeError.
    """
    args = {
        "incident-id": "1234",
        "other-fields": 'Invalid json'
    }
    from IBMResilientSystems import update_incident_command

    with pytest.raises(Exception) as exception:
        update_incident_command(MockClient, args)
    assert 'The other_fields argument is not a valid json.' in exception.value.args[0]


def test_add_note(_mocker):
    """
    Given:
     - An incident that should be updated with a note.

    When:
     - Running add_note_command function.

    Then:
     - Ensure the function runs as expected.
    """
    mock_result = _mocker.patch.object(MockClient, 'post')
    expected_result = ('/incidents/1234/comments', {'text': {'format': 'text', 'content': f'This is a new note\n{TAG_TO_IBM}'}})
    from IBMResilientSystems import add_note_command

    output = add_note_command(MockClient, "1234", "This is a new note", tag_to_ibm=TAG_TO_IBM)

    assert mock_result.call_args.args == expected_result
    assert '1234' in output.readable_output


def test_add_incident_artifact(_mocker):
    """
    Given:
     - An incident should be updated with an artifact.

    When:
     - Running add_artifact_command function.

    Then:
     - Ensure the function runs as expected.
    """
    mock_result = _mocker.patch.object(MockClient, 'post')
    expected_result = ('/incidents/1234/artifacts', {'type': 'IP Address', 'value': '1.1.1.1',
                                                     'description': {'format': 'text',
                                                                     'content': 'This is the artifact description'}})
    from IBMResilientSystems import add_artifact_command

    output = add_artifact_command(MockClient, "1234", "IP Address", "1.1.1.1", "This is the artifact description")

    assert mock_result.call_args.args == expected_result
    assert '1234' in output.get('HumanReadable')


def test_test_module(_mocker):
    """
    Tests whether the test module returns expected result for default http response.
    """

    from IBMResilientSystems import test_module, SimpleClient
    client = SimpleClient()
    _mocker.patch.object(client, 'get', return_value={})
    assert test_module(client, '2024-01-01T00:00:00Z') == "ok"


@pytest.mark.parametrize('fetch_time, expected_result', [
    ('2024-01-01T00:00:00Z', 'ok'),
    ('2024-01-01T00:00:00', 'ok'),
    ('', 'ok'),
    ('2024/01/01 00:00:00', 'fail'),
    ('invalid-date', 'fail'),
])
def test_test_module_fetch_time(fetch_time, expected_result, _mocker):
    """
    Tests whether the test module returns expected result for valid and invalid responses.
    """

    from IBMResilientSystems import test_module, SimpleClient, validate_iso_time_format
    client = SimpleClient()
    _mocker.patch.object(client, 'get', return_value={})
    fetch_time = validate_iso_time_format(fetch_time)
    if expected_result == 'fail':
        with pytest.raises(DemistoException):
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
            'conditions': [{'field_name': 'create_date', 'method': 'lte', 'value': 1641031200000}]
        }],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'length': DEFAULT_MAX_FETCH
    }),

    ({'page': 1, 'page_size': 10, 'last-modified-after': '2022-01-01T10:00:00Z'}, {
        'filters': [{'conditions': [{
            'field_name': 'inc_last_modified_date',
            'method': 'gte',
            'value': 1641031200000
        }]}],
        'sorts': [{'field_name': 'create_date', 'type': 'asc'}],
        'start': 0,
        'length': 10
    })
], ids=['no-filters-query', 'args-1-query', 'args-2-query', 'pagination-params-query']
)
def test_prepare_search_query_data(_mocker, args, expected):
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
            [{'create_date': '2024-07-31T11:11:08Z',
              'created_by': 'Demisto Resilient',
              'id': 0,
              'modify_date': 1722424268280,
              'text': 'insecure?'}]
        ),
        (
            [{"id": 2, "text": " ", "create_date": 1722424253387}],
            [{'create_date': '2024-07-31T11:10:53Z',
              'created_by': ' ',
              'id': 2,
              'modify_date': None,
              'text': ' '}]
        )

    ]
)
def test_prettify_incident_notes(_mocker, input_notes, expected_output):
    from IBMResilientSystems import prettify_incident_notes
    assert prettify_incident_notes(input_notes) == expected_output


@pytest.mark.parametrize('incidents, expected_output', [
    ([], 'No results found.'),
])
def test_search_incidents_command(_mocker, incidents, expected_output):
    from IBMResilientSystems import SimpleClient, search_incidents_command
    client = SimpleClient()
    _mocker.patch('IBMResilientSystems.search_incidents', return_value=incidents)

    assert search_incidents_command(client=client, args={}) == expected_output


@pytest.mark.parametrize(
    "args", [
        (
            {'date-created-after': 1577865600000, 'limit': '1000', 'page': '1', 'page_size': '10'}
        ),
    ]
)
def test_search_incidents(_mocker, args):
    from IBMResilientSystems import SimpleClient, search_incidents, DEFAULT_RETURN_LEVEL
    test_dict_response = load_test_data('./test_data/test_search_incidents_response.json')
    test_response = dict_to_response(test_dict_response)
    request = _mocker.patch.object(Session, "post", return_value=test_response)
    client = SimpleClient()
    client.org_id = 0
    search_incidents(client=client, args=args)

    request_url = request.call_args.args[0]
    request_headers = request.call_args.kwargs['headers']
    request_data = request.call_args.kwargs['data']

    assert request_url.endswith(
        f"/rest/orgs/0/incidents/query_paged?text_content_output_format=objects_convert_text&return_level="
        f"{args.get('return_level', DEFAULT_RETURN_LEVEL)}"
    )
    assert request_headers['content-type'] == 'application/json'
    assert request_data == (
        '{"filters": [{"conditions": [{"field_name": "create_date", "method": "gte", "value": 1577865600000}]}],'
        ' "sorts": [{"field_name": "create_date", "type": "asc"}], "length": 10, "start": 0}')


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
def test_update_incident_command(_mocker, args, processed_payload):
    from IBMResilientSystems import SimpleClient, update_incident_command
    client = SimpleClient()
    client.org_id = 0
    _mocker.patch.object(Session, 'get', return_value=dict_to_response(
        load_test_data('./test_data/test_get_incident_response.json')))

    request = _mocker.patch.object(Session, 'patch', return_value=dict_to_response({
        "success": True, "title": None, "message": None, "hints": []
    }))
    update_incident_command(client, args)
    assert request.call_args.args[0].endswith(f"/rest/orgs/{client.org_id}/incidents/{args['incident-id']}")
    assert json.loads(request.call_args[1]['data']) == processed_payload


def test_update_incident(_mocker):
    from IBMResilientSystems import SimpleClient, update_incident

    request = _mocker.patch.object(Session, 'patch', return_value=dict_to_response({
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
     'E-mail<br>Attrition<br> |  | Not an Issue | This is a test incident. |  | 2024-07-29T11:32:36Z |  | 2024-07-29T11:31:57Z '
     '|  | true | true | ExternalParty | 6 |  |'),
])
def test_get_incident_command(_mocker, incident_id, expected_human_readable):
    from IBMResilientSystems import SimpleClient, get_incident_command

    client = SimpleClient()
    client.org_id = 0
    _mocker.patch('IBMResilientSystems.get_users', return_value=[])
    _mocker.patch('IBMResilientSystems.get_phases', return_value={})
    _mocker.patch.object(Session, 'get', return_value=dict_to_response(
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
def test_list_scripts_command(_mocker, script_id: str, expected_outputs: list, expected_readable_output: str):
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

    _mocker.patch.object(SimpleClient, 'get', side_effect=side_effect)

    command_result = list_scripts_command(client, args)
    assert command_result.readable_output == expected_readable_output
    assert command_result.outputs == expected_outputs


@pytest.mark.parametrize('file_entry_id', ['ENTRY_ID'])
def test_upload_incident_attachment(_mocker, file_entry_id: str):
    from IBMResilientSystems import SimpleClient, upload_incident_attachment_command
    client = SimpleClient()
    client.org_id = 0
    response = {'status_code': 200}
    expected_output = "File was uploaded successfully to 1000."

    def mock_get_file_path(entry_id):  # noqa: F811
        if entry_id == 'ENTRY_ID':
            return {'path': '/path/to/file', 'name': 'filename.txt'}
        return None

    _mocker.patch.object(demisto, 'getFilePath', side_effect=mock_get_file_path)
    post_attachment_request = _mocker.patch.object(SimpleClient, 'post_attachment', return_value=response)

    args = {'entry_id': file_entry_id, 'incident_id': 1000}
    result = upload_incident_attachment_command(SimpleClient(), args, tag_to_ibm="FROM XSOAR")

    assert result.readable_output == expected_output
    post_attachment_request.assert_called_once_with(
        uri=f"/incidents/{args['incident_id']}/attachments",
        filepath='/path/to/file',
        filename=f'filename_{TAG_TO_IBM}.txt'
    )


def test_delete_incidents_command(_mocker):
    from IBMResilientSystems import SimpleClient, delete_incidents_command
    client = SimpleClient()
    client.org_id = 0

    delete_incident_request = _mocker.patch.object(SimpleClient, 'put', return_value={
        "success": True, "title": None, "message": None, "hints": []
    })

    incident_ids = ['1001', '1002']
    delete_incidents_command(client, args={"incident_ids": ','.join(incident_ids)})

    delete_incident_request.assert_called_once_with("/incidents/delete", payload=incident_ids)


def test_list_incident_notes_command(_mocker):
    from IBMResilientSystems import SimpleClient, list_incident_notes_command

    client = SimpleClient()
    client.org_id = 0

    get_incident_notes_request = _mocker.patch.object(
        SimpleClient,
        'get',
        return_value=load_test_data('./test_data/test_get_incident_notes_reponse.json')
    )
    list_incident_notes_command(client, {"incident_id": "2000"})

    get_incident_notes_request.assert_called_once_with(
        "/incidents/2000/comments?text_content_output_format=objects_convert_text"
    )


def test_update_incident_note(_mocker):
    from IBMResilientSystems import SimpleClient, update_incident_note_command

    client = SimpleClient()
    client.org_id = 0

    update_incident_note_request = _mocker.patch.object(
        SimpleClient,
        'put',
        return_value={}
    )
    update_incident_note_command(client, args={
        'incident_id': 2000,
        'note_id': 1,
        'note': "NOTE_BODY"
    })

    update_incident_note_request.assert_called_once_with("/incidents/2000/comments/1", payload={
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
            "due_date": 1680350400000,
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
            "due_date": 1682942400000,
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
def test_add_custom_task_command(_mocker, args, expected_task_dto):
    from IBMResilientSystems import SimpleClient, add_custom_task_command
    client = SimpleClient()
    client.org_id = 0

    def post_side_effect(uri, payload):
        if isinstance(expected_task_dto, Exception):
            raise expected_task_dto
        assert uri == f"/incidents/{args['incident_id']}/tasks"
        assert payload == expected_task_dto
        return {"id": "1234"}

    add_custom_task_request = _mocker.patch.object(
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
        assert (result.readable_output
                == f"Successfully created new task for incident with ID {args['incident_id']}. Task ID: 1234")


def test_list_tasks_command(_mocker):
    from IBMResilientSystems import SimpleClient, list_tasks_command
    client = SimpleClient()
    client.org_id = 0

    get_tasks_request = _mocker.patch.object(
        SimpleClient,
        'get',
        return_value={}
    )
    list_tasks_command(client)
    get_tasks_request.assert_called_with("/tasks")


def test_get_task_members_command(_mocker):
    from IBMResilientSystems import SimpleClient, get_task_members_command
    client = SimpleClient()
    client.org_id = 0
    task_id = "1234"
    get_task_members_request = _mocker.patch.object(
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
def test_delete_tasks_command(_mocker, task_ids, should_raise_exception):
    from IBMResilientSystems import SimpleClient, delete_tasks_command
    client = SimpleClient()
    client.org_id = 0

    delete_tasks_request = _mocker.patch.object(SimpleClient, 'put', return_value={
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


def test_delete_task_members_command(_mocker):
    from IBMResilientSystems import SimpleClient, delete_task_members_command
    client = SimpleClient()
    client.org_id = 0

    task_id = '1234'
    mock_response = {"content": "Members deleted successfully"}

    delete_task_members_request = _mocker.patch.object(
        SimpleClient,
        'delete',
        return_value=mock_response
    )
    delete_task_members_command(client, args={'task_id': task_id})

    delete_task_members_request.assert_called_once_with(f"/tasks/{task_id}/members")


def test_list_task_instructions_command(_mocker):
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

    get_task_instructions_request = _mocker.patch.object(
        SimpleClient,
        'get',
        return_value=mock_response
    )

    list_task_instructions_command(client, args={'task_id': task_id})

    get_task_instructions_request.assert_called_once_with(
        f"/tasks/{task_id}/instructions_ex?text_content_output_format=objects_convert_text"
    )


def test_get_attachment_command(_mocker):
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

    get_attachment_request = _mocker.patch.object(SimpleClient, 'get', side_effect=side_effect)

    args = {'incident_id': '1000', 'attachment_id': '1'}
    get_attachment_command(client, args)

    get_attachment_endpoint = f'/incidents/{args.get("incident_id")}/attachments/{args.get("attachment_id")}'
    get_attachment_contents_endpoint = get_attachment_endpoint + '/contents'

    # Check the calls made to the mock
    get_attachment_request.assert_has_calls([
        _mocker.call(get_attachment_endpoint),
        _mocker.call(get_attachment_contents_endpoint, get_response_object=True)
    ])


def test_get_modified_remote_data_command(_mocker):
    from IBMResilientSystems import SimpleClient, get_modified_remote_data_command
    from CommonServerPython import GetModifiedRemoteDataResponse

    client = SimpleClient()
    client.org_id = 0

    mock_search_incidents = _mocker.patch('IBMResilientSystems.search_incidents', return_value=[
        {'id': 1000, 'last_modified_time': '2023-09-01T12:01:00Z'},
        {'id': 1001, 'last_modified_time': '2023-09-01T12:02:00Z'}
    ])
    expected_output = GetModifiedRemoteDataResponse(['1000', '1001'])

    last_update = '2023-09-01T12:00:00Z'
    args = {'lastUpdate': last_update}
    result = get_modified_remote_data_command(client, args)

    mock_search_incidents.assert_called_once_with(client, args={'last-modified-after': last_update})
    assert result.modified_incident_ids == expected_output.modified_incident_ids


def test_get_remote_data_command(_mocker):
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

    _mocker.patch('IBMResilientSystems.get_incident', return_value=mock_incident_data)
    _mocker.patch('IBMResilientSystems.process_raw_incident', return_value=mock_incident_data)

    # Mock get_attachment and handle_incoming_incident_resolution
    _mocker.patch('IBMResilientSystems.get_attachment', return_value=("filename.txt", b"file content"))
    _mocker.patch('IBMResilientSystems.handle_incoming_incident_resolution', return_value={'Contents': 'Incident resolved'})
    # Call the command and capture the result
    result = get_remote_data_command(client, args, tag_to_ibm="FROM ", tag_from_ibm="TO ")

    # Check if the result contains the expected mirrored data and entries
    assert len(result.entries) == 3  # A note, a file, and a reopen entry.
    assert "Note content" in result.entries[0].get('Contents')
    assert "filename.txt" in result.entries[1].get('File')
    assert result.mirrored_object


def test_update_remote_system_command_no_changes(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command

    client = SimpleClient()
    args = {
        'remoteId': '1000',
        'incidentChanged': False,
        'entries': [],
        'delta': None,
        'data': {},
        'incStatus': 'Active'
    }

    debug_mock = _mocker.patch.object(demisto, 'debug')
    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1000'
    debug_mock.assert_called_with(
        "Skipping updating remote incident fields [1000] as it is not new nor changed"
    )


def test_update_remote_system_command_with_changes(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command

    client = SimpleClient()
    args = {
        'remoteId': '1001',
        'incidentChanged': True,
        'entries': [],
        'delta': {'name': 'Updated Incident Name'},
        'data': {},
        'incStatus': 'Active'
    }

    prepare_mock = _mocker.patch('IBMResilientSystems.prepare_incident_update_dto_for_mirror',
                                 return_value={'name': 'Updated Incident Name'})
    update_mock = _mocker.patch('IBMResilientSystems.update_incident')

    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1001'
    prepare_mock.assert_called_once_with(client, '1001', {'name': 'Updated Incident Name'})
    update_mock.assert_called_once_with(client, '1001', {'name': 'Updated Incident Name'})


def test_update_remote_system_command_with_note(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command
    from CommonServerPython import EntryType

    client = SimpleClient()
    args = {
        'remoteId': '1002',
        'incidentChanged': False,
        'entries': [{'id': '1', 'type': EntryType.NOTE, 'tags': ['FROM XSOAR'], 'Contents': 'Test note'}],
        'delta': None,
        'data': {},
        'incStatus': 'Active'
    }

    add_note_mock = _mocker.patch('IBMResilientSystems.add_note')

    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1002'
    add_note_mock.assert_called_once_with(client, '1002', 'Test note')


def test_update_remote_system_command_with_file(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command
    from CommonServerPython import EntryType

    client = SimpleClient()
    args = {
        'remoteId': '1003',
        'incidentChanged': False,
        'entries': [{'id': '2', 'type': EntryType.FILE, 'tags': ['FROM XSOAR'], 'Contents': 'file content'}],
        'delta': None,
        'data': {},
        'incStatus': 'Active'
    }

    upload_mock = _mocker.patch('IBMResilientSystems.upload_incident_attachment')

    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1003'
    upload_mock.assert_called_once_with(client, '1003', '2', "FROM XSOAR")


def test_update_remote_system_command_with_multiple_entries(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command
    from CommonServerPython import EntryType

    client = SimpleClient()
    args = {
        'remoteId': '1004',
        'incidentChanged': True,
        'entries': [
            {'id': '3', 'type': EntryType.NOTE, 'tags': ['FROM XSOAR'], 'Contents': 'Test note 1'},
            {'id': '4', 'type': EntryType.FILE, 'tags': ['FROM XSOAR'], 'Contents': 'file content'},
            {'id': '5', 'type': EntryType.NOTE, 'tags': ['FROM XSOAR'], 'Contents': 'Test note 2'}
        ],
        'delta': {'description': 'Updated description'},
        'data': {},
        'incStatus': 'Active'
    }

    prepare_mock = _mocker.patch('IBMResilientSystems.prepare_incident_update_dto_for_mirror',
                                 return_value={'description': 'Updated description'})
    update_mock = _mocker.patch('IBMResilientSystems.update_incident')
    add_note_mock = _mocker.patch('IBMResilientSystems.add_note')
    upload_mock = _mocker.patch('IBMResilientSystems.upload_incident_attachment')

    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1004'
    prepare_mock.assert_called_once_with(client, '1004', {'description': 'Updated description'})
    update_mock.assert_called_once_with(client, '1004', {'description': 'Updated description'})
    assert add_note_mock.call_count == 2
    add_note_mock.assert_any_call(client, '1004', 'Test note 1')
    add_note_mock.assert_any_call(client, '1004', 'Test note 2')
    upload_mock.assert_called_once_with(client, '1004', '4', "FROM XSOAR")


def test_update_remote_system_command_with_untagged_entries(_mocker):
    from IBMResilientSystems import SimpleClient, update_remote_system_command
    from CommonServerPython import EntryType

    client = SimpleClient()
    args = {
        'remoteId': '1005',
        'incidentChanged': False,
        'entries': [
            {'id': '6', 'type': EntryType.NOTE, 'tags': [], 'Contents': 'Untagged note'},
            {'id': '7', 'type': EntryType.FILE, 'tags': [], 'Contents': 'Untagged file'}
        ],
        'delta': None,
        'data': {},
        'incStatus': 'Active'
    }

    add_note_mock = _mocker.patch('IBMResilientSystems.add_note')
    upload_mock = _mocker.patch('IBMResilientSystems.upload_incident_attachment')

    result = update_remote_system_command(client, args, tag_to_ibm="FROM XSOAR")

    assert result == '1005'
    add_note_mock.assert_not_called()
    upload_mock.assert_not_called()


def test_get_mapping_fields_command(_mocker):
    from IBMResilientSystems import (
        get_mapping_fields_command, IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME, IBM_QRADAR_INCIDENT_FIELDS
    )
    from CommonServerPython import GetMappingFieldsResponse

    response = get_mapping_fields_command()
    assert isinstance(response, GetMappingFieldsResponse)

    # Get the mapping scheme from the response
    scheme = response.scheme_types_mappings[0]
    # Assert that the scheme has the correct incident schema name
    assert scheme.type_name == IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME

    # Assert that the scheme contains the correct fields
    for field_name, _field_data in IBM_QRADAR_INCIDENT_FIELDS.items():
        assert field_name in scheme.fields


@pytest.mark.parametrize('last_run, first_fetch_time, expected_args, expected_last_run', [
    (None, '2023-01-01T00:00:00Z', {'date-created-after': 1672531200000}, 1672531200001),
    ({'time': 1672531200000}, '2023-01-01T00:00:00Z', {'date-created-after': 1672531200000}, 1672531200001),
])
def test_fetch_incidents(_mocker, last_run, first_fetch_time, expected_args, expected_last_run):
    from IBMResilientSystems import SimpleClient, fetch_incidents

    mock_search_incidents = _mocker.patch('IBMResilientSystems.search_incidents', return_value=[])
    mock_set_last_run = _mocker.patch.object(demisto, 'setLastRun', return_value=None)

    client = SimpleClient()
    client.org_id = 0
    fetch_incidents(client, first_fetch_time, fetch_closed=True)

    mock_search_incidents.assert_called_once_with(client, {'date-created-after': expected_args['date-created-after']})
    mock_set_last_run.assert_called_once_with({'time': expected_last_run})


def test_to_timestamp_with_integer(_mocker):
    from IBMResilientSystems import to_timestamp
    assert to_timestamp(1641024000000) == 1641024000000


def test_to_timestamp_with_string_timestamp(_mocker):
    from IBMResilientSystems import to_timestamp
    assert to_timestamp("1641024000000") == 1641024000000


def test_to_timestamp_with_string_date(_mocker):
    from IBMResilientSystems import to_timestamp
    assert to_timestamp("2022-01-01T12:00:00Z") == 1641038400000


def test_to_timestamp_with_invalid_string(_mocker):
    from IBMResilientSystems import to_timestamp
    import pytest
    with pytest.raises(ValueError):
        to_timestamp("INVALID_DATE_STRING")


def test_validate_iso_time_format_with_milliseconds(_mocker):
    from IBMResilientSystems import validate_iso_time_format
    input_time = "2023-01-01T12:30:45.123456Z"
    expected_output = "2023-01-01T12:30:45Z"
    assert validate_iso_time_format(input_time) == expected_output


def test_validate_iso_time_format_without_z(_mocker):
    from IBMResilientSystems import validate_iso_time_format
    input_time = "2023-01-01T12:30:45"
    expected_output = "2023-01-01T12:30:45Z"
    assert validate_iso_time_format(input_time) == expected_output


def test_validate_iso_time_format_with_z(_mocker):
    from IBMResilientSystems import validate_iso_time_format
    input_time = "2023-01-01T12:30:45Z"
    expected_output = "2023-01-01T12:30:45Z"
    assert validate_iso_time_format(input_time) == expected_output


def test_update_task_command_multiple_fields(_mocker):
    from IBMResilientSystems import SimpleClient, update_task_command
    client = SimpleClient()
    args = {
        'task_id': '5678',
        'name': 'Complex Task',
        'owner_id': '10',
        'due_date': '2023-12-31T23:59:59Z',
        'phase': 'Engage',
        'instructions': 'Investigate thoroughly',
        'status': 'Open'
    }

    update_task_mock = _mocker.patch('IBMResilientSystems.update_task')
    _mocker.patch('IBMResilientSystems.to_timestamp', return_value=1704067199000)

    result = update_task_command(client, args)

    expected_dto = {
        'name': 'Complex Task',
        'inc_owner_id': 10,
        'due_date': 1704067199000,
        'phase_id': 'Engage',
        'instructions': 'Investigate thoroughly',
        'status': 'O'
    }
    update_task_mock.assert_called_once_with(client, '5678', expected_dto)
    assert result.readable_output == 'Task 5678 updated successfully.'


def test_update_task_command_completed_status(_mocker):
    from IBMResilientSystems import SimpleClient, update_task_command
    client = SimpleClient()
    args = {'task_id': '9012', 'status': 'Completed'}

    update_task_mock = _mocker.patch('IBMResilientSystems.update_task')

    result = update_task_command(client, args)

    update_task_mock.assert_called_once_with(client, '9012', {'status': 'C'})
    assert result.readable_output == 'Task 9012 updated successfully.'


def test_update_task_command_invalid_status(_mocker):
    from IBMResilientSystems import SimpleClient, update_task_command
    client = SimpleClient()
    args = {'task_id': '3456', 'status': 'Invalid'}

    update_task_mock = _mocker.patch('IBMResilientSystems.update_task')

    result = update_task_command(client, args)

    update_task_mock.assert_called_once_with(client, '3456', {})
    assert result.readable_output == 'Task 3456 updated successfully.'


def test_update_task_command_empty_args(_mocker):
    from IBMResilientSystems import SimpleClient, update_task_command
    client = SimpleClient()
    args = {'task_id': '7890'}

    update_task_mock = _mocker.patch('IBMResilientSystems.update_task')

    result = update_task_command(client, args)

    update_task_mock.assert_called_once_with(client, '7890', {})
    assert result.readable_output == 'Task 7890 updated successfully.'


def test_process_raw_incident(_mocker):
    _mocker.patch.object(demisto, 'params', return_value={'server': 'example.com:80',
                                                          'org': 'example',
                                                          'proxy': True,
                                                          'fetch_tasks': True,
                                                          'fetch_notes': True
                                                          })

    from IBMResilientSystems import SimpleClient, process_raw_incident
    client = SimpleClient()

    _mocker.patch('IBMResilientSystems.get_tasks', return_value=[])
    _mocker.patch('IBMResilientSystems.get_incident_notes', return_value=[])
    _mocker.patch('IBMResilientSystems.incident_attachments', return_value=[])
    _mocker.patch('IBMResilientSystems.incident_artifacts', return_value=[])
    _mocker.patch('IBMResilientSystems.get_phase_name', return_value="Detect/Analyze")

    result = process_raw_incident(client, load_test_data("./test_data/test_get_incident_response.json"))

    assert result["description"] == "1111 2222 3333"
    assert result["discovered_date"] == "2024-07-29T11:31:57Z"
    assert result["create_date"] == "2024-07-29T11:32:36Z"


@pytest.mark.parametrize("incident_id, delta, expected_dto", [
    (
        "1000",
        {"ibmsecurityqradarsoarname": "Updated Incident Name", "description": "New description"},
        {'changes': [
            {
                'field': 'name',
                'new_value': {'text': 'Updated Incident Name'},
                'old_value': {'text': 'incident_name'}
            },
            {
                'field': 'description',
                'new_value': {
                    'textarea': {
                        'content': 'New description',
                        'format': 'html'
                    }
                },
                'old_value': {
                    'textarea': {
                        'content': '1111 2222 3333',
                        'format': 'html'
                    }
                }
            }
        ]
        }
    ),
    (
        "1001",
        {"resolution_id": ""},
        {
            'changes': [
                {
                    'field': 'plan_status',
                    'new_value': {'text': 'C'},
                    'old_value': {'text': 'A'}},
                {
                    'field': 'resolution_id',
                    'new_value': {'textarea': None},
                    'old_value': {'id': 9}
                }
            ]
        }
    )
])
def test_prepare_incident_update_dto_for_mirror(_mocker, incident_id, delta, expected_dto):
    from IBMResilientSystems import SimpleClient, prepare_incident_update_dto_for_mirror

    client = SimpleClient()
    client.org_id = 0

    mock_get_incident = _mocker.patch('IBMResilientSystems.get_incident',
                                      return_value=load_test_data('./test_data/test_get_incident_response.json'))

    _mocker.patch.object(demisto, 'params', return_value={'close_ibm_incident': True})

    result = prepare_incident_update_dto_for_mirror(client, incident_id, delta)

    mock_get_incident.assert_called_once_with(client, incident_id)
    assert result == expected_dto


def test_prettify_incident_tasks_multiple_tasks(_mocker):
    from IBMResilientSystems import SimpleClient, prettify_incident_tasks
    client = SimpleClient()
    tasks = [
        {
            'id': 1,
            'name': 'Task 1',
            'description': 'Description 1',
            'due_date': 1641024000000,
            'status': 'O',
            'required': True,
            'owner_fname': 'John',
            'owner_lname': 'Doe',
            'phase_id': 1,
            'creator_principal': {'display_name': 'Admin User'},
            'instructions': {'content': 'Instructions 1'}
        },
        {
            'id': 2,
            'name': 'Task 2',
            'description': 'Description 2',
            'due_date': None,
            'status': 'C',
            'required': False,
            'owner_fname': 'Jane',
            'owner_lname': 'Smith',
            'phase_id': 2,
            'creator_principal': None,
            'instructions': None
        }
    ]
    _mocker.patch('IBMResilientSystems.get_phase_name', side_effect=['Initial', 'Analysis'])
    _mocker.patch('IBMResilientSystems.normalize_timestamp', return_value='2022-01-01T12:00:00Z')

    result = prettify_incident_tasks(client, tasks)

    assert len(result) == 2
    assert result[0]['ID'] == 1
    assert result[0]['Name'] == 'Task 1'
    assert result[0]['Status'] == 'Open'
    assert result[0]['DueDate'] == '2022-01-01T12:00:00Z'
    assert result[0]['Phase'] == 'Initial'
    assert result[0]['Creator'] == 'Admin User'
    assert result[0]['Instructions'] == 'Instructions 1'

    assert result[1]['ID'] == 2
    assert result[1]['Name'] == 'Task 2'
    assert result[1]['Status'] == 'Closed'
    assert result[1]['DueDate'] == 'No due date'
    assert result[1]['Phase'] == 'Analysis'
    assert result[1]['Creator'] == ''
    assert result[1]['Instructions'] == ''


def test_prettify_incident_tasks_missing_fields(_mocker):
    from IBMResilientSystems import SimpleClient, prettify_incident_tasks
    client = SimpleClient()
    tasks = [{
        'id': 1,
        'name': 'Minimal Task',
        'description': '',
        'due_date': None,
        'status': 'O',
        'required': False,
        'phase_id': 1
    }]
    _mocker.patch('IBMResilientSystems.get_phase_name', return_value='Initial')

    result = prettify_incident_tasks(client, tasks)

    assert len(result) == 1
    assert result[0]['ID'] == 1
    assert result[0]['Name'] == 'Minimal Task'
    assert result[0]['Description'] == ''
    assert result[0]['DueDate'] == 'No due date'
    assert result[0]['Status'] == 'Open'
    assert result[0]['Required'] is False
    assert result[0]['Owner'] == ' '
    assert result[0]['Phase'] == 'Initial'
    assert result[0]['Creator'] == ''
    assert result[0]['Instructions'] == ''


def test_list_open_incidents(_mocker):
    from IBMResilientSystems import SimpleClient, list_open_incidents
    client = SimpleClient()
    get_incidents_request = _mocker.patch.object(SimpleClient, 'get', return_value=[])

    list_open_incidents(client)
    get_incidents_request.assert_called_once_with('/incidents/open')


def test_get_users(_mocker):
    from IBMResilientSystems import SimpleClient, get_users
    client = SimpleClient()
    _mocker.patch.object(SimpleClient, 'get', return_value=[])
    get_users(client)
    client.get.assert_called_once_with('/users')


def test_get_phase_name(_mocker):
    from IBMResilientSystems import SimpleClient, get_phase_name
    client = SimpleClient()
    _mocker.patch.object(SimpleClient, 'get', return_value={
        "id": 1004,
        "name": "Engage",
        "enabled": True,
        "perms": {
            "deleteable": True,
            "reorderable": True
        },
        "uuid": "0000-0000-0000-00000",
        "order": 1,
        "tags": []
    })

    get_phase_name(client, '1004')

    client.get.assert_called_once_with('/phases/1004')


def test_get_phases(_mocker):
    from IBMResilientSystems import SimpleClient, get_phases
    client = SimpleClient()
    _mocker.patch.object(SimpleClient, 'get', return_value={
        "entities": [
            {
                "id": 1003,
                "name": "Initial",
                "enabled": True,
                "perms": {
                    "deleteable": False,
                    "reorderable": False
                },
                "uuid": "0000-0000-0000-0000",
                "order": 0,
                "tags": []
            }
        ]
    })
    get_phases(client)

    client.get.assert_called_once_with('/phases')


def test_get_tasks(_mocker):
    from IBMResilientSystems import SimpleClient, get_tasks
    client = SimpleClient()
    _mocker.patch.object(SimpleClient, 'get', return_value=[])

    get_tasks(client, '1000')

    client.get.assert_called_once_with('/incidents/1000/tasks?text_content_output_format=objects_convert_text')


@pytest.mark.parametrize("resolution_id, resolution_summary, expected_close_reason, expected_close_notes", [
    (8, "Duplicate issue", "Duplicate", "Duplicate issue"),
    (0, "Hardware failure", "Resolved", "Hardware failure"),
    (None, "User error", "Resolved", "User error")
])
def test_handle_incoming_incident_resolution(_mocker,
                                             resolution_id,
                                             resolution_summary,
                                             expected_close_reason,
                                             expected_close_notes):
    from IBMResilientSystems import EntryType, EntryFormat, handle_incoming_incident_resolution
    incident_id = "1234"
    result = handle_incoming_incident_resolution(incident_id, resolution_id, resolution_summary)

    assert result["Type"] == EntryType.NOTE
    assert result["ContentsFormat"] == EntryFormat.JSON
    assert result["Contents"]["dbotIncidentClose"] is True
    assert result["Contents"]["closeReason"] == expected_close_reason
    assert result["Contents"]["closeNotes"] == f"{expected_close_notes}\nClosed on IBM QRadar SOAR"


def test_handle_incoming_incident_resolution_unknown_resolution(_mocker):
    from IBMResilientSystems import EntryType, EntryFormat, handle_incoming_incident_resolution
    incident_id = "5678"
    resolution_id = 999  # Unknown resolution ID
    resolution_summary = "Unknown resolution"
    result = handle_incoming_incident_resolution(incident_id, resolution_id, resolution_summary)

    assert result["Type"] == EntryType.NOTE
    assert result["ContentsFormat"] == EntryFormat.JSON
    assert result["Contents"]["dbotIncidentClose"] is True
    assert result["Contents"]["closeReason"] == "Resolved"
    assert result["Contents"]["closeNotes"] == "Unknown resolution\nClosed on IBM QRadar SOAR"

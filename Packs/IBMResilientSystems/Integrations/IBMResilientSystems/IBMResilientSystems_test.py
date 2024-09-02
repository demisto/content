import json
from io import BytesIO

import pytest
import requests
from requests import Session

from pytest import raises

import demistomock as demisto
from CommonServerPython import DemistoException

DEFAULT_MAX_FETCH = 1000


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


def test_update_incident_command(mocker):
    """
    Given:
     - An incident should be updated.

    When:
     - Running update_incident_command function with other-fields argument.

    Then:
     - Ensure the parsing before the request works well and json data is in IBM format.
    """
    mocker.patch.object(demisto, 'params', return_value={'server': 'example.com:80', 'org': 'example', 'proxy': True})
    args = {
        "incident-id": "1234",
        "other-fields": '{"description": {"textarea": {"format": "html", "content": "The new description"}},'
                        '"name": {"text": "The new name"}, "owner_id": {"id": 2},'
                        '"discovered_date": {"date": 1624782898010}, "confirmed": {"boolean": "false"}}'
    }
    mock_result = mocker.patch('IBMResilientSystems.update_incident')
    expected_result = {
        'changes': [
            {
                'field': {'name': 'confirmed'},
                'old_value': {'boolean': 'true'},
                'new_value': {'boolean': 'false'}
            },
            {
                'field': {'name': 'discovered_date'},
                'old_value': {'date': 1624782898000},
                'new_value': {'date': 1624782898010}
            },
            {
                'field': {'name': 'owner_id'},
                'old_value': {'id': 1},
                'new_value': {'id': 2}
            },
            {
                'field': {'name': 'description'},
                'old_value': {'textarea': {'format': 'html', 'content': 'The old description'}},
                'new_value': {'textarea': {'format': 'html', 'content': 'The new description'}}
            },
            {
                'field': {'name': 'name'},
                'old_value': {'text': 'The old name'},
                'new_value': {'text': 'The new name'}
            }
        ]
    }
    from IBMResilientSystems import update_incident_command

    update_incident_command(MockClient, args)

    no_order_list_equals(mock_result.call_args.args[2]['changes'], expected_result['changes'])


def no_order_list_equals(l1: list, l2: list):
    assert len(l1) == len(l2)
    assert all(item in l2 for item in l1)


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
    expected_result = ('/incidents/1234/comments', {'text': {'format': 'text', 'content': 'This is a new note'}})
    from IBMResilientSystems import add_note_command

    output = add_note_command(MockClient, "1234", "This is a new note")

    assert mock_result.call_args.args == expected_result
    assert '1234' in output.get('HumanReadable')


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
    ('', 'ok'),
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
    from IBMResilientSystems import test_module, SimpleClient, validate_fetch_time
    client = SimpleClient()
    mocker.patch.object(client, 'get', return_value={})
    fetch_time = validate_fetch_time(fetch_time)
    if expected_result == 'fail':
        with raises(DemistoException):
            test_module(client, fetch_time)
    else:
        assert test_module(client, fetch_time) == expected_result


@pytest.mark.parametrize("args, expected", [
    ({}, {'filters': [{'conditions': []}], 'length': DEFAULT_MAX_FETCH}),  # Test without any filters or pagination params
    ({'severity': 'Low'}, {
        'filters': [{
            'conditions': [{'field_name': 'severity_code', 'method': 'in', 'value': [50]}]
        }],
        'length': DEFAULT_MAX_FETCH
    }),
    ({'date-created-before': '2022-01-01T10:00:00Z'}, {
        'filters': [{
            'conditions': [{'field_name': 'create_date', 'method': 'lte', 'value': 1641024000000}]
        }],
        'length': DEFAULT_MAX_FETCH
    }),
    ({'page': 1, 'page_size': 10, 'last-modified-after': '2022-01-01T10:00:00Z'}, {
        'filters': [{'conditions': [{
            'field_name': 'inc_last_modified_date',
            'method': 'gte',
            'value': 1641024000000
        }]}],
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
                "text": "<div class=\"rte\"><div><s>insecure?</s></div></div>",
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
            [{"id": 0, "text": "insecure?", "create_date": "2024-07-31T14:11:08Z"}]
        ),
        (
            [{"id": 2, "text": "<div class=\"rte\"></div>", "create_date": 1722424253387}],
            [{"id": 2, "text": "", "create_date": "2024-07-31T14:10:53Z"}]
        ),
        (
            [{"id": 3, "text": "<div>note1</div><div>note2</div>", "create_date": 1722424253387}],
            [{"id": 3, "text": "note1note2", "create_date": "2024-07-31T14:10:53Z"}]
        ),
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
        f"/rest/orgs/0/incidents/query_paged?return_level={args.get('return_level', DEFAULT_RETURN_LEVEL)}"
    )
    assert request_headers['content-type'] == 'application/json'
    assert request_data == ('{"filters": [{"conditions": [{"field_name": "create_date", "method": "gte", "value": '
                            '1577865600000}]}], "length": 10, "start": 0}')


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
                     {"field": "resolution_id", "old_value": {"id": 9}, "new_value": {"id": 9}}, {"field": "resolution_summary",
                                                                                                  "old_value": {
                                                                                                      "textarea": {"format": "html",
                                                                                                                   "content": "This is a test incident."}},
                                                                                                  "new_value": {
                                                                                                      "textarea": {"format": "html",
                                                                                                                   "content": "This is a test incident."}}},
                     {"field": "description", "old_value": {"textarea": {"format": "html",
                                                                         "content": "<div class=\"rte\"><div>1111</div><div>2222</div><div>3333</div></div>"}},
                      "new_value": {"textarea": {"format": "html", "content": "Test incident"}}},
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
     '### IBM QRadar SOAR incident ID 1000\n|Id|Name|Description|NistAttackVectors|Phase|Resolution|ResolutionSummary|Owner|CreatedDate|DateOccurred|DiscoveredDate|DueDate|NegativePr|Confirmed|ExposureType|Severity|Reporter|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| 1000 | incident_name | 1111<br>2222<br>3333 | E-mail<br>Attrition<br> |  | Not an Issue | This is a test incident. |  | 2024-07-29T14:32:36Z |  | 2024-07-29T14:31:57Z |  | true | true | ExternalParty | 6 |  |'),
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


@pytest.mark.parametrize('file_entry_id', ['VALID_ENTRY_ID', 'INVALID_ENTRY_ID'])
def test_upload_incident_attachment(mocker, file_entry_id: str):

    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True
    })
    from IBMResilientSystems import SimpleClient, upload_incident_attachment_command
    from CommonServerPython import EntryType
    client = SimpleClient()
    client.org_id = 0
    response = {'status_code': 200}
    expected_output = "File was uploaded successfully to 1000."
    expected_error_output = f"Could not find a file with entry ID: {file_entry_id}"

    def mock_get_file_path(entry_id):  # noqa: F811
        if entry_id == 'VALID_ENTRY_ID':
            return {'path': '/path/to/file', 'name': 'filename.txt'}
        elif entry_id == 'INVALID_ENTRY_ID':
            raise ValueError("Invalid file path")
        return None
    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_get_file_path)
    post_attachment_request = mocker.patch.object(SimpleClient, 'post_attachment', return_value=response)

    args = {'entry_id': file_entry_id, 'incident_id': 1000}
    result = upload_incident_attachment_command(SimpleClient(), args)

    if file_entry_id == 'VALID_ENTRY_ID':
        assert result.readable_output == expected_output
        post_attachment_request.assert_called_once_with(
            uri=f"/incidents/{args['incident_id']}/attachments",
            filepath='/path/to/file',
            filename='filename.txt'
        )
    else:
        assert result.entry_type == EntryType.ERROR
        assert result.readable_output == expected_error_output
        post_attachment_request.assert_not_called()


def test_delete_incidents_command(mocker, ):
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



def test_fetch_incidents(mocker):
    # TODO
    pass

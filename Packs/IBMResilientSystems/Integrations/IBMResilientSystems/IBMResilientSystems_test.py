import json

import pytest
from pytest import raises

import demistomock as demisto
from CommonServerPython import DemistoException
import requests
from io import BytesIO

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
    assert len(l1) == len(l2) and all(item in l2 for item in l1)


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


@pytest.mark.parametrize(
    "args", [
        (
            {'date-created-after': '2020-01-01T10:00:00Z', 'limit': '1000', 'page': '1', 'page_size': '10'}
        ),
    ]
)
def test_search_incidents(mocker, args):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from requests import Session
    from co3 import SimpleClient
    from IBMResilientSystems import search_incidents, DEFAULT_RETURN_LEVEL
    test_dict_response = load_test_data('./test_data/test_response.json')
    test_response = dict_to_response(test_dict_response)
    request = mocker.patch.object(Session, "post", return_value=test_response)
    client = SimpleClient()
    client.org_id = 0
    search_incidents(client=client, args=args)

    request_url = request.call_args.args[0]
    request_headers = request.call_args.kwargs['headers']
    request_data = request.call_args.kwargs['data']
    assert request_url.endswith(
        f"/rest/orgs/0/incidents/query_paged?return_level={args.get('return_level', DEFAULT_RETURN_LEVEL)}")
    assert request_headers['content-type'] == 'application/json'
    assert request_data == ('{"filters": [{"conditions": [{"field_name": "create_date", "method": "gte", "value": '
                            '1577865600000}]}], "length": 10, "start": 0}')

@pytest.mark.parametrize("script_id", ['100', '', 'INVALID_SCRIPT'])
def test_list_scripts(mocker, script_id):
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from requests import Session
    from co3 import SimpleClient
    from IBMResilientSystems import list_scripts_command, DEFAULT_RETURN_LEVEL

    test_dict_response = load_test_data('./test_data/test_response.json')
    test_response = dict_to_response(test_dict_response)
    request = mocker.patch.object(Session, "post", return_value=test_response)
    client = SimpleClient()
    client.org_id = 0
    list_scripts_command(client=client, args=args)

    request_url = request.call_args.args[0]
    request_headers = request.call_args.kwargs['headers']
    request_data = request.call_args.kwargs['data']
    assert request_url.endswith(
        f"/rest/orgs/0/incidents/query_paged?return_level={args.get('return_level', DEFAULT_RETURN_LEVEL)}")
    assert request_headers['content-type'] == 'application/json'
    assert request_data == ('{"filters": [{"conditions": [{"field_name": "create_date", "method": "gte", "value": '
                            '1577865600000}]}], "length": 10, "start": 0}')
class TestGetMappingFieldsCommand:
    def test_get_mapping_fields_command(self):
        response = get_mapping_fields_command()
        assert isinstance(response, GetMappingFieldsResponse)
        assert len(response.scheme_types) == 1
        assert response.scheme_types[0].type_name == IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME
        assert response.scheme_types[0].fields == IBM_QRADAR_INCIDENT_FIELDS

class TestValidateFetchTime:
    @pytest.mark.parametrize("fetch_time, expected", [
        ("2021-01-01T00:00:00", "2021-01-01T00:00:00Z"),
        ("2021-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
        ("", ""),
        (None, None),
    ])
    def test_validate_fetch_time(self, fetch_time, expected):
        assert validate_fetch_time(fetch_time) == expected

class TestNormalizeTimestamp:
    @pytest.mark.parametrize("timestamp, expected", [
        (1609459200000, "2021-01-01T00:00:00Z"),
        (1609459200001, "2021-01-01T00:00:00Z"),
        (0, "1970-01-01T00:00:00Z"),
    ])
    def test_normalize_timestamp(self, timestamp, expected):
        assert normalize_timestamp(timestamp) == expected

class TestPrettifyIncidentNotes:
    def test_prettify_incident_notes(self):
        notes = [
            {"id": 1, "text": "<p>Test note</p>", "create_date": 1609459200000},
            {"id": 2, "text": "<div>Another note</div>", "create_date": 1609545600000},
        ]
        expected = [
            {"id": 2, "text": "Another note", "create_date": "2021-01-02T00:00:00Z"},
            {"id": 1, "text": "Test note", "create_date": "2021-01-01T00:00:00Z"},
        ]
        assert prettify_incident_notes(notes) == expected

class TestPrepareSearchQueryData:
    @pytest.mark.parametrize("args, expected", [
        (
            {"severity": "Low,Medium", "date-created-after": "2021-01-01T00:00:00Z"},
            {
                "filters": [{
                    "conditions": [
                        {"field_name": "severity_code", "method": "in", "value": [50, 51]},
                        {"field_name": "create_date", "method": "gte", "value": 1609459200000}
                    ]
                }],
                "length": 1000
            }
        ),
        (
            {"incident-type": "Malware", "nist": "Web", "status": "Active"},
            {
                "filters": [{
                    "conditions": [
                        {"field_name": "incident_type_ids", "method": "contains", "value": [19]},
                        {"field_name": "nist_attack_vectors", "method": "contains", "value": [3]},
                        {"field_name": "plan_status", "method": "in", "value": ["A"]}
                    ]
                }],
                "length": 1000
            }
        ),
    ])
    def test_prepare_search_query_data(self, args, expected):
        result = prepare_search_query_data(args)
        assert result == expected

class TestGetMirroringData:
    def test_get_mirroring_data(self, mocker):
        mocker.patch.object(demisto, 'params', return_value={'mirror_direction': 'Incoming'})
        mocker.patch.object(demisto, 'integrationInstance', return_value='test_instance')
        expected = {
            'mirror_direction': 'Incoming',
            'mirror_instance': 'test_instance',
            'mirror_tags': []
        }
        assert get_mirroring_data() == expected

class TestGetClient:
    @pytest.mark.parametrize("api_key_id, api_key_secret, username, password, expected_auth", [
        ("test_id", "test_secret", None, None, {"api_key_id": "test_id", "api_key_secret": "test_secret"}),
        (None, None, "test_user", "test_pass", {"email": "test_user", "password": "test_pass"}),
        (None, None, None, None, None),
    ])
    def test_get_client(self, mocker, api_key_id, api_key_secret, username, password, expected_auth):
        mocker.patch.object(resilient, 'get_client', return_value=mocker.Mock())
        mocker.patch.dict(os.environ, {"SSL_CERT_FILE": "test_cert"})
        mocker.patch('builtins.globals', return_value={
            'SERVER': 'test_server',
            'PORT': '443',
            'USE_SSL': True,
            'ORG_NAME': 'test_org',
            'API_KEY_ID': api_key_id,
            'API_KEY_SECRET': api_key_secret,
            'USERNAME': username,
            'PASSWORD': password,
        })

        if expected_auth is None:
            with pytest.raises(SystemExit):
                get_client()
        else:
            client = get_client()
            expected_opts = {
                'host': 'test_server',
                'port': '443',
                'cafile': 'test_cert',
                'org': 'test_org',
                **expected_auth
            }
            resilient.get_client.assert_called_once_with(opts=expected_opts)
            assert client.request_max_retries == DEFAULT_RETRIES

class TestTestModule:
    def test_test_module_success(self, mocker):
        mock_client = mocker.Mock()
        mock_client.get.return_value = {}
        assert test_module(mock_client, "2021-01-01T00:00:00Z") == "ok"

    def test_test_module_invalid_fetch_time(self, mocker):
        mock_client = mocker.Mock()
        with pytest.raises(DemistoException, match="Invalid first fetch timestamp format"):
            test_module(mock_client, "invalid_time_format")

    def test_test_module_client_error(self, mocker):
        mock_client = mocker.Mock()
        mock_client.get.side_effect = Exception("Connection error")
        with pytest.raises(Exception, match="Connection error"):
            test_module(mock_client, "2021-01-01T00:00:00Z")

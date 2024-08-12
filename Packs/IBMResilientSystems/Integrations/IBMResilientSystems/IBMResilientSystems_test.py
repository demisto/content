import pytest

import demistomock as demisto

DEFAULT_MAX_FETCH = 1000

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

    with pytest.raises(Exception) as exception:
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
    Tests whether the test module returns expected result for valid and invalid responses.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'example.com:80', 'org': 'example', 'proxy': True, 'max_fetch': DEFAULT_MAX_FETCH
    })
    from IBMResilientSystems import test_module, SimpleClient
    client = SimpleClient()
    mocker.patch.object(client, 'get', return_value={})
    assert test_module(client) == "ok"

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

# TODO - Complete this
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
    from co3 import SimpleClient
    from IBMResilientSystems import search_incidents, DEFAULT_RETURN_LEVEL
    request = mocker.patch.object(SimpleClient, "post", return_value={"data": [{}]})
    # TODO - fix
    search_incidents(client=SimpleClient, args=args)
    request.assert_called_with(
        method="POST",
        url_suffix=f"/rest/orgs/201/incidents/query_paged?return_level={args.get('return_level', DEFAULT_RETURN_LEVEL)}",
        headers='HEADERS',
        return_empty_response=False,
        json_data={}
    )

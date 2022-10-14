import demistomock as demisto
import pytest


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

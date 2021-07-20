import demistomock as demisto

PARAMS = {
    "server": "www.example.com:8080",
    "org": "example",
    "credentials": {
        "identifier": "admin",
        "password": "123456"
    }
}

ARGS = {
    "incident-id": "1234",
    "other-fields": '{"description": {"textarea": {"format": "html", "content": "The new description"}},'
                    '"name": {"text": "The new name"}, "owner_id": {"id": 2},'
                    '"discovered_date": {"date": 1624782898010}, "confirmed": {"boolean": "false"}}'
}


def mock_get_incident(incident_id):
    return {
        'name': 'The old name',
        'description': {'format': 'html', 'content': 'The old description'},
        'owner_id': 1,
        'discovered_date': 1624782898000,
        'confirmed': 'true'
    }


def mock_update_incident(incident_id, data):
    expected_data = {
        'changes': [
            {
                'field': {'name': 'description'},
                'old_value': {'textarea': {'format': 'html', 'content': 'The old description'}},
                'new_value': {'textarea': {'format': 'html', 'content': 'The new description'}}
            },
            {
                'field': {'name': 'name'},
                'old_value': {'text': 'The old name'},
                'new_value': {'text': 'The new name'}},
            {
                'field': {'name': 'owner_id'},
                'old_value': {'id': 1},
                'new_value': {'id': 2}},
            {
                'field': {'name': 'discovered_date'},
                'old_value': {'date': 1624782898000},
                'new_value': {'date': 1624782898010}},
            {
                'field': {'name': 'confirmed'},
                'old_value': {'boolean': 'true'},
                'new_value': {'boolean': 'false'}
            }
        ]
    }
    if data == expected_data:
        code = 200
    else:
        code = None

    class Response:
        status_code = code
    response = Response

    return response


def mock_client_post(url, body):
    return url, body


def test_update_incident_command(mocker):
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch('IBMResilientSystems.rsilient.get_client', return_value=None)
    mocker.patch('IBMResilientSystems.get_incident', side_effect=mock_get_incident)
    mocker.patch('IBMResilientSystems.update_incident', side_effect=mock_update_incident)
    from IBMResilientSystems import update_incident_command

    results = update_incident_command(ARGS)

    assert results == 'Incident 1234 was updated successfully.'


def test_add_notes(mocker):
    mock_result = mocker.patch('IBMResilientSystems.client.post', side_effect=mock_client_post)
    from IBMResilientSystems import add_notes
    expected_results = ('/incidents/1/comments', {'text': {'format': 'text', 'content': 'Hello-World'}})

    add_notes(1, {"comment": "Hello-World"})

    assert mock_result == expected_results

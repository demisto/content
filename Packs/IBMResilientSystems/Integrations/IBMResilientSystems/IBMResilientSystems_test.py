import demistomock as demisto

ARGS = {
    "incident-id": "2095",
    "other-fields": '{"description": {"textarea": {"format": "html", "content": "This is a description"}},'
                    '"name": {"text": "This is the name."}}'
}


def mock_update_incident(incident_id, data):
    expected_results = [{'field': {'name': 'description'},
                         'old_value': {'textarea': {'format': 'html', 'content': 'this is a old new'}},
                         'new_value': {'textarea': {'format': 'html', 'content': 'this is a old new'}}},
                        {'field': {'name': 'name'},
                         'old_value': {'text': 'Another old new name.'},
                         'new_value': {'text': 'Another old new name.'}}]

    class Response:
        status_code = 200

    if data == expected_results:
        response = Response
    else:
        response = None

    return response


def test_update_incident_command(mocker):
    mocker.patch('IBMResilientSystems.update_incident', side_effect=mock_update_incident)
    from IBMResilientSystems import update_incident_command

    response = update_incident_command(ARGS)

    assert response
import demistomock as demisto

ARGS = {
    "incident-id": "2095",
    "other-fields": '{"description": {"textarea": {"format": "html", "content": "This is a description"}},'
                    '"name": {"text": "This is the name."}}'
}


def test_update_incident_command(mocker):
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    # mocker.patch('IBMResilientSystems.update_incident', side_effect=mock_update_incident)
    # mocker_output = mocker.patch('IBMResilientSystems.update_incident')
    from IBMResilientSystems import update_incident_command

    update_incident_command(demisto.args())

    assert mocker_output == [{'field': {'name': 'description'},
                              'old_value': {'textarea': {'format': 'html', 'content': 'this is a old new'}},
                              'new_value': {'textarea': {'format': 'html', 'content': 'this is a old new'}}},
                             {'field': {'name': 'name'},
                              'old_value': {'text': 'Another old new name.'},
                              'new_value': {'text': 'Another old new name.'}}]

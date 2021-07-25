import demistomock as demisto


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
    mocker.patch.object(demisto, 'params', return_value={
        'proxy': True,
        'server': 'www.example.com:8080',
        'org': 'org'
    })
    mocker.patch.object(demisto, 'args', return_value={
        "incident-id": "1234",
        "other-fields": '{"description": {"textarea": {"format": "html", "content": "The new description"}},'
                        '"name": {"text": "The new name"}, "owner_id": {"id": 2},'
                        '"discovered_date": {"date": 1624782898010}, "confirmed": {"boolean": "false"}}'
    })
    mocker.patch.object(demisto, 'command', return_value='rs-update-incident')
    mocker.patch('IBMResilientSystems.get_client', return_value=MockClient)
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
    from IBMResilientSystems import main

    main()

    assert mock_result.call_args.args[1] == expected_result


def test_add_notes(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'proxy': True,
        'server': 'www.example.com:8080',
        'org': 'org'
    })
    mocker.patch('IBMResilientSystems.CLIENT', return_value=MockClient)
    mock_result = mocker.patch('IBMResilientSystems.CLIENT.post')
    expected_result = ('/incidents/1234/comments', {'text': {'format': 'text', 'content': 'This is a new note'}})
    from IBMResilientSystems import add_notes

    add_notes("1234", "This is a new note")

    assert mock_result.call_args.args == expected_result


def test_add_incident_artifact(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'proxy': True,
        'server': 'www.example.com:8080',
        'org': 'org'
    })
    mocker.patch('IBMResilientSystems.CLIENT', return_value=MockClient)
    mock_result = mocker.patch('IBMResilientSystems.CLIENT.post')
    expected_result = ('/incidents/1234/artifacts', {'type': 'IP Address', 'value': '1.1.1.1',
                                                     'description': {'format': 'text',
                                                                     'content': 'This is the artifact description'}})
    from IBMResilientSystems import add_incident_artifact

    add_incident_artifact("1234", "IP Address", "1.1.1.1", "This is the artifact description")

    assert mock_result.call_args.args == expected_result

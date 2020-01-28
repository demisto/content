import demistomock as demisto
import json


def executeCommand(name, args=None):
    if name == 'demisto-api-get' and args and 'uri' in args and args['uri'] == "/settings/integration-commands":
        file_name = 'TestData/integration_commands.json'
    elif name == 'demisto-api-post' and args and 'uri' in args and args['uri'] == "/settings/integration/search":
        file_name = 'TestData/integration_search.json'
    else:
        raise ValueError('Unimplemented command called: {}'.format(name))

    with open(file_name, 'r') as f:
        raw_data = f.read()
        data = json.loads(raw_data)
        return data


def test_main(mocker):
    from ProvidesCommand import main

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    mocker.patch.object(demisto, 'args', return_value={
        'command': 'send-mail'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] == 'EWS Mail Sender,Gmail,Mail Sender (Deprecated),Mail Sender (New)'

    mocker.patch.object(demisto, 'args', return_value={
        'command': 'send-mail',
        'enabled': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] == 'Mail Sender (New)'

    mocker.patch.object(demisto, 'args', return_value={
        'command': 'send-mail',
        'enabled': 'false'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] == 'EWS Mail Sender,Gmail,Mail Sender (Deprecated)'

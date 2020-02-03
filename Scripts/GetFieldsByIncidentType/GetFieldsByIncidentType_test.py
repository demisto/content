import demistomock as demisto
import json


def executeCommand(name, args=None):
    if name == 'demisto-api-get' and args and 'uri' in args and args['uri'] == "/incidentfields":
        file_name = 'TestData/integration_incidentfields.json'
    else:
        raise ValueError('Unimplemented command called: {}'.format(name))

    with open(file_name, 'r') as f:
        raw_data = f.read()
        data = json.loads(raw_data)
        return data


def test_main(mocker):
    from GetFieldsByIncidentType import main

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    # test short names
    mocker.patch.object(demisto, 'args', return_value={
        'incident_type': 'Test Import',
        'short_names': 'true',
        'explicit_only': 'true',
        'pprint': 'false'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == ['testimportfield1']

    # test pprint
    mocker.patch.object(demisto, 'args', return_value={
        'incident_type': 'Test Import',
        'short_names': 'true',
        'explicit_only': 'true',
        'pprint': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == "['testimportfield1']"

    # test long names
    mocker.patch.object(demisto, 'args', return_value={
        'incident_type': 'Test Import',
        'short_names': False,
        'explicit_only': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == ['Test Import Field 1']

    # test explicit_only
    mocker.patch.object(demisto, 'args', return_value={
        'incident_type': 'Test Import',
        'short_names': False,
        'explicit_only': False
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == ['attachment',
                       'category',
                       'closeNotes',
                       'closeReason',
                       'closingUserId',
                       'dbotClosed',
                       'dbotCreated',
                       'dbotDueDate',
                       'dbotModified',
                       'dbotSource',
                       'dbotStatus',
                       'dbotTotalTime',
                       'Destination IP',
                       'details',
                       'Detection SLA',
                       'droppedCount',
                       'Email dest_ip',
                       'from',
                       'labels',
                       'linkedCount',
                       'md5',
                       'name',
                       'NIST Stage',
                       'occurred',
                       'owner',
                       'phase',
                       'playbookId',
                       'Raw',
                       'Remediation SLA',
                       'reminder',
                       'roles',
                       'runStatus',
                       'severity',
                       'sourceBrand',
                       'sourceInstance',
                       'Source IP',
                       'Test Import Field 1',
                       'Time to Assignment',
                       'to',
                       'type',
                       'URL SSL Verification']

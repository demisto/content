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


def parseJsonFile(file_name):
    with open(file_name, 'r') as f:
        raw_data = f.read()
        data = json.loads(raw_data)
        return data


def test_main(mocker):
    from IncidentFields import main

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    # test custom fields with short names
    mocker.patch.object(demisto, 'args', return_value={
        'exclude_system_fields': 'true',
        'short_names': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == parseJsonFile('./TestData/output_exclude_system_fields_true_shortnames.json')
    assert 'dbotcreated' not in results

    # test custom fields with long names
    mocker.patch.object(demisto, 'args', return_value={
        'exclude_system_fields': 'true',
        'short_names': 'false'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == parseJsonFile('./TestData/output_exclude_system_fields_true_longnames.json')
    assert 'dbotClosed' not in results

    # test system fields with short names
    mocker.patch.object(demisto, 'args', return_value={
        'exclude_system_fields': 'false',
        'short_names': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == parseJsonFile('./TestData/output_exclude_system_fields_false_shortnames.json')
    assert 'labels' in results

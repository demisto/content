import pytest

from CommonServerPython import *
from FindSimilarIncidentsV2 import main

default_args = {
    'hoursBack': 5,
    'timeField': 'created',
    'ignoreClosedIncidents': 'yes',
    'maxNumberOfIncidents': 3000,
    'maxResults': 10,
    'skipMissingValues': 'yes',
    'incidentFieldsAppliedCondition': 'AND'
}

incident1 = {
    'id': 1,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}

context1 = {
    'simpleValue': 'simple',
    'listValue': [{'name': 'test1'}, {'name': 'test2'}]
}
context2 = context1

context3 = {
    'listValue': [{'name': 'test1'}, {'name': 'test3'}]
}

incident2 = {
    'id': 2,
    'name': 'This is incident2',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-01',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject2'}],
    'attachment': [{'name': 'Test word1'}]
}

incident1_dup = {
    'id': 3,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-01',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}


def execute_command(command, args=None):
    if command == 'getIncidents':
        entry = {}
        entry['Type'] = entryTypes['note']
        entry['Contents'] = {}
        entry['Contents']['data'] = [incident1_dup, incident2]
        return [entry]
    elif command == 'getContext':
        if args['id'] == 1:
            return [{'Contents': {'context': context1}}]
        elif args['id'] == 2:
            return [{'Contents': {'context': context2}}]
        elif args['id'] == 3:
            return [{'Contents': {'context': context3}}]
        else:
            return []
    else:
        return []


def test_similar_incidents_fields(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'subject'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3


def test_similar_incidents_fields_with_diff(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'subject:1'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2


def test_similar_incidents_missing_fields(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name,emailbody', 'similarLabelsKeys': 'emailbody'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    with pytest.raises(SystemExit) as err:
        args['skipMissingValues'] = 'no'
        main()
    assert err.type == SystemExit


def test_similar_incidents_list_field(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'attachment.name:1'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2


def test_similar_incidents_no_results(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'unique'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    with pytest.raises(SystemExit) as err:
        main()
    assert err.type == SystemExit


def test_similar_context(mocker):
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'simpleValue'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'listValue'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'listValue.name'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2

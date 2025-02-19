import pytest

from CommonServerPython import *
import demistomock as demisto

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
    'listValue': [{'name': 'test1'}, {'name': 'test2'}],
    'dictListValue': {'test': ['1', '2']},
    'simpleListValue': ['1', '2', '3'],
    'dictListValue2': {'first': ['1', '2', '3'], 'second': ['1']},
    'multipleDictsValue': {
        'test':
            {
                'first':
                    {
                        'word1': '1', 'word2': '2'
                    },
                'second': ['word3', 'word4']
            }
    }
}
context2 = context1

context3 = {
    'listValue': [{'name': 'test1'}, {'name': 'test3'}],
    'dictListValue': {'test': ['2', '1']},
    'simpleListValue': ['2', '1', '3'],
    'dictListValue2': {'first': ['1', '2', '3']},
    'multipleDictsValue': {
        'test':
            {
                'first':
                    {
                        'word1': '4', 'word2': '2'
                    },
                'second': ['word3', 'word4']
            }
    }
}

incident2 = {
    'id': 2,
    'name': 'This is incident2',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
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

incident1_dup2 = {
    'id': 4,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-01',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}

incident_by_keys = [
    {
        'CustomFields': {},
        'account': '',
        'activated': '0001-01-01T00:00:00Z',
        'attachment': None,
        'autime': 1550670443962164000,
        'canvases': None,
        'category': '',
        'closeNotes': '',
        'closeReason': '',
        'closed': '0001-01-01T00:00:00Z',
        'closingUserId': '',
        'created': '2019-02-20T15:47:23.962164+02:00',
        'details': '',
        'droppedCount': 0,
        'dueDate': '2019-03-02T15:47:23.962164+02:00',
        'hasRole': False,
        'id': '1',
        'investigationId': '1',
        'isPlayground': False,
        'labels': [{'type': 'Instance', 'value': 'test'},
                   {'type': 'Brand', 'value': 'Manual'}],
        'lastOpen': '0001-01-01T00:00:00Z',
        'linkedCount': 0,
        'linkedIncidents': None,
        'modified': '2019-02-20T15:47:27.158969+02:00',
        'name': '1',
        'notifyTime': '2019-02-20T15:47:27.156966+02:00',
        'occurred': '2019-02-20T15:47:23.962163+02:00',
        'openDuration': 0,
        'owner': 'analyst',
        'parent': '',
        'phase': '',
        'playbookId': 'playbook0',
        'previousRoles': None,
        'rawCategory': '',
        'rawCloseReason': '',
        'rawJSON': '',
        'rawName': '1',
        'rawPhase': '',
        'rawType': 'Unclassified',
        'reason': '',
        'reminder': '0001-01-01T00:00:00Z',
        'roles': None,
        'runStatus': 'waiting',
        'severity': 0,
        'sla': 0,
        'sourceBrand': 'Manual',
        'sourceInstance': 'amichay',
        'status': 1,
        'type': 'Unclassified',
        'version': 6
    }
]


@pytest.fixture(autouse=True)
def mock_demistoVersion(mocker):
    mocker.patch.object(demisto, 'demistoVersion', return_value={'platform': 'xsoar'})


def execute_command(command, args=None):
    if command == 'getIncidents':
        entry = {}
        entry['Type'] = entryTypes['note']
        entry['Contents'] = {}
        entry['Contents']['data'] = [incident1_dup, incident2, incident1_dup2]
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


def test_get_incidents_by_keys():
    from FindSimilarIncidentsV2 import get_incidents_by_keys
    res = get_incidents_by_keys({u'name': u'\U0001f489'}, 'created', '2020-10-07T19:49:37.392378+03:00', '7137', 72,
                                False, '1000', 'status:Closed', 'AND')
    assert res == incident_by_keys


def test_build_similar_keys_list():
    """
    Given
        - key and value of the incident fields.
    When
        - build_incident_fields_query is called
    Then
        - Ensure that the query matches the type of the incident field: int -> ":=", str -> "=".
    """
    from FindSimilarIncidentsV2 import build_incident_fields_query

    int_res = build_incident_fields_query({u'sla': 0})
    assert int_res == ['sla:=0']

    str_res = build_incident_fields_query({u'employeeid': u'1111'})
    assert str_res == [u'employeeid="1111"']

    list_res = build_incident_fields_query({u'test': [u'name1', 0]})
    assert list_res == [u'test="name1"', 'test:=0']

    list_res = build_incident_fields_query({u'test': []})
    assert list_res == ['test=[]']

    escape_res = build_incident_fields_query({u'test': u'"C:\\test\\escape\\sequence" test'})
    assert escape_res == [u'test="\\"C:\\test\\escape\\sequence\\" test"']


def test_similar_incidents_fields(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'subject'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3


def test_similar_incidents_fields_with_diff(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'subject:1'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 3
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 4
    assert result['EntryContext']['similarIncidentList'][2]['rawId'] == 2


def test_similar_incidents_missing_fields(mocker):
    from FindSimilarIncidentsV2 import main
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
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'attachment.name:1'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 3
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 4
    assert result['EntryContext']['similarIncidentList'][2]['rawId'] == 2


def test_similar_incidents_no_results(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'unique'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    with pytest.raises(SystemExit) as err:
        main()
    assert err.type == SystemExit


def test_similar_incidents_order(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarLabelsKeys': 'subject'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 4


def test_similar_context_simple_value(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'simpleValue'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2


def test_similar_context_list_value(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'listValue.name'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'listValue'})

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2


def test_similar_context_dict_list_value(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'dictListValue'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'dictListValue.test'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2


def test_similar_context_dict_list_value2(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'dictListValue2'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'dictListValue2.first'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'dictListValue2.second'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2


def test_similar_context_multiple_dicts_value(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'multipleDictsValue'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'multipleDictsValue.test.second'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'multipleDictsValue.test'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2

    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'multipleDictsValue.test.first'})
    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 1
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 2


def test_similar_context_simple_list_value(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'similarIncidentFields': 'name', 'similarContextKeys': 'simpleListValue'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    result = main()
    assert len(result['EntryContext']['similarIncidentList']) == 2
    assert result['EntryContext']['similarIncidentList'][0]['rawId'] == 3
    assert result['EntryContext']['similarIncidentList'][1]['rawId'] == 2


def test_similar_context_missing_key(mocker):
    from FindSimilarIncidentsV2 import main
    args = dict(default_args)
    args.update({'skipMissingValues': 'no', 'similarContextKeys': 'missingKey'})

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'incidents', return_value=[incident1])
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'context', return_value=context1)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)

    with pytest.raises(ValueError, match="Error: Missing context key for incident: missingKey"):
        main()


def test_build_incident_query():
    from FindSimilarIncidentsV2 import build_incident_query
    res = build_incident_query('type="test"', True, '826', 'name:incident1')

    assert res == '(-id:826) and (type="test" and -status:Closed) and (name:incident1)'


def test_build_incident_query_without_similar_keys_query():
    from FindSimilarIncidentsV2 import build_incident_query
    res = build_incident_query('', True, '826', 'name:incident1')

    assert res == '(-id:826) and (-status:Closed) and (name:incident1)'


def test_build_incident_query_without_extra_query():
    from FindSimilarIncidentsV2 import build_incident_query
    res = build_incident_query('', True, '826', '')

    assert res == '(-id:826) and (-status:Closed)'


def test_build_incident_query_without_similar_keys_query_and_ignore_closed():
    """
    Given:
        - Fields for creating query without similar_keys_query and ignore_closed flag.

    When:
        - Building incident query using 'build_incident_query' function.

    Then:
        - Ensure the query was created correctly and that the query string got the values needed
          from the formating.
    """
    from FindSimilarIncidentsV2 import build_incident_query
    res = build_incident_query('', False, '826', '')

    assert res == '(-id:826)'


def dt_res(context, keys_to_search):

    keys_list = keys_to_search.split('.')
    context_key_value = None
    for key in keys_list:
        if context_key_value:
            if isinstance(context_key_value, list):
                list_value = []
                for value in context_key_value:
                    if isinstance(value, dict):
                        if value.get(key):
                            list_value.append(value[key])
                    else:
                        list_value.append(value)
                context_key_value = list_value

            elif isinstance(context_key_value, dict):
                dict_list_value = []
                for dict_key in context_key_value.keys():
                    if dict_key == key:
                        if isinstance(context_key_value[dict_key], list):
                            dict_list_value.append(sorted(context_key_value[dict_key]))
                        else:
                            dict_list_value.append(context_key_value[dict_key])

                context_key_value = dict_list_value

            else:
                context = context_key_value
        else:
            context_key_value = context.get(key)
    return context_key_value

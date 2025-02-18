import hashlib

from CommonServerPython import *
from HashIncidentsFields import hash_incident, pattern_match, is_key_match_fields_to_hash

default_args = {
    'fieldsToHash': 'labels, activated, created,  fake, owner, statuss, status, ,,,,11, activated, CustomFields.emailto',
    'contextKeys': 'simpleValue, listValue',
    'outputFormat': 'json',
    'addRandomSeed': ''
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
    'created': '2019-01-01',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject2'}],
    'attachment': [{'name': 'Test word1'}],
}

incident3 = {
    'id': 3,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-01',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}],
}


def get_fields_to_hash(args):
    fields_to_hash = frozenset([x for x in argToList(args.get('fieldsToHash', '')) if x])
    un_populate_fields = frozenset([x for x in argToList(args.get('unPopulateFields', '')) if x])
    return fields_to_hash, un_populate_fields


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
                for dict_key in context_key_value:
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


def execute_command(command, args=None):
    if command == 'GetIncidentsByQuery':
        entry = {}
        entry['Type'] = entryTypes['note']
        entry['Contents'] = json.dumps([incident1, incident2, incident3])
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


def test_length(mocker):
    args = dict(default_args)
    fields_to_hash, un_populate_fields = get_fields_to_hash(args)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    result = hash_incident(fields_to_hash, un_populate_fields)
    assert len(result['Contents']) == 3


def test_hash(mocker):
    args = dict(default_args)
    fields_to_hash, un_populate_fields = get_fields_to_hash(args)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    result = hash_incident(fields_to_hash, un_populate_fields)
    assert result['Contents'][0]['name'] == incident1['name']
    assert result['Contents'][0]['status'] == '1'
    assert result['Contents'][0]['created'] == \
        hashlib.md5(str(incident1['created']).encode('utf-8')).hexdigest()
    assert result['Contents'][0]['labels'][0]['type'] == \
        hashlib.md5(str(incident1['labels'][0]['type']).encode('utf-8')).hexdigest()
    assert list(result['Contents'][0]['labels'][0].keys()) == ['type', 'value']


def test_context(mocker):
    args = dict(default_args)
    fields_to_hash, un_populate_fields = get_fields_to_hash(args)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'dt', side_effect=dt_res)
    result = hash_incident(fields_to_hash, un_populate_fields)
    assert result['Contents'][0]['context']['simpleValue'] == 'simple'
    assert result.get('Contents')[0].get('context').get('simpleListValue') is None


def test_key_matching():
    assert pattern_match("te*", "test")
    assert pattern_match("test", "test")
    assert not pattern_match("notmatch", "test")
    assert pattern_match("*tt*", "aaattaaa")

    assert is_key_match_fields_to_hash("thisIsMyTest", frozenset(["*My*"]))
    assert not is_key_match_fields_to_hash("thisIsMyTest2", frozenset(["*MM*"]))
    assert is_key_match_fields_to_hash("thisIsMyTest3", frozenset(["thisIsMyTest", "*MM*"]))
    assert not is_key_match_fields_to_hash("thisIsMyTest4", frozenset(["MyTest", "*MM*"]))
    assert is_key_match_fields_to_hash("thisIsMyTest", frozenset(["*MM*"]))  # cached
    assert is_key_match_fields_to_hash("slaStatus", frozenset(["sla*"]))

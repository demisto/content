from SearchIncidentsV2 import *
import pytest

data_test_check_if_found_incident = [
    ([], 'failed to get incidents from demisto.\nGot: []'),
    (None, 'failed to get incidents from demisto.\nGot: None'),
    ('', 'failed to get incidents from demisto.\nGot: '),
    ([{'Contents': {'data': None}}], False),
    ([{'Contents': {'data': 'test'}}], True),
    ([{'Contents': {'test': 'test'}}], "{'test': 'test'}"),
]


@pytest.mark.parametrize('_input, expected_output', data_test_check_if_found_incident)
def test_check_if_found_incident(_input, expected_output):
    try:
        output = check_if_found_incident(_input)
    except DemistoException as error:
        output = str(error)
    assert output == expected_output, f'check_if_found_incident({_input}) returns: {output}. expected: {expected_output}'


data_test_is_valid_args = [
    ('\\', True),
    ('\n', True),
    ('\\n', True),
    ('\\t', True),
    ('\\\\', True),
    ('\\"', True),
    ('\\r', True),
    ('\\7', True),
    ('\\\'', True),
]


@pytest.mark.parametrize('_input, expected_output', data_test_is_valid_args)
def test_is_valid_args(_input, expected_output):
    try:
        output = is_valid_args({'test': _input})
    except DemistoException:
        output = False

    assert output == expected_output, f'is_valid_args({_input}) returns: {output}. expected: {expected_output}'


data_test_is_id_valid = [
    (123, True),
    ('123', True),
    (123.3, False),
]


@pytest.mark.parametrize('id_value, expected_output', data_test_is_id_valid)
def test_is_incident_id_valid(id_value, expected_output):
    """
    Given:
        - an incident id

    When:
        - running the script as a playbook task

    Then:
        - validating that the incident is is a valid input from type int or str

    """
    try:
        is_valid_id = is_valid_args({'id': id_value})
    except DemistoException:
        is_valid_id = False
    assert is_valid_id == expected_output


EXAMPLE_INCIDENTS_RAW_RESPONSE = [
    {
        u'id': u'1',
        u'type': u'TypeA',
        u'name': u'Phishing',
    },
    {
        u'id': u'2',
        u'type': u'Type-A',
        u'name': u'Phishing Campaign',
    },
    {
        u'id': u'3',
        u'type': u'SomeType-A',
        u'name': u'Go Phish',
    },
    {
        u'id': u'4',
        u'type': u'Another Type-A',
        u'name': u'Hello',
    },
]

FILTER_TO_MATCHED_INCIDENTS = [
    ({'type': 'Type-A'}, ['2']),
    ({'type': 'Type-A, SomeTypeA'}, ['2']),
    ({'type': ['Type-A', 'SomeType-A']}, ['2', '3']),
    ({'type': 'Another'}, []),
    ({'name': 'Phishing'}, ['1']),
    ({'name': 'Phishing,Phishing Campaign'}, ['1', '2']),
]


@pytest.mark.parametrize('args, expected_incident_ids', FILTER_TO_MATCHED_INCIDENTS)
def test_apply_filters(args, expected_incident_ids):
    incidents = apply_filters(EXAMPLE_INCIDENTS_RAW_RESPONSE, args)
    assert [incident['id'] for incident in incidents] == expected_incident_ids


def test_search_incidents(mocker):
    args = {
        'fromdate': '2 days ago',
        'todate': '1 day ago'
    }
    mocker.patch.object(demisto, 'executeCommand', return_value=EXECUTE_COMMAND_RES)
    md, data, res = search_incidents(args)
    assert data == EXECUTE_COMMAND_RES[0]['Contents']['data']


EXECUTE_COMMAND_RES = [
    {
        "ModuleName": "InnerServicesModule",
        "Brand": "Builtin",
        "Category": "Builtin",
        "ID": "",
        "Version": 0,
        "Type": 1,
        "Contents": {
            "ErrorsPrivateDoNotUse": None,
            "data": [
                {
                    "CustomFields": {
                        "field1": "value1",
                        "field2": "value2",
                        "field3": "value3"
                    },
                    "created": "2022-02-09T15:07:57.90662+02:00",
                    "id": "6210",
                    "occurred": "2022-02-09T15:07:57.90662+02:00",
                    "rawName": "new incident",
                    "rawPhase": "",
                    "rawType": "incident type",
                    "status": 1,
                    "type": "incident type",
                    "version": 5
                }
            ],
            "total": 1
        },
        "Metadata": {
            "id": "",
            "version": 0,
            "modified": "0001-01-01T00:00:00Z"
        }
    }
]

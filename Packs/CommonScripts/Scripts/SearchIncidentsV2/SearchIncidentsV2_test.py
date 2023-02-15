from SearchIncidentsV2 import *
import pytest

data_test_check_if_found_incident = [
    ([], 'failed to get incidents from xsoar.\nGot: []'),
    (None, 'failed to get incidents from xsoar.\nGot: None'),
    ('', 'failed to get incidents from xsoar.\nGot: '),
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
    ('1,2,3', True),
    ([1, 2, 3], True),
    ('[1,2,3]', True),

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
    ({'name': 'Phishing,Phishing Campaign'}, ['1', '2'])
]

INCIDENT = [
    {'CustomFields':
         {'hostname': 'host_name',  # noqa
          'initiatedby': 'initiated_by',
          'targetprocessname': 'target_process_name',
          'username': 'user_name'},

     'status': 0,
     'severity': 1,
     },
]


@pytest.mark.parametrize('args, expected_incident_ids', FILTER_TO_MATCHED_INCIDENTS)
def test_apply_filters(args, expected_incident_ids):
    incidents = apply_filters(EXAMPLE_INCIDENTS_RAW_RESPONSE, args)
    assert [incident['id'] for incident in incidents] == expected_incident_ids


def get_incidents_mock(command, args, extract_contents=True, fail_on_error=True):
    ids = args.get('id', '').split(',')
    return [{'Contents': {'data': [incident for incident in EXAMPLE_INCIDENTS_RAW_RESPONSE if incident['id'] in ids]}}]


@pytest.mark.parametrize('args,filtered_args,expected_result', [
    ({}, {}, []),
    (dict(trimevents='0'), {}, []),
    (dict(trimevents='1'), dict(trimevents='1'), []),
    ({'id': 1}, {'id': '1'}, [EXAMPLE_INCIDENTS_RAW_RESPONSE[0]]),
    ({'id': [1, 2]}, {'id': '1,2'}, [EXAMPLE_INCIDENTS_RAW_RESPONSE[0], EXAMPLE_INCIDENTS_RAW_RESPONSE[1]]),
    ({'id': '1,2'}, {'id': '1,2'}, [EXAMPLE_INCIDENTS_RAW_RESPONSE[0], EXAMPLE_INCIDENTS_RAW_RESPONSE[1]]),
])
def test_filter_events(mocker, args, filtered_args, expected_result):
    """
    Given:
        - The script args.

    When:
        - Running the search_incidents function.

    Then:
        - Validating the outputs as expected.
        - Validating the filtered args that was sent to the api is as expected.
    """
    import SearchIncidentsV2
    execute_mock = mocker.patch.object(SearchIncidentsV2, 'execute_command', side_effect=get_incidents_mock)
    if 'trimevents' in args:
        # trimevents supported only in XSIAM
        mocker.patch.object(demisto, 'demistoVersion', return_value={'platform': 'xsiam'})

    _, res, _ = SearchIncidentsV2.search_incidents(args)
    assert res == expected_result
    assert execute_mock.call_count == 1
    assert execute_mock.call_args[0][1] == filtered_args


@pytest.mark.parametrize('platform, link_type, expected_result', [
    ('x2', 'alertLink', 'alerts?action:openAlertDetails='),
    ('xsoar', 'incidentLink', '#/Details/'),
])
def test_add_incidents_link(mocker, platform, link_type, expected_result):
    mocker.patch.object(demisto, 'getLicenseCustomField', return_value='')
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': ''})
    data = add_incidents_link(EXAMPLE_INCIDENTS_RAW_RESPONSE, platform)
    assert expected_result in data[0][link_type]


def test_transform_to_alert_data():
    incident = transform_to_alert_data(INCIDENT)[0]
    assert incident['hostname'] == 'host_name'
    assert incident['status'] == 'PENDING'
    assert incident['severity'] == 'LOW'


def test_summarize_incidents():
    assert summarize_incidents({'add_fields_to_summarize_context': 'test'}, [{'id': 'test', 'CustomFields': {}}]) == [
        {'closed': 'n/a', 'created': 'n/a', 'id': 'test', 'incidentLink': 'n/a', 'name': 'n/a', 'owner': 'n/a',
         'severity': 'n/a', 'status': 'n/a', 'test': 'n/a', 'type': 'n/a'}]

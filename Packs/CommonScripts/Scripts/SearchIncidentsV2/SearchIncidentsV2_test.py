from SearchIncidentsV2 import *
import pytest
import datetime as dt

data_test_check_if_found_incident = [
    ([], 'failed to get incidents from xsoar.\nGot: []'),
    (None, 'failed to get incidents from xsoar.\nGot: None'),
    ('', 'failed to get incidents from xsoar.\nGot: '),
    ([{'Contents': {'data': None}}], False),
    ([{'Contents': {'data': 'test'}}], True),
    ([{'Contents': {'test': 'test'}}], "{'test': 'test'}"),
]


def create_sample_incidents(start, end, incident_type):
    return [
        {
            'id': f'{i}',
            'type': f'{incident_type}',
            'name': f'incident-{i}',
        } for i in range(start, end + 1)
    ]


def execute_get_incidents_command_side_effect(amount_of_mocked_incidents):
    mocked_incidents = []

    default_jump = 100
    counter = 1
    for start in range(1, amount_of_mocked_incidents + 1, default_jump):
        end = min(amount_of_mocked_incidents, default_jump * counter)

        incident_type = 'A' if counter % 2 == 0 else 'B'
        if counter == 1:
            execute_command_mock = [
                {
                    'Contents': {
                        'data': create_sample_incidents(start, end, incident_type),
                        'total': 0
                    }
                }
            ]
        else:
            execute_command_mock = {
                'data': create_sample_incidents(start, end, incident_type)
            }

        mocked_incidents.append(execute_command_mock)
        counter += 1

    if mocked_incidents:
        mocked_incidents.append({'data': None})

    return mocked_incidents


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
        'id': '1',
        'type': 'TypeA',
        'name': 'Phishing',
    },
    {
        'id': '2',
        'type': 'Type-A',
        'name': 'Phishing Campaign',
    },
    {
        'id': '3',
        'type': 'SomeType-A',
        'name': 'Go Phish',
    },
    {
        'id': '4',
        'type': 'Another Type-A',
        'name': 'Hello',
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


def get_incidents_mock(_, args, extract_contents=True, fail_on_error=True):
    ids = args.get('id', '').split(',')
    incidents_list = [incident for incident in EXAMPLE_INCIDENTS_RAW_RESPONSE if incident['id'] in ids]
    if not extract_contents:
        return [{'Contents': {'data': incidents_list, 'total': len(incidents_list)}}]
    return {'data': None}


@pytest.mark.parametrize('args,filtered_args,expected_result', [
    # ({}, {}, []),
    ({'trimevents': '0'}, {}, []),
    ({'trimevents': '1'}, {'trimevents': '1'}, []),
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
    else:
        mocker.patch.object(demisto, 'demistoVersion', return_value={'platform': 'xsoar'})
    _, res, _ = SearchIncidentsV2.search_incidents(args)
    assert res == expected_result
    assert execute_mock.call_count == 1
    assert execute_mock.call_args[0][1] == filtered_args


def get_incidents_mock_include_informational(_, args, extract_contents=True, fail_on_error=True):
    incidents = [
        {'id': '1', 'informational': False},
        {'id': '2', 'informational': False},
    ]

    includeinformational = args.get('includeinformational', None)

    if includeinformational:
        incidents.extend([
            {'id': '3', 'informational': True},
            {'id': '4', 'informational': True},
        ])

    if not extract_contents:
        return [{'Contents': {'data': incidents, 'total': len(incidents)}}]

    return {'Contents': {'data': incidents}}


INCLUDE_INFORMATIONAL_FIXED_TIME = dt.datetime(2024, 10, 1, 15, 0, 0)
INCLUDE_INFORMATIONAL_NOW = INCLUDE_INFORMATIONAL_FIXED_TIME.isoformat()
INCLUDE_INFORMATIONAL_5_HOURS_AGO = dt.datetime(2024, 10, 1, 10, 0, 0).isoformat()
INCLUDE_INFORMATIONAL_3_HOURS_AGO = dt.datetime(2024, 10, 1, 12, 0, 0).isoformat()


@pytest.mark.parametrize('args,expected_filtered_args,expected_result', [
    ({'includeinformational': 'true', 'fromdate': '3 hours ago', 'todate': 'now'},
     {'includeinformational': True,
      'fromdate': INCLUDE_INFORMATIONAL_3_HOURS_AGO,
      'todate': INCLUDE_INFORMATIONAL_NOW},
     ['1', '2', '3', '4']),
    ({'includeinformational': 'true', 'fromdate': '6 hours ago', 'todate': 'now'},
     {'includeinformational': True,
      'fromdate': INCLUDE_INFORMATIONAL_5_HOURS_AGO,
      'todate': INCLUDE_INFORMATIONAL_NOW},
     ['1', '2', '3', '4']),
    ({'includeinformational': 'true'}, {}, ValueError),
    ({'includeinformational': 'false'}, {}, ['1', '2']),
    ({}, {}, ['1', '2']),
    ({'includeinformational': 'true', 'todate': 'now'}, {}, ValueError),
    ({'includeinformational': 'true', 'fromdate': '3 hours ago'}, {}, ValueError),
])
def test_includeinformational_logic(mocker, args, expected_filtered_args, expected_result):
    """
    Given:
    - Case A: includeinformational=True, with relative fromdate and todate provided, both dates within 5 hours from
    current time.
    - Case B: includeinformational=true, fromdate is more than 5 hours ago, requiring an adjustment of fromdate.
    - Case C: includeinformational=true, but fromdate and todate are missing, should raise a ValueError.
    - Case D: includeinformational=false, meaning no informational incidents should be returned.
    - Case E: includeinformational not present, should behave like false and no informational incidents should be returned.
    - Case F: includeinformational=true,but fromdate is missing, should raise a ValueError.
    - Case G: includeinformational=true, but todate is missing, should raise a ValueError.

    When:
       - Running the search_incidents function to process the input args.

    Then:
       - Case A: Ensure both regular and informational incidents are returned when includeinformational=true.
       - Case B: Ensure fromdate is adjusted to 5 hours ago and incidents (regular + informational) are fetched correctly.
       - Case C: Verify that a ValueError is raised due to missing fromdate and todate when includeinformational=true.
       - Case D: Ensure only regular incidents are returned when includeinformational=false.
       - Case E: Ensure only regular incidents are returned when includeinformational=None (default behavior).
       - Case F: Ensure that a ValueError is raised when fromdate is missing but includeinformational=true.
       - Case G: Ensure that a ValueError is raised when todate is missing but includeinformational=true.
    """
    import SearchIncidentsV2
    mocker.patch.object(dt, 'datetime', autospec=True)
    mocker.patch.object(SearchIncidentsV2, 'is_xsiam', return_value=True)
    dt.datetime.utcnow.return_value = INCLUDE_INFORMATIONAL_FIXED_TIME

    class MockDateTime:
        def utcnow(self):
            return INCLUDE_INFORMATIONAL_FIXED_TIME

    mocker.patch('SearchIncidentsV2.datetime', MockDateTime())

    # mock arg to datetime since internally uses utc which is not the same as the fixed datetime
    mocker.patch.object(SearchIncidentsV2, 'arg_to_datetime', side_effect=lambda x: None if x is None
                        else INCLUDE_INFORMATIONAL_FIXED_TIME - dt.timedelta(
                            hours=int(x.split()[0])) if 'hours ago' in x else INCLUDE_INFORMATIONAL_FIXED_TIME)

    execute_mock = mocker.patch.object(SearchIncidentsV2, 'execute_command', side_effect=get_incidents_mock_include_informational)

    if expected_result is ValueError:
        with pytest.raises(ValueError):
            SearchIncidentsV2.search_incidents(args)
    else:
        _, res, _ = SearchIncidentsV2.search_incidents(args)
        assert [incident['id'] for incident in res] == expected_result
        assert execute_mock.call_count == 1
        assert execute_mock.call_args[0][1] == expected_filtered_args


@pytest.mark.parametrize('platform, version, link_type, expected_result', [
    ('x2', '', 'alertLink', 'alerts?action:openAlertDetails='),
    ('xsoar', '6.10.0', 'incidentLink', '#/Details/'),
    ('xsoar', '8.4.0', 'incidentLink', '/Details/')
])
def test_add_incidents_link(mocker, platform, version, link_type, expected_result):
    mocker.patch.object(demisto, 'getLicenseCustomField', return_value='')
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': ''})
    if version:
        mocker.patch.object(demisto, 'demistoVersion', return_value={'version': version})
    data = add_incidents_link(EXAMPLE_INCIDENTS_RAW_RESPONSE, platform)
    assert expected_result in data[0][link_type]


def test_transform_to_alert_data():
    incident = transform_to_alert_data(INCIDENT)[0]
    assert incident['hostname'] == 'host_name'
    assert incident['status'] == 'PENDING'
    assert incident['severity'] == 'LOW'


def test_summarize_incidents():
    assert summarize_incidents({'add_fields_to_summarize_context': 'test'}, [{'id': 'test', 'CustomFields': {}}],
                               platform='xsoar') == [
        {'closed': 'n/a', 'created': 'n/a', 'id': 'test', 'incidentLink': 'n/a', 'name': 'n/a', 'owner': 'n/a',
         'severity': 'n/a', 'status': 'n/a', 'test': 'n/a', 'type': 'n/a'}]


@pytest.mark.parametrize('amount_of_mocked_incidents, args, expected_incidents_length', [
    (306, {}, 100),
    (306, {"limit": "200"}, 200),
    (105, {"limit": "200"}, 105),
    (1000, {"limit": "100"}, 100),
    (1000, {"limit": "1100"}, 1000),
    (205, {"limit": "105.5"}, 105),
    (700, {"limit": "500", 'type': 'A'}, 300),
    (1500, {"limit": "250", 'type': 'A'}, 250),
    (500, {"limit": "100", 'name': 'incident-8'}, 1),
])
def test_main_flow_with_limit(mocker, amount_of_mocked_incidents, args, expected_incidents_length):
    """
    Given:
       - Case A: Total of 306 incidents matching in XSOAR and no args
       - Case B: Total of 306 incidents matching in XSOAR and limit = 200
       - Case C: Total of 105 incidents matching in XSOAR and limit = 200
       - Case D: Total of 1000 incidents matching in XSOAR and limit = 100
       - Case E: Total of 1000 incidents matching in XSOAR and limit = 1100
       - Case F: Total of 205 incidents matching in XSOAR and limit = 105.5
       - Case G: Total of 700 incidents and only 300 incidents which match type = 'A' and limit = 500
       - Case H: Total of 1500 incidents and only 700 incidents which match type = 'A' and limit = 250
       - Case I: Total of 500 incidents and only 1 incident that its name = 'incident-8' and limit = 100

    When:
       - Running the main flow

    Then:
       - Case A: Make sure only 100 incidents have been returned (default of the limit if not stated)
       - Case B: Make sure only 200 incidents have been returned.
       - Case C: Make sure only 105 incidents have been returned (cause there are fewer incidents than requested limit)
       - Case D: Make sure only 100 incidents have been returned.
       - Case E: Make sure only 1000 incidents have been returned.
       - Case F: Make sure only 105 (rounded) incidents have been returned.
       - Case G: Make sure only 300 incidents have been returned.
       - Case H: Make sure only 250 incidents have been returned.
       - Case I: Make sure only one incident has been returned.

    """
    import SearchIncidentsV2

    mocker.patch.object(
        SearchIncidentsV2,
        'execute_command',
        side_effect=execute_get_incidents_command_side_effect(amount_of_mocked_incidents)
    )

    mocker.patch.object(demisto, 'args', return_value=args)
    return_results_mocker = mocker.patch.object(SearchIncidentsV2, 'return_results')
    mocker.patch('SearchIncidentsV2.get_demisto_version', return_value={})

    SearchIncidentsV2.main()

    assert return_results_mocker.called
    assert len(return_results_mocker.call_args[0][0].outputs) == expected_incidents_length

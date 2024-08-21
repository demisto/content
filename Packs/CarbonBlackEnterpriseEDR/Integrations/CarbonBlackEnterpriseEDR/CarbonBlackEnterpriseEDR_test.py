import pytest
import CarbonBlackEnterpriseEDR as cbe
from CarbonBlackEnterpriseEDR import (
    get_threat_tags_command,
    add_threat_tags_command,
    add_threat_notes_command,
    add_alert_notes_command,
)
import demistomock as demisto
from freezegun import freeze_time

CLIENT = cbe.Client(
    base_url='https://server_url.com',
    use_ssl=False,
    use_proxy=False,
    token=None,
    cb_org_key="123")

PROCESS_CASES = [
    (
        {'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6',
         'process_name': None, 'event_id': None, 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6']},
         'rows': 20, 'start': 0, 'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}
        # expected
    ),
    (
        {"process_name": "svchost.exe,vmtoolsd.exe", 'event_id': None, 'query': None, 'limit': 20,
         'start_time': '1 day',
         'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'],
                      "process_name": ["svchost.exe", "vmtoolsd.exe"]}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', PROCESS_CASES)
def test_create_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    m = mocker.patch.object(CLIENT, '_http_request', return_value={})

    CLIENT.create_search_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


PROCESS_BAD_CASES = [
    (
        {'process_hash': None, 'process_name': None, 'event_id': None, 'query': None, 'limit': 20},
        # args for missing parameters
        "To perform an process search, please provide at least one of the following: "
        "'process_hash', 'process_name', 'event_id' or 'query'"  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_error_msg', PROCESS_BAD_CASES)
def test_create_process_search_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    mocker.patch.object(CLIENT, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        CLIENT.create_search_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


EVENT_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start': 20,
         'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 20,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', EVENT_CASES)
def test_create_event_by_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search event by process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    m = mocker.patch.object(CLIENT, '_http_request', return_value={})

    CLIENT.create_search_event_by_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


EVENT_BAD_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'invalid', 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for invalid parameters
        "Only the following event types can be searched: "
        "'filemod', 'netconn', 'regmod', 'modload', 'crossproc', 'childproc'"  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': None, 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for missing parameters
        "To perform an event search, please provide either event_type or query."  # expected
    )
]


@pytest.mark.parametrize('demisto_args,expected_error_msg', EVENT_BAD_CASES)
def test_event_by_process_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    mocker.patch.object(CLIENT, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        CLIENT.create_search_event_by_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


MOCK_UPDATE_THREAT_TAGS_RESPONSE = {
    'tags': ['tag1', 'tag2']
}


def test_add_threat_tags_command(mocker):
    """
    Given:
        - args with threat_id and tags.

    When:
        - Calling add_threat_tags_command.

    Then:
        - validate that the returned results were parsed as expected.

    """
    mocker.patch.object(CLIENT, '_http_request', return_value=MOCK_UPDATE_THREAT_TAGS_RESPONSE)

    args = {'threat_id': '123456', 'tags': ['tag1', 'tag2']}
    result = add_threat_tags_command(CLIENT, args)

    assert result.outputs == {'ThreatID': '123456', 'Tags': ['tag1', 'tag2']}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'tags'

    assert "Successfully updated threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_UPDATE_THREAT_TAGS_RESPONSE


MOCK_CREATE_THREAT_NOTES_RESPONSE = {
    'notes': 'These are threat notes'
}


def test_add_threat_notes_command(mocker):
    """
    Given:
        - args with threat_id and notes.

    When:
        - Calling add_threat_notes_command.

    Then:
        - validate that the returned results were parsed as expected.

    """
    mocker.patch.object(CLIENT, '_http_request', return_value=MOCK_CREATE_THREAT_NOTES_RESPONSE)

    args = {'threat_id': '123456', 'notes': 'These are threat notes'}
    result = add_threat_notes_command(CLIENT, args)

    assert result.outputs == {'ThreatID': '123456', 'Notes': 'These are threat notes'}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'ThreatID'

    assert "Successfully added notes to threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_CREATE_THREAT_NOTES_RESPONSE


MOCK_GET_THREAT_TAGS_RESPONSE = {
    'list': [
        {'tag': 'malware'},
        {'tag': 'suspicious'}
    ]
}


def test_get_threat_tags_command(mocker):
    """
    Given:
        - args with thread_it.

    When:
        - Calling get_threat_tags_command.

    Then:
        - validate that the returned results was parsed as expected.

    """
    mocker.patch.object(CLIENT, '_http_request', return_value=MOCK_GET_THREAT_TAGS_RESPONSE)

    args = {'threat_id': '123456'}
    result = get_threat_tags_command(CLIENT, args)

    assert result.outputs == {'ThreatID': '123456', 'Tags': [{'tag': 'malware'}, {'tag': 'suspicious'}]}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'ThreatID'

    assert "Successfully sent for threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_GET_THREAT_TAGS_RESPONSE


MOCK_UPDATE_ALERT_NOTES_RESPONSE = {
    'notes': 'These are alert notes'
}


def test_add_alert_notes_command(mocker):
    """
    Given:
        - args with alert_id and notes.

    When:
        - Calling add_alert_notes_command.

    Then:
        - validate that the returned results were parsed as expected.

    """
    mocker.patch.object(CLIENT, '_http_request', return_value=MOCK_UPDATE_ALERT_NOTES_RESPONSE)

    args = {'alert_id': '789012', 'notes': 'These are alert notes'}
    result = add_alert_notes_command(CLIENT, args)

    assert result.outputs == {'AlertID': '789012', 'Notes': 'These are alert notes'}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'AlertID'

    assert "Successfully added notes to alert: \"789012\"" in result.readable_output
    assert result.raw_response == MOCK_UPDATE_ALERT_NOTES_RESPONSE


def test_test_module(mocker):
    """
    Given:
        - All relevant parameters for the integration.

    When:
        - testing the configuration of the integration.

    Then:
        - The http request is called with the right API version.
        - The 'start' field in the body of the request equals to 1.
    """
    from CarbonBlackEnterpriseEDR import test_module
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    test_module(client=CLIENT)
    assert 'api/alerts/v7/orgs' in http_request.call_args.kwargs['url_suffix']
    assert http_request.call_args.kwargs['json_data']['start'] == 1


def test_search_alerts_request(mocker):
    """
    Given:
        - All argument needed for a search_alert_request

    When:
        - calling search_alert_request function

    Then:
        - The http request is called with the right API version.
        - the 'start' field in the body of the request equals to 1.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.search_alerts_request()
    assert 'api/alerts/v7/orgs' in http_request.call_args[0][1]
    assert http_request.call_args.kwargs['json_data']['start'] == 1


def test_alert_workflow_update_get_request(mocker):
    """
    Given:
        - A request_id

    When:
        - Calling alert_workflow_update_get_request function

    Then:
        - The http request is called with the request_id.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.alert_workflow_update_get_request('1234')
    assert '1234' in http_request.call_args[0][1]


def test_alert_workflow_update_request_good_arguments(mocker):
    """
    Given:
        - All required arguments.

    When:
        - Calling alert_workflow_update_request function.

    Then:
        - The http request is called with the right version.
        - The http request is called with the right json body.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.alert_workflow_update_request(alert_id='1234', state='OPEN', comment='bla1', determination='NONE',
                                         time_range='-2w', start='1', end='2', closure_reason='bla2')
    assert 'api/alerts/v7/orgs' in http_request.call_args[0][1]
    assert http_request.call_args.kwargs['json_data'] == {'time_range': {'start': '1', 'end': '2', 'range': '-2w'},
                                                          'criteria': {'id': ['1234']}, 'determination': 'NONE',
                                                          'closure_reason': 'bla2', 'status': 'OPEN', 'note': 'bla1'}


alert_workflow_update_command_func_called_data = [
    ({'alert_id': '123', 'state': 'OPEN'},  # case first time polling (no request_id).
     'alert_workflow_update_request',  # func to be called.
     {'request_id': '123456789'}  # response
     ),
    ({'alert_id': '123', 'request_id': '12345'},  # case there is a request_id.
     'alert_workflow_update_get_request',  # func to be called.
     {'status': 'COMPLETED',
      'job_parameters': {'job_parameters': {'request': {'state': 'OPEN'}, 'userWorkflowDto': {'changed_by': 'bla'}}},
      'last_update_time': 'now'})
]


@pytest.mark.parametrize('args, func_to_be_called, response', alert_workflow_update_command_func_called_data)
def test_alert_workflow_update_command_func_called(mocker, args, func_to_be_called, response):
    """
    Given:
        - All arguments needed.

    When:
        - Running 'cb-eedr-alert-workflow-update' command.

    Then:
        - The right function is called regarding polling.
    """
    from CarbonBlackEnterpriseEDR import alert_workflow_update_command_with_polling
    execute_command = mocker.patch.object(CLIENT, func_to_be_called, return_value=response)
    alert_workflow_update_command_with_polling(args, CLIENT)
    assert execute_command.called is True


alert_workflow_update_command_bad_argument_data = [
    ({'alert_id': '123'}),  # case no status and no determination.
    ({'alert_id': '123', 'start': '2019-01-01T11:00:00.157Z'}),  # case there is start but no end.
    ({'alert_id': '123', 'start': '2019-01-01T11:00:00.157Z', 'end': '2018-01-01T11:00:00.157Z'})  # case end is before start
]


@pytest.mark.parametrize('args', alert_workflow_update_command_bad_argument_data)
def test_alert_workflow_update_command_bad_arguments(args):
    """
    Given:
        - Invalid command's input.
    When:
        - Running 'cb-eedr-alert-workflow-update' command.

    Then:
        - The right exception is called.
    """
    from CarbonBlackEnterpriseEDR import alert_workflow_update_command_with_polling
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException):
        alert_workflow_update_command_with_polling(args, CLIENT)


process_search_command_func_called_data = [
    ({'process_name': 'bla1'},  # case first time polling (no job_id).
     'create_search_process_request'  # func to be called.
     ),
    ({'process_name': 'bla2', 'job_id': '12345'},  # case there is a job_id.
     'get_search_process_request'  # func to be called.
     )]


@pytest.mark.parametrize('args, func_to_be_called', process_search_command_func_called_data)
def test_alert_process_search_command_func_called(mocker, args, func_to_be_called):
    """
    Given:
        - All arguments needed.

    When:
        - Running 'cb-eedr-alert-workflow-update' command.

    Then:
        - The right function is called regarding polling.
    """
    from CarbonBlackEnterpriseEDR import process_search_command_with_polling
    execute_command = mocker.patch.object(CLIENT, func_to_be_called)
    process_search_command_with_polling(args, CLIENT)
    assert execute_command.called is True


test_fetch_incidents_first_run_data = [
    ({'results': [  # response
        {'id': '123', 'backend_timestamp': '2023-05-12T08:16:51.779Z', 'first_event_timestamp': '2000-04-12T08:14:51.779Z'},
        {'id': '456', 'backend_timestamp': '2023-05-12T08:17:51.779Z', 'first_event_timestamp': '2000-04-12T08:14:51.779Z'},
        {'id': '789', 'backend_timestamp': '2023-05-12T08:17:51.779Z', 'first_event_timestamp': '2000-04-12T08:14:51.779Z'}
    ]},
        {'last_fetched_alert_create_time': '2023-05-12T08:17:51.779Z', 'last_fetched_alerts_ids': ['456', '789']}  # expected res
    )
]


@pytest.mark.parametrize('response, expected_res', test_fetch_incidents_first_run_data)
def test_fetch_incidents__first_run(mocker, response, expected_res):
    """
    Given:
        - All arguments needed.

    When:
        - Running 'fetch-incidents' command in the first time.

    Then:
        - The fetch_incidents func returns the right last run.
    """
    from CarbonBlackEnterpriseEDR import fetch_incidents
    mocker.patch.object(CLIENT, 'search_alerts_request', return_value=response)
    mocker.patch('CommonServerPython.parse_date_range', return_value='2023-03-12T08:17:51.779Z')
    _, res = fetch_incidents(CLIENT, '3 days', '3', {})
    assert res == expected_res


test_fetch_incidents_second_run_data = [
    ({'results': [  # response
        {'id': '789', 'backend_timestamp': '2023-05-12T08:17:51.779Z', 'first_event_timestamp': '2000-04-12T08:14:51.779Z'},
        {'id': '123', 'backend_timestamp': '2023-06-12T08:17:51.779Z', 'first_event_timestamp': '2000-05-12T08:14:51.779Z'},
        {'id': '345', 'backend_timestamp': '2023-07-12T08:17:51.779Z', 'first_event_timestamp': '2000-05-12T08:14:51.779Z'}
    ]},
        {'last_fetched_alert_create_time': '2023-05-12T08:17:51.779Z', 'last_fetched_alerts_ids': ['456', '789']}  # last_run
    )
]


@pytest.mark.parametrize('response, last_run', test_fetch_incidents_second_run_data)
def test_fetch_incidents__second_run(mocker, response, last_run):
    """
    Given:
        - All arguments needed.

    When:
        - When the fetch is running for the second cycle (there is an existing last_run to use).

    Then:
        - The fetch_incidents func returns the alerts needed and drops the duplicates.
    """
    from CarbonBlackEnterpriseEDR import fetch_incidents
    mocker.patch.object(CLIENT, 'search_alerts_request', return_value=response)
    mocker.patch('CommonServerPython.parse_date_range', return_value='2023-03-12T08:17:51.779Z')
    incidents, _ = fetch_incidents(CLIENT, '3 days', '3', last_run)
    incidents_ids = "".join([incident['name'] for incident in incidents])
    assert '789' not in incidents_ids
    assert '123' in incidents_ids
    assert '345' in incidents_ids


def test_fetch_incidents__no_alerts(mocker):
    """
    Given:
        - All arguments needed.

    When:
        - Running 'fetch-incidents' command and there are no alerts retrieved.

    Then:
        - The fetch_incidents func doesn't fail and the last run doesn't change.
    """
    from CarbonBlackEnterpriseEDR import fetch_incidents
    mocker.patch.object(CLIENT, 'search_alerts_request', return_value={})
    _, res = fetch_incidents(CLIENT, fetch_time='3 days', fetch_limit='50', last_run={
                             'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]})
    assert res == {'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]}


def test_fetch_incidents__one_alert_in_response(mocker):
    """
    Given:
        - All arguments needed.
    When:
        - Running 'fetch-incidents' command and there is only one alert retrieved (and it will be deduped).
    Then:
        - The fetch_incidents func doesn't fail and the last run doesn't change.
    """
    from CarbonBlackEnterpriseEDR import fetch_incidents
    mocker.patch.object(CLIENT, 'search_alerts_request', return_value={'results': [
        {'id': '123', 'backend_timestamp': '2000-07-16T05:26:05.491Z', 'first_event_timestamp': '2000-04-12T08:14:51.779Z'}
    ]})
    _, res = fetch_incidents(CLIENT, fetch_time='3 days', fetch_limit='50', last_run={
                             'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]})
    assert res == {'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]}


check_getLastRun_data = [
    # case most updated version.
    ({'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]},
     # expected last_run to stay the same.
     {'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]}),
    # case not most updated version.
    ({'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alert_id': "123"},
     # expected last_run to change
     {'last_fetched_alert_create_time': "2000-07-16T05:26:05.491Z", 'last_fetched_alerts_ids': ["123"]})
]


@pytest.mark.parametrize('last_run, expected_last_run', check_getLastRun_data)
def test_check_getLastRun(last_run, expected_last_run):
    """
    Given:
        - A last_run.
    When:
        - Running check_gatLastRun.
    Then:
        - The func returns a last run that is in the same pattern as the most updated version.
    """
    from CarbonBlackEnterpriseEDR import check_get_last_run

    updated_last_run = check_get_last_run(last_run)
    assert updated_last_run == expected_last_run


def test_search_alerts_request__empty_arguments(mocker):
    """
        Given:
            - Empty arguments.
        When:
            - Running list-alerts command.
        Then:
            - The http request is called with no 'time_range' key in the body
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.search_alerts_request()
    assert 'time_range' not in http_request.call_args.kwargs['json_data']


def test_create_search_process_request__event_id_arg(mocker):
    """
        Given:
            - An event_id arg
        When:
            - Running process-search command.
        Then:
            - The http request is called with the event_id in Square bars.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.create_search_process_request(event_id=123, process_hash='', process_name='', query='', start_time='1 day')
    assert http_request.call_args.kwargs['json_data']['criteria']['event_id'] == [123]

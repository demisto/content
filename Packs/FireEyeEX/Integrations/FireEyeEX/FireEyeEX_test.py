import io

import pytest

from FireEyeEX import *
from test_data.result_constants import QUARANTINED_EMAILS_CONTEXT, GET_ALERTS_CONTEXT, GET_ALERTS_DETAILS_CONTEXT, \
    GET_ARTIFACTS_METADATA_CONTEXT, ALLOWEDLIST, BLOCKEDLIST


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_alerts(mocker):
    """Unit test
    Given
    - get_alerts command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request',
                        return_value=util_load_json('test_data/get_alerts.json'))
    command_results = get_alerts(client=client,
                                 args={'limit': '2', 'start_time': '2 months', 'sender_email': 'test@malicious.net'})
    assert command_results.outputs == GET_ALERTS_CONTEXT


def test_get_alert_details(mocker):
    """Unit test
    Given
    - get_alert_details command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alert_details_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alert_details_request',
                        return_value=util_load_json('test_data/get_alert_details.json'))
    command_results = get_alert_details(client=client, args={'alert_id': '3'})
    assert command_results[0].outputs == GET_ALERTS_DETAILS_CONTEXT


def test_get_artifacts_metadata(mocker):
    """Unit test
    Given
    - get_artifacts_metadata_by_uuid command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_artifacts_metadata_by_uuid request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_artifacts_metadata_by_uuid_request',
                        return_value=util_load_json('test_data/get_artifact_metadata.json'))
    command_results = get_artifacts_metadata_by_uuid(client=client, args={'uuid': 'uuid'})
    assert command_results[0].outputs == GET_ARTIFACTS_METADATA_CONTEXT


def test_get_quarantined_emails(mocker):
    """Unit test
    Given
    - get_quarantined_emails command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_quarantined_emails_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_quarantined_emails_request',
                        return_value=util_load_json('test_data/quarantined_emails.json'))
    command_results = get_quarantined_emails(client=client, args={'limit': '2'})
    assert command_results.outputs == QUARANTINED_EMAILS_CONTEXT


def test_get_report_not_found(mocker):
    """Unit test
    Given
    - get_reports command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_reports_request response for a non found report.
    Then
    - Validate the human readable
    """
    error_msg = 'Error in API call [400] - Bad Request ' \
                '{"fireeyeapis": {"@version": "v2.0.0", "description": "WSAPI_REPORT_ALERT_NOT_FOUND.' \
                ' code:WSAPI_WITH_ERRORCODE_2016", "httpStatus": 400,' \
                ' "message": "parameters{infection_id=34013; infection_type=malware-callback}"}}'

    def error_400_mock(*kwargs):
        raise Exception(error_msg)

    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)

    mocker.patch('FireEyeEX.FireEyeClient.get_reports_request', side_effect=error_400_mock)

    command_results = get_reports(client=client, args={'report_type': 'alertDetailsReport', 'infection_id': '34013',
                                                       'infection_type': 'mallware-callback'})
    assert command_results.readable_output == 'Report alertDetailsReport was not found with the given arguments.'


def test_release_quarantined_emails(mocker):
    """Unit test
    Given
    - release_quarantined_emails command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's release_quarantined_emails_request response.
    Then
    - Validate that an error is raised from the command
    """

    def mocked_release_quarantined_emails_requests(*args):
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

            def text(self):
                return '1234'

        return MockResponse({"1234": "Unable to release the email:quarantined email does not exist\\n"}, 200)

    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'release_quarantined_emails_request',
                        side_effect=mocked_release_quarantined_emails_requests)
    with pytest.raises(DemistoException):
        release_quarantined_emails(client=client, args={'queue_ids': '1234'})


def test_delete_quarantined_emails(mocker):
    """Unit test
    Given
    - delete_quarantined_emails command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's delete_quarantined_emails_request response.
    Then
    - Validate that an error is raised from the command
    """

    def mocked_delete_quarantined_emails_requests(*args):
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

            def text(self):
                return '1234'

        return MockResponse({"1234": "Unable to delete the email:quarantined email does not exist\\n"}, 200)

    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'delete_quarantined_emails_request',
                        side_effect=mocked_delete_quarantined_emails_requests)
    with pytest.raises(DemistoException):
        delete_quarantined_emails(client=client, args={'queue_ids': '1234'})


def test_list_allowedlist(mocker):
    """Unit test
    Given
    - list_allowedlist_request command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_allowedlist_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_allowedlist_request',
                        return_value=util_load_json('test_data/list_allowedlist.json'))
    command_results = list_allowedlist(client=client, args={'type': 'url'})
    assert command_results.outputs == ALLOWEDLIST


def test_create_allowedlist_already_exist(mocker):
    """Unit test
    Given
    - create_allowedlist_request command
    - an already existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_allowedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_allowedlist_request',
                        return_value=util_load_json('test_data/list_allowedlist.json'))
    err_str = 'Cannot create the entry_value www.demisto.com as it is already exist in the Allowedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        create_allowedlist(client=client, args={'type': 'url', 'entry_value': 'www.demisto.com', 'matches': '2'})


def test_update_allowedlist_not_exist(mocker):
    """Unit test
    Given
    - update_allowedlist_request command
    - a non existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_allowedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_allowedlist_request',
                        return_value=util_load_json('test_data/list_allowedlist.json'))
    err_str = 'Cannot update the entry_value www.fake.com as it does not exist in the Allowedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        update_allowedlist(client=client, args={'type': 'url', 'entry_value': 'www.fake.com', 'matches': '2'})


def test_delete_allowedlist_not_exist(mocker):
    """Unit test
    Given
    - delete_allowedlist_request command
    - a non existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_allowedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_allowedlist_request',
                        return_value=util_load_json('test_data/list_allowedlist.json'))
    err_str = 'Cannot delete the entry_value www.fake.com as it does not exist in the Allowedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        delete_allowedlist(client=client, args={'type': 'url', 'entry_value': 'www.fake.com'})


def test_list_blockedlist(mocker):
    """Unit test
    Given
    - list_blockedlist_request command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_blockedlist_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request',
                        return_value=util_load_json('test_data/list_blockedlist.json'))
    command_results = list_blockedlist(client=client, args={'type': 'url'})
    assert command_results.outputs == BLOCKEDLIST


def test_list_blockedlist_with_limit(mocker):
    """Unit test
    Given
    - list_blockedlist_request command
    - command args with a limit
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_blockedlist_request response.
    Then
    - Validate The entry context is limited
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request',
                        return_value=util_load_json('test_data/list_blockedlist.json'))
    command_results = list_blockedlist(client=client, args={'type': 'url', 'limit': '1'})
    assert command_results.outputs == BLOCKEDLIST[:1]


def test_list_blockedlist_no_entries(mocker):
    """Unit test
    Given
    - list_blockedlist_request command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_blockedlist_request response.
    Then
    - Validate The human readable yields an appropriate message
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request', return_value={})
    command_results = list_blockedlist(client=client, args={'type': 'sender_domain'})
    assert command_results.readable_output == 'No blocked lists with the given type sender_domain were found.'


def test_create_blockedlist_already_exist(mocker):
    """Unit test
    Given
    - create_blockedlist_request command
    - an already existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_allowedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request',
                        return_value=util_load_json('test_data/list_blockedlist.json'))
    err_str = 'Cannot create the entry_value www.blocksite1.net/path/test.html as it is already exist in the ' \
              'Blockedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        create_blockedlist(client=client, args={'type': 'url', 'entry_value': 'www.blocksite1.net/path/test.html',
                                                'matches': '2'})


def test_update_blockedlist_not_exist(mocker):
    """Unit test
    Given
    - update_blockedlist_request command
    - a non existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_blockedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request',
                        return_value=util_load_json('test_data/list_blockedlist.json'))
    err_str = 'Cannot update the entry_value www.fake.com as it does not exist in the Blockedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        update_blockedlist(client=client, args={'type': 'url', 'entry_value': 'www.fake.com', 'matches': '2'})


def test_delete_blockedlist_not_exist(mocker):
    """Unit test
    Given
    - delete_blockedlist_request command
    - an non existing entry_value
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's list_blockedlist_request response.
    Then
    - Validate The a proper error is raised
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'list_blockedlist_request',
                        return_value=util_load_json('test_data/list_blockedlist.json'))
    err_str = 'Cannot delete the entry_value www.fake.com as it does not exist in the Blockedlist of type url.'
    with pytest.raises(DemistoException, match=err_str):
        delete_blockedlist(client=client, args={'type': 'url', 'entry_value': 'www.fake.com'})


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the last_run.
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=50,
                                          info_level='concise')
    assert len(incidents) == 5
    assert last_run.get('time') == '2021-02-14 17:01:14 +0000'  # occurred time of the last alert


def test_fetch_incidents_with_limit(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args with a harsh limit
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the last_run of the limited incident.
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.ex.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=2,
                                          info_level='concise')
    assert len(incidents) == 2
    assert last_run.get('time') == '2021-02-14 09:43:55 +0000'  # occurred time of the last alert


def test_fetch_incidents_last_alert_ids(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the last_event_alert_ids
    - mock the Client's get_alerts_request.
    Then
    - Validate that no incident will be returned.
    - Validate that the last_run is pushed in two days from the latest incident fetched
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run_time = '2021-02-14T17:01:14+00:00'
    next_run_time = (dateparser.parse(last_run_time[:-6]) + timedelta(hours=48)).isoformat()
    last_alert_ids = '["1", "2", "3", "4", "5"]'
    last_run = {
        'time': last_run_time,
        'last_alert_ids': last_alert_ids
    }
    next_run, incidents = fetch_incidents(client=client,
                                          last_run=last_run,
                                          first_fetch='1 year',
                                          max_fetch=50,
                                          info_level='concise')

    assert len(incidents) == 0
    # trim miliseconds to avoid glitches such as 2021-05-19T10:21:52.121+00:00 != 2021-05-19T10:21:52.123+00:00
    assert next_run.get('time')[:-6] == next_run_time
    assert next_run.get('last_alert_ids') == last_alert_ids


def test_module_test(mocker):
    """
    Given:
        -

    When:
        - Run the test-module command

    Then:
        - Validate the get_alerts_request was called with the start_time argument
    """

    # prepare
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    mocker.patch.object(FireEyeClient, 'get_alerts_request')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)

    # run
    run_test_module(client=client)

    # validate

    # take the date from the whole fe_datetime by split by the T
    start_time = to_fe_datetime_converter('1 day').split('T')[0]
    call_args_dict = FireEyeClient.get_alerts_request.call_args[0][0]
    assert start_time in call_args_dict['start_time']
    assert call_args_dict['duration'] == '24_hours'


@pytest.mark.parametrize(argnames='status_code', argvalues=OK_CODES)
def test_ok_status_codes_in_fe_response(mocker, status_code):
    """
    Given:
        - ok status codes defined in FireEyeApiModule

    When:
        - Run any FireEye request

    Then:
        - Validate the response consider ok and return the data
    """

    # prepare
    mocked_response = requests.Response()
    mocked_response.status_code = status_code
    mocked_response._content = json.dumps({'request_status': 'success'}).encode('utf-8')
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    mocker.patch('requests.sessions.Session.request', return_value=mocked_response)
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)

    # run
    res = client.fe_client.get_alerts_request({
        'info_level': 'concise',
        'start_time': to_fe_datetime_converter('1 day'),
        'duration': '24_hours',
    })

    # validate
    assert res['request_status'] == 'success'


def test_wrong_status_codes_in_fe_response(mocker):
    """
    Given:
        - wrong status codes not defined as ok_codes in FireEyeApiModule

    When:
        - Run any FireEye request

    Then:
        - Validate the request was failed
    """

    # prepare
    mocked_response = requests.Response()
    mocked_response.status_code = 300
    mocked_response._content = json.dumps({'request_status': 'failed'}).encode('utf-8')
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    mocker.patch('requests.sessions.Session.request', return_value=mocked_response)
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)

    # run
    with pytest.raises(DemistoException, match='Error in API call'):
        client.fe_client.get_alerts_request({
            'info_level': 'concise',
            'start_time': to_fe_datetime_converter('1 day'),
            'duration': '24_hours',
        })

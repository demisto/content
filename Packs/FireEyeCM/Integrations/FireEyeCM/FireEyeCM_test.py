
import pytest
from freezegun import freeze_time

from FireEyeCM import *
from test_data.result_constants import QUARANTINED_EMAILS_CONTEXT, GET_ALERTS_CONTEXT, GET_ALERTS_DETAILS_CONTEXT, \
    GET_ARTIFACTS_METADATA_CONTEXT, GET_EVENTS_CONTEXT


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request',
                        return_value=util_load_json('test_data/get_alerts.json'))
    command_results = get_alerts(client=client,
                                 args={'limit': '2', 'start_time': '8 days', 'src_ip': '2.2.2.2'})
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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alert_details_request',
                        return_value=util_load_json('test_data/get_alert_details.json'))
    command_results = get_alert_details(client=client, args={'alert_id': '563'})
    assert command_results[0].outputs == GET_ALERTS_DETAILS_CONTEXT


def test_alert_acknowledge(mocker):
    """Unit test
    Given
    - alert_acknowledge command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's alert_acknowledge_request response.
    Then
    - Validate the human readable
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'alert_acknowledge_request', return_value=None)
    command_results = alert_acknowledge(client=client, args={'uuid': 'uuid'})
    assert command_results[0].readable_output == 'Alert uuid was acknowledged successfully.'


def test_alert_acknowledge_already_acknowledged(mocker):
    """Unit test
    Given
    - alert_acknowledge command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's alert_acknowledge_request response for an already acknowledged alert.
    Then
    - Validate the human readable
    """
    error_msg = 'Error in API call [404] - Not Found' \
                '{"fireeyeapis": {"@version": "v2.0.0", "description": "Alert not found or cannot update.' \
                ' code:ALRTCONF008", "httpStatus": 404, "message": "Alert not found or cannot update"}}'

    def error_404_mock(*kwargs):
        raise Exception(error_msg)

    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)

    mocker.patch('FireEyeCM.FireEyeClient.alert_acknowledge_request', side_effect=error_404_mock)

    command_results = alert_acknowledge(client=client, args={'uuid': 'uuid'})
    assert command_results[0].readable_output == \
        'Alert uuid was not found or cannot update. It may have been acknowledged in the past.'


def test_get_artifacts_metadata(mocker):
    """Unit test
    Given
    - get_artifacts_metadata_by_uuid command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_artifacts_metadata_by_uuidrequest response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_quarantined_emails_request',
                        return_value=util_load_json('test_data/quarantined_emails.json'))
    command_results = get_quarantined_emails(client=client, args={})
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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)

    mocker.patch('FireEyeCM.FireEyeClient.get_reports_request', side_effect=error_400_mock)

    command_results = get_reports(client=client, args={'report_type': 'alertDetailsReport', 'infection_id': '34013',
                                                       'infection_type': 'mallware-callback'})
    assert command_results.readable_output == 'Report alertDetailsReport was not found with the given arguments.'


def test_get_events_no_events(mocker):
    """Unit test
    Given
    - get_events command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_events_request response for no events.
    Then
    - Validate the human readable
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_events_request',
                        return_value=util_load_json('test_data/get_events_none.json'))
    command_results = get_events(client=client, args={'end_time': '2020-05-19T23:00:00.000-00:00',
                                                      'duration': '48_hours', 'limit': '3'})
    assert command_results.readable_output == 'No events in the given timeframe were found.'


def test_get_events(mocker):
    """Unit test
    Given
    - get_events command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_events_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_events_request',
                        return_value=util_load_json('test_data/get_events.json'))
    command_results = get_events(client=client, args={'end_time': '2021-05-19T23:00:00.000-00:00',
                                                      'duration': '48_hours', 'limit': '3'})
    assert command_results.outputs == GET_EVENTS_CONTEXT


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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'release_quarantined_emails_request',
                        side_effect=mocked_release_quarantined_emails_requests)
    with pytest.raises(DemistoException):
        release_quarantined_emails(client=client, args={'sensor_name': 'FireEyeEX', 'queue_ids': '1234'})


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
        delete_quarantined_emails(client=client, args={'sensor_name': 'FireEyeEX', 'queue_ids': '1234'})


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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=50,
                                          info_level='concise')
    assert len(incidents) == 11
    assert last_run.get('time') == '2021-05-18 12:02:54 +0000'  # occurred time of the last alert


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
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=5,
                                          info_level='concise')
    assert len(incidents) == 5
    assert last_run.get('time') == '2021-05-18 05:04:36 +0000'  # occurred time of the last alert


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
    - Validate that no incidents will be returned.
    - Validate that the last_run is pushed in two days from the latest incident fetched
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run_time = '2021-05-18T12:02:54+00:00'
    next_run_time = (dateparser.parse(last_run_time[:-6]) + timedelta(hours=48)).isoformat()
    last_alert_ids = '["35267", "35268", "35269", "35272", "35273", "35274", "35275", "35276", "35277", "35278", ' \
                     '"35279"]'
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


# We freeze the time since we are using dateparser.parse('now') in the fetch incidents
@freeze_time('2021-02-15T17:10:00+00:00')
def test_fetch_incidents_no_alerts(mocker):
    """Unit test
    Given
    - Current time is 2021-02-15 17:10:00 +00:00
    - Fetch incidents command is called

    When
    - No results returned from the search for the start_time = 2021-02-14 17:01:14 +00:00 (no new alerts created until
    now)

    Then
    - Validate that no incident will be returned.
    - Validate that the last_run is set to the current time minus ten minutes (2021-02-15 17:00:00 +00:00)
    - Validate last_alert_ids is reset to empty list
    """
    mocker.patch.object(FireEyeClient, '_get_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(FireEyeClient, 'get_alerts_request', return_value=util_load_json('test_data/no_alerts.json'))
    last_run_time = '2021-02-14T17:01:14+00:00'
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
    assert next_run.get('time') == '2021-02-15T17:00:00+00:00'
    assert next_run.get('last_alert_ids') == []

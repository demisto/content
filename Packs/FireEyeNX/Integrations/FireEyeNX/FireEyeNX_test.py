from datetime import timezone
from unittest import mock
from unittest.mock import patch

import pytest
from requests.exceptions import MissingSchema, InvalidSchema, SSLError, InvalidURL, HTTPError
from requests import Response
from CommonServerPython import *

API_TOKEN = 'API Token for FireEye'
CONTENT_TYPE_JSON = 'application/json'
SAMPLE_URL = 'https://sample.api.com'

AUTHENTICATION_RESP_HEADER = {
    'X-FeApi-Token': API_TOKEN,
    'Content-Type': CONTENT_TYPE_JSON
}

MOCK_INTEGRATION_CONTEXT = {
    'api_token': API_TOKEN,
    'valid_until': time.time() + 900
}

PARAMS = {
    'url': SAMPLE_URL,
    'fetch_limit': 10,
    'firstFetchTimestamp': '1 hour'
}

MOCK_TEST_URL_SUFFIX = '/test/url/suffix'

ALERT_ID_TYPE_ERROR = 'The given value for alert_id is invalid. Expected integer value.'
ALERT_DETAILS_REPORT = 'Alert Details Report'
CONTENT_TYPE_ZIP = 'application/zip'

''' HELPER FUNCTION'''


@pytest.fixture()
def client():
    from FireEyeNX import Client
    return Client(base_url=SAMPLE_URL,
                  verify=False,
                  proxy=False,
                  auth=('username', 'password'),
                  request_timeout=60)


def mock_http_response(status=200, headers=None, json_data=None, raise_for_status=None, text=None, content=None):
    mock_resp = mock.Mock()
    # mock raise_for_status call w/optional error
    mock_resp.raise_for_status = mock.Mock()
    if raise_for_status:
        mock_resp.raise_for_status.side_effect = raise_for_status
    # set status code
    mock_resp.status_code = status
    # add header if provided
    mock_resp.text = text
    mock_resp.content = content
    if headers:
        mock_resp.headers = headers
    mock_resp.ok = True if status < 400 else False
    # add json data if provided
    if json_data:
        mock_resp.json = mock.Mock(
            return_value=json_data
        )
    return mock_resp


class MockResponse:
    def __init__(self, content, headers, status_code):
        self.content = content
        self.status_code = status_code
        self.headers = headers

    def text(self):
        return self.content

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if self.status_code != 200:
            raise HTTPError('test')


''' Unit Test Cases '''


@patch('FireEyeNX.Client.http_request')
@patch('demistomock.getIntegrationContext')
@patch('demistomock.setIntegrationContext')
def test_get_api_token_when_not_found_in_integration_context(mocker_set_context, mocker_get_context, mock_request,
                                                             client):
    """
        When get_api_token method called and headers is set with X-FeApi-Token also call_count is one,
        it should match.
    """
    mocker_get_context.return_value = {}
    mocker_set_context.return_value = {}

    mock_request.return_value = mock_http_response(status=200, headers=AUTHENTICATION_RESP_HEADER, text='')

    api_token = client.get_api_token()

    assert api_token == AUTHENTICATION_RESP_HEADER['X-FeApi-Token']
    assert mocker_set_context.call_count == 1


@patch('FireEyeNX.Client._http_request')
@patch('demistomock.getIntegrationContext')
@patch('demistomock.setIntegrationContext')
def test_get_api_token_when_found_in_integration_context(mocker_set_context, mocker_get_context, mock_request,
                                                         client):
    """
        When get_api_token method called and headers is set with X-FeApi-Token also call_count is zero, it should match.
    """
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    mocker_set_context.return_value = {}

    mock_request.return_value = mock_http_response(status=200, headers=AUTHENTICATION_RESP_HEADER, text='')

    api_token = client.get_api_token()

    assert api_token == AUTHENTICATION_RESP_HEADER['X-FeApi-Token']
    assert mocker_set_context.call_count == 0


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_invalid_schema_error(mock_base_http_request, client):
    """
        When http request return invalid schema exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = InvalidSchema

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Invalid API URL. Supplied schema is invalid, supports http(s).'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_proxy_error(mock_base_http_request, client):
    """
        When http request return proxy error with exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('Proxy Error')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\'' \
                           ' check-box or check the host, authentication details and connection details for the proxy.'


@patch('FireEyeNX.Client._http_request')
def test_http_request_connection_error(mock_base_http_request, client):
    """
        When http request return connection error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ConnectionError')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Connectivity failed. Check your internet connection or the API URL.'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_read_timeout_error(mock_base_http_request, client):
    """
        When http request return connection error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ReadTimeoutError')

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Request timed out. Check the configured HTTP(S) Request Timeout (in seconds) value.'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_ssl_error(mock_base_http_request, client):
    """
        When http request return ssl error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('SSLError')
    # Execute
    with pytest.raises(SSLError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox ' \
                           'in the integration configuration.'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_missing_schema_error(mock_base_http_request, client):
    """
        When http request return MissingSchema exception then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.side_effect = MissingSchema

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Invalid API URL. No schema supplied: http(s).'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_invalid_url_error(mock_base_http_request, client):
    """
        When http request return invalid url exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = InvalidURL

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'Invalid API URL.'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_other_demisto_exception(mock_base_http_request, client):
    """
        When http request return other custom Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('custom')

    # Execute
    with pytest.raises(Exception) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX)

    # Assert
    assert str(e.value) == 'custom'


def test_main_success(mocker):
    """
        When main function called test function should call.
    """
    import FireEyeNX

    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(FireEyeNX, 'test_function', return_value='ok')
    FireEyeNX.main()
    assert FireEyeNX.test_function.called


def test_main_all_argunment_should_strip(mocker):
    import FireEyeNX

    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='fireeye-nx-get-alerts')
    mocker.patch.object(FireEyeNX, 'get_alerts_command', return_value='ok')
    args = {
        'malware_name': ' malware_name ',
        'malware_type': ' domain_match ',
        'url': SAMPLE_URL
    }
    actual_output = {
        'malware_name': 'malware_name',
        'malware_type': 'domain_match',
        'url': SAMPLE_URL
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    FireEyeNX.main()
    assert args == actual_output


def test_main_when_fetch_incident_called_it_should_called_fetch_incident_method(mocker):
    import FireEyeNX
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(FireEyeNX, 'fetch_incidents', return_value='ok')
    mocker.patch.object(demisto, 'setLastRun', return_value='')
    mocker.patch.object(demisto, 'incidents', return_value='')
    FireEyeNX.main()


@patch('FireEyeNX.return_error')
def test_main_failure(mock_return_error, mocker):
    """
        When main function get some exception then valid message should be print.
    """
    import FireEyeNX
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(FireEyeNX, 'test_function', side_effect=Exception)
    FireEyeNX.main()

    mock_return_error.assert_called_once_with('Error: ')


@patch('FireEyeNX.BaseClient._http_request')
def test_module_success_without_test_fetch_incident(mock_request, client):
    """
        When test_function called with status code 200 without is_fetch=false, it successful return ok.
    """
    from FireEyeNX import test_function

    mock_request.return_value = mock_http_response(status=200, headers=AUTHENTICATION_RESP_HEADER, text='')
    first_fetch_time = '12 hours'
    fetch_limit = '1'
    malware_type = ''
    is_fetch = False
    fetch_type = 'Alert'
    mvx_correlated = False
    replace_alert_url = False
    instance_url = SAMPLE_URL
    fetch_artifacts = False

    resp = test_function(client=client, first_fetch_time=first_fetch_time, fetch_limit=fetch_limit,
                         malware_type=malware_type, is_fetch=is_fetch, fetch_type=fetch_type,
                         mvx_correlated=mvx_correlated, replace_alert_url=replace_alert_url, instance_url=instance_url,
                         fetch_artifacts=fetch_artifacts)

    assert resp == 'ok'


@patch('FireEyeNX.get_incidents_for_alert')
@patch('FireEyeNX.BaseClient._http_request')
def test_module_success_with_fetch_incident(mock_get_alert, mock_request, client):
    """
        When test_function called with status code 200 without is_fetch=False, it successful return ok.
    """
    from FireEyeNX import test_function
    mock_get_alert.return_value = []
    mock_last_run = {
        'start_time': datetime.now().replace(tzinfo=timezone.utc).timestamp()
    }

    mock_request.return_value = mock_http_response(status=200, headers=AUTHENTICATION_RESP_HEADER, text='')
    first_fetch_time = '12 hours'
    fetch_limit = '1'
    malware_type = None
    is_fetch = True
    fetch_type = 'Alert'
    mvx_correlated = False
    replace_alert_url = False
    instance_url = SAMPLE_URL
    fetch_artifacts = False
    resp = test_function(client=client, first_fetch_time=first_fetch_time, fetch_limit=fetch_limit,
                         malware_type=malware_type,
                         is_fetch=is_fetch, fetch_type=fetch_type,
                         mvx_correlated=mvx_correlated, replace_alert_url=replace_alert_url, instance_url=instance_url,
                         fetch_artifacts=fetch_artifacts, last_run=mock_last_run)

    assert resp == 'ok'


def test_validate_date_range_failure():
    """
        When validate_date_range_failure() method call and date more then 48 hour then raise value error.
    """
    from FireEyeNX import validate_date_range
    fetch_time = '49 hours'

    with pytest.raises(ValueError) as e:
        validate_date_range(fetch_time)

    assert str(e.value) == 'The First fetch time interval should be up to 48 hour as per API limitation.'


def test_fetch_limit_when_valid_value_success(mocker):
    """
        When valid fetch_limit is given, test should pass.
    """
    from FireEyeNX import get_fetch_limit
    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    fetch_limit = get_fetch_limit(fetch_limit='')
    assert fetch_limit == 50


@pytest.mark.parametrize('inputs', ['0', '201', 'dfdf'])
def test_fetch_limit_when_invalid_value_should_raise_exception(mocker, inputs):
    """
        When invalid fetch limit is passed, should raises value error.
    """
    from FireEyeNX import get_fetch_limit
    mocker.patch.object(demisto, 'params', return_value={'fetch_limit': inputs})

    with pytest.raises(ValueError) as e:
        get_fetch_limit(inputs)

    assert str(e.value) == 'Value of Fetch Limit should be an integer and between range 1 to 200.'


def test_command_called_from_main_success(mocker, client):
    """
        When main function is called get_reports_command should be called if that command is triggered.
    """
    import FireEyeNX

    mocker.patch.object(demisto, 'command', return_value='fireeye-nx-get-reports')
    mocker.patch.object(FireEyeNX, 'get_reports_command', return_value='No report contents were '
                                                                       'found for the given argument(s).')
    FireEyeNX.main()
    assert FireEyeNX.get_reports_command.called


@patch('FireEyeNX.Client.http_request')
def test_get_artifacts_metadata_by_alert_command_invalid_uuid(client):
    """
        When fireeye-nx-get-artifacts-metadata-by-alert command executes with uuid and it failure due to
        artifacts metadata is not present.
    """
    from FireEyeNX import get_artifacts_metadata_by_alert_command
    client.http_request.return_value = {
        'artifactsInfoList': []
    }

    args = {
        'uuid': 'abc-dsh-didA'
    }
    return_value = get_artifacts_metadata_by_alert_command(client, args)

    assert return_value == 'No artifacts metadata were found for the given argument(s).'


@patch('FireEyeNX.Client.http_request')
def test_get_artifacts_metadata_by_alert_command_success(client):
    """
        When fireeye-nx-get-artifacts-metadata-by-alert command executes successfully then context output and
        response should match.
    """
    from FireEyeNX import get_artifacts_metadata_by_alert_command

    args = {
        'uuid': 'test'
    }

    with open('TestData/get_artifacts_metadata_by_alert_response.json') as f:
        expected_res = json.load(f)

    client.http_request.return_value = expected_res

    cmd_res = get_artifacts_metadata_by_alert_command(client, args)
    with open('TestData/get_artifacts_metadata_by_alert_context.json', encoding='utf-8') as f:
        expected_ec = json.load(f)

    with open('TestData/get_artifacts_metadata.md') as f:
        expected_hr = f.read()

    assert cmd_res.raw_response == expected_res
    assert cmd_res.outputs == expected_ec
    assert cmd_res.readable_output == expected_hr


@patch('FireEyeNX.BaseClient._http_request')
@pytest.mark.parametrize('args', [
    {
        'report_type': ALERT_DETAILS_REPORT,
        'type': 'pdf',
        'time_frame': 'between',
        'start_time': '2020-01-29',
        'end_time': '2020-02-29T23:59:59+13:00',
        'infection_id': 'rt', 'infection_type': 'all'
    },
    {
        'report_type': ALERT_DETAILS_REPORT,
        'type': 'pdf',
        'time_frame': 'between',
        'start_time': '2020-01-29T23:59:59+13:01',
        'end_time': '2020-02-29',
        'infection_id': 'rt', 'infection_type': 'all'
    }
])
def test_get_reports_success(mock_request, args, client):
    """
        When fireeye-nx-get-reports command execute and passed valid arguments, it should be successful.
    """
    from FireEyeNX import get_reports_command

    with open('TestData/get_reports_response.pdf', encoding='utf-8') as f:
        expected_res = f.read()

    headers = {
        'X-FeApi-Token': API_TOKEN,
        'Content-Type': 'application/pdf',
        'Content-Length': 56
    }

    mock_request.return_value = mock_http_response(status=200, headers=headers, content=expected_res)

    result = get_reports_command(client, args=args)
    assert result.get('File', '') != ''
    assert result.get('FileID', '') != ''


@patch('FireEyeNX.BaseClient._http_request')
def test_get_reports_no_records_found(mock_request, client):
    """
        When fireeye-nx-get-reports command returns empty response then corresponding message should be populated.
    """
    from FireEyeNX import get_reports_command

    with open('TestData/get_reports_response.pdf', encoding='utf-8') as f:
        expected_res = f.read()

    headers = {
        'X-FeApi-Token': API_TOKEN,
        'Content-Type': 'application/pdf',
        'Content-Length': 0
    }

    mock_request.return_value = mock_http_response(status=200, headers=headers, content=expected_res)

    args = {
        'report_type': 'IPS Top N Attackers Report',
        'limit': 56,
        'interface': 'C',
        'type': 'csv'
    }

    result = get_reports_command(client, args=args)
    assert result == 'No report contents were found for the given argument(s).'


def test_reports_command_invalid_report_type(client):
    """
        When fireeye-nx-get-reports command is provided invalid report type argument
        it should give an error message.
    """
    from FireEyeNX import get_reports_params
    args = {
        'report_type': 'XYZ'
    }
    with pytest.raises(ValueError) as e:
        get_reports_params(args=args)

    assert str(e.value) == 'The given value for report_type is invalid.'


def test_reports_command_invalid_output_type(client):
    """
        When fireeye-nx-get-reports command is provided invalid output type argument
        it should give an error message.
    """
    from FireEyeNX import get_reports_params
    args = {
        'report_type': ALERT_DETAILS_REPORT,
        'type': 'csv'
    }
    with pytest.raises(ValueError) as e:
        get_reports_params(args=args)

    assert str(e.value) == 'The given value for the argument type (report\'s format) is invalid. Valid value(s): pdf.'


def test_reports_command_invalid_limit(client):
    """
        When fireeye-nx-get-reports command is provided with invalid value of limit it should give an error message.
    """
    from FireEyeNX import get_reports_params
    args = {
        'report_type': 'IPS Top N Attackers Report',
        'limit': 'dummy',
        'end_time': '--'
    }
    with pytest.raises(ValueError) as e:
        get_reports_params(args=args)

    assert str(e.value) == 'The given value for limit is invalid. Expected integer value.'


def test_reports_command_missing_alert_argument():
    """
        When fireeye-nx-get-reports command is provided with same value of
        start_time and end_time it should give an error message.
    """
    from FireEyeNX import get_reports_params
    args = {
        'report_type': ALERT_DETAILS_REPORT,
        'type': 'pdf'
    }
    with pytest.raises(ValueError) as e:
        get_reports_params(args=args)

    assert str(e.value) == 'For fetching Alert Details Report, "infection_id" and ' \
                           '"infection_type" arguments are required.'


@pytest.mark.parametrize('args', [
    {
        'duration': '1_hour',
        'end_time': '2020',
        'mvx_correlated_only': 'dummy',
        'start_time': '2020'
    },
    {
        'duration': '1_hour',
        'end_time': '2020',
        'mvx_correlated_only': 'dummy',
        'start_time': '2020'
    }
])
def test_events_command_invalid_bool_value(args):
    """
        When fireeye-nx-get-events command is provided with invalid bool value of an argument
        it should give an error message.
    """
    from FireEyeNX import get_events_params

    with pytest.raises(ValueError) as e:
        get_events_params(args=args)

    assert str(e.value) == 'The given value for mvx_correlated_only argument is invalid. Valid values: true, false.'


def test_request_timeout_success():
    """
        When provided valid request timeout then test should be passed.
    """
    from FireEyeNX import get_request_timeout
    request_timeout = '5'

    request_timeout_int = get_request_timeout(request_timeout)
    assert request_timeout_int == int(request_timeout)


@pytest.mark.parametrize('request_timeout', ['invalid_str_value', '-5', '0'])
def test_request_timeout_invalid_value(request_timeout):
    """
        When provided invalid request timeout then display error message.
    """
    from FireEyeNX import get_request_timeout

    # Execute
    with pytest.raises(ValueError) as e:
        get_request_timeout(request_timeout)

    # Assert
    assert str(e.value) == 'HTTP(S) Request timeout parameter must be a positive integer.'


def test_request_timeout_large_value_failure():
    """
        When too large value provided for request timeout then raised value error and
        appropriate error message should display.
    """
    from FireEyeNX import get_request_timeout
    request_timeout = '990000000000000000'

    # Execute
    with pytest.raises(ValueError) as e:
        get_request_timeout(request_timeout)

    assert str(e.value) == 'Value is too large for HTTP(S) Request Timeout.'


@patch('FireEyeNX.BaseClient._http_request')
def test_http_request_when_response_type_is_json_return_type_should_match(mock_request, client):
    """
        When http_request called and response type is json and content is '{}' passed
        then response should match with {}.
    """
    headers = {
        'X-FeApi-Token': API_TOKEN,
        'Content-Type': CONTENT_TYPE_JSON
    }
    mock_request.return_value = MockResponse(status_code=200, content='{}', headers=headers)
    mock_request.return_value.ok = True
    resp = client.http_request(method='GET', url_suffix='')

    assert resp == {}


def test_handle_error_response_when_status_code_not_in_list_then_raise_for_status():
    """
        When handle_error_response method called and status is not in list then it must raise DemistoException.
    """
    from FireEyeNX import Client
    resp = MockResponse(content='{}', headers={}, status_code=200)

    with pytest.raises(DemistoException):
        Client.handle_error_response(resp)


def test_handle_error_response_when_content_type_zip(client):
    """
        When handle_error_response method called and status is not in list and content type is application/zip
        then it must called raise_for_status.
    """
    from FireEyeNX import Client
    resp = {

    }
    resp = mock_http_response(text='Could not fetch any artifact due to wrong uuid',
                              headers={'Content-Type': 'application/zip'}, status=403)
    with pytest.raises(DemistoException) as e:
        Client.handle_error_response(resp)
    assert str(e.value) == 'Could not fetch any artifact due to wrong uuid'


def test_handle_error_response_when_content_not_type_json_throw_value_error():
    """
        When handle_error_response method called and json string have error then through ValueError and it passed
        and again raise DemistoException.
    """
    from FireEyeNX import Client
    resp = MockResponse(content='{[]}', headers={}, status_code=400)
    with pytest.raises(DemistoException) as e:
        Client.handle_error_response(resp)

    assert str(e.value) == 'An error occurred while fetching the data. '


def test_set_integration_context_api_token_empty_failure():
    """
        When set_integration_context method called api token not there then must throw ValueError.
    """
    from FireEyeNX import Client
    resp = MockResponse(content='{}', headers={}, status_code=200)
    with pytest.raises(ValueError) as e:
        Client.set_integration_context(resp)

    assert str(e.value) == 'No api token found. Please try again'


@patch('FireEyeNX.replace_alert_url_key_domain_to_instance_url')
@patch('FireEyeNX.Client.http_request')
def test_get_alerts_command_success(mock_request, replace_url, client):
    """
        When fireeye-nx-get-alerts command is passed with valid arguments, it should be successful.
    """
    from FireEyeNX import get_alerts_command
    args = {
        'src_ip': '0.0.0.0',
        'dst_ip': '0.0.0.0',
        'duration': '1_hour',
        'start_time': '2017-06-21T16:30:00',
        'file_name': 'file_name',
        'file_type': 'file_type',
        'info_level': 'extended',
        'malware_name': 'malware_name',
        'malware_type': 'domain_match',
        'url': SAMPLE_URL
    }

    with open('TestData/get_alerts_response.json', encoding='utf-8') as f:
        expected_res = json.load(f)

    with open('TestData/get_alerts_context.json', encoding='utf-8') as f:
        expected_outputs = json.load(f)

    with open('TestData/get_alerts.md', encoding='utf-8') as f:
        expected_hr = f.read()

    mock_request.return_value = expected_res
    replace_url.return_value = None

    replace_alert_url = True
    instance_url = SAMPLE_URL

    cmd_result = get_alerts_command(client, args, replace_alert_url, instance_url)

    assert cmd_result.raw_response == expected_res
    assert cmd_result.outputs == expected_outputs
    assert cmd_result.readable_output == expected_hr


@patch('FireEyeNX.Client.http_request')
def test_get_alerts_command_no_record_failure(mock_request, client):
    """
        When fireeye-nx-get-alerts command called and passed with valid arguments but records are not present
        then it must return error message.
    """
    from FireEyeNX import get_alerts_command
    args = {
        'alert_id': '1',
        'src_ip': '0.0.0.0',
        'dst_ip': '0.0.0.0',
        'duration': '1_hour',
        'start_time': '2017-06-21T16:30:00',
        'file_name': 'file_name',
        'file_type': 'file_type',
        'info_level': 'concise',
        'malware_name': 'malware_name',
        'malware_type': 'domain_match',
        'url': SAMPLE_URL
    }

    mock_request.return_value = {}
    replace_alert_url = False
    instance_url = SAMPLE_URL
    cmd_result = get_alerts_command(client, args, replace_alert_url, instance_url)

    assert cmd_result == 'No alert(s) were found for the given argument(s).'


@patch('FireEyeNX.Client.http_request')
def test_get_events_command_no_record_failure(mock_request, client):
    """
        When fireeye-nx-get-events command called passed with valid arguments but records are not present
        then it must return error message.
    """
    from FireEyeNX import get_events_command
    args = {
        'duration': '1_hour',
        'end_time': '2017-06-21T16:30:00',
        'mvx_correlated_only': 'true'
    }

    mock_request.return_value = {}
    cmd_result = get_events_command(client, args=args)

    assert cmd_result == 'No event(s) were found for the given argument(s).'


@patch('FireEyeNX.Client.http_request')
def test_get_artifacts_by_alert_command_zero_content_length_failure(mock_request, client):
    """
        When fireeye-nx-get-artifacts-by-alert command called with Content-Length is zero
        then it should return error message.
    """
    from FireEyeNX import get_artifacts_by_alert_command
    headers = {
        'X-FeApi-Token': API_TOKEN,
        'Content-Type': CONTENT_TYPE_ZIP,
        'Content-Length': 0
    }
    args = {
        'uuid': 'abc-def'
    }

    mock_request.return_value = MockResponse(status_code=200, headers=headers, content='test')
    cmd_result = get_artifacts_by_alert_command(client, args=args)

    assert cmd_result == 'No artifacts data were found for the given argument(s).'


@patch('FireEyeNX.BaseClient._http_request')
def test_get_artifacts_by_alert_command_success(mock_request, client):
    """
        When fireeye-nx-get-artifacts-by-alert command called and passed with valid arguments, it should be successful.
    """
    from FireEyeNX import get_artifacts_by_alert_command
    args = {'uuid': 'abc-def-ghI'}
    with open('TestData/test-get-artifacts-by-alert.zip', encoding='IBM437') as f:
        expected_res = f.read()

    headers = {
        'X-FeApi-Token': API_TOKEN,
        'Content-Type': CONTENT_TYPE_ZIP,
        'Content-Length': 56
    }

    mock_request.return_value = mock_http_response(status=200, headers=headers, content=expected_res)

    result = get_artifacts_by_alert_command(client, args=args)

    assert result.get('File', '') != ''
    assert result.get('FileID', '') != ''


def test_is_supported_context_type_failure(client):
    """
        When is_supported_context_type() method called invalid argument then should return False.
    """
    assert client.is_supported_context_type('application/octet-stream') is False


def test_is_supported_context_type_success(client):
    """
        When is_supported_context_type() method called valid argument then should return True.
    """
    assert client.is_supported_context_type(CONTENT_TYPE_ZIP) is True


@patch('FireEyeNX.Client.http_request')
def test_get_events_command_success(mock_request, client):
    """
        When fireeye-nx-get-events command executes successfully then context output and
        response should match.
    """
    from FireEyeNX import get_events_command

    args = {
        'duration': '48_hours',
        'mvx_correlated_only': 'false',
        'end_time': '2020-08-10T06:31:00.000+00:00'
    }

    with open('TestData/get_events_response.json') as f:
        expected_res = json.load(f)

    mock_request.return_value = expected_res

    cmd_res = get_events_command(client, args)
    with open('TestData/get_events_context.json', encoding='utf-8') as f:
        expected_outputs = json.load(f)

    with open('TestData/get_events.md') as f:
        expected_hr = f.read()

    assert cmd_res.raw_response == expected_res
    assert cmd_res.outputs == expected_outputs
    assert cmd_res.readable_output == expected_hr


def test_add_time_suffix_into_arguments(client):
    """
        When add_time_suffix_into_arguments() method called it should add time suffix if format is suitable
        else return as it is.
    """
    from FireEyeNX import add_time_suffix_into_arguments
    args = {
        'start_time': '2020-05-20',
        'end_time': '2020-05-20'
    }
    add_time_suffix_into_arguments(args)
    actual_output = {'end_time': '2020-05-20T00:00:00.000-00:00',
                     'start_time': '2020-05-20T00:00:00.000-00:00'}
    assert actual_output == args


def test_replace_alert_url_key_domain_to_instance_url():
    """
        When replace_alert_url_key_domain_to_instance_url() method called it should Change domain
        of 'alertUrl' to the instance URL.
    """
    from FireEyeNX import replace_alert_url_key_domain_to_instance_url
    alerts_resp = [
        {
            'alertUrl': 'https://WWW.fireeye-1234/event/evenid=123'
        },
        {
            'alertUrl': 'http://www.fireeye-1234/event/evenid=124'  # NOSONAR
        }
    ]
    instance_url = 'https://example.com'

    actual_res = [
        {
            'alertUrl': 'https://example.com/event/evenid=123'
        },
        {
            'alertUrl': 'https://example.com/event/evenid=124'
        }
    ]

    replace_alert_url_key_domain_to_instance_url(alerts_resp, instance_url)

    assert actual_res == alerts_resp


@patch('FireEyeNX.replace_alert_url_key_domain_to_instance_url')
@patch('FireEyeNX.set_attachment_file')
@patch('FireEyeNX.BaseClient._http_request')
@patch('FireEyeNX.Client.get_api_token')
def test_fetch_incidents_for_alert_success(mock_api_token, mock_request, set_attachment, replace_url, client):
    """
        When fetch_incidents() method called with fetch_type='Alerts' and pass all required arg it success.
    """
    from FireEyeNX import fetch_incidents
    # Configure
    mock_last_run = {
        'start_time': datetime.now().replace(tzinfo=timezone.utc).timestamp()
    }
    dummy_first_fetch = 1
    mock_fetch_limit = 12
    mock_malware_type = 'malware-type'
    mock_api_token.return_value = API_TOKEN

    with open('TestData/fetch_incidents_alert_response.json', 'r') as f:
        dummy_response = f.read()

    resp = Response()
    resp._content = dummy_response.encode()
    resp.status_code = 200
    resp._ok = True
    resp.headers = {
        'Content-Type': CONTENT_TYPE_JSON
    }
    mock_request.return_value = resp

    set_attachment.return_value = None
    replace_url.return_value = None

    # Execute
    next_run, incidents = fetch_incidents(
        client=client,
        malware_type=mock_malware_type,
        last_run=mock_last_run,
        first_fetch=dummy_first_fetch,
        fetch_limit=mock_fetch_limit,
        fetch_type='Alerts',
        mvx_correlated=False,
        replace_alert_url=True,
        instance_url=SAMPLE_URL,
        fetch_artifacts=True,
        is_test=False
    )

    # Assert
    assert len(incidents) == mock_fetch_limit
    assert next_run.get('start_time') is not None


@patch('FireEyeNX.Client.http_request')
def test_set_attachment_file(mock_request, client):
    # incident: dict, uuid: str, headers: dict
    from FireEyeNX import set_attachment_file
    uuid = 'abc'
    headers = {}

    resp = Response()
    resp._ok = True
    resp.status_code = 200
    resp._content = b'a'
    resp.headers = {
        'Content-Length': '1'
    }

    mock_request.return_value = resp
    excepted_incident = {}

    set_attachment_file(client, excepted_incident, uuid, headers)
    assert excepted_incident != {}


@patch('FireEyeNX.BaseClient._http_request')
@patch('FireEyeNX.Client.get_api_token')
def test_fetch_incidents_for_event_success(mock_api_token, mock_request, client):
    """
        When fetch_incidents() method called with fetch_type='Alerts' and pass all required arg it success.
    """
    from FireEyeNX import fetch_incidents
    # Configure
    mock_last_run = {
        'start_time': datetime.now().replace(tzinfo=timezone.utc).timestamp()
    }
    dummy_first_fetch = 1
    mock_fetch_limit = 1
    mock_api_token.return_value = API_TOKEN

    with open('TestData/fetch_incidents_event_response.json', 'r') as f:
        dummy_response = f.read()

    resp = Response()
    resp._content = dummy_response.encode()
    resp.status_code = 200
    resp._ok = True
    resp.headers = {
        'Content-Type': CONTENT_TYPE_JSON
    }
    mock_request.return_value = resp

    next_run, incidents = fetch_incidents(
        client=client,
        malware_type=None,
        last_run=mock_last_run,
        first_fetch=dummy_first_fetch,
        fetch_limit=mock_fetch_limit,
        fetch_type='IPS Events',
        mvx_correlated=True,
        replace_alert_url=True,
        instance_url='',
        fetch_artifacts=False,
        is_test=False
    )

    # Assert
    assert len(incidents) == mock_fetch_limit
    assert next_run.get('start_time') is not None

from unittest import mock
from unittest.mock import patch

import pytest
from requests.exceptions import MissingSchema, InvalidSchema, SSLError, InvalidURL, HTTPError
from CommonServerPython import *

API_TOKEN = 'dummy_token'
CONTENT_TYPE_JSON = 'application/json'
SAMPLE_URL = 'https://sample.api.com'

AUTHENTICATION_RESP_HEADER = {
    "access_token": API_TOKEN,
    "token_type": "Bearer",
    "expires_in": 14400,
    "created_at": 1604920579
}

PAYLOAD = "client_id=client_dummy_id&client_secret" \
          "=client_dummy_secret "

MOCK_INTEGRATION_CONTEXT = {
    'api_token': API_TOKEN,
    'valid_until': time.time() + 14400
}

PARAMS = {
    'url': SAMPLE_URL,
    'apikey': 'client_dummy_api_key',
    'apisecret': 'client_dummy_api_secret',
    'isFetch': False,
    'incidentType': 'Agari Phishing Defense Policy Event',
    'max_fetch': 40,
    'first_fetch': '3 days',
    'fetch_policy_actions': 'none',
    'policy_filter': ''
}
SAMPLE_FETCH_DATE = '2020-11-22T12:41:36Z'
MOCK_TEST_URL_SUFFIX = '/test/url/suffix'

''' HELPER FUNCTION'''


@pytest.fixture()
@patch('AgariPhishingDefense.Client.get_api_token')
@patch('demistomock.setIntegrationContext')
@patch('demistomock.getIntegrationContext')
def client(mocker_get_context, mocker_set_context, mocker_get_api_token):
    from AgariPhishingDefense import Client
    mocker_get_context.return_value = {}
    mocker_set_context.return_value = {}
    mocker_get_api_token.return_value = API_TOKEN, 14400
    return Client(base_url=SAMPLE_URL,
                  verify=False,
                  proxy=False,
                  payload=PAYLOAD,
                  request_timeout=14400)


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


@patch('demistomock.debug')
@patch('AgariPhishingDefense.Client.http_request')
@patch('demistomock.setIntegrationContext')
@patch('demistomock.getIntegrationContext')
def test_get_api_token_when_not_found_in_integration_context(mocker_get_context, mocker_set_context, mock_request,
                                                             mocker_demisto_debug, client):
    """
        When get_api_token method called and headers is set with access-token also call_count is one,
        it should match.
    """
    mocker_get_context.return_value = {}
    mocker_set_context.return_value = {}

    mocker_demisto_debug.return_value = True

    mock_request.return_value = AUTHENTICATION_RESP_HEADER
    api_token, valid = client.get_api_token()

    assert api_token == 'Bearer ' + AUTHENTICATION_RESP_HEADER['access_token']
    assert mocker_set_context.call_count == 1


@patch('demistomock.debug')
@patch('AgariPhishingDefense.Client._http_request')
@patch('demistomock.getIntegrationContext')
@patch('demistomock.setIntegrationContext')
def test_get_api_token_when_found_in_integration_context(mocker_set_context, mocker_get_context, mock_request,
                                                         mocker_demisto_debug, client):
    """
        When get_api_token method called and headers is set with X-FeApi-Token also call_count is zero, it should match.
    """
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    mocker_set_context.return_value = {}
    mocker_demisto_debug.return_value = True

    mock_request.return_value = AUTHENTICATION_RESP_HEADER

    api_token, valid = client.get_api_token()

    assert api_token == AUTHENTICATION_RESP_HEADER['access_token']
    assert mocker_set_context.call_count == 0


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_invalid_schema_error(mocker_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return invalid schema exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = InvalidSchema
    mocker_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Invalid API URL. Supplied schema is invalid, supports http(s).'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_proxy_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return proxy error with exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('Proxy Error')
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}
    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Proxy Error - cannot connect to proxy. Either try clearing the \'Use system proxy\'' \
                           ' check-box or check the host, authentication details and connection details for the proxy.'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.Client._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_connection_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return connection error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mocker_get_api_token.return_value = API_TOKEN, 14400
    mock_base_http_request.side_effect = DemistoException('ConnectionError')
    demisto_version.return_value = {"version": "6.0.2"}

    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Connectivity failed. Check your internet connection or the API URL.'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_read_timeout_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return connection error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('ReadTimeoutError')
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}
    # Execute
    with pytest.raises(ConnectionError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Request timed out. Check the configured HTTP(S) Request Timeout (in seconds) value.'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_ssl_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return ssl error with Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('SSLError')
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}
    # Execute
    with pytest.raises(SSLError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox ' \
                           'in the integration configuration.'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_missing_schema_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return MissingSchema exception then appropriate error message should display.
    """
    # Configure
    mock_base_http_request.side_effect = MissingSchema
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Invalid API URL. No schema supplied: http(s).'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_invalid_url_error(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return invalid url exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = InvalidURL
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}

    # Execute
    with pytest.raises(ValueError) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'Invalid API URL.'


@patch('demistomock.demistoVersion', create=True)
@patch('AgariPhishingDefense.BaseClient._http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_http_request_other_demisto_exception(mocker_get_api_token, mock_base_http_request, demisto_version, client):
    """
        When http request return other custom Demisto exception then appropriate error message should match.
    """
    # Configure
    mock_base_http_request.side_effect = DemistoException('custom')
    mocker_get_api_token.return_value = API_TOKEN, 14400
    demisto_version.return_value = {"version": "6.0.2"}

    # Execute
    with pytest.raises(Exception) as e:
        client.http_request('GET', MOCK_TEST_URL_SUFFIX, headers={})

    # Assert
    assert str(e.value) == 'custom'


@patch('demistomock.results')
@patch('demistomock.debug')
@patch('demistomock.info')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_main_success(mocker_get_api_token, mocker_demisto_debug, mocker_demisto_info, mocker_demisto_results, mocker):
    """
        When main function called test function should call.
    """
    import AgariPhishingDefense

    mocker_get_api_token.return_value = API_TOKEN, 14400
    mocker_demisto_debug.return_value = True
    mocker_demisto_info.return_value = True
    mocker_demisto_results.return_value = True
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AgariPhishingDefense, 'test_function', return_value='ok')

    AgariPhishingDefense.main()

    assert AgariPhishingDefense.test_function.called


@patch('demistomock.results')
@patch('demistomock.info')
@patch('demistomock.debug')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_main_all_argunment_should_strip(mock_api_token, mocker_demisto_debug, mocker_demisto_info,
                                         mocker_demisto_results, mocker):
    import AgariPhishingDefense

    mocker_demisto_debug.return_value = True
    mocker_demisto_info.return_value = True
    mocker_demisto_results.return_value = True
    mock_api_token.return_value = API_TOKEN, 14400
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='agari-list-policy-events')
    mocker.patch.object(AgariPhishingDefense, 'list_policy_events_command', return_value='ok')
    args = {
        'policy_name': ' SystemAlert ',
        'limit': 4,
        'url': SAMPLE_URL
    }
    actual_output = {
        'policy_name': 'SystemAlert',
        'limit': 4,
        'url': SAMPLE_URL
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    AgariPhishingDefense.main()
    assert args == actual_output


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_get_events_command_no_record_failure(mock_api_token, mock_request, client):
    """
        When agari-list-policy-events command called passed with valid arguments but records are not present
        then it must return error message.
    """
    mock_api_token.return_value = API_TOKEN
    from AgariPhishingDefense import list_policy_events_command
    args = {
        'policy_name': 'SystemAlert',
        'limit': 4,
        'url': SAMPLE_URL
    }

    mock_request.return_value = {"alert_events": []}
    cmd_result = list_policy_events_command(client, args=args)

    assert cmd_result == 'No event(s) were found for the given argument(s).'


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_get_events_command_success(mock_api_token, mock_request, client):
    """
        When agari-list-policy-events command executes successfully then context output and
        response should match.
    """
    from AgariPhishingDefense import list_policy_events_command

    mock_api_token.return_value = API_TOKEN
    args = {
        'policy_name': 'SystemAlert',
        'limit': 4,
        'url': SAMPLE_URL
    }

    with open('test_data/get_events_response.json') as f:
        expected_res = json.load(f)

    mock_request.return_value = expected_res

    cmd_res = list_policy_events_command(client, args)
    with open('test_data/get_events_context.json', encoding='utf-8') as f:
        expected_outputs = json.load(f)

    with open('test_data/get_events.md') as f:
        expected_hr = f.read()

    assert cmd_res.raw_response['alert_events'] == expected_res['alert_events']
    assert cmd_res.outputs == expected_outputs['alert_events']
    assert cmd_res.readable_output == expected_hr


def test_handle_error_response_when_status_code_not_in_list_then_raise_for_status():
    """
        When handle_error_response method called and status is not in list then it must raise DemistoException.
    """

    from AgariPhishingDefense import Client

    err_res = {
        "version": 1,
        "status": "error",
        "code": 401,
        "error": "Unauthorized",
        "error_description": "You are not authorized to make that request."
    }
    resp = MockResponse(content=str(err_res), headers={}, status_code=200, )

    with pytest.raises(DemistoException):
        Client.handle_error_response(resp)


@patch('demistomock.debug')
def test_handle_error_response_when_content_not_type_json_throw_value_error(mocker_demisto_debug):
    """
        When handle_error_response method called and json string have error then through ValueError and it passed
        and again raise DemistoException.
    """
    from AgariPhishingDefense import Client
    mocker_demisto_debug.return_value = True
    resp = MockResponse(content='{[]}', headers={}, status_code=400)
    with pytest.raises(DemistoException) as e:
        Client.handle_error_response(resp)

    assert str(e.value) == 'An error occurred while fetching the data. '


def test_fetch_limit_when_valid_value_success(mocker):
    """
        When valid fetch_limit is given, test should pass.
    """
    from AgariPhishingDefense import get_fetch_limit
    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    fetch_limit = get_fetch_limit(fetch_limit='')
    assert fetch_limit == 50


def test_validate_fetch_policy_action(mocker):
    """
        When valid policy_action is given, test should pass.
    """
    from AgariPhishingDefense import validate_fetch_policy_action

    with pytest.raises(ValueError) as e:
        validate_fetch_policy_action('None')

    assert str(e.value) == 'The given value for Policy Actions is invalid. Expected "deliver", "mark-spam", "move", ' \
                           '"inbox", "delete" or "none". '


def test_validate_exclude_alert_type(mocker):
    """
        When valid policy_action is given, test should pass.
    """
    from AgariPhishingDefense import validate_exclude_alert_type

    with pytest.raises(ValueError) as e:
        validate_exclude_alert_type("SystemAlert")

    assert str(e.value) == 'The given value for Exclude Alerts is invalid. Expected "System Alert" or "Message Alert". '


def test_event_params_invalid_limit():
    """
        When limit is negative or greater than 200 then through value error.
    """
    from AgariPhishingDefense import get_events_params
    args = {
        'limit': '2as'
    }
    with pytest.raises(ValueError) as e:
        get_events_params(args=args, max_record=200)

    assert str(e.value) == 'Argument limit must be a positive integer between 1 to 200.'


def test_event_params_invalid_page_id():
    """
        When page_id is negative then through value error.
    """
    from AgariPhishingDefense import get_events_params
    args = {
        'page_id': '-1',
        'limit': '50'
    }
    with pytest.raises(ValueError) as e:
        get_events_params(args=args, max_record=200)

    assert str(e.value) == 'Argument page_id must be a positive integer.'


def test_event_params_invalid_start_date():
    """
        When start_date is invalid then through value error.
    """
    from AgariPhishingDefense import get_events_params
    args = {
        'start_date': '2'
    }
    with pytest.raises(ValueError) as e:
        get_events_params(args=args)

    assert str(e.value) == 'The given value for start_date argument is invalid.'


def test_event_params_invalid_end_date():
    """
        When end_date is invalid then through value error.
    """
    from AgariPhishingDefense import get_events_params
    args = {
        'end_date': 'end_date'
    }
    with pytest.raises(ValueError) as e:
        get_events_params(args=args)

    assert str(e.value) == 'The given value for end_date argument is invalid.'


def test_event_params_invalid_rem_fields():
    """
        When end_date is invalid then through value error.
    """
    from AgariPhishingDefense import get_events_params
    args = {
        'rem_fields': 'id,created_at'
    }
    with pytest.raises(ValueError) as e:
        get_events_params(args=args)

    assert str(e.value) == 'Cannot pass "id" in rem_fields argument.'


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_remediate_message_valid_id_passed(mock_api_token, http_request, client):
    """
    When valid ID (message id) is passed and API returns 200
    """
    from AgariPhishingDefense import remediate_message_command

    args = {
        'id': '53daff5a-2ac4-11eb-9375-0a8f2da72108',
        'operation': 'move'
    }

    with open('test_data/remediate_success_resp.json') as f:
        expected_res = json.load(f)

    mock_api_token.return_value = API_TOKEN
    http_request.return_value = expected_res

    expected_hr = "Message ID - 53daff5a-2ac4-11eb-9375-0a8f2da72108 remediated successfully with operation 'move'."

    result = remediate_message_command(client, args)

    # ASSERT
    assert result.readable_output == expected_hr


def test_remediate_when_action_is_wrong(client):
    from AgariPhishingDefense import remediate_message_command

    args = {
        'id': '53daff5a-2ac4-11eb-9375-0a8f2da72108',
        'action': ' '
    }

    with pytest.raises(ValueError) as e:
        remediate_message_command(args=args, client=client)

    assert str(e.value) == 'Invalid argument value. Requires both "id" and "operation" argument.'


def test_incident_params_invalid_fetch_limit():
    """
        When fetch_limit is invalid then through value error.
    """
    from AgariPhishingDefense import fetch_incidents_params
    args = {
        'start_date': SAMPLE_FETCH_DATE,
        'fetch_limit': '300',
        'id': '',
        'policy_filter': ''
    }
    with pytest.raises(ValueError) as e:
        fetch_incidents_params(**args)

    assert str(e.value) == 'Value of Fetch Limit must be a positive integer between 1 to 200.'


def test_incident_params_valid():
    """
        Check for all valid params.
    """
    from AgariPhishingDefense import fetch_incidents_params
    args = {
        'start_date': SAMPLE_FETCH_DATE,
        'id': '544635182',
        'fetch_limit': '',
        'policy_filter': 'created_at.gt(2020-11-22T12:59:59Z)',
        'fetch_policy_actions': 'inbox',
        'exclude_alert_type': 'System Alert'
    }

    params = fetch_incidents_params(**args)
    assert params['exclude_alert_types'] == 'SystemAlert'
    assert params['sort'] == 'created_at ASC,id ASC'
    assert params['filter'] == 'created_at.gt(2020-11-22T12:59:59Z) and id.gt(+544635182)'


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_fetch_incidents_command_no_record_failure(mock_api_token, mock_request, client):
    """
        When fetch_incidents command called passed with valid arguments but records are not present
        then it must return error message.
    """
    mock_api_token.return_value = API_TOKEN
    from AgariPhishingDefense import fetch_incidents
    args = {
        'policy_name': 'SystemAlert',
        'limit': 2,
        'url': SAMPLE_URL,
        'start_date': SAMPLE_FETCH_DATE,
        'policy_filter': 'inbox'
    }

    mock_request.return_value = {"alert_events": []}
    last_run = {'last_fetch': '2020-11-23T12:41:36Z'}
    cmd_result, _ = fetch_incidents(client, last_run=last_run, args=args)

    assert cmd_result == last_run


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_fetch_incident_command_success(mock_api_token, mock_request, client):
    """
        When fetch_incidents command executes successfully then response should match
    """
    from AgariPhishingDefense import fetch_incidents

    mock_api_token.return_value = API_TOKEN, 14400
    args = {
        'start_date': '',
        'id': '',
        'fetch_limit': '1',
        'policy_filter': ''
    }

    with open('test_data/get_fetch_response.json') as f:
        expected_res = json.load(f)
    mock_request.side_effect = expected_res

    ans = []
    cmd_res_next_run, incidents = fetch_incidents(client, {}, args)
    ans.append(cmd_res_next_run)
    ans.append(incidents)
    assert ans == expected_res[3]


@patch('AgariPhishingDefense.Client.http_request')
@patch('AgariPhishingDefense.Client.get_api_token')
def test_list_message_data_command_success(mock_api_token, mock_request, client):
    """
        When agari-list-policy-events command executes successfully then context output and
        response should match.
    """
    from AgariPhishingDefense import list_message_data_command

    mock_api_token.return_value = API_TOKEN
    args = {
        'limit': 4,
        'url': SAMPLE_URL
    }

    with open('test_data/get_messages_response.json') as f:
        expected_res = json.load(f)

    mock_request.return_value = expected_res

    cmd_res = list_message_data_command(client, args)
    with open('test_data/get_messages_context.json', encoding='utf-8') as f:
        expected_outputs = json.load(f)

    with open('test_data/get_messages.md') as f:
        expected_hr = f.read()

    assert cmd_res.raw_response['messages'] == expected_res['messages']
    assert cmd_res.outputs == expected_outputs['messages']
    assert cmd_res.readable_output == expected_hr

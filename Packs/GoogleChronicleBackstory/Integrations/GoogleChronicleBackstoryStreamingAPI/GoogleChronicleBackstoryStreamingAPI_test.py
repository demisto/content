"""Test File for GoogleChronicleBackstory Integration."""
import json
import os
import time

import pytest
from unittest import mock

from CommonServerPython import arg_to_datetime
import demistomock as demisto

from GoogleChronicleBackstoryStreamingAPI import DATE_FORMAT, MAX_CONSECUTIVE_FAILURES, MAX_DELTA_TIME_FOR_STREAMING_DETECTIONS, \
    fetch_samples, service_account, auth_requests, validate_configuration_parameters, stream_detection_alerts_in_retry_loop, \
    validate_response, test_module as main_test_module, timezone, timedelta, MESSAGES, Client, parse_error_message, main


GENERIC_INTEGRATION_PARAMS = {
    'credentials': {
        'password': '{}',
    },
    'first_fetch': '1 days'
}

FILTER_PARAMS = {
    "credentials": {
        "password": "{}",
    },
    "first_fetch": "1 days",
    "alert_type": ["Rule Detection Alerts"],
    "detection_severity": ["low"],
    "rule_names": ["SampleRule"],
    "exclude_rule_names": False,
    "rule_ids": ["ru_e6abfcb5-1b85-41b0-b64c-695b3250436f"],
    "exclude_rule_ids": False
}


class MockResponse:
    status_code = 200
    json = lambda **_: {}  # noqa: E731
    text = "{}"
    request = lambda **_: ""  # noqa: E731
    post = lambda **_: ""  # noqa: E731


class StreamResponse:

    def __init__(self, **_):
        pass

    def __enter__(self):
        return self.mock_response

    def __exit__(self, *_):
        pass


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def mock_client_for_filter_params(mocker):
    """Fixture for the http client."""
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, 'from_service_account_info', return_value=credentials)
    mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=MockResponse)
    client = Client(params=FILTER_PARAMS, proxy=False, disable_ssl=True)
    return client


@pytest.fixture
def special_mock_client():
    """Fixture for the http client with no original client class response."""
    mocked_client = mock.Mock()
    mocked_client.region = "General"
    return mocked_client


@pytest.fixture()
def mock_client(mocker):
    """Fixture for the http client."""
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, 'from_service_account_info', return_value=credentials)
    mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=MockResponse)
    client = Client(params=GENERIC_INTEGRATION_PARAMS, proxy=False, disable_ssl=True)
    return client


def test_validate_configuration_parameters(capfd):
    """Test case scenario for validating the configuration parameters."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    capfd.close()
    validate_configuration_parameters(integration_params, 'test-module')


@pytest.mark.parametrize('first_fetch', ['invalid', '8 days'])
def test_validate_configuration_parameters_with_invalid_first_fetch(capfd, first_fetch):
    """Test case scenario for validating the configuration parameters with invalid first fetch."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params['first_fetch'] = first_fetch
    capfd.close()
    with pytest.raises(ValueError):
        validate_configuration_parameters(integration_params, 'test-module')


def test_validate_configuration_parameters_with_invalid_credentials():
    """Test case scenario for validating the configuration parameters with invalid credentials."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params['credentials'] = {'password': 'invalid'}
    with pytest.raises(ValueError):
        validate_configuration_parameters(integration_params, 'test-module')


def test_parse_error_message_with_invalid_json(capfd):
    """Test case scenario for parsing error message with invalid json."""
    capfd.close()
    assert parse_error_message('invalid json', 'General') == MESSAGES['INVALID_JSON_RESPONSE']


def test_parse_error_message_with_invalid_region(capfd):
    """Test case scenario for parsing error message with invalid region."""
    capfd.close()
    assert parse_error_message('service unavailable 404', 'invalid region') == MESSAGES['INVALID_REGION']


def test_validate_response(mocker, capfd):
    """
    Test case scenario for successful execution of validate_response.

    Given:
       - mocked client
    When:
       - Calling `validate_response` function.
    Then:
       - Returns an ok message
    """
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, 'from_service_account_info', return_value=credentials)
    mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=MockResponse)
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params['region'] = 'other'
    integration_params['other_region'] = 'new-region'
    client = Client(params=integration_params, proxy=False, disable_ssl=True)

    mocker.patch.object(client.http_client, 'request', return_value=MockResponse)
    capfd.close()
    assert validate_response(client, '') == {}


@mock.patch('demistomock.error')
@pytest.mark.parametrize('args', [{"status_code": 429, "message": 'API rate limit'},
                                  {"status_code": 300, "message": 'Status code: 300'},
                                  {"status_code": 500, "message": 'Internal server error'},
                                  {"status_code": 400, "message": 'Status code: 400'},
                                  {"status_code": 403,
                                   "text": '{"error": {"code": 403}}', "message": 'Permission denied'},
                                  {"text": "", "message": 'Technical Error'},
                                  {"text": "*", "message": MESSAGES['INVALID_JSON_RESPONSE']}])
def test_429_or_500_error_for_validate_response(mock_error, special_mock_client, capfd, args):
    """
    Test behavior for 429 and 500 error codes for validate_response.
    """
    mock_error.return_value = {}

    class MockResponse:
        status_code = 200
        text = '[{"error": {}}]'

        def json(self):
            return json.loads(self.text)

    mock_response = MockResponse()
    if 'status_code' in args:
        mock_response.status_code = args.get('status_code')
    if 'text' in args:
        mock_response.text = args.get('text')

    special_mock_client.http_client.request.side_effect = [mock_response]
    capfd.close()
    with pytest.raises(ValueError) as value_error:
        validate_response(special_mock_client, '')

    assert args.get('message') in str(value_error.value)
    assert special_mock_client.http_client.request.call_count == 1


def test_test_module(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        assert main_test_module(mock_client, {}) == 'ok'


def test_test_module_using_main(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of test_module using main function.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()
    param = {
        'credentials': {'password': '{"key":"value"}'},
    }

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        mocker.patch.object(demisto, 'params', return_value=param)
        mocker.patch.object(demisto, 'command', return_value="test-module")
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        main()


def test_test_module_for_error(mocker, mock_client, capfd):
    """
    Test case scenario for unsuccessful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections_error_2.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        assert main_test_module(mock_client, {}) == 'Connection closed with error: "error"'
        mock_response.post = None


def test_fetch_samples(mocker):
    """
    Test case scenario for successful execution of fetch_samples.

    Given:
       - mocked client
    When:
       - Calling `fetch_samples` function.
    Then:
       - Returns list of incidents stored in context.
    """
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'sample_events': '[{}]'})
    assert fetch_samples() == [{}]


def test_stream_detection_alerts_with_filter(mocker, mock_client_for_filter_params, capfd):
    """
    Test case scenario for successful execution of stream_detection_alerts with filter.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()
        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)

        capfd.close()
        assert stream_detection_alerts_in_retry_loop(
            mock_client_for_filter_params, arg_to_datetime('now'),
            test_mode=True) == {"continuation_time": "2024-03-21T09:44:04.877670709Z", }


def test_stream_detection_alerts_in_retry_loop(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of stream_detection_alerts_in_retry_loop.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    stream_detection_outputs: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                 'test_data/steam_detection_outputs.json'))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        capfd.close()
        assert stream_detection_alerts_in_retry_loop(
            mock_client, arg_to_datetime('now'), test_mode=True) == stream_detection_outputs


def test_stream_detection_alerts_in_retry_loop_with_error(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when error response comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert exception value.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections_error.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        capfd.close()
        with pytest.raises(RuntimeError) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime('now'), test_mode=True)

        assert str(exc_info.value) == MESSAGES['CONSECUTIVELY_FAILED'].format(MAX_CONSECUTIVE_FAILURES + 1)


def test_stream_detection_alerts_in_retry_loop_with_empty_response(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when empty response comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Returns an ok message
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections_empty.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        capfd.close()
        with pytest.raises(Exception) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime('now'), test_mode=True)
        assert str(exc_info.value) == str(KeyError('continuationTime'))


def test_stream_detection_alerts_in_retry_loop_with_400(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when 400 status code comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert exception value.
    """
    mock_response = MockResponse()
    mock_response.status_code = 400

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'test_data/stream_detections_error.txt'), 'r') as f:

        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=mock_response)
        mocker.patch.object(time, 'sleep', return_value=lambda **_: None)
        new_continuation_time = arg_to_datetime(MAX_DELTA_TIME_FOR_STREAMING_DETECTIONS).astimezone(
            timezone.utc) + timedelta(minutes=1)  # type: ignore
        new_continuation_time_str = new_continuation_time.strftime(DATE_FORMAT)
        integration_context = {'continuation_time': new_continuation_time_str}
        mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)
        capfd.close()
        with pytest.raises(RuntimeError) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime('now'), test_mode=True)

        assert str(exc_info.value) == MESSAGES['INVALID_ARGUMENTS'] + ' with status=400, error={}'

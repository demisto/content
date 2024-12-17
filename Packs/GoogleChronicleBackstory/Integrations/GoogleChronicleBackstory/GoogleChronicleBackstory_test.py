"""Test File for GoogleChronicleBackstory Integration."""
import json
from unittest import mock

import pytest

import demistomock as demisto

from GoogleChronicleBackstory import MESSAGES, ASSET_IDENTIFIER_NAME_DICT, USER_IDENTIFIER_NAME_DICT, \
    CHRONICLE_OUTPUT_PATHS, VALID_CONTENT_TYPE

PROXY_MOCK = {
    "proxy": "0.0.0.0"
}

SUCCESS_ASSET_NAME = 'www.google.com'
FAILURE_ASSET_NAME = 'www.xyz.com'

PARAMS = {
    'malicious_categories': 'APT-Activity',
    'suspicious_categories': 'Observed serving executables',
    'override_severity_malicious': ['high'],
    'override_severity_suspicious': ['medium'],
    'override_confidence_score_malicious_threshold': '80',
    'override_confidence_score_suspicious_threshold': '40',
    'integrationReliability': 'B - Usually reliable'
}

PARAMS_FOR_STR_CONFIDENCE_SCORE = {
    'malicious_categories': 'APT-Activity',
    'suspicious_categories': 'Observed serving executables',
    'override_severity_malicious': ['high'],
    'override_severity_suspicious': ['medium'],
    'override_confidence_level_malicious': 'medium',
    'override_confidence_level_suspicious': 'low'
}

ARGS = {
    'artifact_value': '0.0.0.0',
    'ip': '0.0.0.0',
    'domain': 'test.com'
}
IP_CONTEXT_PATH = 'IP(val.Address && val.Address == obj.Address)'

invalid_start_time_error_message = 'Invalid start time. Some supported formats are ISO date format and relative time. ' \
                                   'e.g. 2019-10-17T00:00:00Z, 3 days'

invalid_end_time_error_message = 'Invalid end time. Some supported formats are ISO date format and relative time. ' \
                                 'e.g. 2019-10-17T00:00:00Z, 3 days'
DUMMY_DICT = '{"key":"value"}'
DUMMY_FETCH = '10 day'
ASSET_ALERT_TYPE = 'Assets with alerts'
START_TIME = "2020-01-29T14:13:20Z"
DEFAULT_FIRST_FETCH = '3 days'
DETECTION_ALERT_TYPE = 'Detection Alerts'
CURATEDRULE_DETECTION_ALERT_TYPE = 'Curated Rule Detection alerts'
USER_ALERT = 'User alerts'
VERSION_ID = 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631093_146879000'
CURATEDRULE_ID = 'ur_ttp_GCP__MassSecretDeletion'
LAST_RUN_TIME = '2020-11-20T12:00:00Z'
RETURN_ERROR_MOCK_PATH = 'GoogleChronicleBackstory.return_error'
COMMON_RESP = {
    'PERM_DENIED_RESP': "{ \"error\": { \"code\": 403, \"message\": \"Permission denied\" \
                     , \"status\": \"PERMISSION_DENIED\", \"details\": [ {  } ] } } ",
    'PERM_DENIED_MSG': 'Status code: 403\nError: Permission denied',
    'INVALID_PAGE_SIZE': "Page size must be a non-zero and positive numeric value",
    'ERROR_RESPONSE': '{"error": {}}'
}
DUMMY_RULE_TEXT = "meta events condition"


@pytest.fixture
def client():
    """Fixture for the http client."""
    mocked_client = mock.Mock()
    mocked_client.region = "General"
    return mocked_client


def return_error(error):
    """Mock for CommonServerPython's return_error."""
    raise ValueError(error)


def test_gcb_list_ioc_success(mocker):
    """When valid response comes in gcb-list-iocs command it should respond with result."""
    from GoogleChronicleBackstory import gcb_list_iocs_command, Client, service_account, auth_requests
    with open("test_data/list_ioc_response.txt") as f:
        dummy_response = f.read()
    with open("test_data/list_ioc_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

        def mount(self, y):
            return ""
        request = lambda **kwargs: ""  # noqa: E731

    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, 'from_service_account_info', return_value=credentials)
    mocker.patch.object(auth_requests, 'AuthorizedSession', return_value=MockResponse)

    client = Client({"service_account_credential": json.dumps(credentials), "region": "General"}, proxy={},
                    disable_ssl=True)
    mocker.patch.object(client.http_client, 'request', return_value=MockResponse)

    hr, ec, json_data = gcb_list_iocs_command(client, {})
    assert ec["Domain(val.Name && val.Name == obj.Name)"] == dummy_ec["Domain(val.Name && val.Name == obj.Name)"]
    key = "GoogleChronicleBackstory.Iocs(val.Artifact && val.Artifact == obj.Artifact)"
    assert ec[key] == dummy_ec[key]
    assert json_data == json.loads(dummy_response)


def test_gcb_list_ioc_failure_response(client):
    """When response not come with invalid response come in gcb-list-iocs command then it should raise ValueError \
    'Failed to parse response'."""
    from GoogleChronicleBackstory import gcb_list_iocs_command
    with open("test_data/list_ioc_response.txt") as f:
        dummy_response = f.read()

    def json_method():
        return json.loads(dummy_response + '}')

    class MockResponse:
        status_code = 200
        text = dummy_response + '}'
        json = json_method

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as error:
        gcb_list_iocs_command(client, {})
    assert str(error.value) == 'Invalid response format while making API call to Chronicle. Response not in JSON format'


def test_gcb_list_ioc_failure_response_400(client, mocker):
    """When status code 400 occurred in gcb-list-iocs command it should raise ValueError 'page not found'."""
    from GoogleChronicleBackstory import gcb_list_iocs_command

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)

    response = '{"error": { "code": 400, "message": "page not found", "status": "INVALID_ARGUMENT" } }'

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as error:
        gcb_list_iocs_command(client, {})
    assert str(error.value) == 'Status code: 400\nError: page not found'


def test_gcb_ioc_details_command_success(client):
    """When command execute successfully then it should prepare valid hr, ec."""
    from GoogleChronicleBackstory import gcb_ioc_details_command

    with open("test_data/list_ioc_details_response.json") as f:
        dummy_response = f.read()
    with open("test_data/gcb_ioc_details_command_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = gcb_ioc_details_command(client, ARGS)

    assert ec[IP_CONTEXT_PATH] == dummy_ec[
        IP_CONTEXT_PATH]

    key = 'GoogleChronicleBackstory.IocDetails(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_gcb_ioc_details_command_empty_response(client):
    """When there is an empty response the command should response empty ec and valid text in hr."""
    from GoogleChronicleBackstory import gcb_ioc_details_command
    expected_hr = '### For artifact: {}\n'.format(ARGS['artifact_value'])
    expected_hr += MESSAGES["NO_RECORDS"]

    dummy_response = '{}'

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = gcb_ioc_details_command(client, ARGS)

    assert hr == expected_hr


def test_gcb_ioc_details_command_failure(client, mocker):
    """When there is a invalid response then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import gcb_ioc_details_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.ip_address\': Cannot bind query parameter. Field \'ip_address\' could not be found" \
                     " in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    class MockResponse:
        status_code = 400
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        gcb_ioc_details_command(client, ARGS)
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.ip_address\':" \
                       " Cannot bind query parameter. Field \'ip_address\' could not be found in request message."
    assert str(error.value) == expected_message


def test_gcb_ioc_details_command_failure_permission_denied(client, mocker):
    """When there is a response for permission denied then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import gcb_ioc_details_command

    dummy_response = COMMON_RESP['PERM_DENIED_RESP']

    class MockResponse:
        status_code = 403
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        gcb_ioc_details_command(client, ARGS)
    expected_message = COMMON_RESP['PERM_DENIED_MSG']
    assert str(error.value) == expected_message


def test_reputation_operation_command_success(client):
    """When two comma separated arguments will be passed then function return_outputs should be call twice \
    with valid arguments."""
    from GoogleChronicleBackstory import reputation_operation_command
    with mock.patch('GoogleChronicleBackstory.return_outputs') as mock_return_outputs:
        fun = mock.Mock()
        args = {
            'ip': '0.0.0.0,0.0.0.0'
        }
        fun.return_value = ('', {}, {})

        reputation_operation_command(client, args['ip'], fun)

        mock_return_outputs.assert_called_with(*fun(client, '0.0.0.0'))

        assert mock_return_outputs.call_count == 2


def test_function_success(client):
    """When success response come then test_function command should pass."""
    from GoogleChronicleBackstory import test_function

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return json.loads('{}')

    client.http_client.request.return_value = MockResponse

    with mock.patch('GoogleChronicleBackstory.demisto.results') as mock_demisto_result:
        test_function(client, PROXY_MOCK)
    mock_demisto_result.assert_called_with('ok')


def test_function_failure_status_code_400(client, mocker):
    """When unsuccessful response come then test_function command should raise ValueError with appropriate message."""
    from GoogleChronicleBackstory import test_function
    dummy_response = '{"error": { "code": 400, "message": ' \
                     '"Request contains an invalid argument.", "status": "INVALID_ARGUMENT" } }'

    class MockResponse:
        status_code = 400
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == 'Status code: 400\nError: Request contains an invalid argument.'


def test_function_failure_status_code_403(client, mocker):
    """When entered JSON is correct but client has not given any access, should return permission denied."""
    from GoogleChronicleBackstory import test_function

    dummy_response = '{"error": { "code": 403, "message": "Permission denied" } }'

    class MockResponse:
        status_code = 403
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == COMMON_RESP['PERM_DENIED_MSG']


def test_validate_parameter_success(mocker):
    """When valid input is added on Integration Configuration then it should pass."""
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import validate_configuration_parameters
    param = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '20',
        'first_fetch': DUMMY_FETCH
    }
    validate_configuration_parameters(param)


def test_validate_parameter_failure_wrong_json():
    """When wrong JSON format of User Service account JSON input is added it should return validation error."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_credentials = {
        'service_account_credential': '{"key","value"}',
        'max_fetch': '20',
        'first_fetch': DUMMY_FETCH
    }

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_credentials)
    assert str(error.value) == "User's Service Account JSON has invalid format"


def test_validate_parameter_failure_page_size():
    """When page size not in positive number then it should raise ValueError."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_page_sizes = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '2a0',
        'first_fetch': DUMMY_FETCH
    }

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_page_sizes)
    assert str(error.value) == "Incidents fetch limit must be a number"


def test_validate_parameter_failure_wrong_first_fetch_format():
    """When First fetch is not valid date it should raise ValueError."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_format = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '20',
        'first_fetch': '29 feb 2021'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_format)
    assert str(error.value) == 'Invalid date: "First fetch time"="29 feb 2021"'


def test_validate_parameter_failure_wrong_first_fetch_number():
    """When First fetch field's number is invalid then it should raise ValueError."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_number = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '20',
        'first_fetch': '120000 months'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_number)
    assert str(error.value) == 'Invalid date: "First fetch time"="120000 months"'


def test_validate_parameter_failure_wrong_first_fetch_unit():
    """When First fetch field's unit is invalid then it should raise ValueError."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_unit = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '20',
        'first_fetch': '10 dais'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_unit)
    assert str(error.value) == 'Invalid date: "First fetch time"="10 dais"'


def test_validate_parameter_failure_when_no_ruleid_provided_for_curated_detection():
    """When no rule ID(s) is provided while fetching Curated Rule Detection alerts."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_unit = {'backstory_alert_type': 'curated rule detection alerts'}
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_unit)
    assert str(error.value) == MESSAGES['PROVIDE_CURATED_RULE_ID']


def test_main_success(mocker, client):
    """When command execute successfully then main should pass."""
    import GoogleChronicleBackstory
    param = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '20',
        'first_fetch': DUMMY_FETCH,
        'configured_maliciuos_categories': "Spyware Reporting Server, Target of a DDoS, Known Spam Source"
    }

    dummy_response = '{}'

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch.object(demisto, 'params', return_value=param)
    mocker.patch.object(demisto, 'command', return_value="test-module")
    mocker.patch.object(GoogleChronicleBackstory, 'test_function', return_value=('', {}, {}))
    mocker.patch('GoogleChronicleBackstory.Client', return_value=client)
    GoogleChronicleBackstory.main()
    assert GoogleChronicleBackstory.test_function.called


def test_gcb_assets_command_success(client):
    """When valid response come in gcb-assets command it should respond with result."""
    from GoogleChronicleBackstory import gcb_assets_command

    with open("test_data/asset_response.json", encoding='utf-8') as f:
        expected_response = json.load(f)

    class MockResponse:
        status_code = 200
        text = json.dumps(expected_response)

        def json():
            return expected_response

    client.http_client.request.return_value = MockResponse
    hr, ec, response = gcb_assets_command(client, {'artifact_value': SUCCESS_ASSET_NAME})
    with open("test_data/asset_ec.json") as f:
        expected_ec = json.load(f)
    assert ec == expected_ec
    assert response == expected_response


def test_gcb_assets_command_failure(client):
    """When Null response come in gcb-assets command it should respond with No Records Found."""
    from GoogleChronicleBackstory import gcb_assets_command

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    hr, ec, response = gcb_assets_command(client, {'artifact_value': FAILURE_ASSET_NAME})
    assert ec == {}
    assert response == {}


def test_gcb_assets_command_failure_with_uri_empty_response(client):
    """When Null response come in gcb-assets command it should respond with No Records Found."""
    from GoogleChronicleBackstory import gcb_assets_command

    with open("test_data/asset_with_no_response.json", encoding='utf-8') as f:
        expected_response = json.load(f)

    class MockResponse:
        status_code = 200
        text = json.dumps(expected_response)

        def json():
            return expected_response

    client.http_client.request.return_value = MockResponse
    hr, ec, response = gcb_assets_command(client, {'artifact_value': FAILURE_ASSET_NAME})
    assert ec == {}
    assert hr == '### Artifact Accessed: www.xyz.com \n\nNo Records Found'
    assert response == expected_response


def test_get_artifact_type():
    """When valid artifact pass in get_artifact_type function then it should pass else raise ValueError."""
    from GoogleChronicleBackstory import get_artifact_type

    ip = get_artifact_type('10.0.0.1')  # NOSONAR
    assert ip == 'destination_ip_address'

    ipv6 = get_artifact_type('000::000')
    assert ipv6 == 'destination_ip_address'

    md5 = get_artifact_type('c8092abd8d581750c0530fa1fc8d8318')
    assert md5 == 'hash_md5'

    sha1 = get_artifact_type('52483514f07eb14570142f6927b77deb7b4da99f')
    assert sha1 == 'hash_sha1'

    sha256 = get_artifact_type('42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59')
    assert sha256 == 'hash_sha256'

    domain_name = get_artifact_type('www.google.com')
    assert domain_name == 'domain_name'

    domain_name = get_artifact_type('255.256')
    assert domain_name == 'domain_name'


def test_fetch_incident_success_with_no_param_no_alerts(client):
    """Check the fetch incident success with empty params and empty response."""
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    fetch_incidents(client, param)

    assert client.http_client.request.called


def validate_ioc_domain_incident(incidents):
    """Validate ioc domain key for fetch incident event."""
    assert len(incidents) == 4
    for incident_alert in incidents:
        assert incident_alert['name']
        assert incident_alert['details']
        assert incident_alert['rawJSON']
        raw_data = json.loads(incident_alert['rawJSON'])
        assert raw_data['Artifact']


def test_fetch_incident_run_ioc_domain_matches(mocker, client):
    """With IOC Domain Matches as default selection should be called and create incident in Demisto."""
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    with open("test_data/list_ioc_response.txt", "rb") as f:
        dummy_response = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    mocker.patch.object(demisto, 'incidents', new=validate_ioc_domain_incident)
    client.http_client.request.return_value = MockResponse
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_fetch_incident_error_in_response(client, mocker):
    """Check fetch incident failure on error response."""
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    expected_response = '{"error": { "code": 400, "message": "Invalid Argument", "status": "INVALID_ARGUMENT" } }'

    class MockResponse:
        status_code = 400
        text = expected_response

        def json():
            return json.loads(expected_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        fetch_incidents(client, param)

    assert client.http_client.request.called
    assert str(error.value) == "Status code: 400\nError: Invalid Argument"


def validate_incident(incidents):
    """
    Assert incidents.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert len(incidents) == 3
    for incident in incidents:
        assert incident['name']
        assert incident['rawJSON']
        raw_json = json.loads(incident['rawJSON'])
        assert raw_json['FirstSeen']
        assert raw_json['LastSeen']
        assert raw_json['Occurrences']
        assert raw_json['Alerts']
        assert raw_json['Asset']
        assert raw_json['AlertName']
        assert raw_json['Severities']


def test_fetch_incident_success_with_param_and_alerts_when_executed_1st_time(mocker, client):
    """Check fetch incident success without last run."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '4 days',
        'max_fetch': 20,
        'incident_severity': 'ALL',
        'time_window': '60',
        'backstory_alert_type': ASSET_ALERT_TYPE
    }

    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_success_with_alerts_with_demisto_last_run(mocker, client):
    """Check the fetch incident success with last run."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'incident_severity': None,
        'backstory_alert_type': ASSET_ALERT_TYPE
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_incident)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={'start_time': "2020-01-29T14:13:20+00:00"})

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_asset_with_multiple_alerts_human_readable(client):
    """
    If multiple alerts per assert is found then, it should display asset per alerts in human readable.

    :return:
    """
    from GoogleChronicleBackstory import group_infos_by_alert_asset_name, get_gcb_alerts
    from CommonServerPython import datetime

    with open("test_data/gcb_alerts_human_readable.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    events = get_gcb_alerts(client, datetime.utcnow(), datetime.utcnow(), 20, None)
    alert_per_asset, _ = group_infos_by_alert_asset_name(events)

    assert alert_per_asset
    assert len(alert_per_asset) == 4
    assert 'svetla-Command Shell Launched by Office Applications' in alert_per_asset
    assert 'svetla-Suspicious PowerShell Process Ancestry' in alert_per_asset
    assert 'dc12-Suspicious PowerShell Process Ancestry' in alert_per_asset
    assert 'dc12-Possible Bitsadmin Exfiltration' in alert_per_asset


def test_gcb_list_alert_with_no_arg_supplied_success(mocker, client):
    """
    Should return hr, ec and events when multiple events are responded.

    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {}

    class MockResponse:
        status_code = 200
        text = get_hr_gcb_alerts()

        def json():
            return json.loads(get_hr_gcb_alerts())

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr
    assert ec
    with open("test_data/alerts_ec.json") as f:
        expected_ec = json.load(f)

    assert ec == expected_ec
    assert events
    assert client.http_client.request.called


def test_gcb_list_alert_with_severity_medium_arg_supplied_success(mocker, client):
    """
    Should return hr, ec and alerts when multiple 'Medium' severity is supplied.

    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        'severity': 'Medium'
    }

    class MockResponse:
        status_code = 200
        text = get_hr_gcb_alerts()

        def json():
            return json.loads(get_hr_gcb_alerts())

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr
    assert ec
    with open("test_data/medium_alert_ec.json") as f:
        expected_ec = json.load(f)

    assert ec == expected_ec
    assert events
    assert client.http_client.request.called


def test_gcb_list_alert_with_severity_lowercase_medium_arg_supplied_success(mocker, client):
    """
    Should return hr, ec and alerts when multiple 'Medium' severity even in lowercase input.

    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        'severity': 'medium'
    }

    class MockResponse:
        status_code = 200
        text = get_hr_gcb_alerts()

        def json():
            return json.loads(get_hr_gcb_alerts())

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr
    assert ec
    with open("test_data/medium_alert_ec.json") as f:
        expected_ec = json.load(f)

    assert ec == expected_ec
    assert events
    assert client.http_client.request.called


def get_hr_gcb_alerts():
    """Read and return gcb_alerts human readable."""
    with open("test_data/gcb_alerts_human_readable.txt") as f:
        gcb_alert_sample = f.read()
    return gcb_alert_sample


def test_gcb_list_alert_when_no_alert_found(mocker, client):
    """Test gcb_list_alerts_command to display 'No Record Found' message when empty but 200 status is responded."""
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {}

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr == '### Security Alert(s): No Records Found'
    assert not ec
    assert not events
    assert client.http_client.request.called


def test_validate_page_size():
    """When there is a invalid page size then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import validate_page_size
    with pytest.raises(ValueError) as error:
        validate_page_size('5s')
    assert str(error.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    with pytest.raises(ValueError) as error:
        validate_page_size('0')
    assert str(error.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    assert validate_page_size(10)

    with pytest.raises(ValueError) as error:
        validate_page_size(None)
    assert str(error.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    with pytest.raises(ValueError) as error:
        validate_page_size('')
    assert str(error.value) == COMMON_RESP['INVALID_PAGE_SIZE']


def test_ip_command_success(mocker, client):
    """When command execute successfully then it should prepare valid hr, ec."""
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import ip_command

    with open("test_data/list_ioc_details_response.json") as f:
        dummy_response = f.read()
    with open("test_data/ip_command_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert ec['DBotScore'] == dummy_ec['DBotScore']
    assert ec[IP_CONTEXT_PATH] == dummy_ec[
        IP_CONTEXT_PATH]

    key = 'GoogleChronicleBackstory.IP(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_ip_command_empty_response_when_uri_empty_response(client):
    """Test ip_command for empty response."""
    from GoogleChronicleBackstory import ip_command

    with open("test_data/empty_list_ioc_details.json") as f:
        dummy_response = f.read()
    expected_hr = '### IP: {} found with Reputation: Unknown\n'.format(ARGS['ip'])
    expected_hr += MESSAGES["NO_RECORDS"]

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert hr == expected_hr


def test_ip_command_invalid_ip_address(client):
    """When user add invalid IP Address then it should raise ValueError with valid response."""
    from GoogleChronicleBackstory import ip_command
    expected_message = 'Invalid IP - string'

    with pytest.raises(ValueError) as error:
        ip_command(client, 'string')

    assert str(error.value) == expected_message


def test_ip_command_empty_response(client):
    """When there is an empty response the command should response empty ec and valid text in hr."""
    from GoogleChronicleBackstory import ip_command
    expected_hr = '### IP: {} found with Reputation: Unknown\n'.format(ARGS['ip'])
    expected_hr += MESSAGES["NO_RECORDS"]

    dummy_response = '{}'

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert hr == expected_hr


def test_ip_command_failure(client, mocker):
    """When there is a invalid response then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import ip_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.ip_address\': Cannot bind query parameter. Field \'ip_address\' could not be found" \
                     " in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    class MockResponse:
        status_code = 400
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        ip_command(client, ARGS['ip'])
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.ip_address\':" \
                       " Cannot bind query parameter. Field \'ip_address\' could not be found in request message."
    assert str(error.value) == expected_message


def test_ip_command_failure_permission_denied(client, mocker):
    """When there is a response for permission denied then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import ip_command

    dummy_response = COMMON_RESP['PERM_DENIED_RESP']

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)

    class MockResponse:
        status_code = 403
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as error:
        ip_command(client, ARGS['ip'])
    expected_message = COMMON_RESP['PERM_DENIED_MSG']
    assert str(error.value) == expected_message


def test_domain_command_success(mocker, client):
    """When command execute successfully then it should prepare valid hr, ec."""
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import domain_command

    with open("test_data/list_ioc_details_response.json") as f:
        dummy_response = f.read()
    with open("test_data/domain_command_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert ec['DBotScore'] == dummy_ec['DBotScore']
    assert ec['Domain(val.Name && val.Name == obj.Name)'] == dummy_ec['Domain(val.Name && val.Name == obj.Name)']

    key = 'GoogleChronicleBackstory.Domain(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_domain_command_empty_response(client):
    """Test domain_command for empty response."""
    from GoogleChronicleBackstory import domain_command

    with open("test_data/empty_list_ioc_details.json") as f:
        dummy_response = f.read()
    expected_hr = '### Domain: {} found with Reputation: Unknown\n'.format(ARGS['domain'])
    expected_hr += MESSAGES["NO_RECORDS"]

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert hr == expected_hr


def test_gcb_domain_command_empty_response(client):
    """When there is an empty response the command should response empty ec and valid text in hr."""
    from GoogleChronicleBackstory import domain_command
    expected_hr = '### Domain: {} found with Reputation: Unknown\n'.format(ARGS['domain'])
    expected_hr += MESSAGES["NO_RECORDS"]

    dummy_response = '{}'

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert hr == expected_hr


def test_domain_command_failure(client, mocker):
    """When there is a invalid response then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import domain_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.domai_name\': Cannot bind query parameter. Field \'domai_name\' could not be found " \
                     "in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    class MockResponse:
        status_code = 400
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        domain_command(client, ARGS['domain'])
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.domai_name\': " \
                       "Cannot bind query parameter. Field \'domai_name\' could not be found in request message."
    assert str(error.value) == expected_message


def test_domain_command_failure_permission_denied(client, mocker):
    """When there is a response for permission denied then ValueError should be raised with valid message."""
    from GoogleChronicleBackstory import domain_command

    dummy_response = COMMON_RESP['PERM_DENIED_RESP']

    class MockResponse:
        status_code = 403
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        domain_command(client, ARGS['domain'])
    expected_message = COMMON_RESP['PERM_DENIED_MSG']
    assert str(error.value) == expected_message


def test_evaluate_dbot_score_get_all_none(mocker):
    """When category, severity and confidence score are none then dbot score should be 0."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 0

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_malicious(mocker):
    """When category, severity and confidence score are in malicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 93)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_suspicious(mocker):
    """When category, severity and confidence score are in suspicious category then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious(mocker):
    """When category, severity and confidence score are in suspicious category then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious(mocker):
    """When category is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_suspicious(mocker):
    """When category suspicious and severity suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_malicious(mocker):
    """When category suspicious and severity malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_suspicious(mocker):
    """When category malicious and severity suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_malicious(mocker):
    """When category malicious and severity malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_confidencescore_suspicious(mocker):
    """When category suspicious and confidence score suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_confidencescore_malicious(mocker):
    """When category suspicious and confidence score malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_confidencescore_suspicious(mocker):
    """When category malicious and confidence score suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_confidencescore_malicious(mocker):
    """When category malicious and confidence score malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious(mocker):
    """When severity suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 20)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious(mocker):
    """When severity malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 20)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_confidencescore_suspicious(mocker):
    """When severity suspicious and confidence score suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_confidencescore_suspicious(mocker):
    """When severity malicious and confidence score suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_confidencescore_malicious(mocker):
    """When severity suspicious and confidence score malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_confidencescore_malicious(mocker):
    """When severity malicious and confidence score malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_confidencescore_suspicious(mocker):
    """When confidence score suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 55)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_confidencescore_malicious(mocker):
    """When confidence score malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 94)
    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_suspicious_malicious(mocker):
    """When category suspicious, severity suspicious and confidence score malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_suspicious(mocker):
    """When category suspicious, severity malicious and confidence score suspicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 40)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_malicious(mocker):
    """When category suspicious, severity malicious and confidence score malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 120)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_malicious_suspicious(mocker):
    """When category malicious, severity malicious and confidence score suspicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 40)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_suspicious(mocker):
    """When category malicious, severity suspicious and confidence score suspicious are in suspicious category \
    then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 50)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_malicious(mocker):
    """When category malicious, severity suspicious and confidence score malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_none_str_confidencescore(mocker):
    """When category, severity and confidence score in string are not match with \
    input configurations then dbot score should be 0."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 0

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_malicious_str_confidencescore(mocker):
    """When category, severity and confidence score in string are in malicious category \
    then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_suspicious_str_confidencescore(mocker):
    """When category, severity and confidence score in string are in suspicious category \
    then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore(mocker):
    """When category, severity and confidence score in string are in suspicious category \
    then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore(mocker):
    """When category is malicious and confidence score in string then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_suspicious_str_confidencescore(mocker):
    """When category suspicious and severity suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_malicious_str_confidencescore(mocker):
    """When category suspicious and severity malicious and confidence score in string then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_suspicious_str_confidencescore(mocker):
    """When category malicious and severity suspicious and confidence score in string then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_malicious_str_confidencescore(mocker):
    """When category malicious and severity malicious and confidence score in string then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore_suspicious(mocker):
    """When category suspicious and confidence score in string is suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore_malicious(mocker):
    """When category suspicious and confidence score in string is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Low', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore_suspicious(mocker):
    """When category malicious and confidence score in string is suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore_malicious(mocker):
    """When category malicious and confidence score in string is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore(mocker):
    """When severity suspicious and confidence score in string then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore(mocker):
    """When severity malicious and confidence score in string then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore_suspicious(mocker):
    """When severity suspicious and confidence score in string is suspicious then dbot score should be 2."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore_suspicious(mocker):
    """When severity malicious and confidence score in string is suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore_malicious(mocker):
    """When severity suspicious and confidence score in string is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore_malicious(mocker):
    """When severity malicious and confidence score in string is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_str_confidencescore_suspicious(mocker):
    """When confidence score in string is suspicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_str_confidencescore_malicious(mocker):
    """When confidence score in string is malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'High')
    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_suspicious_malicious_str_confidencescore(mocker):
    """When category suspicious, severity suspicious and confidence score in string is malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'Medium', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_suspicious_str_confidencescore(mocker):
    """When category suspicious, severity malicious and confidence score in string is suspicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_malicious_str_confidencescore(mocker):
    """When category suspicious, severity malicious and confidence score in string is malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score(PARAMS['suspicious_categories'], 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_malicious_suspicious_str_confidencescore(mocker):
    """When category malicious, severity malicious and confidence score in string is suspicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_suspicious_str_confidencescore(mocker):
    """When category malicious, severity suspicious and confidence score in string is suspicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_malicious_str_confidencescore(mocker):
    """When category malicious, severity suspicious and confidence score in string is malicious are in \
    suspicious category then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_category_blank(mocker):
    """When category blank and others set to malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_severity_blank(mocker):
    """When severity blank and others set to malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', '', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_category_blank_str_confidencescore(mocker):
    """When category blank and others set to malicious with string confidence score then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('', 'Medium', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_severity_blank_str_confidencescore(mocker):
    """When severity blank and others set to malicious with string confidence score then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', '', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_str_confidencescore_blank(mocker):
    """When confidence score in string blank and others set to malicious then dbot score should be 3."""
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', '')

    # Assert
    assert expected_dbot_score == dbot_score


def test_preset_time_range():
    """When valid duration value pass in validate_duration function then it should pass else raise ValueError."""
    # Execute
    from GoogleChronicleBackstory import validate_preset_time_range

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last10days')
    assert str(error.value) == MESSAGES["INVALID_DAY_ARGUMENT"]

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 10days')
    assert str(error.value) == MESSAGES["INVALID_DAY_ARGUMENT"]

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 4 days')
    assert str(error.value) == MESSAGES["INVALID_DAY_ARGUMENT"]

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 1 month')
    assert str(error.value) == MESSAGES["INVALID_DAY_ARGUMENT"]

    assert validate_preset_time_range('Last 1 day') == '1 day'
    assert validate_preset_time_range('Last 15 days') == '15 days'


def test_parse_error_message():
    """Test correct parsing for parse_error_message method."""
    from GoogleChronicleBackstory import parse_error_message

    error = parse_error_message('service unavailable', '')
    assert error == 'Invalid response received from Chronicle API. Response not in JSON format.'


def test_list_events_command(client):
    """Test gcb_list_events_command for non-empty and empty response."""
    from GoogleChronicleBackstory import gcb_list_events_command

    with open("test_data/list_events_response.json") as f:
        dummy_response = f.read()

    with open("test_data/list_events_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_events_command(client, {})

    event = 'GoogleChronicleBackstory.Events(val.id == obj.id)'
    assert ec[event] == dummy_ec[event]

    # Test command when no events found
    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_list_events_command(client, {})
    assert ec == {}
    assert hr == 'No Events Found'


def test_gcb_udm_search_command(client):
    """Test gcb_udm_search_command for non-empty and empty response."""
    from GoogleChronicleBackstory import gcb_udm_search_command

    with open("test_data/udm_search_response.json") as f:
        dummy_response = f.read()

    with open("test_data/udm_search_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/udm_search_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_udm_search_command(client, {'query': 'ip!="8.8.8.8"'})

    event = CHRONICLE_OUTPUT_PATHS['UDMEvents']

    assert ec[event] == dummy_ec[event]
    assert hr == dummy_hr

    # Test command when no events found
    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_udm_search_command(client, {'query': 'ip!="8.8.8.8"'})
    assert ec == {}
    assert hr == 'No events were found for the specified UDM search query.'


def test_gcb_udm_search_command_for_invalid_returned_date(capfd, client):
    """Test gcb_udm_search_command for invalid returned date from response."""
    from GoogleChronicleBackstory import gcb_udm_search_command

    with open("test_data/udm_search_response_invalid_date.json") as f:
        dummy_response = f.read()

    with open("test_data/udm_search_ec_invalid_date.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/udm_search_hr_invalid_date.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    with capfd.disabled():
        hr, ec, _ = gcb_udm_search_command(client, {'query': 'ip!="8.8.8.8"'})

    event = CHRONICLE_OUTPUT_PATHS['UDMEvents']

    assert ec[event] == dummy_ec[event]
    assert hr == dummy_hr


@pytest.mark.parametrize("args, error_msg", [
    ({}, MESSAGES['QUERY_REQUIRED']),
    ({'query': 'ip!="8.8.8.8"', 'start_time': '3 days', 'end_time': '0 days', 'limit': 'invalid_limit'},
     MESSAGES['INVALID_LIMIT_TYPE']),
    ({'query': 'ip!="8.8.8.8"', 'limit': '0'}, MESSAGES['INVALID_LIMIT_TYPE']),
    ({'query': 'ip!="8.8.8.8"', 'limit': '-1'}, MESSAGES['INVALID_LIMIT_TYPE']),
    ({'query': 'ip!="8.8.8.8"', 'limit': '1001'}, MESSAGES['INVALID_LIMIT_RANGE'].format(1000))
])
def test_gcb_udm_search_command_for_invalid_args(args, error_msg):
    """Test gcb_udm_search_command for failing arguments."""
    from GoogleChronicleBackstory import gcb_udm_search_command

    with pytest.raises(ValueError) as e:
        gcb_udm_search_command(client, args)

    assert str(e.value) == error_msg


def test_list_detections_command(client):
    """Test gcb_list_detections_command for non-empty and empty response."""
    from GoogleChronicleBackstory import gcb_list_detections_command

    args = {'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '2019-10-17T00:00:00Z',
            'detection_end_time': '2 days ago'}

    with open("test_data/list_detections_response.json") as f:
        dummy_response = f.read()

    with open("test_data/list_detections_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_detections_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_detections_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no detections found
    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_list_detections_command(client, args)
    assert ec == {}
    assert hr == 'No Detections Found'


@pytest.mark.parametrize("args, error_msg", [
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'page_size': 'dummy'}, COMMON_RESP['INVALID_PAGE_SIZE']),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'page_size': '100000'}, 'Page size should be in the range '
                                                                                    'from 1 to 1000.'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '645.08'},
     'Invalid date: "detection_start_time"="645.08"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '-325.21'},
     'Invalid date: "detection_start_time"="-325.21"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '645.08'},
     'Invalid date: "detection_end_time"="645.08"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '-325.21'},
     'Invalid date: "detection_end_time"="-325.21"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '645.08'},
     'Invalid date: "start_time"="645.08"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '-325.21'},
     'Invalid date: "start_time"="-325.21"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '645.08'}, 'Invalid date: "end_time"="645.08"'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '-325.21'},
     'Invalid date: "end_time"="-325.21"'),
    ({'detection_for_all_versions': True}, "If \"detection_for_all_versions\" is true, rule id is required."),
    ({'list_basis': 'CREATED_TIME'}, "To sort detections by \"list_basis\", either \"start_time\" or \"end_time\" "
                                     "argument is required.")
])
def test_validate_and_parse_list_detections_args(args, error_msg):
    """Test validate_and_parse_list_detections_args for failing arguments."""
    from GoogleChronicleBackstory import validate_and_parse_list_detections_args

    with pytest.raises(ValueError) as e:
        validate_and_parse_list_detections_args(args)

    assert str(e.value) == error_msg


def test_list_curatedrule_detections_command(client):
    """Test gcb_list_curatedrule_detections_command for non-empty and empty response."""
    from GoogleChronicleBackstory import gcb_list_curatedrule_detections_command

    args = {'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'detection_start_time': '2023-06-14T17:28:00Z',
            'detection_end_time': '2 days ago'}

    with open("test_data/list_curatedrule_detections_response.json") as f:
        dummy_response = f.read()

    with open("test_data/list_curatedrule_detections_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_curatedrule_detections_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_curatedrule_detections_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no detections found
    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_list_curatedrule_detections_command(client, args)
    assert ec == {}
    assert hr == 'No Curated Detections Found'


@pytest.mark.parametrize("args, error_msg", [
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'page_size': 'dummy'}, COMMON_RESP['INVALID_PAGE_SIZE']),
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'page_size': '100000'}, 'Page size should be in the range '
                                                                       'from 1 to 1000.'),
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'start_time': '645.08'},
     'Invalid date: "start_time"="645.08"'),
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'start_time': '-325.21'},
     'Invalid date: "start_time"="-325.21"'),
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'end_time': '645.08'}, 'Invalid date: "end_time"="645.08"'),
    ({'id': 'ur_ttp_GCP__GlobalSSHKeys_Added', 'end_time': '-325.21'},
     'Invalid date: "end_time"="-325.21"'),
    ({}, MESSAGES['CURATED_RULE_ID_REQUIRED']),
])
def test_validate_and_parse_list_curatedrule_detections_args(args, error_msg):
    """Test validate_and_parse_list_curatedrule_detections_args for failing arguments."""
    from GoogleChronicleBackstory import validate_and_parse_list_curatedrule_detections_args

    with pytest.raises(ValueError) as e:
        validate_and_parse_list_curatedrule_detections_args(args)

    assert str(e.value) == error_msg


def validate_duplicate_incidents(incidents):
    """
    Assert deduplicated incidents.

    Internal method used in test_gcb_fetch_incident_success_with_alerts_with_incident_identifiers
    """
    assert len(incidents) == 1


def test_gcb_fetch_incident_success_with_alerts_with_incident_identifiers(mocker, client):
    """Check the fetched incident in case duplicate asset alerts are fetched in next iteration."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'incident_severity': None,
        'backstory_alert_type': ASSET_ALERT_TYPE,
        'time_window': '45'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_incidents)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': START_TIME,
                            'assets_alerts_identifiers': [
                                '6a1b7ffcbb7a0fb51bd4bebfbbbbb0e094c8e7543dd64858354d486d0288798d',
                                'bccf9ae7dbfdc1fcaea98fe4043fa3f20f5c4f38a71bad062c8b2d849d79bed8']})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_generate_delayed_start_time():
    """Check if the start time is delayed according to user input."""
    from GoogleChronicleBackstory import generate_delayed_start_time

    start_time = '2020-01-29T14:13:20Z'
    delayed_start_time = generate_delayed_start_time('45', start_time)
    assert delayed_start_time == '2020-01-29T13:28:20.000000Z'


def test_validate_parameter_failure_invalid_time_window_values():
    """When time window configuration parameter has invalid value then it should raise ValueError."""
    from GoogleChronicleBackstory import validate_configuration_parameters
    invalid_time_window = {
        'service_account_credential': DUMMY_DICT,
        'max_fetch': '10'
    }

    invalid_time_window_error_message = 'Time window(in minutes) should be in the numeric range from 1 to 60.'
    with pytest.raises(ValueError) as e:
        invalid_time_window['time_window'] = 'sad'
        validate_configuration_parameters(invalid_time_window)

    assert str(e.value) == invalid_time_window_error_message

    with pytest.raises(ValueError) as e:
        invalid_time_window['time_window'] = '90'
        validate_configuration_parameters(invalid_time_window)

    assert str(e.value) == invalid_time_window_error_message

    with pytest.raises(ValueError) as e:
        invalid_time_window['time_window'] = '-1'
        validate_configuration_parameters(invalid_time_window)

    assert str(e.value) == invalid_time_window_error_message


def validate_detection_incident(incidents):
    """
    Assert detection incidents.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert incidents

    for incident in incidents:
        assert incident['name']
        assert incident['rawJSON']


def test_fetch_incident_detection_when_1st_sync_n_data_less_thn_max_fetch_and_ids_is_1(client, mocker):
    """Case when 2 detections with no-NT."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': VERSION_ID
    }

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_detection_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.call_count == 1


def validate_last_run_whn_last_pull(last_run):
    """
    Assert returned last run without detections to pull.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert not last_run.get("rule_first_fetched_time")
    assert not last_run.get("detection_to_process")
    assert not last_run.get("detection_to_pull")
    assert not last_run.get("pending_rule_or_version_id")


def validate_last_run_without_curatedrule_detection_to_pull(last_run):
    """
    Assert returned last run without curated rule detections to pull.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert not last_run.get("curatedrule_first_fetched_time")
    assert not last_run.get("curatedrule_detection_to_process")
    assert not last_run.get("curatedrule_detection_to_pull")
    assert not last_run.get("pending_curatedrule")


def validate_last_run_wth_dtc_to_pull(last_run):
    """
    Assert returned last run with detections to pull.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert last_run.get("rule_first_fetched_time")
    assert not last_run.get("detection_to_process")
    assert last_run.get("detection_to_pull")
    assert not last_run.get("pending_rule_or_version_id")


def validate_last_run_with_curatedrule_detection_to_pull(last_run):
    """
    Assert returned last run with curated rule detections to pull.

    Internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert last_run.get("curatedrule_first_fetched_time")
    assert not last_run.get("curatedrule_detection_to_process")
    assert last_run.get("curatedrule_detection_to_pull")
    assert not last_run.get("pending_curatedrule")


def validate_detections_case_2_iteration_1(incidents):
    """
    Assert number of detection incidents for case 2 iteration 1.

    Internal method used in test_fetch_incident_detection_case_2
    """
    assert len(incidents) == 5


def validate_detections_case_2_iteration_2(incidents):
    """
    Assert number of detection incidents for case 2 iteration 2.

    Internal method used in test_fetch_incident_detection_case_2
    """
    assert len(incidents) == 2


def test_fetch_incident_detection_case_2(client, mocker):
    """
    Test fetch incidents detection case 2.

    max_fetch =5
    1Id return 5, with NT
    1Id on 2nd call return 2, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': VERSION_ID
    }

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    class MockResponse2:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.side_effect = [MockResponse5, MockResponse2]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_1)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run_wth_dtc_to_pull)

    fetch_incidents(client, param)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run_whn_last_pull)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_detections_case_3_iteration_1(incidents):
    """
    Assert number of detection incidents for case 3 iteration 1.

    Internal method used in test_fetch_incident_detection_case_3
    """
    assert len(incidents) == 3


def validate_detections_case_3_iteration_2(incidents):
    """
    Assert number of detection incidents for case 3 iteration 2.

    Internal method used in test_fetch_incident_detection_case_3
    """
    assert len(incidents) == 2


@mock.patch('GoogleChronicleBackstory.get_detections')
@mock.patch('demistomock.error')
def test_no_duplicate_rule_id_on_detection_to_pull_exception(mock_error, mock_build, client):
    """Demo test for get_max_fetch_detections."""
    from GoogleChronicleBackstory import get_max_fetch_detections

    mock_build.side_effect = ValueError('123')
    z = ['123', '456']
    mock_error.return_value = {}
    for _ in range(5):
        x, y, z, w = get_max_fetch_detections(client, '12', '23', 5,
                                              [{'id': '123',
                                                'detection': [{'ruleVersion': '3423', 'ruleName': 'SampleRule'}]},
                                               {'id': '1234',
                                                'detection': [{'ruleVersion': '342', 'ruleName': 'SampleRule'}]},
                                               {'id': '12345',
                                                'detection': [{'ruleVersion': '34', 'ruleName': 'SampleRule'}]}],
                                              {'rule_id': '456',
                                               'next_page_token': 'foorbar'},
                                              z, '', {}, "CREATED_TIME")

    assert z == ['123', '456']


def test_fetch_incident_detection_case_3(client, mocker):
    """
    Test fetch incidents detection case 3.

    1Id return 2, with no NT
    2Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 3,
        'backstory_alert_type': DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631091_146879001, '
                                  'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631092_146879002'
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.side_effect = [MockResponse2, MockResponse3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_3_iteration_1)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'detection_to_process': [{'id': '123', 'detection': [{'ruleVersion': '3423', 'ruleName': 'SampleRule'}]},
                                 {'id': '1234', 'detection': [{'ruleVersion': '342', 'ruleName': 'SampleRule'}]}],
        'detection_to_pull': {},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': [], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_3_iteration_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


@mock.patch('GoogleChronicleBackstory.get_detections')
def test_detection_to_pull_is_empty_when_2nd_rule_returns_data_with_no_next_token(mock_build, client):
    """
    Test get_max_fetch_detections when detection to pull is empty and response contains no next page token.

    case - rule_1 has 5 records, rule_2 has 2 records
    max_fetch - 3
    Assumption : On 1st call we pulled rule_1 - 3 indicators with detection_to_pull(next_token, rule_id)
    On 2nd call we have next_token and rule_id for rule_1 that contains 2 records. This will pull 2 records
    for rule_1 and 2 records for rule_2 and complete the fetch-incident cycle since we don't have any rule to process
    test_detection_to_pull_is_empty
    """
    from GoogleChronicleBackstory import get_max_fetch_detections, get_detections

    with open("test_data/fetch_detection_size_2.json", encoding='utf-8') as f:
        get_detection_json_size_2 = json.loads(f.read())

    mock_build.return_value = ('p', get_detection_json_size_2)
    z = ['456']

    x, y, z, w = get_max_fetch_detections(client, 'st_dummy', 'et_dummy', 3,
                                          [],
                                          {'rule_id': '123',
                                           'next_page_token': 'foorbar'},
                                          z, '', {}, "CREATED_TIME")

    assert len(x) == 4
    assert y == {}
    assert z == []
    # Making sure that get_detections called 2 times.
    assert get_detections.call_count == 2


@mock.patch('GoogleChronicleBackstory.validate_response')
def test_when_detection_to_pull_is_not_empty_and_return_empty_result(mock_validate_response, client):
    """
    Test get_max_fetch_detections when detection to pull is not empty and response is empty.

    - case when detection_to_pull is not empty and api return empty response with 200 status
      then logic should pop next rule and set detection_to_pull empty
    - Issue reported - 27/04/2021, cfd-992
    - Debug Log of customer shows 11 HTTP streams (one stream per one rule id)
      simultaneously (within the same minute) which then gives a 429 error if more are attempted.
    """
    from GoogleChronicleBackstory import get_max_fetch_detections, validate_response

    mock_validate_response.return_value = {}
    z = ['rule_2', 'rule_3']
    x, y, z, w = get_max_fetch_detections(client, 'st_dummy', 'et_dummy', 5,
                                          [],
                                          {'rule_id': 'rule_1',
                                           'next_page_token': 'foorbar'},
                                          z, '', {}, "CREATED_TIME")

    assert z == []
    assert y == {}
    assert len(x) == 0
    # Making sure that validate_response called 3 times.
    assert validate_response.call_count == 3


@mock.patch('demistomock.error')
def test_429_or_500_error_with_max_attempts_60(mock_error, client):
    """
    Test behavior for 429 and 500 error codes with maximum attempts 60.

    case :   rule_1 - 429 error 30 times, return 3 records
             rule_2 - 500 error 60 times
             rule_3 - 500 error 1 times, return 3 records
    """
    from GoogleChronicleBackstory import get_max_fetch_detections
    mock_error.return_value = {}

    class MockResponse429:
        status_code = 429
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    class MockResponse500:
        status_code = 500
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    client.http_client.request.side_effect = [MockResponse429] * 30 + [MockResponse3] + [
        MockResponse500] * 61 + [MockResponse3]
    pending_rule_or_version_id = ['rule_2', 'rule_3']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'foorbar'}
    simple_backoff_rules = {}
    for _ in range(93):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules = get_max_fetch_detections(
            client,
            'st_dummy',
            'et_dummy', 5,
            [],
            detection_to_pull,
            pending_rule_or_version_id,
            '', simple_backoff_rules, "CREATED_TIME")

    assert client.http_client.request.call_count == 93


@mock.patch('demistomock.error')
def test_400_and_404_error(mock_error, client):
    """
    Test behavior on 400 and 404 response.

    case : rule_1 ok, rule_2 throw 400, rule_3 ok, rule_5 throw 404, rule_5 ok
    """
    from GoogleChronicleBackstory import get_max_fetch_detections

    mock_error.return_value = {}

    class MockResponse400:
        status_code = 400
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    class MockResponse404:
        status_code = 404
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    client.http_client.request.side_effect = [MockResponse3, MockResponse400,
                                              MockResponse3, MockResponse404,
                                              MockResponse3]

    pending_rule_or_version_id = ['rule_2', 'rule_3', 'rule_4', 'rule_5']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'foorbar'}

    simple_backoff_rules = {}
    for _ in range(5):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules = get_max_fetch_detections(
            client,
            'st_dummy',
            'et_dummy', 15,
            [],
            detection_to_pull,
            pending_rule_or_version_id,
            '', simple_backoff_rules, "CREATED_TIME")


def validate_detections_case_4_iteration_1_and_2(incidents):
    """
    Assert number of detection incidents for case 4 iteration 1 and 2.

    internal method used in test_fetch_incident_detection_case_4
    """
    assert len(incidents) == 5


def validate_detections_case_4_iteration_3(incidents):
    """
    Assert number of detection incidents for case 4 iteration 3.

    Internal method used in test_fetch_incident_detection_case_4
    """
    assert len(incidents) == 3


def test_fetch_incident_detection_case_4(client, mocker):
    """
    Test fetch incidents for case no. 4.

    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': '123, 456, 789'
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json

        def json():
            return json.loads(get_detection_json)

    client.http_client.request.side_effect = [MockResponse3, MockResponse5, MockResponse2,
                                              MockResponse3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_1_and_2)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'rule_first_fetched_time': '2020-11-20T12:00:01Z',
        'detection_to_process': [{'id': '123', 'detection': [{'ruleVersion': '3423', 'ruleName': 'SampleRule'}]},
                                 {'id': '1234', 'detection': [{'ruleVersion': '342', 'ruleName': 'SampleRule'}]},
                                 {'id': '12345', 'detection': [{'ruleVersion': '34', 'ruleName': 'SampleRule'}]}],
        'detection_to_pull': {'rule_id': '456',
                              'next_page_token': 'foorbar'},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_1_and_2)
    fetch_incidents(client, param)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_3)
    mock_last_run_2 = {
        'start_time': LAST_RUN_TIME,
        'rule_first_fetched_time': '2020-11-20T12:00:01Z',
        'detection_to_process': [],
        'detection_to_pull': {},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_detections_case_5_iteration_1_2_3(incidents):
    """Assert number of detection incidents for case 5 iteration 1, 2 and 3."""
    assert len(incidents) == 5


def test_fetch_incident_detection_case_5(client, mocker):
    """
    Test fetch incidents for case no. 5.

    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 5, with NT

    3 + 2
    (3) + 2

    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'fetch_detection_by_ids': '123, 456, 789',
        'backstory_alert_type': DETECTION_ALERT_TYPE
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json

        def json():
            return json.loads(get_detection_json)

    client.http_client.request.side_effect = [MockResponse3, MockResponse5, MockResponse2,
                                              MockResponse5]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'detection_to_process': [{'id': '123', 'detection': [{'ruleVersion': '3423', 'ruleName': 'SampleRule'}]},
                                 {'id': '1234', 'detection': [{'ruleVersion': '342', 'ruleName': 'SampleRule'}]},
                                 {'id': '12345', 'detection': [{'ruleVersion': '34', 'ruleName': 'SampleRule'}]}],
        'detection_to_pull': {'rule_id': '456',
                              'next_page_token': 'foorbar'},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)
    fetch_incidents(client, param)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)
    mock_last_run_2 = {
        'start_time': LAST_RUN_TIME,
        'detection_to_process': [],
        'detection_to_pull': {},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_duplicate_detections(incidents):
    """
    Assert deduplication.

    Internal method used in test_gcb_fetch_incident_success_with_detections_with_incident_identifiers
    """
    assert len(incidents) == 3


def test_gcb_fetch_incident_success_with_detections_with_incident_identifiers(mocker, client):
    """Check the fetched incident in case duplicate detections are fetched in next iteration."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': VERSION_ID
    }

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    client.http_client.request.return_value = MockResponse5
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_detections)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': START_TIME,
                            'detection_identifiers': [{'id': 'de_e6abfcb5-1b85-41b0-b64c-695b32504361',
                                                       'ruleVersion': 'ru_e6abfcb5-1b85-41b0-b64c-695b32'
                                                                      '50436f@v_1602631093_146879000'},
                                                      {'id': 'de_e6abfcb5-1b85-41b0-b64c-695b32504362',
                                                       'ruleVersion': 'ru_e6abfcb5-1b85-41b0-b64c-695b32'
                                                                      '50436f@v_1602631093_146879000'}]})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_fetch_incident_curatedrule_detection_case_4(client, mocker):
    """
    Test fetch incidents with curated rule for case no. 4.

    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_alert_state': 'ALERTING',
        'fetch_detection_by_ids': '123, 456, 789'
    }

    with open("test_data/fetch_curatedrule_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_curatedrule_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    with open("test_data/fetch_curatedrule_detection_size_2.json") as f:
        get_detection_json = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json

        def json():
            return json.loads(get_detection_json)

    client.http_client.request.side_effect = [MockResponse3, MockResponse5, MockResponse2,
                                              MockResponse3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_1_and_2)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'curatedrule_first_fetched_time': '2023-01-01T12:00:01Z',
        'curatedrule_detection_to_process': [
            {'id': '123', 'detection': [{'ruleName': 'SampleRule'}]},
            {'id': '1234', 'detection': [{'ruleName': 'SampleRule'}]},
            {'id': '12345', 'detection': [{'ruleName': 'SampleRule'}]}],
        'curatedrule_detection_to_pull': {'rule_id': '456', 'next_page_token': 'next_page_token'},
        'pending_curatedrule_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_1_and_2)
    fetch_incidents(client, param)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_3)
    mock_last_run_2 = {
        'start_time': LAST_RUN_TIME,
        'curatedrule_first_fetched_time': '2023-01-01T12:00:01Z',
        'curatedrule_detection_to_process': [],
        'curatedrule_detection_to_pull': {},
        'pending_curatedrule_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_fetch_incident_curatedrule_detection_when_1st_sync_n_data_less_thn_max_fetch_and_ids_is_1(client, mocker):
    """Case when 2 curated rule detections with no-NT."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': CURATEDRULE_ID
    }

    with open("test_data/fetch_curatedrule_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_detection_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.call_count == 1


def test_fetch_incident_curatedrule_detection_case_2(client, mocker):
    """
    Test fetch incidents curated rule detection case 2.

    max_fetch =5
    1Id return 5, with NT
    1Id on 2nd call return 2, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': CURATEDRULE_ID
    }

    with open("test_data/fetch_curatedrule_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    with open("test_data/fetch_curatedrule_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    class MockResponse2:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.side_effect = [MockResponse5, MockResponse2]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_1)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run_with_curatedrule_detection_to_pull)

    fetch_incidents(client, param)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run_without_curatedrule_detection_to_pull)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


@mock.patch('GoogleChronicleBackstory.get_curatedrule_detections')
@mock.patch('demistomock.error')
def test_no_duplicate_curated_rule_id_on_detection_to_pull_exception(mock_error, mock_build, client):
    """Demo test for get_max_fetch_curatedrule_detections."""
    from GoogleChronicleBackstory import get_max_fetch_curatedrule_detections

    mock_build.side_effect = ValueError('123')
    z = ['123', '456']
    mock_error.return_value = {}
    for _ in range(5):
        x, y, z, w = get_max_fetch_curatedrule_detections(client, '12', '23', 5,
                                                          [{'id': '123',
                                                            'detection': [{'ruleName': 'SampleRule'}]},
                                                           {'id': '1234',
                                                            'detection': [{'ruleName': 'SampleRule'}]},
                                                           {'id': '12345',
                                                            'detection': [{'ruleName': 'SampleRule'}]}],
                                                          {'rule_id': '456',
                                                           'next_page_token': 'next_page_token'},
                                                          z, '', {}, "CREATED_TIME")

    assert z == ['123', '456']


def test_fetch_incident_curatedrule_detection_case_3(client, mocker):
    """
    Test fetch incidents for curated rule detection case 3.

    1Id return 2, with no NT
    2Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 3,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': 'de_50fd0957-0959-0000-d556-c6f8000016b1, '
                                  'de_662d8ff5-8eea-deb8-274e-f3410c7b935a'
    }

    with open("test_data/fetch_curatedrule_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_curatedrule_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json_size_2

        def json():
            return json.loads(get_detection_json_size_2)

    client.http_client.request.side_effect = [MockResponse2, MockResponse3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_3_iteration_1)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'curatedrule_detection_to_process': [{'id': '123', 'detection': [{'ruleName': 'SampleRule'}]},
                                             {'id': '1234', 'detection': [{'ruleName': 'SampleRule'}]}],
        'curatedrule_detection_to_pull': {},
        'pending_curatedrule_with_alert_state': {'rule_id': [], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_3_iteration_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


@mock.patch('GoogleChronicleBackstory.get_curatedrule_detections')
def test_curatedrule_detection_to_pull_is_empty_when_2nd_rule_returns_data_with_no_next_token(mock_build, client):
    """
    Test get_max_fetch_curatedrule_detections when detection to pull is empty and response contains no next page token.

    case - rule_1 has 5 records, rule_2 has 2 records
    max_fetch - 3
    Assumption : On 1st call we pulled rule_1 - 3 indicators with curatedrule_detection_to_pull(next_token, rule_id)
    On 2nd call we have next_token and rule_id for rule_1 that contains 2 records. This will pull 2 records
    for rule_1 and 2 records for rule_2 and complete the fetch-incident cycle since we don't have any rule to process.
    """
    from GoogleChronicleBackstory import get_max_fetch_curatedrule_detections, get_curatedrule_detections

    with open("test_data/fetch_curatedrule_detection_size_2.json", encoding='utf-8') as f:
        get_detection_json_size_2 = json.loads(f.read())

    mock_build.return_value = ('p', get_detection_json_size_2)
    z = ['456']

    x, y, z, w = get_max_fetch_curatedrule_detections(client, 'st_dummy', 'et_dummy', 3,
                                                      [],
                                                      {'rule_id': '123',
                                                       'next_page_token': 'next_page_token'},
                                                      z, '', {}, "CREATED_TIME")

    assert len(x) == 4
    assert y == {}
    assert z == []
    # Making sure that get_curatedrule_detections called 2 times.
    assert get_curatedrule_detections.call_count == 2


@mock.patch('GoogleChronicleBackstory.validate_response')
def test_when_curatedrule_detection_to_pull_is_not_empty_and_return_empty_result(mock_validate_response, client):
    """
    Test get_max_fetch_curatedrule_detections when detection to pull is not empty and response is empty.

    - case when curatedrule_detection_to_pull is not empty and api return empty response with 200 status
      then logic should pop next rule and set curatedrule_detection_to_pull empty.
    """
    from GoogleChronicleBackstory import get_max_fetch_curatedrule_detections, validate_response

    mock_validate_response.return_value = {}
    z = ['rule_2', 'rule_3']
    x, y, z, w = get_max_fetch_curatedrule_detections(client, 'st_dummy', 'et_dummy', 5,
                                                      [],
                                                      {'rule_id': 'rule_1',
                                                       'next_page_token': 'next_page_token'},
                                                      z, '', {}, "CREATED_TIME")

    assert z == []
    assert y == {}
    assert len(x) == 0
    # Making sure that validate_response called 3 times.
    assert validate_response.call_count == 3


@mock.patch('demistomock.error')
def test_429_or_500_error_with_max_attempts_60_for_curatedrule_detection(mock_error, client):
    """
    Test behavior for 429 and 500 error codes with maximum attempts 60.

    case :   rule_1 - 429 error 30 times, return 3 records
             rule_2 - 500 error 60 times
             rule_3 - 500 error 1 times, return 3 records
    """
    from GoogleChronicleBackstory import get_max_fetch_curatedrule_detections
    mock_error.return_value = {}

    class MockResponse429:
        status_code = 429
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    class MockResponse500:
        status_code = 500
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    with open("test_data/fetch_curatedrule_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    client.http_client.request.side_effect = [MockResponse429] * 30 + [MockResponse3] + [
        MockResponse500] * 61 + [MockResponse3]
    pending_rule_or_version_id = ['rule_2', 'rule_3']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'next_page_token'}
    simple_backoff_rules = {}
    for _ in range(93):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, \
            simple_backoff_rules = get_max_fetch_curatedrule_detections(client, 'st_dummy', 'et_dummy', 5, [],
                                                                        detection_to_pull, pending_rule_or_version_id,
                                                                        '', simple_backoff_rules, "CREATED_TIME")

    assert client.http_client.request.call_count == 93


@mock.patch('demistomock.error')
def test_400_and_404_error_for_curatedrule_detection(mock_error, client):
    """
    Test behavior on 400 and 404 response.

    case : rule_1 ok, rule_2 throw 400, rule_3 ok, rule_5 throw 404, rule_5 ok
    """
    from GoogleChronicleBackstory import get_max_fetch_curatedrule_detections

    mock_error.return_value = {}

    class MockResponse400:
        status_code = 400
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    class MockResponse404:
        status_code = 404
        text = COMMON_RESP['ERROR_RESPONSE']

        def json():
            return json.loads(COMMON_RESP['ERROR_RESPONSE'])

    with open("test_data/fetch_curatedrule_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    client.http_client.request.side_effect = [MockResponse3, MockResponse400,
                                              MockResponse3, MockResponse404,
                                              MockResponse3]

    pending_rule_or_version_id = ['rule_2', 'rule_3', 'rule_4', 'rule_5']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'next_page_token'}

    simple_backoff_rules = {}
    for _ in range(5):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, \
            simple_backoff_rules = get_max_fetch_curatedrule_detections(client, 'st_dummy', 'et_dummy', 15, [],
                                                                        detection_to_pull, pending_rule_or_version_id,
                                                                        '', simple_backoff_rules, "CREATED_TIME")


def test_fetch_incident_curatedrule_detection_case_5(client, mocker):
    """
    Test fetch incidents with curated rule detection for case no. 5.

    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 5, with NT

    3 + 2
    (3) + 2

    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'fetch_detection_by_ids': '123, 456, 789',
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE
    }

    with open("test_data/fetch_curatedrule_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    class MockResponse3:
        status_code = 200
        text = get_detection_json_size_3

        def json():
            return json.loads(get_detection_json_size_3)

    with open("test_data/fetch_curatedrule_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    with open("test_data/fetch_curatedrule_detection_size_2.json") as f:
        get_detection_json = f.read()

    class MockResponse2:
        status_code = 200
        text = get_detection_json

        def json():
            return json.loads(get_detection_json)

    client.http_client.request.side_effect = [MockResponse3, MockResponse5, MockResponse2,
                                              MockResponse5]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': LAST_RUN_TIME,
        'curatedrule_detection_to_process': [
            {'id': '123', 'detection': [{'ruleName': 'SampleRule'}]},
            {'id': '1234', 'detection': [{'ruleName': 'SampleRule'}]},
            {'id': '12345', 'detection': [{'ruleName': 'SampleRule'}]}],
        'curatedrule_detection_to_pull': {'rule_id': '456', 'next_page_token': 'next_page_token'},
        'pending_curatedrule_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)
    fetch_incidents(client, param)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)
    mock_last_run_2 = {
        'start_time': LAST_RUN_TIME,
        'curatedrule_detection_to_process': [],
        'curatedrule_detection_to_pull': {},
        'pending_curatedrule_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_success_for_curatedrule_detections_with_incident_identifiers(mocker, client):
    """Check the fetched incident in case duplicate curated rule detections are fetched in next iteration."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': CURATEDRULE_ID
    }

    with open("test_data/fetch_curatedrule_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    class MockResponse5:
        status_code = 200
        text = get_detection_json_size_5

        def json():
            return json.loads(get_detection_json_size_5)

    client.http_client.request.return_value = MockResponse5
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_detections)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': START_TIME,
                            'curatedrule_detection_identifiers': [{'id': 'de_50fd0957-0959-0000-d556-c6f8000016b1'},
                                                                  {'id': 'de_662d8ff5-8eea-deb8-274e-f3410c7b935a'}]})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_for_curatedrule_detections_with_empty_curatedrule_id(mocker, client):
    """Check the fetched incident for curated rule detections where empty rule ID is provided."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': DEFAULT_FIRST_FETCH,
        'max_fetch': 5,
        'backstory_alert_type': CURATEDRULE_DETECTION_ALERT_TYPE,
        'fetch_detection_by_ids': ""
    }

    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={})

    with pytest.raises(ValueError) as err:
        fetch_incidents(client, param)

    assert str(err.value) == MESSAGES['PROVIDE_CURATED_RULE_ID']


def validate_user_alert_incident(incidents):
    """
    Assert alert incidents.

    Internal method used in test_fetch_user_alert_incident_success_with_param_alerts
    """
    assert len(incidents) == 3
    for incident in incidents:
        assert incident['name']
        assert incident['rawJSON']
        raw_json = json.loads(incident['rawJSON'])
        assert raw_json['FirstSeen']
        assert raw_json['LastSeen']
        assert raw_json['Occurrences']
        assert raw_json['Alerts']
        assert raw_json['User']
        assert raw_json['AlertName']


def test_fetch_user_alert_incident_success_with_param_and_alerts_when_executed_1st_time(mocker, client):
    """Check the alert incident success without last run (1st execution)."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '4 days',
        'max_fetch': 20,
        'time_window': '60',
        'backstory_alert_type': USER_ALERT
    }

    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_user_alert_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_user_alert_fetch_incident_success_with_alerts_with_demisto_last_run(mocker, client):
    """Check the alert incident success with last run."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'backstory_alert_type': USER_ALERT
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_user_alert_incident)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={'start_time': "2020-01-29T14:13:20+00:00"})

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_user_alert_success_with_alerts_with_incident_identifiers(mocker, client):
    """Check the fetched incident in case duplicate user alerts are fetched in next iteration."""
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'backstory_alert_type': USER_ALERT,
        'time_window': '45'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    class MockResponse:
        status_code = 200
        text = gcb_alert_sample

        def json():
            return json.loads(gcb_alert_sample)

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_incidents)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': START_TIME,
                            'user_alerts_identifiers': [
                                '21a03d1fa2ce7e342534447e947a94b9f9f0ccfc57e96e86ca56a0074b646852',
                                '32ac16aa49a087d751644d78ee37d61399f474889a963d017643dd6f566f6c0f']})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_list_user_alert_with_no_arg_supplied_success(mocker, client):
    """Should return hr, ec and events when multiple events are responded."""
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        "alert_type": "User Alerts"
    }

    class MockResponse:
        status_code = 200
        text = get_hr_gcb_alerts()

        def json():
            return json.loads(get_hr_gcb_alerts())

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr
    assert ec
    with open("test_data/user_alerts_ec.json") as f:
        expected_ec = json.load(f)

    assert ec == expected_ec
    assert events
    assert client.http_client.request.called


def test_gcb_list_user_alert_when_no_alert_found(mocker, client):
    """Should display 'No Record Found' message when empty but 200 status is responded."""
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        "alert_type": "User Alerts"
    }

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr == '### User Alert(s): No Records Found'
    assert not ec
    assert not events
    assert client.http_client.request.called


def test_list_rules_command(client):
    """When valid response comes in gcb-list-rules command it should respond with result."""
    from GoogleChronicleBackstory import gcb_list_rules_command

    args = {'page_size': '2',
            'page_token': 'foobar_page_token'}

    with open("test_data/list_rules_response.json") as f:
        dummy_response = f.read()

    with open("test_data/list_rules_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_rules_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_rules_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no rules found
    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_list_rules_command(client, args)
    assert ec == {}
    assert hr == 'No Rules Found'


def test_get_rules():
    """Internal method used in gcb-list-rules command."""
    from GoogleChronicleBackstory import get_rules

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': 'dummy'})

    assert str(e.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '100000'})

    assert str(e.value) == 'Page size should be in the range from 1 to 1000.'

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '-5'})

    assert str(e.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '0'})

    assert str(e.value) == COMMON_RESP['INVALID_PAGE_SIZE']

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'live_rule': 'dummy'})

    assert str(e.value) == 'Live rule should be true or false.'


def test_gcb_list_rules_live_rule_argument_true(client):
    """Test gcb_list_rules command when live_rule argument is true."""
    from GoogleChronicleBackstory import gcb_list_rules_command

    with open("test_data/list_rules_live_rule_true.json") as f:
        response_true = f.read()

    with open("test_data/list_rules_live_rule_true_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = response_true

        def json():
            return json.loads(response_true)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_rules_command(client, args={'live_rule': 'true'})

    assert ec == dummy_ec


def test_gcb_list_rules_live_rule_argument_false(client):
    """Test gcb_list_rules command when live_rule argument is false."""
    from GoogleChronicleBackstory import gcb_list_rules_command

    with open("test_data/list_rules_live_rule_false.json") as f:
        response_false = f.read()

    with open("test_data/list_rules_live_rule_false_ec.json") as f:
        dummy_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = response_false

        def json():
            return json.loads(response_false)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_rules_command(client, args={'live_rule': 'false'})

    assert ec == dummy_ec


def test_gcb_create_rule_command_with_valid_response(client):
    """Test gcb_create_rule command when valid response is returned."""
    from GoogleChronicleBackstory import gcb_create_rule_command

    with open("test_data/create_rule_response.json") as f:
        response = f.read()

    with open("test_data/create_rule_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/create_rule_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {
        "rule_text": """rule demoRuleCreatedFromAPI {
        meta:
        author = \"testuser\"
        description = \"single event rule that should generate detections\"

        events:
        $e.metadata.event_type = \"NETWORK_DNS\"

        condition:
        $e
    }"""
    }

    hr, ec, json_data = gcb_create_rule_command(client, args=args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_create_rule_command_with_invalid_arguments(client):
    """Test gcb_create_rule command when invalid argument provided."""
    from GoogleChronicleBackstory import gcb_create_rule_command

    args = {
        "rule_text": """rule demoRuleCreatedFromAPI {
            meta:
            author = \"testuser\"
            description = \"single event rule that should generate detections\"

            condition:
            $e
        }"""
    }

    with pytest.raises(ValueError) as err:
        gcb_create_rule_command(client, args)

    assert str(err.value) == MESSAGES['INVALID_RULE_TEXT']


def test_gcb_create_rule_command_when_400_error_code_returned(client):
    """Test gcb_create_rule command when 400 error code is returned."""
    from GoogleChronicleBackstory import gcb_create_rule_command

    args = {
        "rule_text": DUMMY_RULE_TEXT
    }

    with open("test_data/create_rule_400_response.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as err:
        gcb_create_rule_command(client, args)

    assert str(
        err.value) == 'Status code: 400\nError: generic::invalid_argument: compiling rule: parsing: error ' \
                      'with token: "events"\nexpected meta\nline: 2 \ncolumn: 9-15 '


def test_gcb_get_rule_command_when_empty_args_given(client):
    """Test gcb_get_rule_command when Rule ID is a string with space."""
    from GoogleChronicleBackstory import gcb_get_rule_command
    with pytest.raises(ValueError) as e:
        gcb_get_rule_command(client, args={'id': ''})
    assert str(e.value) == 'Missing argument id.'


def test_gcb_get_rule_output_when_valid_args_provided(client):
    """Test gcb_get_rule_command when valid args are provided and gives valid output."""
    from GoogleChronicleBackstory import gcb_get_rule_command
    args = {'id': 'dummy rule or version id'}

    with open("test_data/gcb_get_rule_response.json") as f:
        dummy_response = f.read()

    with open("test_data/gcb_get_rule_ec.json") as f:
        dummy_ec = json.loads(f.read())

    with open("test_data/gcb_get_rule_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_get_rule_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr


def test_gcb_get_rule_command_when_rule_id_provided_does_not_exist(client):
    """Test gcb_get_rule_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_get_rule_command
    with open('test_data/gcb_get_rule_invalid_id_400.json') as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_get_rule_command(client, args={'id': '1234'})
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: version ID must be in format ' \
                           '{rule_id} or {rule_id}@v_{version_timestamp.seconds}_{version_timestamp.nanos}'


def test_gcb_delete_rule_command_with_valid_response(client):
    """Test gcb_delete_rule command when valid response is returned."""
    from GoogleChronicleBackstory import gcb_delete_rule_command

    with open("test_data/delete_rule_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/delete_rule_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    args = {
        'rule_id': 'test_rule_id'
    }
    hr, ec, json_data = gcb_delete_rule_command(client, args=args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_delete_rule_command_when_empty_rule_id_provided(client):
    """Test gcb_delete_rule command when empty rule id provided."""
    from GoogleChronicleBackstory import gcb_delete_rule_command

    args = {
        'rule_id': ""
    }

    with pytest.raises(ValueError) as err:
        gcb_delete_rule_command(client, args)

    assert str(err.value) == MESSAGES['REQUIRED_ARGUMENT'].format('rule_id')


def test_gcb_delete_rule_command_when_400_error_code_returned(client):
    """Test gcb_delete_rule command when 400 error code is returned."""
    from GoogleChronicleBackstory import gcb_delete_rule_command

    args = {
        "rule_id": "12345"
    }

    with open("test_data/delete_rule_400_response.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as err:
        gcb_delete_rule_command(client, args)

    assert str(err.value) == 'Status code: 400\nError: generic::invalid_argument: provided rule ID 12345 is not valid'


@pytest.mark.parametrize('args,error_msg', [({"rule_id": "dummy", "rule_text": ""}, "Missing argument rule_text."),
                                            ({"rule_id": "", "rule_text": "dummy"}, "Missing argument rule_id.")])
def test_gcb_create_rule_version_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_create_rule_version_command when empty arguments provided."""
    from GoogleChronicleBackstory import gcb_create_rule_version_command
    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_create_rule_version_command_when_invalid_rule_text_provided(client):
    """Test gcb_create_rule_version_command when rule text provided is not valid."""
    from GoogleChronicleBackstory import gcb_create_rule_version_command
    args = {
        "rule_id": "dummy",
        "rule_text": "1234"
    }
    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == 'Invalid rule text provided. Section "meta", "events" or "condition" is missing.'


def test_gcb_create_rule_version_command_when_provided_rule_id_is_not_valid(client):
    """Test gcb_create_rule_version_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_create_rule_version_command
    with open('test_data/gcb_create_rule_version_command_invalid_id_400.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
        "rule_text": DUMMY_RULE_TEXT
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: provided rule ID dummy is not valid'


def test_gcb_create_rule_version_command_when_valid_args_provided(client):
    """Test gcb_create_rule_version_command for correct output when valid arguments are given."""
    from GoogleChronicleBackstory import gcb_create_rule_version_command
    with open("test_data/gcb_create_rule_version_command_response.json") as f:
        expected_response = f.read()
    with open("test_data/gcb_create_rule_version_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_create_rule_version_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = expected_response

        def json():
            return json.loads(expected_response)

    client.http_client.request.return_value = MockResponse
    args = {
        "rule_id": "dummy rule",
        "rule_text": DUMMY_RULE_TEXT
    }
    hr, ec, json_data = gcb_create_rule_version_command(client, args)
    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize('args,error_msg',
                         [({"rule_id": "dummy", "alerting_status": ""}, "Missing argument alerting_status."),
                          ({"rule_id": "", "alerting_status": "dummy"}, "Missing argument rule_id.")])
def test_gcb_change_rule_alerting_status_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_change_rule_alerting_status_command when empty arguments are provided."""
    from GoogleChronicleBackstory import gcb_change_rule_alerting_status_command
    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_change_rule_alerting_status_command_when_invalid_alerting_status_provided(client):
    """Test gcb_change_rule_alerting_status_command when invalid argument value for alerting_status is provided."""
    from GoogleChronicleBackstory import gcb_change_rule_alerting_status_command
    args = {
        "rule_id": "dummy",
        "alerting_status": "status"
    }
    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == "alerting_status can have one of these values only enable, disable."


def test_gcb_change_rule_alerting_status_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_change_rule_alerting_status_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_change_rule_alerting_status_command
    with open('test_data/gcb_change_rule_alerting_status_command_invalid_id_400.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
        "alerting_status": "enable"
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: provided rule ID dummy is not valid'


def test_gcb_change_rule_alerting_status_command_when_valid_args_provided(client):
    """Test gcb_change_rule_alerting_status_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_change_rule_alerting_status_command

    with open('test_data/gcb_change_rule_alerting_status_ec.json') as f:
        expected_ec = json.loads(f.read())

    with open('test_data/gcb_change_rule_alerting_status_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}
    args = {"rule_id": "ru_ab4d76c1-20d2-4cde-9825-3fb1c09a9b62", "alerting_status": "enable"}
    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_change_rule_alerting_status_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize('args,error_msg',
                         [({"rule_id": "dummy", "live_rule_status": ""}, "Missing argument live_rule_status."),
                          ({"rule_id": "", "live_rule_status": "dummy"}, "Missing argument rule_id.")])
def test_gcb_change_live_rule_status_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_change_live_rule_status_command when empty arguments are provided."""
    from GoogleChronicleBackstory import gcb_change_live_rule_status_command
    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_change_live_rule_status_command_when_invalid_live_rule_status_provided(client):
    """Test gcb_change_live_rule_status_command when invalid argument value for live_rule_status is provided."""
    from GoogleChronicleBackstory import gcb_change_live_rule_status_command
    args = {
        "rule_id": "dummy",
        "live_rule_status": "status"
    }
    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)
    assert str(e.value) == "live_rule_status can have one of these values only enable, disable."


def test_gcb_change_live_rule_status_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_change_live_rule_status_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_change_live_rule_status_command
    with open('test_data/gcb_change_live_rule_status_command_invalid_id_400.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
        "live_rule_status": "enable"
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)

    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: provided rule ID dummy is not valid'


def test_gcb_change_live_rule_status_command_when_valid_args_provided(client):
    """Test gcb_change_live_rule_status_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_change_live_rule_status_command

    with open('test_data/gcb_change_live_rule_status_command_ec.json') as f:
        expected_ec = json.loads(f.read())

    with open('test_data/gcb_change_live_rule_status_command_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}
    args = {"rule_id": "ru_abcd", "live_rule_status": "enable"}
    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_change_live_rule_status_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize('args,error_msg',
                         [({"rule_id": "ru_ab4d76c1-20d2-4cde-9825-3fb1c09a9b62", "start_time": "dummy",
                            "end_time": "today"},
                           'Invalid date: "start_time"="dummy"'),
                          ({"rule_id": "ru_ab4d76c1-20d2-4cde-9825-3fb1c09a9b62", "start_time": "1 day",
                            "end_time": "dummy"},
                           'Invalid date: "end_time"="dummy"'),
                          ({"rule_id": "", "start_time": "1 day", "end_time": "today"}, "Missing argument rule_id.")])
def test_gcb_start_retrohunt_when_invalid_arguments_provided(client, args, error_msg):
    """Test gcb_start_retrohunt_command when invalid arguments are provided."""
    from GoogleChronicleBackstory import gcb_start_retrohunt_command
    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_start_retrohunt_command_when_invalid_rule_id_provided(client):
    """Test gcb_start_retrohunt_command when rule id provided is invalid."""
    from GoogleChronicleBackstory import gcb_start_retrohunt_command
    with open('test_data/gcb_start_retrohunt_command_invalid_id_400.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
        "start_time": "1 day",
        "end_time": "today"
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)

    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: version ID must be in format {rule_id} ' \
                           'or {rule_id}@v_{version_timestamp.seconds}_{version_timestamp.nanos}'


def test_gcb_start_retrohunt_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_start_retrohunt_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_start_retrohunt_command
    with open('test_data/gcb_start_retrohunt_command_id_does_not_exist_404.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
        "start_time": "1 day",
        "end_time": "today"
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)

    assert str(e.value) == 'Status code: 404\nError: generic::not_found: rule with ID ' \
                           'ru_2c66ed52-2920-4f37-b8d2-a7c7787f357b could not be found'


def test_gcb_start_retrohunt_command_when_valid_args_provided(client):
    """Test gcb_start_retrohunt_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_start_retrohunt_command

    with open('test_data/gcb_start_retrohunt_command_ec.json') as f:
        expected_ec = json.loads(f.read())

    with open('test_data/gcb_start_retrohunt_command_hr.md') as f:
        expected_hr = f.read()

    with open('test_data/start_retrohunt_response.json') as f:
        mocked_response = f.read()

    class MockResponse:
        status_code = 200
        text = mocked_response

        def json():
            return json.loads(mocked_response)

    client.http_client.request.return_value = MockResponse
    args = {"rule_id": "ru_abcd", "start_time": "1 day", "end_time": "today"}
    hr, ec, json_data = gcb_start_retrohunt_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize("args, err_msg", [({'id': ''}, "Missing argument id."),
                                           ({'id': 'test', 'retrohunt_id': ''}, "Missing argument retrohunt_id.")])
def test_gcb_get_retrohunt_command_when_empty_args_provided(client, args, err_msg):
    """Test gcb_get_retrohunt command when empty args provided."""
    from GoogleChronicleBackstory import gcb_get_retrohunt_command

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args=args)

    assert str(e.value) == err_msg


def test_gcb_get_retrohunt_command_when_valid_args_provided(client):
    """Test gcb_get_retrohunt_command when valid args are provided and gives valid output."""
    from GoogleChronicleBackstory import gcb_get_retrohunt_command
    args = {'id': 'dummy_rule_or_version_id', 'retrohunt_id': 'dummy_retrohunt_id'}

    with open("test_data/gcb_get_retrohunt_command_response.json") as f:
        dummy_response = f.read()

    with open("test_data/gcb_get_retrohunt_command_ec.json") as f:
        dummy_ec = json.loads(f.read())

    with open("test_data/gcb_get_retrohunt_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_get_retrohunt_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr


def test_gcb_get_retrohunt_command_when_rule_id_provided_is_invalid(client):
    """Test gcb_get_retrohunt_command when rule id provided is invalid."""
    from GoogleChronicleBackstory import gcb_get_retrohunt_command

    with open('test_data/gcb_get_retrohunt_command_invalid_id_400.json') as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={'id': 'test', 'retrohunt_id': 'test'})
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: version ID must be in format ' \
                           '{rule_id} or {rule_id}@v_{version_timestamp.seconds}_{version_timestamp.nanos}'


def test_gcb_get_retrohunt_command_when_retrohunt_id_provided_is_invalid(client):
    """Test gcb_get_retrohunt_command when retrohunt id provided is invalid."""
    from GoogleChronicleBackstory import gcb_get_retrohunt_command

    with open('test_data/gcb_get_retrohunt_command_invalid_retrohunt_id_400.json') as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={'id': 'test', 'retrohunt_id': 'test'})
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: provided retrohunt ID test is not valid'


def test_gcb_get_retrohunt_command_when_retrohunt_id_provided_does_not_exists(client):
    """Test gcb_get_retrohunt_command when retrohunt id provided does not exists."""
    from GoogleChronicleBackstory import gcb_get_retrohunt_command

    with open('test_data/gcb_get_retrohunt_command_invalid_retrohunt_id_404.json') as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={'id': 'test', 'retrohunt_id': 'oh_54c2f72b-7527-4f51-8d28-adb30d2d0'})
    assert str(e.value) == 'Status code: 404\nError: generic::not_found: retrohunt not found with ID ' \
                           'oh_54c2f72b-7527-4f51-8d28-adb30d2d0'


arg_error = [({'page_size': '-20'}, COMMON_RESP['INVALID_PAGE_SIZE']),
             ({'page_size': '20000'}, 'Page size should be in the range from 1 to 1000.'),
             ({'retrohunts_for_all_versions': 'dummy'}, 'Argument does not contain a valid boolean-like value'),
             ({'retrohunts_for_all_versions': 'True', 'id': 'abc@xyz'},
              "Invalid value in argument 'id'. Expected rule_id.")]


@pytest.mark.parametrize('args,error_msg', arg_error)
def test_gcb_list_retrohunts_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_list_retrohunts_command when invalid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_list_retrohunts_command_when_empty_response_is_obtained(client):
    """Test gcb_list_retrohunts_command when empty response is obtained for a rule."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    args = {
        "id": "dummy",
    }

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_retrohunts_command(client, args)
    assert hr == '## RetroHunt Details\nNo Records Found.'
    assert ec == {}


def test_gcb_list_retrohunts_command_when_retrohunts_for_all_versions_is_set_true(client):
    """Test gcb_list_retrohunts_command when retrohunts_for_all_versions is true and rule_id is provided."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with open('test_data/gcb_list_retrohunts_all_versions_true.json') as f:
        response_false = f.read()
    with open('test_data/gcb_list_retrohunts_all_versions_true_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_retrohunts_all_versions_true_hr.md') as f:
        expected_hr = f.read()
    args = {
        "id": "dummy",
        "gcb_list_retrohunts_command": "true"
    }

    class MockResponse:
        status_code = 200
        text = response_false

        def json():
            return json.loads(response_false)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_retrohunts_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test__gcb_list_retrohunts_command_when_retrohunts_for_all_versions_is_set_false(client):
    """Test gcb_list_retrohunts_command when retrohunts_for_all_versions is false and rule_id is provided."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with open('test_data/gcb_list_retrohunts_all_versions_false.json') as f:
        response_true = f.read()
    with open('test_data/gcb_list_retrohunts_all_versions_false_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_retrohunts_all_versions_false_hr.md') as f:
        expected_hr = f.read()
    args = {
        "id": "dummy",
        "gcb_list_retrohunts_command": "false"
    }

    class MockResponse:
        status_code = 200
        text = response_true

        def json():
            return json.loads(response_true)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_retrohunts_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_retrohunts_command_when_no_arg_supplied_success(client):
    """Test gcb_list_retrohunts_command when no argumnets are provided."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with open('test_data/gcb_list_retrohunts_no_arg.json') as f:
        response = f.read()
    with open('test_data/gcb_list_retrohunts_no_arg_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_retrohunts_no_arg_hr.md') as f:
        expected_hr = f.read()
    args = {}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_retrohunts_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_retrohunts_command_when_provided_rule_id_is_not_valid(client):
    """Test gcb_list_retrohunts_command when rule id provided is not valid."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with open('test_data/gcb_list_retrohunts_command_invalid_id_400.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(
        e.value) == 'Status code: 400\nError: generic::invalid_argument: invalid wildcard version ID: invalid ' \
                    'rule_id: invalid rule_id ru_f04b9ef9-bd49, must be either a user rule_id or an uppercase rule_id'


def test_gcb_list_retrohunts_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_list_retrohunts_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_list_retrohunts_command
    with open('test_data/gcb_list_retrohunts_command_id_does_not_exist_404.json') as f:
        raw_response = f.read()
    args = {
        "rule_id": "ru_f04b9ef9-bd49-4431-ae07-eb77bd3d00c9",
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(
        e.value) == 'Status code: 404\nError: generic::not_found: rule with ' \
                    'ID ru_f04b9ef9-bd49-4431-ae07-eb77bd3d00c9 could not be found'


@pytest.mark.parametrize('args, error_msg', [({"id": "", "retrohunt_id": "dummy"}, 'Missing argument id.'),
                                             ({"id": "dummy", "retrohunt_id": ""}, 'Missing argument retrohunt_id.')])
def test_gcb_cancel_retrohunt_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_cancel_retrohunt_command when arguments provided are empty."""
    from GoogleChronicleBackstory import gcb_cancel_retrohunt_command
    with pytest.raises(ValueError) as e:
        gcb_cancel_retrohunt_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_cancel_retrohunt_command_when_valid_args_are_provided(client):
    """Test gcb_cancel_retrohunt_command for valid output when valid args are provided."""
    from GoogleChronicleBackstory import gcb_cancel_retrohunt_command

    with open('test_data/gcb_cancel_retrohunt_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_cancel_retrohunt_hr.md') as f:
        expected_hr = f.read()
    args = {"id": "dummy_id", "retrohunt_id": "dummy_retrohunt_id"}

    class MockResponse:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_cancel_retrohunt_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_cancel_retrohunt_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_list_retrohunts_command when rule id provided does not exist."""
    from GoogleChronicleBackstory import gcb_cancel_retrohunt_command
    with open('test_data/gcb_cancel_retrohunt_id_does_not_exist_404.json') as f:
        raw_response = f.read()
    args = {
        "id": "dummy",
        "retrohunt_id": "dummy"
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_cancel_retrohunt_command(client, args)
    assert str(e.value) == 'Status code: 404\nError: generic::not_found: retrohunt with ID ' \
                           'oh_bd93f3a6-e832-48df-a343-59dd7231273b does not belong to ' \
                           'rule ID ru_f04b9ef9-bd49-4431-ae07-eb77bd3d00c7. Provide the correct rule ID'


def test_gcb_cancel_retrohunt_command_when_provided_retrohunt_id_is_not_in_running_state(client):
    """Test gcb_list_retrohunts_command when retrohunt provided is already DONE or CANCELLED."""
    from GoogleChronicleBackstory import gcb_cancel_retrohunt_command
    with open('test_data/gcb_cancel_retrohunt_id_does_not_exist_400.json') as f:
        raw_response = f.read()
    args = {
        "id": "dummy",
        "retrohunt_id": "dummy"
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_cancel_retrohunt_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::failed_precondition: cannot transition retrohunt status' \
                           ' from CANCELLED to CANCELLED'


arg_error = [
    ({"name": "", "description": "dummy", "lines": "l1,l2"}, 'Missing argument name.'),
    ({"name": "dummy_name", "description": "", "lines": "l1,l2"}, 'Missing argument description.'),
    ({"name": "dummy_name", "description": "dummy", "lines": ""}, 'Missing argument lines.'),
    ({"name": "dummy_name", "description": "dummy", "lines": "[]"}, 'Missing argument lines.'),
    ({"name": "dummy_name", "description": "dummy", "lines": ", ,"}, 'Missing argument lines.'),
    ({"name": "dummy_name", "description": "dummy", "lines": "l1,l2", "content_type": "type"},
     MESSAGES['VALIDATE_SINGLE_SELECT'].format('content_type', ', '.join(VALID_CONTENT_TYPE)))
]


@pytest.mark.parametrize('args,error_msg', arg_error)
def test_gcb_create_reference_list_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_create_reference_list comamnd when empty arguments are provided."""
    from GoogleChronicleBackstory import gcb_create_reference_list_command
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_create_reference_list_command_when_valid_args_provided(client):
    """Test gcb_create_reference_list command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_create_reference_list_command
    args = {
        "name": "dummy_name",
        "description": "dummy_description",
        "lines": "L1,L2,L3,L4"
    }
    with open('test_data/gcb_create_reference_list_response.json') as f:
        response = f.read()
    with open('test_data/gcb_create_reference_list_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_create_reference_list_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_create_reference_list_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_create_reference_list_command_when_delimiter_provided(client):
    """Test gcb_create_reference_list command for valid output when delimiter is provided."""
    from GoogleChronicleBackstory import gcb_create_reference_list_command
    args = {
        "name": "dummy_name",
        "description": "dummy_description",
        "lines": "L1:L2:L3:L4",
        "delimiter": ":"
    }
    with open('test_data/gcb_create_reference_list_response.json') as f:
        response = f.read()
    with open('test_data/gcb_create_reference_list_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_create_reference_list_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_create_reference_list_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_create_reference_list_command_when_list_already_exists(client):
    """Test gcb_create_reference_list command when a list with same name already exists."""
    from GoogleChronicleBackstory import gcb_create_reference_list_command
    args = {
        "name": "dummy_name",
        "description": "dummy_description",
        "lines": "dummy"
    }
    with open('test_data/gcb_create_reference_list_400.json') as f:
        response = f.read()

    class MockResponse:
        status_code = 409
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == 'Status code: 409\nError: generic::already_exists: list with name' \
                           ' demo_list14_created_from_api already exists'


def test_gcb_create_reference_list_command_when_invalid_lines_content_provided(client):
    """Test gcb_create_reference_list command when invalid lines content is provided accordingly to the content_type."""
    from GoogleChronicleBackstory import gcb_create_reference_list_command
    args = {
        "name": "dummy_name",
        "description": "dummy_description",
        "lines": "dummy_lines",
        "content_type": "CIDR"
    }
    with open('test_data/gcb_create_reference_list_invalid_lines_content_400.json') as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: validating parsed content: '\
        'invalid cidr pattern dummy_lines'


arg_error = [({'page_size': '-20'}, 'Page size must be a non-zero and positive numeric value'),
             ({'page_size': '20000'}, 'Page size should be in the range from 1 to 1000.'),
             ({'page_size': '10', 'view': 'dummy'}, 'view can have one of these values only BASIC, FULL.')]


@pytest.mark.parametrize('args,error_msg', arg_error)
def test_gcb_list_reference_list_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb-list-reference-list-command when invalid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_reference_list_command
    with pytest.raises(ValueError) as e:
        gcb_list_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_list_reference_list_command_when_invalid_page_token_provided(client):
    """Test gcb-list-reference-list-command when invalid page-token is provided."""
    from GoogleChronicleBackstory import gcb_list_reference_list_command
    with open('test_data/gcb_list_reference_lists_command_invalid_token_400.json') as f:
        raw_response = f.read()
    args = {
        "page_size": "3",
        "page_token": "abcd"
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_reference_list_command(client, args)
    assert str(
        e.value) == 'Status code: 400\nError: generic::invalid_argument: page token is not valid'


def test_gcb_list_reference_list_command_when_valid_args_provided(client):
    """Test gcb-list-reference-list-command when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_reference_list_command
    with open('test_data/gcb_list_reference_list_valid_args.json') as f:
        response = f.read()
    with open('test_data/gcb_list_reference_list_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_reference_list_hr.md') as f:
        expected_hr = f.read()
    args = {
        "page_size": "3",
        "view": "BASIC"
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize('args,error_msg', [({"name": "", "view": "FULL"}, 'Missing argument name.'),
                                            ({"name": "dummy", "view": "dummy"},
                                             'view can have one of these values only FULL, BASIC.')])
def test_gcb_get_reference_list_command_when_invalid_args_are_provided(client, args, error_msg):
    """Test gcb_get_reference_list_command when arguments provided are invalid."""
    from GoogleChronicleBackstory import gcb_get_reference_list_command
    with pytest.raises(ValueError) as e:
        gcb_get_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_get_reference_list_command_when_provided_list_name_does_not_exist(client):
    """Test gcb_get_reference_list_command when list name provided does not exists."""
    from GoogleChronicleBackstory import gcb_get_reference_list_command
    with open('test_data/gcb_get_reference_lists_command_list_name_not_found_404.json') as f:
        raw_response = f.read()
    args = {
        "name": "dummy",
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_get_reference_list_command(client, args)
    assert str(e.value) == 'Status code: 404\nError: generic::not_found: list with name dummy not found'


def test_gcb_get_reference_list_command_when_valid_arguments_provided(client):
    """Test gcb_get_reference_list_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_get_reference_list_command
    with open('test_data/gcb_get_reference_list_valid_args.json') as f:
        response = f.read()
    with open('test_data/gcb_get_reference_list_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_get_reference_list_hr.md') as f:
        expected_hr = f.read()
    args = {
        "name": "dummy",
        "view": "FULL"
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_get_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize('args,error_msg',
                         [({"name": "dummy", "lines": ""}, "Missing argument lines."),
                          ({"name": "dummy_name", "lines": "[]"}, 'Missing argument lines.'),
                          ({"name": "dummy_name", "lines": ", ,"}, 'Missing argument lines.'),
                          ({"name": "", "lines": "dummy"}, "Missing argument name."),
                          ({"name": "x", "lines": "y", "content_type": "type"},
                           MESSAGES['VALIDATE_SINGLE_SELECT'].format('content_type', ', '.join(VALID_CONTENT_TYPE)))])
def test_gcb_update_reference_list_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_update_reference_list command when provided args are empty."""
    from GoogleChronicleBackstory import gcb_update_reference_list_command
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_update_reference_list_command_when_valid_args_provided(client):
    """Test gcb_update_reference_list command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_update_reference_list_command
    args = {"name": "dummy", "lines": "L1;L2;L3", "description": "dummy_description", "delimiter": ";"}
    with open("test_data/gcb_update_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_update_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_update_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_update_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_update_reference_list_command_when_valid_args_provided_without_content_type(client):
    """Test gcb_update_reference_list command for valid output when valid arguments without content_type are provided."""
    from GoogleChronicleBackstory import gcb_update_reference_list_command
    args = {"name": "dummy", "lines": "L1;L2;L3", "description": "dummy_description", "delimiter": ";"}
    with open("test_data/gcb_update_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_update_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_update_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse1:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    class MockResponse2:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    # The first call is to get the reference list and the second call is to update the reference list
    client.http_client.request.side_effect = [MockResponse1(), MockResponse2()]
    MockResponse1.json = lambda _: json.loads(response)
    MockResponse2.json = lambda _: json.loads(response)
    hr, ec, json_data = gcb_update_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_update_reference_list_command_when_name_prided_does_not_exists(client):
    """Test gcb_update_reference_list command when name provided does not exist."""
    from GoogleChronicleBackstory import gcb_update_reference_list_command
    args = {"name": "dummy", "lines": "L1,L2,L3", "description": "dummy_description"}
    with open("test_data/gcb_update_reference_list_command_response_404.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 404
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == 'Status code: 404\nError: generic::not_found: expected list with name dummy to ' \
                           'already exist, but it does not exist'


def test_gcb_update_reference_list_command_when_invalid_lines_content_provided(client):
    """Test gcb_update_reference_list command when invalid lines content is provided accordingly to the content_type."""
    from GoogleChronicleBackstory import gcb_update_reference_list_command
    args = {
        "name": "dummy_name",
        "description": "dummy_description",
        "lines": "dummy_lines",
        "content_type": "Regex"
    }
    with open('test_data/gcb_update_reference_list_invalid_lines_content_400.json') as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: validating parsed content: '\
        'invalid regex pattern dummy_lines'


@pytest.mark.parametrize('args,error_msg',
                         [({"lines": ""}, "Missing argument lines."),
                          ({"lines": "[]"}, "Missing argument lines."),
                          ({"lines": ",,"}, "Missing argument lines."),
                          ({"lines": "L1", "content_type": "type"}, MESSAGES['VALIDATE_SINGLE_SELECT'].format(
                              'content_type', ', '.join(VALID_CONTENT_TYPE)))])
def test_gcb_verify_reference_list_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_verify_reference_list command when provided args are invalid."""
    from GoogleChronicleBackstory import gcb_verify_reference_list_command
    with pytest.raises(ValueError) as e:
        gcb_verify_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_verify_reference_list_command_when_valid_args_provided(client):
    """Test gcb_verify_reference_list command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_verify_reference_list_command
    args = {"lines": "L1;0.0.0.1/1;L3", "content_type": "CIDR", "delimiter": ";"}
    with open("test_data/gcb_verify_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_verify_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_verify_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_verify_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_verify_reference_list_command_when_lines_content_are_valid(client):
    """Test gcb_verify_reference_list command for valid output when valid lines_content are provided."""
    from GoogleChronicleBackstory import gcb_verify_reference_list_command
    args = {"lines": "L1;0.0.0.1/1;L3", "content_type": "PLAIN_TEXT", "delimiter": ";"}
    with open("test_data/gcb_verify_reference_list_command_all_valid_lines_response.json") as f:
        response = f.read()
    with open("test_data/gcb_verify_reference_list_command_all_valid_lines_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_verify_reference_list_command_all_valid_lines_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_verify_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize('args,error_msg',
                         [({"rule_text": "meta events condition", "start_time": "dummy"},
                           'Invalid date: "start_time"="dummy"'),
                          ({"rule_text": "meta events condition", "start_time": "1 day ago", "end_time": "dummy"},
                           'Invalid date: "end_time"="dummy"'),
                          ({"rule_text": "meta events condition", "start_time": "1 day ago", "end_time": "1 day ago",
                            "max_results": 0}, 'Max Results should be in the range 1 to 10000.'),
                          ({"rule_text": "meta events condition", "start_time": "1 day ago", "end_time": "1 day ago",
                            "max_results": "asd"}, '"asd" is not a valid number'),
                          ({"rule_text": "meta events", "start_time": "1 day ago", "end_time": "1 day ago",
                            "max_results": "3"},
                           'Invalid rule text provided. Section "meta", "events" or "condition" is missing.')])
def test_gcb_test_rule_stream_command_invalid_args(client, args, error_msg):
    """Test gcb_test_rule_stream_command when invalid args are provided."""
    from GoogleChronicleBackstory import gcb_test_rule_stream_command
    with pytest.raises(ValueError) as e:
        gcb_test_rule_stream_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_test_rule_stream_command_valid_args(client):
    """Test gcb_test_rule_stream_command for valid response when valid args are provided."""
    from GoogleChronicleBackstory import gcb_test_rule_stream_command

    args = {
        "rule_text": """rule demoRuleCreatedFromAPIVersion2 {
                            meta:
                            author = \"securityuser2\"
                            description = \"double event rule that should generate detections\"

                            events:
                            $e.metadata.event_type = \"NETWORK_DNS\"

                            condition:
                            $e
                        }""",
        "start_time": "2 day ago",
        "end_time": "1 day ago",
        "max_results": "2"
    }
    with open("test_data/gcb_test_rule_stream_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_test_rule_stream_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_test_rule_stream_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_test_rule_stream_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_test_rule_stream_command_invalid_rule_text_provided(client):
    """Test gcb_test_rule_stream_command when invalid rule text is provided."""
    from GoogleChronicleBackstory import gcb_test_rule_stream_command
    args = {
        "rule_text": """rule demoRuleCreatedFromAPIVersion2 {
                                    meta:
                                    author = "Crest Data Systems"
                                    severity = "Medium"

                                    events:
                                    $event1.metadata.event_type = "PROCESS_LAUNCH"
                                    $full_path = /.*cmd\\.exe$/ nocase

                                    $event1.principal.hostname = $hostname
                                    $event2.principal.hostname = $hostname

                                    not $event1.principal.process.file.full_path = /.*explorer\\.exe$/ nocase
                                    $event1.target.process.file.full_path = $full_path

                                    $event2.principal.process.file.full_path = $full_path
                                    $event2.target.process.file.full_path = /.*reg\\.exe$/ nocase

                                  match:
                                    $full_path over 5m

                                  condition:
                                    $event1 and $event2 and $full_path
                                }""",
        "start_time": "2 day ago",
        "end_time": "1 day ago",
        "max_results": "2"
    }
    with open("test_data/gcb_test_rule_stream_command_400.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_test_rule_stream_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: generic::invalid_argument: compiling rule: : variable full_path' \
                           ' used in both condition section and match section, should only be used in one\nline: 23 \n' \
                           'column: 30-39 '


@pytest.mark.parametrize('args,error_msg',
                         [({"asset_identifier_type": "Host Name", "asset_identifier": ""},
                           MESSAGES['REQUIRED_ARGUMENT'].format('asset_identifier')),
                          ({"asset_identifier_type": "invalid_type", "asset_identifier": "example.com"},
                           MESSAGES['VALIDATE_SINGLE_SELECT'].format(
                               'asset_identifier_type', ASSET_IDENTIFIER_NAME_DICT.keys())),
                          ({"asset_identifier_type": "Host Name", "asset_identifier": "example.com",
                            "start_time": "invalid_time"}, 'Invalid date: "start_time"="invalid_time"'),
                          ({"asset_identifier_type": "Host Name", "asset_identifier": "example.com",
                            "end_time": "invalid_time"}, 'Invalid date: "end_time"="invalid_time"'),
                          ({"asset_identifier_type": "Host Name", "asset_identifier": "example.com",
                            "page_size": "invalid_size"}, "Page size must be a non-zero and positive numeric value"),
                          ({"asset_identifier_type": "Host Name", "asset_identifier": "example.com",
                            "page_size": "-1"}, "Page size must be a non-zero and positive numeric value")])
def test_gcb_asset_aliases_list_command_invalid_args(client, args, error_msg):
    """Test gcb_list_asset_aliases_command when invalid args are provided."""
    from GoogleChronicleBackstory import gcb_list_asset_aliases_command
    with pytest.raises(ValueError) as e:
        gcb_list_asset_aliases_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_asset_aliases_list_command_when_valid_arguments_provided(client):
    """Test gcb_list_asset_aliases_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_asset_aliases_command
    with open('test_data/gcb_list_asset_aliases_response.json') as f:
        response = f.read()
    with open('test_data/gcb_list_asset_aliases_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_asset_aliases_hr.md') as f:
        expected_hr = f.read()
    args = {
        "asset_identifier_type": "Host Name",
        "asset_identifier": "example.com"
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_asset_aliases_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_asset_aliases_list_command_when_response_contains_single_alias(client):
    """Test gcb_list_asset_aliases_command when response contains single asset alias."""
    from GoogleChronicleBackstory import gcb_list_asset_aliases_command
    with open('test_data/gcb_list_asset_aliases_response_with_single_alias.json') as f:
        response = f.read()

    with open('test_data/gcb_list_asset_aliases_ec_with_single_alias.json') as f:
        expected_ec = json.loads(f.read())

    args = {
        "asset_identifier_type": "Host Name",
        "asset_identifier": "example.com"
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_asset_aliases_command(client, args)
    assert hr == MESSAGES['EMPTY_ASSET_ALIASES'].format(args.get('asset_identifier'))
    assert ec == expected_ec


@pytest.mark.parametrize('args,error_msg',
                         [({"page_size": "-1"}, "Page size must be a non-zero and positive numeric value"),
                          ({"page_size": "1001"}, MESSAGES["INVALID_PAGE_SIZE"].format('1000'))])
def test_gcb_curated_rules_list_command_invalid_args(client, args, error_msg):
    """Test gcb_list_curated_rules_command when invalid args are provided."""
    from GoogleChronicleBackstory import gcb_list_curated_rules_command
    with pytest.raises(ValueError) as e:
        gcb_list_curated_rules_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_curated_rules_list_command_when_valid_arguments_provided(client):
    """Test gcb_list_curated_rules_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_curated_rules_command
    with open('test_data/gcb_list_curated_rules_response.json') as f:
        response = f.read()
    with open('test_data/gcb_list_curated_rules_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_curated_rules_hr.md') as f:
        expected_hr = f.read()
    args = {
        "page_size": '2'
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_curated_rules_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize('args,error_msg',
                         [({"user_identifier_type": "Email", "user_identifier": ""},
                           MESSAGES['REQUIRED_ARGUMENT'].format('user_identifier')),
                          ({"user_identifier_type": "invalid_type", "user_identifier": "xyz@example.com"},
                           MESSAGES['VALIDATE_SINGLE_SELECT'].format(
                               'user_identifier_type', USER_IDENTIFIER_NAME_DICT.keys())),
                          ({"user_identifier_type": "Email", "user_identifier": "xyz@example.com",
                            "start_time": "invalid_time"}, 'Invalid date: "start_time"="invalid_time"'),
                          ({"user_identifier_type": "Email", "user_identifier": "xyz@example.com",
                            "end_time": "invalid_time"}, 'Invalid date: "end_time"="invalid_time"'),
                          ({"user_identifier_type": "Email", "user_identifier": "xyz@example.com",
                            "page_size": "invalid_size"}, "Page size must be a non-zero and positive numeric value"),
                          ({"user_identifier_type": "Email", "user_identifier": "xyz@example.com",
                            "page_size": "-1"}, "Page size must be a non-zero and positive numeric value")])
def test_gcb_user_aliases_list_command_invalid_args(client, args, error_msg):
    """Test gcb_list_user_aliases_command when invalid args are provided."""
    from GoogleChronicleBackstory import gcb_list_user_aliases_command
    with pytest.raises(ValueError) as e:
        gcb_list_user_aliases_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_user_aliases_list_command_when_valid_arguments_provided(client):
    """Test gcb_list_user_aliases_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_list_user_aliases_command
    with open('test_data/gcb_list_user_aliases_response.json') as f:
        response = f.read()
    with open('test_data/gcb_list_user_aliases_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_list_user_aliases_hr.md') as f:
        expected_hr = f.read()
    args = {
        "user_identifier_type": "Email",
        "user_identifier": "xyz@example.com"
    }

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_user_aliases_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_verify_value_in_reference_list_command_success(client):
    """ Test gcb_verify_value_in_reference_list_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_verify_value_in_reference_list_command
    with open('test_data/gcb_verify_value_in_reference_list_command_response.json') as f:
        response = json.loads(f.read())
    with open('test_data/gcb_verify_value_in_reference_list_command_ec.json') as f:
        expected_ec = json.loads(f.read())
    with open('test_data/gcb_verify_value_in_reference_list_command_hr.md') as f:
        expected_hr = f.read()

    args = {
        'reference_list_names': 'list1,list2,list3, ',
        'values': 'value1,Value2,value4,value1,[-\\{\\}\\^],0.0.0.1/0',
        'add_not_found_reference_lists': 'true',
        'case_insensitive_search': 'true'
    }
    with mock.patch('GoogleChronicleBackstory.gcb_get_reference_list') as mock_gcb_get_reference_list:
        mock_gcb_get_reference_list.side_effect = [
            ({}, {'lines': ['value1', 'value2', '0.0.0.1/0']}),
            ({}, {'lines': ['value3', '[-\\{\\}\\^]']}),
            Exception('Error: Status code: 404\n Error: generic::not_found: list with name xyz not found')
        ]
        with mock.patch('GoogleChronicleBackstory.return_warning') as mock_return:
            hr, ec, data = gcb_verify_value_in_reference_list_command(client, args)
            assert mock_return.call_args[0][0] == 'The following Reference lists were not found: list3'
        assert data == response
        assert ec == expected_ec
        assert hr == expected_hr


@pytest.mark.parametrize('args,error_msg',
                         [({'reference_list_names': ' , , ', 'values': 'value1'},
                           MESSAGES['REQUIRED_ARGUMENT'].format('reference_list_names')),
                          ({'reference_list_names': 'list1', 'values': '   ,   ,  '},
                           MESSAGES['REQUIRED_ARGUMENT'].format('values'))])
def test_gcb_verify_value_in_reference_list_command_invalid_args(client, capfd, args, error_msg):
    """Test gcb_verify_value_in_reference_list_command when invalid arguments are provided."""
    from GoogleChronicleBackstory import gcb_verify_value_in_reference_list_command

    with pytest.raises(ValueError) as e:
        with capfd.disabled():
            gcb_verify_value_in_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_verify_value_in_reference_list_command_system_exit(capfd, client):
    """Test gcb_verify_value_in_reference_list_command when all reference lists are not found."""
    from GoogleChronicleBackstory import gcb_verify_value_in_reference_list_command

    args = {
        'reference_list_names': 'list1,list2,list3',
        'values': 'value1,Value2,value4',
        'case_insensitive_search': 'true'
    }
    with mock.patch('GoogleChronicleBackstory.gcb_get_reference_list') as mock_gcb_get_reference_list:
        mock_gcb_get_reference_list.side_effect = [
            Exception('Error: Status code: 404\n Error: generic::not_found: list with name list1 not found'),
            Exception('Error: Status code: 404\n Error: generic::not_found: list with name list2 not found'),
            Exception('Error: Status code: 404\n Error: generic::not_found: list with name list3 not found')
        ]
        with capfd.disabled():
            with pytest.raises(SystemExit) as err:
                gcb_verify_value_in_reference_list_command(client, args)

        assert err.value.code == 0


def test_gcb_verify_rule_command_with_valid_response(client):
    """Test gcb_verify_rule command when valid response is returned."""
    from GoogleChronicleBackstory import gcb_verify_rule_command

    with open('test_data/gcb_verify_rule_response.json') as f:
        response = f.read()

    with open('test_data/gcb_verify_rule_ec.json') as f:
        expected_ec = json.loads(f.read())

    with open('test_data/gcb_verify_rule_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {
        'rule_text': """rule singleEventRule2 {
        meta:
        author = \"testuser\"
        description = \"single event rule that should generate detections\"

        events:
        $e.metadata.event_type = \"NETWORK_DNS\"

        condition:
        $e
    }"""
    }

    hr, ec, json_data = gcb_verify_rule_command(client, args=args)

    assert json.loads(response) == json_data
    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize('args,error_msg', [
    ({'rule_text': """rule demoRuleCreatedFromAPI { meta: author = \"testuser\" description = \"single
      event rule that should generate detections\" condition:$e }"""}, MESSAGES['INVALID_RULE_TEXT']),
    ({'rule_text': ''}, MESSAGES['REQUIRED_ARGUMENT'].format('rule_text'))])
def test_gcb_verify_rule_command_with_invalid_arguments(client, args, error_msg, capfd):
    """Test gcb_verify_rule command when invalid argument provided."""
    from GoogleChronicleBackstory import gcb_verify_rule_command

    with pytest.raises(ValueError) as err:
        with capfd.disabled():
            gcb_verify_rule_command(client, args)

    assert str(err.value) == error_msg


def test_gcb_verify_rule_command_when_rule_text_invalid_yaral_format(client):
    """Test gcb_create_rule command when rule text has invalid YARA-L format."""
    from GoogleChronicleBackstory import gcb_verify_rule_command

    args = {
        'rule_text': DUMMY_RULE_TEXT
    }

    with open('test_data/gcb_verify_rule_invalid_format_response.json') as f:
        response = f.read()

    with open('test_data/gcb_verify_rule_invalid_format_ec.json') as f:
        expected_ec = json.loads(f.read())

    with open('test_data/gcb_verify_rule_invalid_format_hr.md') as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_verify_rule_command(client, args=args)

    assert json.loads(response) == json_data
    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_get_event_command_success(client):
    """ Test gcb_get_event_command for valid output when valid arguments are provided."""
    from GoogleChronicleBackstory import gcb_get_event_command

    with open('test_data/get_event_response.json') as f:
        dummy_response = f.read()

    with open('test_data/get_event_ec.json') as f:
        dummy_ec = json.load(f)

    with open('test_data/get_event_hr.md') as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_get_event_command(client, {'event_id': 'dummy_id'})

    event = 'GoogleChronicleBackstory.Events(val.id == obj.id)'
    assert ec[event] == dummy_ec[event]
    assert hr == dummy_hr

    class MockResponseEmpty:
        status_code = 200
        text = '{}'

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, json_data = gcb_get_event_command(client, {'event_id': 'dummy_id'})

    assert ec[event] == [{}]
    assert json_data == {}
    assert hr == ''


def test_gcb_get_event_command_invalid_args(client, capfd):
    """Test gcb_get_event_command when invalid arguments are provided."""
    from GoogleChronicleBackstory import gcb_get_event_command
    with pytest.raises(ValueError) as e:
        with capfd.disabled():
            gcb_get_event_command(client, {'event_id': ""})
    assert str(e.value) == MESSAGES['REQUIRED_ARGUMENT'].format('event_id')


def test_gcb_get_event_command_invalid_event_id(client, capfd):
    """Test gcb_get_event_command when the given event_id is invalid."""
    from GoogleChronicleBackstory import gcb_get_event_command

    with open('test_data/gcb_get_event_command_invalid_event_id_400.json') as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        with capfd.disabled():
            gcb_get_event_command(client, {'event_id': 'invalid_event_id'})

    error_m = 'Status code: 400\nError: Invalid value at \'name\' (TYPE_BYTES), Base64 decoding failed for "invalid_event_id"'
    assert str(e.value) == error_m

import json
from unittest import mock

import pytest
from httplib2 import Response

import demistomock as demisto

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
    'override_confidence_score_suspicious_threshold': '40'
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

invalid_start_time_error_message = 'Invalid start time. Some supported formats are ISO date format and relative time. ' \
                                   'e.g. 2019-10-17T00:00:00Z, 3 days'

invalid_end_time_error_message = 'Invalid end time. Some supported formats are ISO date format and relative time. ' \
                                 'e.g. 2019-10-17T00:00:00Z, 3 days'


@pytest.fixture
def client():
    mocked_client = mock.Mock()
    mocked_client.region = "General"
    return mocked_client


def return_error(error):
    raise ValueError(error)


def test_gcb_list_ioc_success(client):
    """
    When valid response comes in gcb-list-iocs command it should respond with result.
    """
    from GoogleChronicleBackstory import gcb_list_iocs_command
    with open("test_data/list_ioc_response.txt", "rb") as f:
        dummy_response = f.read()
    with open("test_data/list_ioc_ec.json") as f:
        dummy_ec = json.load(f)

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_iocs_command(client, {})
    assert ec["Domain(val.Name && val.Name == obj.Name)"] == dummy_ec["Domain(val.Name && val.Name == obj.Name)"]
    key = "GoogleChronicleBackstory.Iocs(val.Artifact && val.Artifact == obj.Artifact)"
    assert ec[key] == dummy_ec[key]


def test_gcb_list_ioc_failure_response(client):
    """
    When response not come with invalid response come in gcb-list-iocs command then it should raise ValueError
    'Failed to parse response.'
    """
    from GoogleChronicleBackstory import gcb_list_iocs_command
    with open("test_data/list_ioc_response.txt", "rb") as f:
        dummy_response = f.read()

    mock_response = (
        Response(dict(status=200)),
        dummy_response + b'}'
    )

    client.http_client.request.return_value = mock_response
    with pytest.raises(ValueError) as error:
        gcb_list_iocs_command(client, {})
    assert str(error.value) == 'Invalid response format while making API call to Chronicle. Response not in JSON format'


def test_gcb_list_ioc_failure_response_400(client, mocker):
    """
    When status code 400 occurred in gcb-list-iocs command it should raise ValueError 'page not found'.
    """
    from GoogleChronicleBackstory import gcb_list_iocs_command

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)

    mock_response = (
        Response(dict(status=400)),
        b'{"error": { "code": 400, "message": "page not found", "status": "INVALID_ARGUMENT" } }'
    )

    client.http_client.request.return_value = mock_response
    with pytest.raises(ValueError) as error:
        gcb_list_iocs_command(client, {})
    assert str(error.value) == 'Status code: 400\nError: page not found'


def test_gcb_ioc_details_command_success(client):
    """
    When command execute successfully then it should prepare valid hr, ec
    """
    from GoogleChronicleBackstory import gcb_ioc_details_command

    with open("test_data/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("test_data/gcb_ioc_details_command_ec.json", "r") as f:
        dummy_ec = json.load(f)

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = gcb_ioc_details_command(client, ARGS)

    assert ec['IP(val.Address && val.Address == obj.Address)'] == dummy_ec[
        'IP(val.Address && val.Address == obj.Address)']

    key = 'GoogleChronicleBackstory.IocDetails(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_gcb_ioc_details_command_empty_response(client):
    """
    When there is an empty response the command should response empty ec and valid text in hr
    """
    from GoogleChronicleBackstory import gcb_ioc_details_command
    expected_hr = '### For artifact: {}\n'.format(ARGS['artifact_value'])
    expected_hr += 'No Records Found'

    dummy_response = '{}'
    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = gcb_ioc_details_command(client, ARGS)

    assert hr == expected_hr


def test_gcb_ioc_details_command_failure(client, mocker):
    """
    When there is a invalid response then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import gcb_ioc_details_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.ip_address\': Cannot bind query parameter. Field \'ip_address\' could not be found" \
                     " in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    mock_response = (
        Response(dict(status=400)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        gcb_ioc_details_command(client, ARGS)
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.ip_address\':" \
                       " Cannot bind query parameter. Field \'ip_address\' could not be found in request message."
    assert str(error.value) == expected_message


def test_gcb_ioc_details_command_failure_permission_denied(client, mocker):
    """
    When there is a response for permission denied then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import gcb_ioc_details_command

    dummy_response = "{ \"error\": { \"code\": 403, \"message\": \"Permission denied\" \
                     , \"status\": \"PERMISSION_DENIED\", \"details\": [ {  } ] } } "

    mock_response = (
        Response(dict(status=403)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        gcb_ioc_details_command(client, ARGS)
    expected_message = 'Status code: 403\nError: Permission denied'
    assert str(error.value) == expected_message


def test_reputation_operation_command_success(client):
    """
    When two comma separated arguments will be passed then function return_outputs should be call twice with valid
    arguments
    """
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
    """
    When success response come then test_function command should pass.
    """
    from GoogleChronicleBackstory import test_function
    mock_response = (
        Response(dict(status=200)),
        b'{}'
    )
    client.http_client.request.return_value = mock_response

    with mock.patch('GoogleChronicleBackstory.demisto.results') as mock_demisto_result:
        test_function(client, PROXY_MOCK)
    mock_demisto_result.assert_called_with('ok')


def test_function_failure_status_code_400(client, mocker):
    """
    When unsuccessful response come then test_function command should raise ValueError with appropriate message.
    """
    from GoogleChronicleBackstory import test_function
    mock_response = (
        Response(dict(status=400)),
        b'{"error": { "code": 400, "message": "Request contains an invalid argument.", "status": "INVALID_ARGUMENT" } }'
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == 'Status code: 400\nError: Request contains an invalid argument.'


def test_function_failure_status_code_403(client, mocker):
    """
    When entered JSON is correct but client has not given any access, should return permission denied
    """
    from GoogleChronicleBackstory import test_function
    mock_response = (
        Response(dict(status=403)),
        b'{"error": { "code": 403, "message": "Permission denied" } }'
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == 'Status code: 403\nError: Permission denied'


def test_validate_parameter_success(mocker):
    """
    When valid input is added on Integration Configuration then it should pass
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import validate_configuration_parameters
    param = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '20',
        'first_fetch': '10 day'
    }
    validate_configuration_parameters(param)


def test_validate_parameter_failure_wrong_json():
    """
    When wrong JSON format of User Service account JSON input is added it should return validation error
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_credentials = {
        'service_account_credential': '{"key","value"}',
        'max_fetch': '20',
        'first_fetch': '10 day'
    }

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_credentials)
    assert str(error.value) == "User's Service Account JSON has invalid format"


def test_validate_parameter_failure_page_size():
    """
    When page size not in positive number then it should raise ValueError
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_page_sizes = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '2a0',
        'first_fetch': '10 day'
    }

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_page_sizes)
    assert str(error.value) == "Incidents fetch limit must be a number"


def test_validate_parameter_failure_wrong_fetch_days_format():
    """
    When page size not in positive number then it should raise ValueError
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_format = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '20',
        'first_fetch': '10dad'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_format)
    assert str(error.value) == 'First fetch days must be "number time_unit", ' \
                               'examples: (10 days, 6 months, 1 year, etc.)'


def test_validate_parameter_failure_wrong_fetch_days_number():
    """
    When First fetch days field's number is invalid then it should raise ValueError
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_number = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '20',
        'first_fetch': 'Ten day'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_number)
    assert str(error.value) == 'First fetch days must be "number time_unit", ' \
                               'examples: (10 days, 6 months, 1 year, etc.)'


def test_validate_parameter_failure_wrong_fetch_days_unit():
    """
    When First fetch days field's unit is invalid then it should raise ValueError
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    wrong_fetch_days_unit = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '20',
        'first_fetch': '10 dad'
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_fetch_days_unit)
    assert str(error.value) == "First fetch days field's unit is invalid. Must be in day(s), month(s) or year(s)"


def test_main_success(mocker, client):
    """
    When command execute successfully then main should pass
    """
    import GoogleChronicleBackstory
    param = {
        'service_account_credential': '{"key":"value"}',
        'max_fetch': '20',
        'first_fetch': '10 day',
        'configured_maliciuos_categories': "Spyware Reporting Server, Target of a DDoS, Known Spam Source"

    }
    mock_response = (
        Response(dict(status=200)),
        b'{"error": { "code": 400, "message": "Request contains an invalid argument.", "status": "INVALID_ARGUMENT" } }'
    )
    client.http_client.request.return_value = mock_response

    mocker.patch.object(demisto, 'params', return_value=param)
    mocker.patch.object(demisto, 'command', return_value="test-module")
    mocker.patch.object(GoogleChronicleBackstory, 'test_function', return_value=('', {}, {}))
    mocker.patch('GoogleChronicleBackstory.Client', return_value=client)
    GoogleChronicleBackstory.main()
    assert GoogleChronicleBackstory.test_function.called


def test_gcb_assets_command_success(client):
    """
    When valid response come in gcb-assets command it should respond with result.
    """
    from GoogleChronicleBackstory import gcb_assets_command

    with open("test_data/asset_response.json", encoding='utf-8') as f:
        expected_response = json.load(f)

    success_mock_response = (
        Response(dict(status=200)),
        json.dumps(expected_response, indent=2).encode('utf-8')
    )

    client.http_client.request.return_value = success_mock_response
    hr, ec, response = gcb_assets_command(client, {'artifact_value': SUCCESS_ASSET_NAME})
    with open("test_data/asset_ec.json") as f:
        expected_ec = json.load(f)
    assert ec == expected_ec
    assert response == expected_response


def test_gcb_assets_command_failure(client):
    """
    When Null response come in gcb-assets command it should respond with No Records Found.
    """
    from GoogleChronicleBackstory import gcb_assets_command

    failure_mock_response = (
        Response(dict(status=200)),
        json.dumps({}, indent=2).encode('utf-8')
    )
    client.http_client.request.return_value = failure_mock_response
    hr, ec, response = gcb_assets_command(client, {'artifact_value': FAILURE_ASSET_NAME})
    assert ec == {}
    assert response == {}


def test_gcb_assets_command_failure_with_uri_empty_response(client):
    """
    When Null response come in gcb-assets command it should respond with No Records Found.
    """
    from GoogleChronicleBackstory import gcb_assets_command

    with open("test_data/asset_with_no_response.json", encoding='utf-8') as f:
        expected_response = json.load(f)

    failure_mock_response = (
        Response(dict(status=200)),
        json.dumps(expected_response, indent=2).encode('utf-8')
    )
    client.http_client.request.return_value = failure_mock_response
    hr, ec, response = gcb_assets_command(client, {'artifact_value': FAILURE_ASSET_NAME})
    assert ec == {}
    assert hr == '### Artifact Accessed: www.xyz.com \n\nNo Records Found'
    assert response == expected_response


def test_get_artifact_type():
    """
    When valid artifact pass in get_artifact_type function then it should pass else raise ValueError
    """
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


def test_validate_date():
    """
    When valid date pass in validate_date function then it should pass else raise ValueError
    """
    from GoogleChronicleBackstory import validate_start_end_date
    from datetime import datetime, timedelta

    next_date = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    with pytest.raises(ValueError) as error:
        validate_start_end_date('11111', next_date)
    assert str(error.value) == "Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"

    with pytest.raises(ValueError) as error:
        validate_start_end_date('11eee11', next_date)
    assert str(error.value) == "Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"

    with pytest.raises(ValueError) as error:
        validate_start_end_date(next_date, "december")
    assert str(error.value) == "Invalid end time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"


def test_fetch_incident_success_with_no_param_no_alerts(client):
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    mock_response = (
        Response(dict(status=200)),
        b'{}'
    )
    client.http_client.request.return_value = mock_response
    fetch_incidents(client, param)

    assert client.http_client.request.called


def validate_ioc_domain_incident(incidents):
    """
    validates ioc domain key for fetch incident event
    """
    assert len(incidents) == 2
    for incident_alert in incidents:
        assert incident_alert['name']
        assert incident_alert['details']
        assert incident_alert['rawJSON']


def test_fetch_incident_run_ioc_domain_matches(mocker, client):
    """
    With IOC Domain Matches as default selection should be called and create incident in Demisto
    """
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    with open("test_data/list_ioc_response.txt", "rb") as f:
        dummy_response = f.read()

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    mocker.patch.object(demisto, 'incidents', new=validate_ioc_domain_incident)
    client.http_client.request.return_value = mock_response
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_fetch_incident_error_in_response(client, mocker):
    from GoogleChronicleBackstory import fetch_incidents
    param = {}

    mock_response = (
        Response(dict(status=400)),
        b'{"error": { "code": 400, "message": "Invalid Argument", "status": "INVALID_ARGUMENT" } }'
    )
    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        fetch_incidents(client, param)

    assert client.http_client.request.called
    assert str(error.value) == "Status code: 400\nError: Invalid Argument"


def validate_incident(incidents):
    """
    internal method used in test_fetch_incident_success_with_param_alerts
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
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '4 days',
        'max_fetch': 20,
        'incident_severity': 'ALL',
        'time_window': '60',
        'backstory_alert_type': 'Assets with alerts'
    }

    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_success_with_alerts_with_demisto_last_run(mocker, client):
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'incident_severity': None,
        'backstory_alert_type': 'Assets with alerts'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_incident)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={'start_time': "2020-01-29T14:13:20+00:00"})

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_asset_with_multiple_alerts_human_readable(client):
    """
    if multiple alerts per assert is found then, it should display asset per alerts in human readable
    :return:
    """
    from GoogleChronicleBackstory import group_infos_by_alert_asset_name, get_gcb_alerts
    from CommonServerPython import datetime

    with open("test_data/gcb_alerts_human_readable.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    events = get_gcb_alerts(client, datetime.utcnow(), datetime.utcnow(), 20, None)
    alert_per_asset, _ = group_infos_by_alert_asset_name(events)

    assert alert_per_asset
    assert len(alert_per_asset) == 4
    assert 'svetla-Command Shell Launched by Office Applications' in alert_per_asset.keys()
    assert 'svetla-Suspicious PowerShell Process Ancestry' in alert_per_asset.keys()
    assert 'dc12-Suspicious PowerShell Process Ancestry' in alert_per_asset.keys()
    assert 'dc12-Possible Bitsadmin Exfiltration' in alert_per_asset.keys()


def test_gcb_list_alert_with_no_arg_supplied_success(mocker, client):
    """
    Should return hr, ec and events when multiple events are responded
    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {}

    mock_response = (
        Response(dict(status=200)),
        get_hr_gcb_alerts()
    )
    client.http_client.request.return_value = mock_response
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
    Should return hr, ec and alerts when multiple 'Medium' severity is supplied
    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        'severity': 'Medium'
    }

    mock_response = (
        Response(dict(status=200)),
        get_hr_gcb_alerts()
    )
    client.http_client.request.return_value = mock_response
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
    Should return hr, ec and alerts when multiple 'Medium' severity even in lowercase input
    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        'severity': 'medium'
    }

    mock_response = (
        Response(dict(status=200)),
        get_hr_gcb_alerts()
    )
    client.http_client.request.return_value = mock_response
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
    with open("test_data/gcb_alerts_human_readable.txt") as f:
        gcb_alert_sample = f.read()
    return gcb_alert_sample


def test_gcb_list_alert_when_no_alert_found(mocker, client):
    """
    should display 'No Record Found' message when empty but 200 status is responded.
    :param mocker:
    :return:
    """
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {}

    mock_response = (
        Response(dict(status=200)),
        b'{}'
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr == '### Security Alert(s): No Records Found'
    assert not ec
    assert not events
    assert client.http_client.request.called


def test_validate_page_size():
    """
    When there is a invalid page size then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import validate_page_size
    with pytest.raises(ValueError) as error:
        validate_page_size('5s')
    assert str(error.value) == "Page size must be a non-zero numeric value"

    with pytest.raises(ValueError) as error:
        validate_page_size('0')
    assert str(error.value) == "Page size must be a non-zero numeric value"

    assert validate_page_size(10)

    with pytest.raises(ValueError) as error:
        validate_page_size(None)
    assert str(error.value) == "Page size must be a non-zero numeric value"

    with pytest.raises(ValueError) as error:
        validate_page_size('')
    assert str(error.value) == "Page size must be a non-zero numeric value"


def test_ip_command_success(mocker, client):
    """
    When command execute successfully then it should prepare valid hr, ec
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import ip_command

    with open("test_data/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("test_data/ip_command_ec.json", "r") as f:
        dummy_ec = json.load(f)

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert ec['DBotScore'] == dummy_ec['DBotScore']
    assert ec['IP(val.Address && val.Address == obj.Address)'] == dummy_ec[
        'IP(val.Address && val.Address == obj.Address)']

    key = 'GoogleChronicleBackstory.IP(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_ip_command_empty_response_when_uri_empty_response(client):
    from GoogleChronicleBackstory import ip_command

    with open("test_data/empty_list_ioc_details.json", "r") as f:
        dummy_response = f.read()
    expected_hr = '### IP: {} found with Reputation: Unknown\n'.format(ARGS['ip'])
    expected_hr += 'No Records Found'

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert hr == expected_hr


def test_ip_command_invalid_ip_address(client):
    """
    When user add invalid IP Address then it should raise ValueError with valid response
    """
    from GoogleChronicleBackstory import ip_command
    expected_message = 'Invalid IP - string'

    with pytest.raises(ValueError) as error:
        ip_command(client, 'string')

    assert str(error.value) == expected_message


def test_ip_command_empty_response(client):
    """
    When there is an empty response the command should response empty ec and valid text in hr
    """
    from GoogleChronicleBackstory import ip_command
    expected_hr = '### IP: {} found with Reputation: Unknown\n'.format(ARGS['ip'])
    expected_hr += 'No Records Found'

    dummy_response = '{}'
    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = ip_command(client, ARGS['ip'])

    assert hr == expected_hr


def test_ip_command_failure(client, mocker):
    """
    When there is a invalid response then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import ip_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.ip_address\': Cannot bind query parameter. Field \'ip_address\' could not be found" \
                     " in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    mock_response = (
        Response(dict(status=400)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        ip_command(client, ARGS['ip'])
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.ip_address\':" \
                       " Cannot bind query parameter. Field \'ip_address\' could not be found in request message."
    assert str(error.value) == expected_message


def test_ip_command_failure_permission_denied(client, mocker):
    """
    When there is a response for permission denied then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import ip_command

    dummy_response = "{ \"error\": { \"code\": 403, \"message\": \"Permission denied\" \
                     , \"status\": \"PERMISSION_DENIED\", \"details\": [ {  } ] } } "

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    mock_response = (
        Response(dict(status=403)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    with pytest.raises(ValueError) as error:
        ip_command(client, ARGS['ip'])
    expected_message = 'Status code: 403\nError: Permission denied'
    assert str(error.value) == expected_message


def test_domain_command_success(mocker, client):
    """
    When command execute successfully then it should prepare valid hr, ec
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from GoogleChronicleBackstory import domain_command

    with open("test_data/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("test_data/domain_command_ec.json", "r") as f:
        dummy_ec = json.load(f)

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert ec['DBotScore'] == dummy_ec['DBotScore']
    assert ec['Domain(val.Name && val.Name == obj.Name)'] == dummy_ec['Domain(val.Name && val.Name == obj.Name)']

    key = 'GoogleChronicleBackstory.Domain(val.IoCQueried && val.IoCQueried == obj.IoCQueried)'
    assert ec[key] == dummy_ec[key]


def test_domain_command_empty_response(client):
    from GoogleChronicleBackstory import domain_command

    with open("test_data/empty_list_ioc_details.json", "r") as f:
        dummy_response = f.read()
    expected_hr = '### Domain: {} found with Reputation: Unknown\n'.format(ARGS['domain'])
    expected_hr += 'No Records Found'

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert hr == expected_hr


def test_gcb_domain_command_empty_response(client):
    """
    When there is an empty response the command should response empty ec and valid text in hr
    """
    from GoogleChronicleBackstory import domain_command
    expected_hr = '### Domain: {} found with Reputation: Unknown\n'.format(ARGS['domain'])
    expected_hr += 'No Records Found'

    dummy_response = '{}'
    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, response = domain_command(client, ARGS['domain'])

    assert hr == expected_hr


def test_domain_command_failure(client, mocker):
    """
    When there is a invalid response then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import domain_command

    dummy_response = "{ \"error\": { \"code\": 400, \"message\": \"Invalid JSON payload received. Unknown name " \
                     "\'artifact.domai_name\': Cannot bind query parameter. Field \'domai_name\' could not be found " \
                     "in request message.\", \"status\": \"INVALID_ARGUMENT\", \"details\": [ {  } ] } } "

    mock_response = (
        Response(dict(status=400)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        domain_command(client, ARGS['domain'])
    expected_message = "Status code: 400\nError: Invalid JSON payload received. Unknown name \'artifact.domai_name\': " \
                       "Cannot bind query parameter. Field \'domai_name\' could not be found in request message."
    assert str(error.value) == expected_message


def test_domain_command_failure_permission_denied(client, mocker):
    """
    When there is a response for permission denied then ValueError should be raised with valid message
    """
    from GoogleChronicleBackstory import domain_command

    dummy_response = "{ \"error\": { \"code\": 403, \"message\": \"Permission denied\" \
                     , \"status\": \"PERMISSION_DENIED\", \"details\": [ {  } ] } } "

    mock_response = (
        Response(dict(status=403)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    mocker.patch('GoogleChronicleBackstory.return_error', new=return_error)
    with pytest.raises(ValueError) as error:
        domain_command(client, ARGS['domain'])
    expected_message = 'Status code: 403\nError: Permission denied'
    assert str(error.value) == expected_message


def test_evaluate_dbot_score_get_all_none(mocker):
    """
    When category, severity and confidence score are none then dbot score should be 0
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 0

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_malicious(mocker):
    """
    When category, severity and confidence score are in malicious category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 93)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_suspicious(mocker):
    """
    When category, severity and confidence score are in suspicious category then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious(mocker):
    """
    When category, severity and confidence score are in suspicious category then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious(mocker):
    """
    When category is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_suspicious(mocker):
    """
    When category suspicious and severity suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_malicious(mocker):
    """
    When category suspicious and severity malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_suspicious(mocker):
    """
    When category malicious and severity suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_malicious(mocker):
    """
    When category malicious and severity malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 24)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_confidencescore_suspicious(mocker):
    """
    When category suspicious and confidence score suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_confidencescore_malicious(mocker):
    """
    When category suspicious and confidence score malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_confidencescore_suspicious(mocker):
    """
    When category malicious and confidence score suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_confidencescore_malicious(mocker):
    """
    When category malicious and confidence score malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious(mocker):
    """
    When severity suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 20)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious(mocker):
    """
    When severity malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 20)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_confidencescore_suspicious(mocker):
    """
    When severity suspicious and confidence score suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_confidencescore_suspicious(mocker):
    """
    When severity malicious and confidence score suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 44)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_confidencescore_malicious(mocker):
    """
    When severity suspicious and confidence score malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_confidencescore_malicious(mocker):
    """
    When severity malicious and confidence score malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_confidencescore_suspicious(mocker):
    """
    When confidence score suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 55)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_confidencescore_malicious(mocker):
    """
    When confidence score malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 94)
    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_suspicious_malicious(mocker):
    """
    When category suspicious, severity suspicious and confidence score malicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_suspicious(mocker):
    """
    When category suspicious, severity malicious and confidence score suspicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 40)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_malicious(mocker):
    """
    When category suspicious, severity malicious and confidence score malicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 120)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_malicious_suspicious(mocker):
    """
    When category malicious, severity malicious and confidence score suspicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 40)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_suspicious(mocker):
    """
    When category malicious, severity suspicious and confidence score suspicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 50)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_malicious(mocker):
    """
    When category malicious, severity suspicious and confidence score malicious are in suspicious category then dbot
    score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_none_str_confidencescore(mocker):
    """
    When category, severity and confidence score in string are not match with input configurations then dbot score
    should be 0
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 0

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_malicious_str_confidencescore(mocker):
    """
    When category, severity and confidence score in string are in malicious category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_all_suspicious_str_confidencescore(mocker):
    """
    When category, severity and confidence score in string are in suspicious category then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore(mocker):
    """
    When category, severity and confidence score in string are in suspicious category then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore(mocker):
    """
    When category is malicious and confidence score in string then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_suspicious_str_confidencescore(mocker):
    """
    When category suspicious and severity suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_severity_malicious_str_confidencescore(mocker):
    """
    When category suspicious and severity malicious and confidence score in string then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_suspicious_str_confidencescore(mocker):
    """
    When category malicious and severity suspicious and confidence score in string then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_severity_malicious_str_confidencescore(mocker):
    """
    When category malicious and severity malicious and confidence score in string then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'informational')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore_suspicious(mocker):
    """
    When category suspicious and confidence score in string is suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_suspicious_str_confidencescore_malicious(mocker):
    """
    When category suspicious and confidence score in string is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Low', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore_suspicious(mocker):
    """
    When category malicious and confidence score in string is suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_categories_malicious_str_confidencescore_malicious(mocker):
    """
    When category malicious and confidence score in string is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Low', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore(mocker):
    """
    When severity suspicious and confidence score in string then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore(mocker):
    """
    When severity malicious and confidence score in string then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'unknown_severity')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore_suspicious(mocker):
    """
    When severity suspicious and confidence score in string is suspicious then dbot score should be 2
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore_suspicious(mocker):
    """
    When severity malicious and confidence score in string is suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_suspicious_str_confidencescore_malicious(mocker):
    """
    When severity suspicious and confidence score in string is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Medium', 'medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_severity_malicious_str_confidencescore_malicious(mocker):
    """
    When severity malicious and confidence score in string is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_str_confidencescore_suspicious(mocker):
    """
    When confidence score in string is suspicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 2

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_str_confidencescore_malicious(mocker):
    """
    When confidence score in string is malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Unwanted', 'Low', 'High')
    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_suspicious_malicious_str_confidencescore(mocker):
    """
    When category suspicious, severity suspicious and confidence score in string is malicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'Medium', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_suspicious_str_confidencescore(mocker):
    """
    When category suspicious, severity malicious and confidence score in string is suspicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_suspicious_malicious_malicious_str_confidencescore(mocker):
    """
    When category suspicious, severity malicious and confidence score in string is malicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('Observed serving executables', 'High', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_malicious_suspicious_str_confidencescore(mocker):
    """
    When category malicious, severity malicious and confidence score in string is suspicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_suspicious_str_confidencescore(mocker):
    """
    When category malicious, severity suspicious and confidence score in string is suspicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Low')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_get_malicious_suspicious_malicious_str_confidencescore(mocker):
    """
    When category malicious, severity suspicious and confidence score in string is malicious are in suspicious
    category then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'Medium', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_category_blank(mocker):
    """
    When category blank and others set to malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('', 'Medium', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_severity_blank(mocker):
    """
    When severity blank and others set to malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', '', 90)

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_category_blank_str_confidencescore(mocker):
    """
    When category blank and others set to malicious with string confidence score then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('', 'Medium', 'Medium')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_severity_blank_str_confidencescore(mocker):
    """
    When severity blank and others set to malicious with string confidence score then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', '', 'High')

    # Assert
    assert dbot_score == expected_dbot_score


def test_evaluate_dbot_score_str_confidencescore_blank(mocker):
    """
    When confidence score in string blank and others set to malicious then dbot score should be 3
    """
    # Configure
    mocker.patch.object(demisto, 'params', return_value=PARAMS_FOR_STR_CONFIDENCE_SCORE)
    expected_dbot_score = 3

    # Execute
    from GoogleChronicleBackstory import evaluate_dbot_score
    dbot_score = evaluate_dbot_score('APT-Activity', 'High', '')

    # Assert
    assert expected_dbot_score == dbot_score


def test_preset_time_range():
    """
    When valid duration value pass in validate_duration function then it should pass else raise ValueError
    """
    # Execute
    from GoogleChronicleBackstory import validate_preset_time_range

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last10days')
    assert str(error.value) == 'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", ' \
                               '"Last 15 days" and "Last 30 days"'

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 10days')
    assert str(error.value) == 'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", ' \
                               '"Last 15 days" and "Last 30 days"'

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 4 days')
    assert str(error.value) == 'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", ' \
                               '"Last 15 days" and "Last 30 days"'

    with pytest.raises(ValueError) as error:
        validate_preset_time_range('Last 1 month')
    assert str(error.value) == 'Invalid value provided. Allowed values are  "Last 1 day", "Last 7 days", ' \
                               '"Last 15 days" and "Last 30 days"'

    assert validate_preset_time_range('Last 1 day') == '1 day'
    assert validate_preset_time_range('Last 15 days') == '15 days'


def test_parse_error_message():
    from GoogleChronicleBackstory import parse_error_message

    with pytest.raises(ValueError) as error:
        parse_error_message('service unavailable')
    assert str(error.value) == 'Invalid response received from Chronicle Search API. Response not in JSON format.'


def test_list_events_command(client):
    from GoogleChronicleBackstory import gcb_list_events_command

    with open("test_data/list_events_response.json", "r") as f:
        dummy_response = f.read()

    with open("test_data/list_events_ec.json", "r") as f:
        dummy_ec = json.load(f)

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_events_command(client, {})

    event = 'GoogleChronicleBackstory.Events'
    assert ec[event] == dummy_ec[event]

    # Test command when no events found
    client.http_client.request.return_value = (
        Response(dict(status=200)),
        '{}'
    )

    hr, ec, json_data = gcb_list_events_command(client, {})
    assert ec == {}
    assert hr == 'No Events Found'


def test_list_detections_command(client):
    from GoogleChronicleBackstory import gcb_list_detections_command

    args = {'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '2019-10-17T00:00:00Z',
            'detection_end_time': '2 days ago'}

    with open("test_data/list_detections_response.json", "r") as f:
        dummy_response = f.read()

    with open("test_data/list_detections_ec.json", "r") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_detections_hr.md", "r") as f:
        dummy_hr = f.read()

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_detections_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no detections found
    client.http_client.request.return_value = (
        Response(dict(status=200)),
        '{}'
    )

    hr, ec, json_data = gcb_list_detections_command(client, args)
    assert ec == {}
    assert hr == 'No Detections Found'


@pytest.mark.parametrize("args, error_msg", [
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'page_size': 'dummy'}, 'Page size must be a non-zero '
                                                                                   'numeric value'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'page_size': '100000'}, 'Page size should be in the range '
                                                                                    'from 1 to 1000.'),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': 'December 2019'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '6'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '-5'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '645.08'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_start_time': '-325.21'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': 'December 2019'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '6'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '-5'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '645.08'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'detection_end_time': '-325.21'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': 'December 2019'},
     invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '6'}, invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '-5'}, invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '645.08'}, invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'start_time': '-325.21'}, invalid_start_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': 'December 2019'},
     invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '6'}, invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '-5'}, invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '645.08'}, invalid_end_time_error_message),
    ({'rule_id': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f', 'end_time': '-325.21'}, invalid_end_time_error_message),
    ({'detection_for_all_versions': True}, "If \"detection_for_all_versions\" is true, rule id is required."),
    ({'list_basis': 'CREATED_TIME'}, "To sort detections by \"list_basis\", either \"start_time\" or \"end_time\" "
                                     "argument is required.")
])
def test_validate_and_parse_list_detections_args(args, error_msg):
    from GoogleChronicleBackstory import validate_and_parse_list_detections_args

    with pytest.raises(ValueError) as e:
        validate_and_parse_list_detections_args(args)

    assert str(e.value) == error_msg


def validate_duplicate_incidents(incidents):
    """
    internal method used in test_gcb_fetch_incident_success_with_alerts_with_incident_identifiers
    """
    assert len(incidents) == 1


def test_gcb_fetch_incident_success_with_alerts_with_incident_identifiers(mocker, client):
    """
    Check the fetched incident in case duplicate asset alerts are fetched in next iteration.
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'incident_severity': None,
        'backstory_alert_type': 'Assets with alerts',
        'time_window': '45'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_incidents)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': "2020-01-29T14:13:20Z",
                            'assets_alerts_identifiers': [
                                '6a1b7ffcbb7a0fb51bd4bebfbbbbb0e094c8e7543dd64858354d486d0288798d',
                                'bccf9ae7dbfdc1fcaea98fe4043fa3f20f5c4f38a71bad062c8b2d849d79bed8']})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_generate_delayed_start_time():
    """
    Check if the start time is delayed according to user input
    """
    from GoogleChronicleBackstory import generate_delayed_start_time

    start_time = '2020-01-29T14:13:20Z'
    delayed_start_time = generate_delayed_start_time('45', start_time)
    assert delayed_start_time == '2020-01-29T13:28:20.000000Z'


def test_validate_parameter_failure_invalid_time_window_values():
    """
    When time window configuration parameter has invalid value then it should raise ValueError
    """
    from GoogleChronicleBackstory import validate_configuration_parameters
    invalid_time_window = {
        'service_account_credential': '{"key":"value"}',
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
    internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert incidents

    for incident in incidents:
        assert incident['name']
        assert incident['rawJSON']


def test_fetch_incident_detection_when_1st_sync_n_data_less_thn_max_fetch_and_ids_is_1(client, mocker):
    """
    case when 2 detections with no-NT.
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 5,
        'backstory_alert_type': 'Detection Alerts',
        'fetch_detection_by_ids': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631093_146879000'
    }

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    mock_response = (
        Response(dict(status=200)),
        get_detection_json_size_2
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_detection_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.call_count == 1


def validate_last_run__whn_last_pull(last_run):
    """
    internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert not last_run.get("rule_first_fetched_time")
    assert not last_run.get("detection_to_process")
    assert not last_run.get("detection_to_pull")
    assert not last_run.get("pending_rule_or_version_id")


def validate_last_run_wth_dtc_to_pull(last_run):
    """
    internal method used in test_fetch_incident_success_with_param_alerts
    """
    assert last_run
    assert last_run.get("rule_first_fetched_time")
    assert not last_run.get("detection_to_process")
    assert last_run.get("detection_to_pull")
    assert not last_run.get("pending_rule_or_version_id")


def validate_detections_case_2_iteration_1(incidents):
    """
    internal method used in test_fetch_incident_detection_case_2
    """
    assert len(incidents) == 5


def validate_detections_case_2_iteration_2(incidents):
    """
    internal method used in test_fetch_incident_detection_case_2
    """
    assert len(incidents) == 2


def test_fetch_incident_detection_case_2(client, mocker):
    """
    max_fetch =5
    1Id return 5, with NT
    1Id on 2nd call return 2, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 5,
        'backstory_alert_type': 'Detection Alerts',
        'fetch_detection_by_ids': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631093_146879000'
    }

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    mock_response_5 = (
        Response(dict(status=200)),
        get_detection_json_size_5
    )

    mock_response_2 = (
        Response(dict(status=200)),
        get_detection_json_size_2
    )

    client.http_client.request.side_effect = [mock_response_5, mock_response_2]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_1)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run_wth_dtc_to_pull)

    fetch_incidents(client, param)

    mocker.patch.object(demisto, 'setLastRun', new=validate_last_run__whn_last_pull)
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_2_iteration_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_detections_case_3_iteration_1(incidents):
    """
    internal method used in test_fetch_incident_detection_case_3
    """
    assert len(incidents) == 3


def validate_detections_case_3_iteration_2(incidents):
    """
    internal method used in test_fetch_incident_detection_case_3
    """
    assert len(incidents) == 2


@mock.patch('GoogleChronicleBackstory.get_detections')
@mock.patch('demistomock.error')
def test_no_duplicate_rule_id_on_detection_to_pull_exception(mock_error, mock_build, client):
    """
    Demo test for get_max_fetch_detections
    """
    from GoogleChronicleBackstory import get_max_fetch_detections

    mock_build.side_effect = ValueError('123')
    z = ['123', '456']
    mock_error.return_value = {}
    for o in range(5):
        x, y, z, w = get_max_fetch_detections(client, '12', '23', 5,
                                              [{'id': '123',
                                                'detection': [{'ruleVersion': '3423', 'ruleName': 'SampleRule'}]},
                                               {'id': '1234',
                                                'detection': [{'ruleVersion': '342', 'ruleName': 'SampleRule'}]},
                                               {'id': '12345',
                                                'detection': [{'ruleVersion': '34', 'ruleName': 'SampleRule'}]}],
                                              {'rule_id': '456',
                                               'next_page_token': 'foorbar'},
                                              z, '', {})

    assert z == ['123', '456']


def test_fetch_incident_detection_case_3(client, mocker):
    """
    1Id return 2, with no NT
    2Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 3,
        'backstory_alert_type': 'Detection Alerts',
        'fetch_detection_by_ids': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631091_146879001, '
                                  'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631092_146879002'
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    mock_response_size_3 = (
        Response(dict(status=200)),
        get_detection_json_size_3
    )

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json_size_2 = f.read()

    mock_response_size_2 = (
        Response(dict(status=200)),
        get_detection_json_size_2
    )

    client.http_client.request.side_effect = [mock_response_size_2, mock_response_size_3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_3_iteration_1)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': '2020-11-20T12:00:00Z',
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
    case - rule_1 has 5 records, rule_2 has 2 records
    max_fetch - 3
    Assumption : On 1st call we pulled rule_1 - 3 indicators with detection_to_pull(next_token, rule_id)
    On 2nd call we have next_token and rule_id for rule_1 that contains 2 records. This will pull 2 records
    for rule_1 and 2 records for rule_2 and complete the fetch-incident cycle since we don't have any rule to process
    test_detection_to_pull_is_empty
    """
    from GoogleChronicleBackstory import get_max_fetch_detections, get_detections
    import io

    with io.open("test_data/fetch_detection_size_2.json", mode='r', encoding='utf-8') as f:
        get_detection_json_size_2 = json.loads(f.read())

    mock_build.return_value = ('p', get_detection_json_size_2)
    z = ['456']

    x, y, z, w = get_max_fetch_detections(client, 'st_dummy', 'et_dummy', 3,
                                          [],
                                          {'rule_id': '123',
                                           'next_page_token': 'foorbar'},
                                          z, '', {})

    assert len(x) == 4
    assert y == {}
    assert z == []
    # Making sure that get_detections called 2 times.
    assert get_detections.call_count == 2


@mock.patch('GoogleChronicleBackstory.validate_response')
def test_when_detection_to_pull_is_not_empty_and_return_empty_result(mock_validate_response, client):
    """
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
                                          z, '', {})

    assert z == []
    assert y == {}
    assert len(x) == 0
    # Making sure that validate_response called 3 times.
    assert validate_response.call_count == 3


@mock.patch('demistomock.error')
def test_429_or_500_error_with_max_attempts_60(mock_error, client):
    """
    case :   rule_1 - 429 error 30 times, return 3 records
             rule_2 - 500 error 60 times
             rule_3 - 500 error 1 times, return 3 records
    """
    from GoogleChronicleBackstory import get_max_fetch_detections
    mock_error.return_value = {}
    mock_response_with_429_error = (Response(dict(status=429)),
                                    '{"error": {}}')

    mock_response_with_500_error = (Response(dict(status=500)),
                                    '{"error": {}}')

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    mock_response_size_3 = (
        Response(dict(status=200)),
        get_detection_json_size_3
    )
    client.http_client.request.side_effect = [mock_response_with_429_error] * 30 + [mock_response_size_3] + [
        mock_response_with_500_error] * 61 + [mock_response_size_3]
    pending_rule_or_version_id = ['rule_2', 'rule_3']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'foorbar'}
    simple_backoff_rules = {}
    for i in range(93):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules = get_max_fetch_detections(
            client,
            'st_dummy',
            'et_dummy', 5,
            [],
            detection_to_pull,
            pending_rule_or_version_id,
            '', simple_backoff_rules)

    assert client.http_client.request.call_count == 93


@mock.patch('demistomock.error')
def test_400_and_404_error(mock_error, client):
    """
    case : rule_1 ok, rule_2 throw 400, rule_3 ok, rule_5 throw 404, rule_5 ok
    """
    from GoogleChronicleBackstory import get_max_fetch_detections

    mock_error.return_value = {}
    mock_response_with_400_error = (Response(dict(status=400)),
                                    '{"error": {}}')

    mock_response_with_404_error = (Response(dict(status=404)),
                                    '{"error": {}}')

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    mock_response_size_3 = (
        Response(dict(status=200)),
        get_detection_json_size_3
    )
    client.http_client.request.side_effect = [mock_response_size_3, mock_response_with_400_error,
                                              mock_response_size_3, mock_response_with_404_error,
                                              mock_response_size_3]

    pending_rule_or_version_id = ['rule_2', 'rule_3', 'rule_4', 'rule_5']
    detection_to_pull = {'rule_id': 'rule_1', 'next_page_token': 'foorbar'}

    simple_backoff_rules = {}
    for i in range(5):
        detection_incidents, detection_to_pull, pending_rule_or_version_id, simple_backoff_rules = get_max_fetch_detections(
            client,
            'st_dummy',
            'et_dummy', 15,
            [],
            detection_to_pull,
            pending_rule_or_version_id,
            '', simple_backoff_rules)


def validate_detections_case_4_iteration_1_and_2(incidents):
    """
    internal method used in test_fetch_incident_detection_case_4
    """
    assert len(incidents) == 5


def validate_detections_case_4_iteration_3(incidents):
    """
    internal method used in test_fetch_incident_detection_case_4
    """
    assert len(incidents) == 3


def test_fetch_incident_detection_case_4(client, mocker):
    """
    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 3, with no NT
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 5,
        'backstory_alert_type': 'Detection Alerts',
        'fetch_detection_by_ids': '123, 456, 789'
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    mock_response_size_3 = (
        Response(dict(status=200)),
        get_detection_json_size_3
    )

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    mock_response_size_5 = (
        Response(dict(status=200)),
        get_detection_json_size_5
    )

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json = f.read()

    mock_response_size_2 = (
        Response(dict(status=200)),
        get_detection_json
    )

    client.http_client.request.side_effect = [mock_response_size_3, mock_response_size_5, mock_response_size_2,
                                              mock_response_size_3]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_4_iteration_1_and_2)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': '2020-11-20T12:00:00Z',
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
        'start_time': '2020-11-20T12:00:00Z',
        'rule_first_fetched_time': '2020-11-20T12:00:01Z',
        'detection_to_process': [],
        'detection_to_pull': {},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_detections_case_5_iteration_1_2_3(incidents):
    assert len(incidents) == 5


def test_fetch_incident_detection_case_5(client, mocker):
    """
    1Id return 3, with no NT
    2Id return 5, with NT
    2Id return 2, with no NT
    3Id return 5, with NT

    3 + 2
    (3) + 2

    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 5,
        'fetch_detection_by_ids': '123, 456, 789',
        'backstory_alert_type': 'Detection Alerts'
    }

    with open("test_data/fetch_detection_size_3.json") as f:
        get_detection_json_size_3 = f.read()

    mock_response_size_3 = (
        Response(dict(status=200)),
        get_detection_json_size_3
    )

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    mock_response_size_5 = (
        Response(dict(status=200)),
        get_detection_json_size_5
    )

    with open("test_data/fetch_detection_size_2.json") as f:
        get_detection_json = f.read()

    mock_response_size_2 = (
        Response(dict(status=200)),
        get_detection_json
    )

    client.http_client.request.side_effect = [mock_response_size_3, mock_response_size_5, mock_response_size_2,
                                              mock_response_size_5]
    mocker.patch.object(demisto, 'incidents', new=validate_detections_case_5_iteration_1_2_3)

    fetch_incidents(client, param)
    mock_last_run = {
        'start_time': '2020-11-20T12:00:00Z',
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
        'start_time': '2020-11-20T12:00:00Z',
        'detection_to_process': [],
        'detection_to_pull': {},
        'pending_rule_or_version_id_with_alert_state': {'rule_id': ['789'], 'alert_state': ''}
    }
    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_2)
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_duplicate_detections(incidents):
    """
    internal method used in test_gcb_fetch_incident_success_with_detections_with_incident_identifiers
    """
    assert len(incidents) == 3


def test_gcb_fetch_incident_success_with_detections_with_incident_identifiers(mocker, client):
    """
    Check the fetched incident in case duplicate detections are fetched in next iteration.
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '3 days',
        'max_fetch': 5,
        'backstory_alert_type': 'Detection Alerts',
        'fetch_detection_by_ids': 'ru_e6abfcb5-1b85-41b0-b64c-695b3250436f@v_1602631093_146879000'
    }

    with open("test_data/fetch_detection_size_5_NT.json") as f:
        get_detection_json_size_5 = f.read()

    mock_response = (
        Response(dict(status=200)),
        get_detection_json_size_5
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_detections)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': "2020-01-29T14:13:20Z",
                            'detection_identifiers': [{'id': 'de_e6abfcb5-1b85-41b0-b64c-695b32504361',
                                                       'ruleVersion': 'ru_e6abfcb5-1b85-41b0-b64c-695b32'
                                                                      '50436f@v_1602631093_146879000'},
                                                      {'id': 'de_e6abfcb5-1b85-41b0-b64c-695b32504362',
                                                       'ruleVersion': 'ru_e6abfcb5-1b85-41b0-b64c-695b32'
                                                                      '50436f@v_1602631093_146879000'}]})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def validate_user_alert_incident(incidents):
    """
    internal method used in test_fetch_user_alert_incident_success_with_param_alerts
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
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'first_fetch': '4 days',
        'max_fetch': 20,
        'time_window': '60',
        'backstory_alert_type': 'User alerts'
    }

    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_user_alert_incident)

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_user_alert_fetch_incident_success_with_alerts_with_demisto_last_run(mocker, client):
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'backstory_alert_type': 'User alerts'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_user_alert_incident)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={'start_time': "2020-01-29T14:13:20+00:00"})

    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_fetch_incident_user_alert_success_with_alerts_with_incident_identifiers(mocker, client):
    """
    Check the fetched incident in case duplicate user alerts are fetched in next iteration.
    """
    from GoogleChronicleBackstory import fetch_incidents

    param = {
        'max_fetch': 20,
        'backstory_alert_type': 'User alerts',
        'time_window': '45'
    }
    with open("test_data/gcb_alerts_response.txt") as f:
        gcb_alert_sample = f.read()

    mock_response = (
        Response(dict(status=200)),
        gcb_alert_sample
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'incidents', new=validate_duplicate_incidents)
    mocker.patch.object(demisto, 'command', return_value='gcb-fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'start_time': "2020-01-29T14:13:20Z",
                            'user_alerts_identifiers': [
                                '21a03d1fa2ce7e342534447e947a94b9f9f0ccfc57e96e86ca56a0074b646852',
                                '32ac16aa49a087d751644d78ee37d61399f474889a963d017643dd6f566f6c0f']})
    fetch_incidents(client, param)
    assert client.http_client.request.called


def test_gcb_list_user_alert_with_no_arg_supplied_success(mocker, client):
    """Should return hr, ec and events when multiple events are responded"""
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        "alert_type": "User Alerts"
    }

    mock_response = (
        Response(dict(status=200)),
        get_hr_gcb_alerts()
    )
    client.http_client.request.return_value = mock_response
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
    """should display 'No Record Found' message when empty but 200 status is responded."""
    from GoogleChronicleBackstory import gcb_list_alerts_command
    param = {
        "alert_type": "User Alerts"
    }

    mock_response = (
        Response(dict(status=200)),
        b'{}'
    )
    client.http_client.request.return_value = mock_response
    mocker.patch.object(demisto, 'command', return_value='gcb-list-alerts')

    hr, ec, events = gcb_list_alerts_command(client, param)
    assert hr == '### User Alert(s): No Records Found'
    assert not ec
    assert not events
    assert client.http_client.request.called


def test_list_rules_command(client):
    """
    When valid response comes in gcb-list-rules command it should respond with result.
    """
    from GoogleChronicleBackstory import gcb_list_rules_command

    args = {'page_size': '2',
            'page_token': 'foobar_page_token'}

    with open("test_data/list_rules_response.json", "r") as f:
        dummy_response = f.read()

    with open("test_data/list_rules_ec.json", "r") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_rules_hr.md", "r") as f:
        dummy_hr = f.read()

    mock_response = (
        Response(dict(status=200)),
        dummy_response
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_rules_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no rules found
    client.http_client.request.return_value = (
        Response(dict(status=200)),
        '{}'
    )

    hr, ec, json_data = gcb_list_rules_command(client, args)
    assert ec == {}
    assert hr == 'No Rules Found'


def test_get_rules():
    """
    Internal method used in gcb-list-rules command.
    """
    from GoogleChronicleBackstory import get_rules

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': 'dummy'})

    assert str(e.value) == 'Page size must be a non-zero numeric value'

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '100000'})

    assert str(e.value) == 'Page size should be in the range from 1 to 1000.'

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '-5'})

    assert str(e.value) == 'Page size must be a non-zero numeric value'

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'page_size': '0'})

    assert str(e.value) == 'Page size must be a non-zero numeric value'

    with pytest.raises(ValueError) as e:
        get_rules(client, args={'live_rule': 'dummy'})

    assert str(e.value) == 'Live rule should be true or false.'


def test_gcb_list_rules_live_rule_argument_true(client):
    """
     Test gcb_list_rules command when live_rule argument is true.
    """
    from GoogleChronicleBackstory import gcb_list_rules_command

    with open("test_data/list_rules_live_rule_true.json", "r") as f:
        response_true = f.read()

    with open("test_data/list_rules_live_rule_true_ec.json", "r") as f:
        dummy_ec = json.load(f)
    mock_response = (
        Response(dict(status=200)),
        response_true
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_rules_command(client, args={'live_rule': 'true'})

    assert ec == dummy_ec


def test_gcb_list_rules_live_rule_argument_false(client):
    """
     Test gcb_list_rules command when live_rule argument is false.
    """
    from GoogleChronicleBackstory import gcb_list_rules_command

    with open("test_data/list_rules_live_rule_false.json", "r") as f:
        response_false = f.read()

    with open("test_data/list_rules_live_rule_false_ec.json", "r") as f:
        dummy_ec = json.load(f)
    mock_response = (
        Response(dict(status=200)),
        response_false
    )

    client.http_client.request.return_value = mock_response

    hr, ec, json_data = gcb_list_rules_command(client, args={'live_rule': 'false'})

    assert ec == dummy_ec

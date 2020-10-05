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


@pytest.fixture
def client():
    return mock.Mock()


def return_error(error):
    raise ValueError(error)


def test_gcb_list_ioc_success(client):
    """
    When valid response comes in gcb-list-iocs command it should respond with result.
    """
    from GoogleChronicleBackstory import gcb_list_iocs_command
    with open("./TestData/list_ioc_response.txt", "rb") as f:
        dummy_response = f.read()
    with open("./TestData/list_ioc_ec.json") as f:
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
    with open("./TestData/list_ioc_response.txt", "rb") as f:
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

    with open("./TestData/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("./TestData/gcb_ioc_details_command_ec.json", "r") as f:
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

    with open("./TestData/asset_response.json", encoding='utf-8') as f:
        expected_response = json.load(f)

    success_mock_response = (
        Response(dict(status=200)),
        json.dumps(expected_response, indent=2).encode('utf-8')
    )

    client.http_client.request.return_value = success_mock_response
    hr, ec, response = gcb_assets_command(client, {'artifact_value': SUCCESS_ASSET_NAME})
    with open("./TestData/asset_ec.json") as f:
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

    with open("./TestData/asset_with_no_response.json", encoding='utf-8') as f:
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


def test_gcb_assets_command_invalid_date(client):
    """
    When query for invalid start date in gcb-assets command it should raise ValueError.
    """
    from GoogleChronicleBackstory import gcb_assets_command

    with pytest.raises(ValueError) as error:
        gcb_assets_command(client, {'artifact_value': SUCCESS_ASSET_NAME, 'start_time': '2020-02-08'})
    assert str(error.value) == "Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"


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

    with pytest.raises(ValueError) as error:
        validate_start_end_date('2020-01-30')
    assert str(error.value) == "Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"

    next_date = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    with pytest.raises(ValueError) as error:
        validate_start_end_date('200000-01-31T00:00:00Z')
    assert str(error.value) == "Invalid start time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"

    with pytest.raises(ValueError) as error:
        validate_start_end_date(next_date)
    assert str(error.value) == "Invalid start time, can not be greater than current UTC time"

    with pytest.raises(ValueError) as error:
        validate_start_end_date('2020-01-15T00:00:00Z', '2020-01-30')
    assert str(error.value) == "Invalid end time, supports ISO date format only. e.g. 2019-10-17T00:00:00Z"

    with pytest.raises(ValueError) as error:
        validate_start_end_date('2020-01-15T00:00:00Z', next_date)
    assert str(error.value) == "Invalid end time, can not be greater than current UTC time"

    with pytest.raises(ValueError) as error:
        validate_start_end_date('2020-01-15T00:00:00Z', '2020-01-10T00:00:00Z')
    assert str(error.value) == "End time must be later than Start time"


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

    with open("./TestData/list_ioc_response.txt", "rb") as f:
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
        'backstory_alert_type': 'Assets with alerts'
    }

    with open("./TestData/gcb_alerts_response.txt") as f:
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
    with open("./TestData/gcb_alerts_response.txt") as f:
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

    with open("./TestData/gcb_alerts_human_readable.txt") as f:
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
    with open("./TestData/alerts_ec.json") as f:
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
    with open("./TestData/medium_alert_ec.json") as f:
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
    with open("./TestData/medium_alert_ec.json") as f:
        expected_ec = json.load(f)

    assert ec == expected_ec
    assert events
    assert client.http_client.request.called


def get_hr_gcb_alerts():
    with open("./TestData/gcb_alerts_human_readable.txt") as f:
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
    assert hr == '### Security Alert(s):No Records Found'
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

    with open("./TestData/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("./TestData/ip_command_ec.json", "r") as f:
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

    with open("./TestData/empty_list_ioc_details.json", "r") as f:
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

    with open("./TestData/list_ioc_details_response.json", "r") as f:
        dummy_response = f.read()
    with open("./TestData/domain_command_ec.json", "r") as f:
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

    with open("./TestData/empty_list_ioc_details.json", "r") as f:
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

    with open("./TestData/list_events_response.json", "r") as f:
        dummy_response = f.read()

    with open("./TestData/list_events_ec.json", "r") as f:
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

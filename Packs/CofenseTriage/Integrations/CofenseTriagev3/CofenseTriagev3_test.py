import json
import time
import os
import pytest
from unittest import mock
from unittest.mock import patch
import dateparser

from CommonServerPython import DemistoException
from CofenseTriagev3 import MESSAGES
from test_data import input_data

BASE_URL = "https://triage.example.com"
API_TOKEN = "dummy_token"
MOCK_INTEGRATION_CONTEXT = {
    'api_token': API_TOKEN,
    'valid_until': time.time() + 7200
}
AUTHENTICATION_RESP_HEADER = {
    "access_token": API_TOKEN,
    "token_type": "Bearer",
    "expires_in": 7200,
    "created_at": 1604920579
}
MOCKER_HTTP_METHOD = 'CofenseTriagev3.Client.http_request'


def util_load_json(path: str) -> dict:
    """Load a json to python dict."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def mocked_client():
    mocked_client = mock.Mock()
    return mocked_client


@pytest.fixture()
def client():
    from CofenseTriagev3 import Client
    return Client(BASE_URL, False, False, "client_id", "client_secret")


def test_test_module_when_valid_response_is_returned(mocked_client):
    """Test test_module function for success cases."""
    from CofenseTriagev3 import test_module
    mocked_client.http_request.return_value = {}
    assert test_module(mocked_client, {}) == 'ok'


def test_http_request_when_valid_response_is_returned(mocker, requests_mock, client):
    """Test case scenario for successful execution of http_request function"""
    from CofenseTriagev3 import URL_SUFFIX

    mocker.patch('CofenseTriagev3.Client.get_api_token', new=lambda x: False)
    mocker.patch('CofenseTriagev3.Client.set_integration_context', new=lambda x, y: "token")
    requests_mock.get(BASE_URL + URL_SUFFIX["SYSTEM_STATUS"], json={"status": True}, status_code=200)
    requests_mock.post(BASE_URL + "/oauth/token?client_id=client_id&client_secret=client_secret&grant_type"
                                  "=client_credentials",
                       json={"access_token": "token"}, status_code=200)
    assert client.http_request(URL_SUFFIX["SYSTEM_STATUS"]) == {"status": True}


def test_http_request_when_error_is_returned(mocker, requests_mock, client):
    """Test case for failure scenario of http_request function"""
    from CofenseTriagev3 import URL_SUFFIX

    mocker.patch('CofenseTriagev3.Client.get_api_token', new=lambda x: "token")

    requests_mock.get(BASE_URL + URL_SUFFIX["SYSTEM_STATUS"], json={"status": True}, status_code=401)
    with pytest.raises(DemistoException) as err:
        client.http_request(URL_SUFFIX["SYSTEM_STATUS"])
    assert str(err.value) == "Authentication error: please provide valid Client ID and Client Secret."


def test_set_token_in_integration_context(client):
    """Test case scenario for setting api_token in integration context"""
    response = client.set_integration_context(AUTHENTICATION_RESP_HEADER)
    assert response == "Bearer " + API_TOKEN


def test_error_while_getting_api_token(client):
    """ Test cases for scenario when there is no access_token in API response """
    with pytest.raises(ValueError, match=MESSAGES["API_TOKEN"]):
        client.set_integration_context({})


@patch('CofenseTriagev3.Client._http_request')
@patch('demistomock.getIntegrationContext')
@patch('demistomock.setIntegrationContext')
def test_get_api_token_when_found_in_integration_context(mocker_set_context, mocker_get_context, mock_request,
                                                         client):
    """ Test cases for scenario when there is api_token and valid_until in integration context."""
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    mocker_set_context.return_value = {}

    mock_request.return_value = AUTHENTICATION_RESP_HEADER

    api_token = client.get_api_token()

    assert api_token == AUTHENTICATION_RESP_HEADER['access_token']


@pytest.mark.parametrize("integration_context", input_data.integration_context)
@patch('demistomock.getIntegrationContext')
@patch('demistomock.setIntegrationContext')
def test_get_api_token_when_not_found_in_integration_context(mocker_set_context, mocker_get_context, client,
                                                             integration_context):
    """ Test cases for scenario when there is no api_token or no valid_until or valid_until < current timestamp in
    integration context """
    mocker_get_context.return_value = integration_context
    mocker_set_context.return_value = {}

    api_token = client.get_api_token()

    assert api_token == bool(False)


@patch(MOCKER_HTTP_METHOD)
def test_cofense_report_list_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-report-list command."""
    from CofenseTriagev3 import cofense_report_list_command

    with open('test_data/report/report_list_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/report/report_list_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/report/report_list.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'page_size': '20'}

    result = cofense_report_list_command(client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_cofense_report_list_command_when_empty_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-report-list command with an empty response."""
    from CofenseTriagev3 import cofense_report_list_command
    mocker_http_request.return_value = {}

    args = {'page_size': '20'}

    result = cofense_report_list_command(client, args)

    assert result.readable_output == "No report(s) were found for the given argument(s)."


@pytest.mark.parametrize("args, err_msg", input_data.list_report_cmd_arg)
def test_validate_list_report_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_report_args
    with pytest.raises(ValueError) as err:
        validate_list_report_args(args)
    assert str(err.value) == err_msg


def test_validate_list_report_args_when_valid_args_are_provided():
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import validate_list_report_args
    # Arguments to be passed
    args = {
        "match_priority": "1",
        "tags": "test",
        "categorization_tags": "snow",
        "report_location": "inbox",
        "filter_by": '{"categorization_tags_any": "test", "match_priority": "2", "location_eq": "processed"'
                     ', "tags_any": "test1", "risk_score_eq": "1,2"}'
    }
    # Expected response
    params = {
        'filter[categorization_tags_any]': 'snow',
        'filter[location]': 'inbox',
        'filter[match_priority]': '1',
        'filter[tags_any]': 'test',
        'filter[risk_score_eq]': '1,2'
    }
    assert validate_list_report_args(args) == params


@pytest.mark.parametrize("reason, status_code, result, expected_err_msg",
                         input_data.exception_handler)
def test_exception_handler(mocker, reason, status_code, result, expected_err_msg):
    """Test cases for the scenario when the response does not have status_code as valid.
     So to ensure that error messages are as per expected error messages."""
    from CofenseTriagev3 import Client

    mocked_response = mocker.Mock()
    mocked_response.reason = reason
    mocked_response.status_code = status_code
    mocked_response.json.return_value = result
    mocked_response.text = result
    with pytest.raises(DemistoException) as err:
        Client.exception_handler(mocked_response)

    assert str(err.value) == expected_err_msg


def test_validate_list_command_args_when_valid_args_are_provided():
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import validate_list_command_args

    # Arguments to be passed
    args = {"page_size": "2",
            "page_number": 3,
            "sort_by": " threat_level, -threat_value, , ",
            "filter_by": "threat_level_eq= ,Malicious, ; updated_at_gt=2020-10-21T20:54:24.185Z, ; ",
            "fields_to_retrieve": " threat_level,threat_type, ,threat_value", "created_at": "2020-10-21T20:54:23.444Z"}

    # Expected response
    params = ({'page[size]': 2, 'page[number]': 3, 'sort': 'threat_level,-threat_value',
               'fields[threat_indicators]': 'threat_level,threat_type,threat_value',
               'filter[created_at_gteq]': dateparser.parse('2020-10-21T20:54:23.444Z')}, ["created_at"])

    assert validate_list_command_args(args, "threat_indicators") == params


@pytest.mark.parametrize("args, params", input_data.valid_dates)
def test_validate_list_command_args_when_valid_dates_are_provided(args, params):
    from CofenseTriagev3 import validate_list_command_args
    result = validate_list_command_args(args, "threat_indicators")
    result = result[0]["filter[created_at_gteq]"].strftime("%Y-%m-%d")

    assert result == params


@pytest.mark.parametrize("args, err_msg", input_data.validate_args)
def test_validate_list_command_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_command_args
    with pytest.raises(ValueError) as err:
        validate_list_command_args(args, "threat_indicators")
    assert str(err.value) == err_msg


def test_cofense_threat_indicator_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-threat-indicator-list command."""

    from CofenseTriagev3 import cofense_threat_indicator_list_command

    response = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_context.json"))

    with open(os.path.join("test_data", "threat_indicator/threat_indicators_command_readable_output.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "298",
            "filter_by": '{"threat_level_eq":"Benign","updated_at_gt":"2020-10-21T20:54:24.185Z",'
                         '"threat_level": "Malicious","threat_type": "URl", "threat_value":'
                         ' "https://example.com/carolann","threat_source": "Generic Threat Intel"}'}
    command_response = cofense_threat_indicator_list_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.ThreatIndicator'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_threat_indicator_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-threat-indicator-list command with an empty response."""

    from CofenseTriagev3 import cofense_threat_indicator_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No threat indicators were found for the given argument(s)."

    # Execute
    command_response = cofense_threat_indicator_list_command(mocked_client, {})

    # Assert
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args", input_data.invalid_args_for_threat_indicator_list)
def test_validate_list_threat_indicator_args_when_invalid_args_are_provided(args):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_threat_indicator_args

    with pytest.raises(ValueError) as err:
        validate_list_threat_indicator_args(args)

    assert str(err.value) == MESSAGES["FILTER"]


def test_cofense_report_download_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-download command."""

    from CofenseTriagev3 import cofense_report_download_command
    result = cofense_report_download_command(mocked_client, args={'id': '4'})
    assert result.get('File') == 'Report ID - 4.eml'


def test_cofense_report_download_command_when_invalid_args_are_provided(mocked_client):
    """Test case scenario for failure execution of cofense-report-download command."""

    from CofenseTriagev3 import cofense_report_download_command
    args = {
        "id": ""
    }
    with pytest.raises(ValueError) as err:
        cofense_report_download_command(mocked_client, args)
    assert str(err.value) == MESSAGES["REQUIRED_ARGUMENT"].format("id")


def test_cofense_report_categorize_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-categorize command."""

    from CofenseTriagev3 import cofense_report_categorize_command
    mocked_client.http_request.return_value.status_code = 204
    response = cofense_report_categorize_command(mocked_client,
                                                 args={'id': '4', "category_id": "3", "categorization_tags": " a,b, c",
                                                       "response_id": "5"})
    assert response.readable_output == "Report with ID = 4 is categorized successfully."


def test_cofense_report_categorize_when_wrong_category_id_is_provided(mocked_client):
    """Test case scenario when wrong category_id is provided for cofense-report-categorize command."""

    from CofenseTriagev3 import cofense_report_categorize_command

    with pytest.raises(ValueError) as err:
        cofense_report_categorize_command(mocked_client, args={'id': '4', "category_id": "3, 34"})
    assert str(err.value) == '"3, 34" is not a valid number'


def test_cofense_report_categorize_when_wrong_report_id_is_assigned(mocked_client):
    """Test case scenario when wrong report_id is provided for cofense-report-categorize command."""

    from CofenseTriagev3 import cofense_report_categorize_command

    with pytest.raises(ValueError) as err:
        cofense_report_categorize_command(mocked_client, args={'id': '4, 3; 5', "category_id": "3"})
    assert str(err.value) == '"4, 3; 5" is not a valid number'


@pytest.mark.parametrize("args, msg", [
    ({"id": "", "category_id": "2"}, "id"),
    ({"id": "1", "category_id": ""}, "category_id")])
def test_cofense_report_categorize_command_when_invalid_args_are_provided(mocked_client, args, msg):
    """Test case scenario for failure execution of cofense-report-download command."""

    from CofenseTriagev3 import cofense_report_categorize_command

    with pytest.raises(ValueError):
        cofense_report_categorize_command(mocked_client, args)


@patch(MOCKER_HTTP_METHOD)
def test_cofense_category_list_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-category-list command."""
    from CofenseTriagev3 import cofense_category_list_command

    with open('test_data/category/category_list_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/category/category_list_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/category/category_list.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'page_size': '2'}

    result = cofense_category_list_command(client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_cofense_category_list_command_when_empty_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-category-list command with an empty response."""
    from CofenseTriagev3 import cofense_category_list_command
    mocker_http_request.return_value = {}

    args = {'page_size': '2'}

    result = cofense_category_list_command(client, args)

    assert result.readable_output == "No categories were found for the given argument(s)."


@pytest.mark.parametrize("args, err_msg", input_data.list_category_cmd_arg)
def test_validate_list_category_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_category_args
    with pytest.raises(ValueError) as err:
        validate_list_category_args(args)
    assert str(err.value) == err_msg


def test_validate_list_category_args_when_valid_args_are_provided():
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import validate_list_category_args
    # Arguments to be passed
    args = {
        "name": "Spam",
        "is_malicious": "true",
        "score": "5,10",
        "filter_by": '{"name":"test", "malicious":"false" ,"score":"15" ,"archived":"false"}'
    }
    # Expected response
    params = {
        'filter[name]': 'Spam',
        'filter[malicious]': 'true',
        'filter[score]': '5,10',
        'filter[archived]': 'false',
    }
    assert validate_list_category_args(args) == params


def test_validate_fetch_incident_parameters_when_valid_params_are_provided():
    """Test case scenario when the parameters provided are valid."""

    from CofenseTriagev3 import validate_fetch_incidents_parameters
    # Parameters passed
    params = {
        "max_fetch": 15,
        "first_fetch": "03/06/2021",
        "match_priority": ['0', '1', '2'],
        "tags": "test",
        "categorization_tags": "snow",
        "mailbox_location": ["Inbox", "Processed"],
        "filter_by": '{"categorization_tags_any":"test","match_priority":"2","tags_any":"test1","risk_score_eq":"1,2"}'
    }
    # Expected response
    fetch_params = {
        'page[size]': 15,
        'filter[updated_at_gteq]': '2021-03-06T00:00:00.000000Z',
        'filter[categorization_tags_any]': 'snow',
        'filter[location]': 'Inbox,Processed',
        'filter[match_priority]': '0,1,2',
        'filter[tags_any]': 'test',
        'filter[risk_score_eq]': '1,2'
    }
    assert validate_fetch_incidents_parameters(params) == fetch_params


@pytest.mark.parametrize("args, err_msg", input_data.fetch_incident_params)
def test_validate_fetch_incident_parameters_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the parameters provided are not valid."""

    from CofenseTriagev3 import validate_fetch_incidents_parameters
    with pytest.raises(ValueError) as err:
        validate_fetch_incidents_parameters(args)
    assert str(err.value) == err_msg


@patch("demistomock.integrationInstance", create=True)
@patch(MOCKER_HTTP_METHOD)
def test_fetch_incidents_when_valid_response_is_returned(mocker_http_request, mocker_integration_instance, client):
    """Test case scenario for successful execution of fetch_incident."""
    from CofenseTriagev3 import fetch_incidents
    response = util_load_json(
        os.path.join("test_data", "fetch_incidents/fetch_incidents_response.json"))

    mocker_http_request.return_value = response
    mocker_integration_instance.return_value = "Cofense Triage v3_instance_1"

    context_output = util_load_json(
        os.path.join("test_data", "fetch_incidents/fetch_incidents.json"))

    params = {'max_fetch': '2', 'first_fetch': '1 year', 'mirror_direction': 'Incoming'}

    _, incidents = fetch_incidents(client, {}, params)

    assert incidents == context_output["incidents"]


def test_cofense_url_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-url-list command."""

    from CofenseTriagev3 import cofense_url_list_command

    response = util_load_json(
        os.path.join("test_data", "url/list_url_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "url/list_url_command_context.json"))

    with open(os.path.join("test_data", "url/list_url_command_readable_output.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "15", "filter_by": '{"risk_score_eq":" 1,2", "updated_at_gt":"2020-10-21T20:54:24.185Z"}',
            "risk_score": "1,2,3"}
    command_response = cofense_url_list_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.Url'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_url_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-url-list command with an empty response."""

    from CofenseTriagev3 import cofense_url_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No URLs were found for the given argument(s)."

    # Execute
    command_response = cofense_url_list_command(mocked_client, {})

    # Assert
    assert command_response.readable_output == readable_output


def test_validate_list_urls_args_when_invalid_args_are_provided():
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_url_args

    args = {
        "risk_score": "1 , -2, abc"
    }

    with pytest.raises(ValueError) as err:
        validate_list_url_args(args)
    assert str(err.value) == '"abc" is not a valid number'


@patch(MOCKER_HTTP_METHOD)
def test_cofense_rule_list_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-rule-list command."""
    from CofenseTriagev3 import cofense_rule_list_command

    with open('test_data/rule/rule_list_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/rule/rule_list_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/rule/rule_list.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'page_size': '2'}

    result = cofense_rule_list_command(client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_cofense_rule_list_command_when_empty_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-rule-list command with an empty response."""
    from CofenseTriagev3 import cofense_rule_list_command
    mocker_http_request.return_value = {}

    args = {'page_size': '2'}

    result = cofense_rule_list_command(client, args)

    assert result.readable_output == "No rule(s) were found for the given argument(s)."


@pytest.mark.parametrize("args, err_msg", input_data.list_rule_cmd_arg)
def test_validate_list_rule_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_rule_args
    with pytest.raises(ValueError) as err:
        validate_list_rule_args(args)
    assert str(err.value) == err_msg


def test_validate_list_rule_args_when_valid_args_are_provided():
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import validate_list_rule_args
    # Arguments to be passed
    args = {
        "name": "MX-Testing",
        "priority": "1",
        "tags": "Test",
        "scope": "Email",
        "active": "true",
        "author_name": "dummy",
        "rule_context": "Phishing Tactic",
        "filter_by": '{"name":"Test","rule_context":"Unknown"}'
    }
    # Expected response
    params = {
        'filter[name]': 'MX-Testing',
        'filter[priority]': '1',
        'filter[tags_any]': 'Test',
        'filter[scope]': 'Email',
        'filter[active]': 'true',
        'filter[author_name]': 'dummy',
        'filter[rule_context]': 'Phishing Tactic'
    }
    assert validate_list_rule_args(args) == params


def test_cofense_threat_indicator_create_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-threat-indicator-create command."""

    from CofenseTriagev3 import cofense_threat_indicator_create_command

    response = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_context.json"))

    with open(os.path.join("test_data", "threat_indicator/threat_indicators_command_readable_output.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"threat_level": "Malicious", "threat_type": "URl", "threat_value": "https://example.com/carolann",
            "threat_source": "Generic Threat Intel"}
    command_response = cofense_threat_indicator_create_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.ThreatIndicator'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


@pytest.mark.parametrize("args, err_msg", input_data.create_threat_indicators_cmd_arg)
def test_validate_create_threat_indicator_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_create_threat_indicator_args

    with pytest.raises(ValueError) as err:
        validate_create_threat_indicator_args(args)
    assert str(err.value) == err_msg


@pytest.mark.parametrize("args, params, err_msg", input_data.check_fetch_incident_configuration_args)
def test_check_fetch_incident_configuration_when_invalid_args_are_provided(args, params, err_msg):
    """Test case scenario when the parameters provided are not valid."""

    from CofenseTriagev3 import check_fetch_incident_configuration
    with pytest.raises(ValueError) as err:
        check_fetch_incident_configuration(args, params)
    assert str(err.value) == err_msg


def test_cofense_integration_submission_get_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-integration-submission-get command."""

    from CofenseTriagev3 import cofense_integration_submission_get_command

    response = util_load_json(
        os.path.join("test_data", "integration_submission/integration_submission_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "integration_submission/integration_submission_context.json"))

    with open(os.path.join("test_data", "integration_submission/integration_submission_command_readable_output.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "190", "type": "attachment_payloads"}
    command_response = cofense_integration_submission_get_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.IntegrationSubmission'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_integration_submission_get_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-integration-submission-get with an empty response."""

    from CofenseTriagev3 import cofense_integration_submission_get_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No integration submissions were found for the given argument(s)."

    # Execute
    command_response = cofense_integration_submission_get_command(mocked_client, {"id": "15"})

    # Assert
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args, err_msg", input_data.get_integration_submission_cmd_arg)
def test_cofense_integration_submission_get_command_when_invalid_args_are_provided(mocked_client, args, err_msg):
    """Test case scenario for failure execution of cofense-integration-submission-get."""

    from CofenseTriagev3 import cofense_integration_submission_get_command
    with pytest.raises(ValueError) as err:
        cofense_integration_submission_get_command(mocked_client, args)
    assert str(err.value) == err_msg


def test_cofense_reporter_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-reporter-list command."""

    from CofenseTriagev3 import cofense_reporter_list_command

    response = util_load_json(
        os.path.join("test_data", "reporter/reporter_list_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "reporter/reporter_list_context.json"))

    with open(os.path.join("test_data", "reporter/reporter_list.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "4", "filter_by": '{"reports_count_gt": "10","updated_at_gt":"2020-10-21T20:54:24.185Z"}',
            "reputation_score": "2,3,4", "vip": "true", "email": "no-reply@xforce.ibmcloud.com"}

    command_response = cofense_reporter_list_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.Reporter'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_reporter_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-reporter-list command with an empty response."""

    from CofenseTriagev3 import cofense_reporter_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No reporters were found for the given argument(s)."

    # Execute
    command_response = cofense_reporter_list_command(mocked_client, {})

    # Assert
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args, err_msg", input_data.list_reporter_cmd_arg)
def test_validate_list_reporter_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_reporter_args

    with pytest.raises(ValueError) as err:
        validate_list_reporter_args(args)

    assert str(err.value) == err_msg


def test_cofense_attachment_payload_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-attachment-payload-list command."""

    from CofenseTriagev3 import cofense_attachment_payload_list_command

    response = util_load_json(
        os.path.join("test_data", "attachment_payload/attachment_payload_list_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "attachment_payload/attachment_payload_list_context.json"))

    with open(os.path.join("test_data", "attachment_payload/attachment_payload_list.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "4", "filter_by": '{"updated_at_gt" :"2020-10-21T20:54:24.185Z"}', "risk_score": "1,2"}

    command_response = cofense_attachment_payload_list_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.AttachmentPayload'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_attachment_payload_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-attachment-payload-list command with an empty response."""

    from CofenseTriagev3 import cofense_attachment_payload_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No attachment payloads were found for the given argument(s)."

    # Execute
    command_response = cofense_attachment_payload_list_command(mocked_client, {})

    # Assert
    assert command_response.readable_output == readable_output


def test_validate_list_attachment_payload_args_when_invalid_args_are_provided():
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_attachment_payload_args

    args = {
        "risk_score": "1 , -2, x"
    }

    with pytest.raises(ValueError) as err:
        validate_list_attachment_payload_args(args)
    assert str(err.value) == '"x" is not a valid number'


@patch(MOCKER_HTTP_METHOD)
def test_cofense_comment_list_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-comment-list command."""
    from CofenseTriagev3 import cofense_comment_list_command

    mock_response = util_load_json('test_data/comment/comment_list_response.json')
    mocker_http_request.return_value = mock_response

    expected_res = util_load_json('test_data/comment/comment_list_context.json')

    with open('test_data/comment/comment_list_hr.md') as data:
        expected_hr = data.read()

    args = {'page_size': '20'}

    result = cofense_comment_list_command(client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_cofense_comment_list_command_when_empty_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-comment-list command with an empty response."""
    from CofenseTriagev3 import cofense_comment_list_command
    mocker_http_request.return_value = {}

    args = {'page_size': '20'}

    result = cofense_comment_list_command(client, args)

    assert result.readable_output == "No comment(s) were found for the given argument(s)."


@pytest.mark.parametrize("args, err_msg", input_data.list_comment_cmd_arg)
def test_validate_list_comment_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_comment_list_args
    with pytest.raises(ValueError) as err:
        validate_comment_list_args(args)
    assert str(err.value) == err_msg


@patch(MOCKER_HTTP_METHOD)
def test_get_remote_data(mocker_http_request, client):
    """Test case scenario for successful execution of get-remote-data command"""
    from CofenseTriagev3 import get_remote_data_command
    raw_response = util_load_json(
        os.path.join("test_data", "fetch_incidents/get_remote_data_command.json"))
    response = util_load_json(
        os.path.join("test_data", "fetch_incidents/get_remote_data_command_response.json"))
    mocker_http_request.return_value = raw_response
    args = {
        'id': 4,
        'lastUpdate': "2021-05-17T05:11:51.667Z"
    }

    command_response = get_remote_data_command(client, args)
    assert command_response.mirrored_object == response


def test_cofense_threat_indicator_update_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-threat-indicator-update command."""

    from CofenseTriagev3 import cofense_threat_indicator_update_command

    response = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "threat_indicator/threat_indicators_command_context.json"))

    with open(os.path.join("test_data", "threat_indicator/threat_indicators_command_readable_output.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"threat_level": "Malicious", "id": "298", "threat_source": "Generic Threat Intel"}
    command_response = cofense_threat_indicator_update_command(mocked_client, args)

    # Assert
    assert command_response.outputs_prefix == 'Cofense.ThreatIndicator'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


@pytest.mark.parametrize("args, err_msg", input_data.update_threat_indicators_cmd_arg)
def test_validate_update_threat_indicator_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_update_threat_indicator_args

    with pytest.raises(ValueError) as err:
        validate_update_threat_indicator_args(args)
    assert str(err.value) == err_msg


@patch(MOCKER_HTTP_METHOD)
def test_cofense_cluster_list_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-cluster-list command."""
    from CofenseTriagev3 import cofense_cluster_list_command

    with open('test_data/cluster/cluster_list_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/cluster/cluster_list_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/cluster/cluster_list.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'page_size': '2'}

    result = cofense_cluster_list_command(client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_cofense_cluster_list_command_when_empty_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-cluster-list command with an empty response."""
    from CofenseTriagev3 import cofense_cluster_list_command
    mocker_http_request.return_value = {}

    args = {'page_size': '2'}

    result = cofense_cluster_list_command(client, args)

    assert result.readable_output == "No cluster(s) were found for the given argument(s)."


@pytest.mark.parametrize("args, err_msg", input_data.list_cluster_cmd_arg)
def test_validate_list_cluster_args_when_invalid_args_are_provided(args, err_msg):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import validate_list_cluster_args
    with pytest.raises(ValueError) as err:
        validate_list_cluster_args(args)
    assert str(err.value) == err_msg


def test_validate_list_cluster_args_when_valid_args_are_provided():
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import validate_list_cluster_args
    # Arguments to be passed
    args = {
        "match_priority": "2",
        "tags": " ",
        "total_reports_count": "15",
        "filter_by": "{\"match_priority\":\"4\",\"tags_any\":\"clusterTest\",\"total_reports_count\":\"20\"}"
    }
    # Expected response
    params = {
        'filter[match_priority]': '2',
        'filter[tags_any]': 'clusterTest',
        'filter[total_reports_count]': '15'
    }
    assert validate_list_cluster_args(args) == params


@patch(MOCKER_HTTP_METHOD)
def test_get_modified_remote_data(mocker_http_request, client):
    """Test case scenario for successful execution of get-modified-remote-data command"""
    from CofenseTriagev3 import get_modified_remote_data_command

    raw_response = util_load_json(os.path.join("test_data", "fetch_incidents/get_modified_remote_data_command.json"))

    mocker_http_request.return_value = raw_response
    args = {
        'lastUpdate': "2021-05-17T05:11:51.667Z"
    }

    command_response = get_modified_remote_data_command(client, args)
    assert command_response.modified_incident_ids == ['4', '6']


@patch(MOCKER_HTTP_METHOD)
def test_cofense_report_image_download_command_when_valid_response_is_returned(mocker_http_request, client):
    """Test case scenario for successful execution of cofense-report-image-download command."""

    from CofenseTriagev3 import cofense_report_image_download_command

    mocker_http_request.return_value = b'\u2715'

    result = cofense_report_image_download_command(client, args={'id': '4'})
    assert result.get('File') == 'Report ID - 4.png'


@pytest.mark.parametrize("args, err_msg", input_data.report_image_download)
def test_cofense_report_image_download_command_when_invalid_args_are_provided(mocked_client, args, err_msg):
    """Test case scenario for failure execution of cofense-report-image-download command."""

    from CofenseTriagev3 import cofense_report_image_download_command

    with pytest.raises(ValueError) as err:
        cofense_report_image_download_command(mocked_client, args)
    assert str(err.value) == err_msg


def test_cofense_report_attachment_payload_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-attachment-payload-list command."""

    from CofenseTriagev3 import cofense_report_attachment_payload_list_command

    response = util_load_json(
        os.path.join("test_data", "report_attachment_payload/report_attachment_payload_list_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "report_attachment_payload/report_attachment_payload_list_context.json"))

    with open(os.path.join("test_data", "report_attachment_payload/report_attachment_payload_list.md")) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "4720", "updated_at": "2020-10-21T20:30:24.185Z"}

    command_response = cofense_report_attachment_payload_list_command(mocked_client, args)
    # Assert
    assert command_response.outputs_prefix == 'Cofense.AttachmentPayload'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_report_attachment_payload_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-attachment-payload-list command with an empty
    response. """

    from CofenseTriagev3 import cofense_report_attachment_payload_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No attachment payloads were found for the given argument(s)."

    # Execute
    command_response = cofense_report_attachment_payload_list_command(mocked_client, {'id': 'test'})
    # Assert
    assert command_response.readable_output == readable_output


def test_validate_report_attachment_payload_list_args_when_invalid_args_are_provided(mocked_client):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import MESSAGES, cofense_report_attachment_payload_list_command

    args = {
        "id": None,
    }

    with pytest.raises(ValueError) as err:
        cofense_report_attachment_payload_list_command(mocked_client, args)
    assert str(err.value) == MESSAGES['REQUIRED_ARGUMENT'].format('id')


def test_cofense_report_attachment_list_command_when_invalid_args_are_provided(mocked_client):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import MESSAGES, cofense_report_attachment_list_command

    args = {
        "id": None,
    }

    with pytest.raises(ValueError) as err:
        cofense_report_attachment_list_command(mocked_client, args)
    assert str(err.value) == MESSAGES['REQUIRED_ARGUMENT'].format('id')


def test_cofense_report_attachment_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-attachment-list command with an empty
    response. """

    from CofenseTriagev3 import cofense_report_attachment_list_command
    mocked_client.http_request.return_value = {"data": {}}
    readable_output = "No attachments were found for the given argument(s)."

    # Execute
    command_response = cofense_report_attachment_list_command(mocked_client, {'id': 'test'})
    # Assert
    assert command_response.readable_output == readable_output


def test_cofense_report_attachment_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of cofense-report-attachment-list command."""

    from CofenseTriagev3 import cofense_report_attachment_list_command

    response = util_load_json(
        os.path.join("test_data", os.path.join("report_attachment", "report_attachment_list_response.json")))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", os.path.join("report_attachment", "report_attachment_list_context.json")))

    with open(os.path.join("test_data", os.path.join("report_attachment", "report_attachment_list.md"))) as f:
        readable_output = f.read()

    # Execute
    args = {"id": "30339", "updated_at": "2020-10-21T20:30:24.185Z"}

    command_response = cofense_report_attachment_list_command(mocked_client, args)
    # Assert
    assert command_response.outputs_prefix == 'Cofense.Attachment'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_cofense_report_attachment_download_command_when_invalid_args_are_provided(mocked_client):
    """Test case scenario when the arguments provided are not valid."""

    from CofenseTriagev3 import MESSAGES, cofense_report_attachment_download_command

    args = {
        "id": None,
    }

    with pytest.raises(ValueError) as err:
        cofense_report_attachment_download_command(mocked_client, args)
    assert str(err.value) == MESSAGES['REQUIRED_ARGUMENT'].format('id')


def test_cofense_report_attachment_download_command_when_valid_args_are_provided(mocked_client):
    """Test case scenario when the arguments provided are valid."""

    from CofenseTriagev3 import cofense_report_attachment_download_command

    with open(os.path.join("test_data", os.path.join("report_attachment", "report_attachment_download_response.xml"))) as f:
        response = f.read()

    # Mock response with the valid headers.
    class MockResponse:
        content = response
        headers = {"Content-Disposition": """attachment; filename="xl%2FordStrings.xml"; filename*=UTF-8''xl%2FordStrings.xml"""}

    mocked_client.http_request.return_value = MockResponse

    args = {"id": "30339"}
    command_response = cofense_report_attachment_download_command(mocked_client, args)

    # Assert for file name based on the header.
    assert command_response["File"] == 'xl/ordStrings.xml'

    # Mock response with empty headers
    MockResponse.headers = {}

    mocked_client.http_request.return_value = MockResponse

    args = {"id": "30339"}
    command_response = cofense_report_attachment_download_command(mocked_client, args)

    # Assert for file name based on the attachment ID.
    assert command_response["File"] == 'Attachment ID - 30339'

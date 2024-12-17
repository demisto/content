import json
import time
import unittest
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import dateparser
import pytest
import requests
from requests import Response
from requests.exceptions import MissingSchema, InvalidSchema

from BmcHelixRemedyForce import Client, MESSAGES, date_to_timestamp, HR_MESSAGES, get_request_params, \
    bmc_remedy_create_service_request_command, remove_prefix, update_incident, OUTPUT_PREFIX, DISPLAY_DATE_FORMAT
from BmcHelixRemedyForce import bmc_remedy_impact_details_get_command, bmc_remedy_service_offering_details_get_command, \
    bmc_remedy_category_details_get_command, INCIDENT_CATEGORY_OBJECT, SERVICE_REQUEST_CATEGORY_OBJECT, \
    POSSIBLE_CATEGORY_TYPES, bmc_remedy_broadcast_details_get_command, URL_SUFFIX
from BmcHelixRemedyForce import bmc_remedy_template_details_get_command, bmc_remedy_asset_details_get_command, \
    bmc_remedy_account_details_get_command, bmc_remedy_urgency_details_get_command, get_service_request_details

from BmcHelixRemedyForce import get_valid_arguments, bmc_remedy_update_service_request_command, DemistoException, \
    prepare_outputs_for_get_service_request, bmc_remedy_service_request_get_command

INCIDENT_TEST_DATA_FILE = './TestData/incident_data.json'


def prepare_expected_response_for_fetch_incidents():
    """
    Prepares expected incidents list from response.
    :return: raw response, incident list.
    """
    from BmcHelixRemedyForce import remove_empty_elements, prepare_date_or_markdown_fields_for_fetch_incidents
    with open('./TestData/fetch_incident_response.json') as f:
        expected_response = json.load(f)
    incidents = expected_response['records'][0]
    prepare_date_or_markdown_fields_for_fetch_incidents(incidents)
    incidents['Bmc Severity'] = 4
    # expected incidents.
    expected_incidents = [{
        'name': 'SR19657',
        'rawJSON': json.dumps(remove_empty_elements(incidents)),
    }]
    return expected_response, expected_incidents


def fetch_dummy_response():
    """To mock requests.response object it is a dummy method."""
    with open('./TestData/service_request.json', encoding='utf-8') as f:
        data = json.load(f)
    return data


def fetch_dummy_get_impacts():
    """To mock requests.response object for fetch impacts command."""
    with open('./TestData/get_impacts.json', encoding='utf-8') as f:
        data = json.load(f)
    return data


def fetch_dummy_categories():
    """To mock requests.response object for fetch categories command."""
    with open('./TestData/get_categories.json', encoding='utf-8') as f:
        data = json.load(f)
    return data


def fetch_dummy_broadcasts():
    """To mock requests.response object for fetch broadcasts command."""
    with open('./TestData/get_broadcasts.json', encoding='utf-8') as f:
        data = json.load(f)
    return data


def get_failure_sr():
    """To mock requests.response object it is a dummy method."""
    return {
        "Success": False
    }


def fetch_empty_dummy_response():
    """To mock requests.response object it is a dummy method."""
    return {}


def mock_incident_success_response(method, *args, **kwargs):
    with open(INCIDENT_TEST_DATA_FILE) as f:
        api_response = json.load(f)

    if method == 'POST':
        return api_response['create_success']
    elif method == 'PATCH':
        patch_response = Response()
        patch_response.status_code = 204
        return patch_response


def mock_incident_warning_response(method, *args, **kwargs):
    with open(INCIDENT_TEST_DATA_FILE) as f:
        api_response = json.load(f)

    if method == 'POST':
        return api_response['create_success']
    elif method == 'PATCH':
        raise DemistoException("SOME_ISSUE_WITH_UPDATE")


def get_no_content_success_response():
    resp = Response()
    resp.status_code = 204
    return resp


class BmcHelixRemedyForceTestCase(unittest.TestCase):
    client = Client(
        base_url='https://sample.api.com',  # Compliant
        verify=False,
        proxy=False,
        username='username',
        password='password',
        request_timeout=60)

    with open('./TestData/update_service_request.json', encoding='utf-8') as f:
        data = json.load(f)
    with open("TestData/get_remedy_command_return_null_result.json", encoding='utf-8') as f:
        expected_return_null_result = json.load(f)
    with open("TestData/dummy_categories.json", encoding='utf-8') as f:
        dummy_categories = json.load(f)
    with open("TestData/dummy_broadcasts.json", encoding='utf-8') as f:
        dummy_broadcasts = json.load(f)
    with open("TestData/get_service_request.json", encoding='utf-8') as f:
        get_service_request_response = json.load(f)
    incorrect_args = data["incorrect_args"]
    correct_args = data["correct_args"]
    valid_session_id = 'SOME_VALID_SESSION_ID'
    msg_for_invalid_format = '{}'.format(MESSAGES["INVALID_DATA_FORMAT"]).format(
        'additional_fields')
    expected_zero_record = {'totalSize': 0, 'done': True, 'records': []}

    @patch('demistomock.getIntegrationContext')
    @patch('BmcHelixRemedyForce.Client.get_salesforce_session')
    @patch('demistomock.setIntegrationContext')
    def test_get_session_id_valid_credentials(self, mocker_set_context, mocker_session, mocker_get_context):
        """
        Given no integration context or integration context contains an expired session id
        when credentials are valid
        then a valid session id should be returned and integration context should be set once.

        :param mocker_get_context: mocker object for getting integration context
        :param mocker_session: mocker object for getting salesforce session
        :param mocker_set_context: mocker object for setting integration context
        :return: None
        """
        mocker_get_context.return_value = {}
        mocker_set_context.return_value = {}

        mocked_positive_response = Response()
        mocked_positive_response.status_code = 200
        with open('./TestData/successful_login_response.txt', encoding='utf-8') as f:
            mocked_positive_response._content = f.read()
        mocker_session.return_value = mocked_positive_response

        session_id = self.client.get_session_id()

        assert session_id == self.valid_session_id
        assert mocker_set_context.call_count == 1

    @patch('demistomock.getIntegrationContext')
    @patch('BmcHelixRemedyForce.Client.get_salesforce_session')
    @patch('demistomock.setIntegrationContext')
    def test_get_session_id_invalid_credentials(self, mocker_set_context, mocker_session, mocker_get_context):
        """
        Given no integration context
        when credentials are invalid
        then a demisto exception should be raised and integration context should not be set.

        :param mocker_get_context: mocker object for getting integration context
        :param mocker_session: mocker object for getting salesforce session
        :param mocker_set_context: mocker object for setting integration context
        :return: None
        """
        mocker_get_context.return_value = {}
        mocker_set_context.return_value = {}

        mocked_negative_response = Response()
        mocked_negative_response.status_code = 500
        mocker_session.return_value = mocked_negative_response

        with pytest.raises(DemistoException):
            self.client.get_session_id()

        assert mocker_set_context.call_count == 0

    @patch('demistomock.getIntegrationContext')
    @patch('BmcHelixRemedyForce.Client.get_salesforce_session')
    @patch('demistomock.setIntegrationContext')
    def test_get_session_id_valid_context(self, mocker_set_context, mocker_session, mocker_get_context):
        """
        Given integration context
        when session id in the context is valid
        then a valid session id should be returned, login attempt should not be made and integration
        context should not be set.

        :param mocker_get_context: mocker object for getting integration context
        :param mocker_session: mocker object for getting salesforce session
        :param mocker_set_context: mocker object for setting integration context
        :return: None
        """
        some_future_time = time.time() + 2700

        mocker_get_context.return_value = {
            'sessionId': self.valid_session_id,
            'validUntil': some_future_time
        }
        mocker_set_context.return_value = {}
        mocker_session.return_value = {}

        session_id = self.client.get_session_id()

        assert session_id == self.valid_session_id
        assert mocker_session.call_count == 0
        assert mocker_set_context.call_count == 0

    @patch('CommonServerPython.BaseClient._http_request')
    def test_get_salesforce_session_success(self, mocker_http_request):
        """
        Given working authentication API
        When method for getting salesforce session is called
        Then valid authentication response data should be returned

        :param mocker_http_request:
        :return: None
        """
        mocked_http_response = Response()
        mocked_http_response.status_code = 200
        mocker_http_request.return_value = mocked_http_response

        assert self.client.get_salesforce_session().ok

    @patch('CommonServerPython.BaseClient._http_request')
    def test_get_salesforce_session_failure(self, mocker_http_request):
        """
        Given failing authentication API
        When method for getting salesforce session is called
        Then some exception should be thrown

        :param mocker_http_request:
        :return: None
        """

        mocker_http_request.side_effect = DemistoException('some error!')

        with pytest.raises(DemistoException):
            self.client.get_salesforce_session()

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_success_response(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When http response is successful
        Then json response content should be returned

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id

        dummy_response = {'test': 15}

        mocked_positive_response = Response()
        mocked_positive_response.status_code = 200
        mocked_positive_response._content = json.dumps(dummy_response).encode('utf-8')
        mocker_http_request.return_value = mocked_positive_response

        response = self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert response == dummy_response

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_success_response_no_content(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When http response is successful with 204
        Then response should be returned as it is

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id

        mocked_positive_response = Response()
        mocked_positive_response.status_code = 204
        mocker_http_request.return_value = mocked_positive_response

        response = self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert response == mocked_positive_response

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch('demistomock.getIntegrationContext')
    @patch('demistomock.setIntegrationContext')
    def test_http_request_unauthorized_response(self, mocker_set_context, mocker_get_context, mocker_get_session_id,
                                                mocker_http_request):
        """
        Given the overridden http request method
        When response is unauthorized
        Then integration context should be set and DemistoException should be raised

        :param mocker_set_context: mocker object for setting integration context
        :param mocker_get_context: mocker object for getting integration context
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = 'SOME_INVALID_SESSION_ID'
        mocker_get_context.return_value = {}
        mocker_set_context.return_value = {}

        mocked_unauthorized_response = Response()
        mocked_unauthorized_response.status_code = 401  # Unauthorized response
        mocker_http_request.return_value = mocked_unauthorized_response

        with pytest.raises(DemistoException):
            self.client.http_request('GET', 'SOME_URL_SUFFIX')

        assert mocker_get_context.call_count == 1
        assert mocker_set_context.call_count == 1

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_missing_schema(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there is missing schema error making the http call
        Then DemistoException should be raised with proper error message

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocker_http_request.side_effect = MissingSchema('missing schema')

        with pytest.raises(DemistoException) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX", headers={'test': 'test2'})

        assert str(e.value) == MESSAGES['MISSING_SCHEMA_ERROR']

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_invalid_schema(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there is invalid schema error making the http call
        Then DemistoException should be raised with proper error message

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocker_http_request.side_effect = InvalidSchema('invalid schema')

        with pytest.raises(DemistoException) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert str(e.value) == MESSAGES['INVALID_SCHEMA_ERROR']

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_proxy_error(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there is proxy error while making the http call
        Then ConnectionError should be raised with proper error message

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocker_http_request.side_effect = DemistoException('Proxy Error')

        with pytest.raises(ConnectionError) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert str(e.value) == MESSAGES['PROXY_ERROR']

    @patch('CommonServerPython.handle_proxy')
    def test_http_request_proxy_blank_error(self, handle_proxy):
        """
        Given proxy=true
        When there is proxy set to blank in configuration
        Then Value Error should be raised with proper error message

        :param handle_proxy: mock of handle proxy method.
        :return: None
        """
        handle_proxy.return_value = {}
        with pytest.raises(ValueError) as e:
            Client(base_url='https://sample.api.com',  # Compliant
                   verify=False,
                   proxy=True,
                   username='username',
                   password='password',
                   request_timeout=60)
        assert str(e.value) == MESSAGES['PROXY_ERROR']

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_connection_error(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there is 'ConnectionError'  or 'ConnectTimeout' error while making the http call
        Then ConnectionError should be raised with proper error message

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocker_http_request.side_effect = DemistoException('ConnectionError or ConnectTimeout')

        with pytest.raises(ConnectionError) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert str(e.value) == MESSAGES['CONNECTION_ERROR']

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_other_demisto_exception(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there some error while making the http call
        Then DemistoException should be raised with proper error message

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocker_http_request.side_effect = DemistoException('Some other error!')

        with pytest.raises(DemistoException) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert str(e.value) == 'Some other error!'

    @patch('CommonServerPython.BaseClient._http_request')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    def test_http_request_bad_request(self, mocker_get_session_id, mocker_http_request):
        """
        Given overridden http request method
        When there bad request response while making the http call
        Then DemistoException should be raised with proper error message from the http response

        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_http_request: mocker object for making http request call
        :return: None
        """

        response_data = [
            {
                "message": "custom bad request error message"
            }
        ]

        mocker_get_session_id.return_value = self.valid_session_id
        mocked_http_response = Response()
        mocked_http_response.status_code = 400
        mocked_http_response._content = json.dumps(response_data).encode('utf-8')
        mocker_http_request.return_value = mocked_http_response

        with pytest.raises(DemistoException) as e:
            self.client.http_request("GET", "SOME_URL_SUFFIX")

        assert "custom bad request error message" in str(e.value)

    @patch('demistomock.params')
    def test_get_request_timeout_valid(self, mocker_params):
        """
        Given working integration configuration parameters
        When parameter value of request_timeout is valid
        Then valid request_timeout value should be returned

        :return: None
        """
        mocker_params.return_value = {
            "request_timeout": 25
        }

        from BmcHelixRemedyForce import get_request_timeout
        assert get_request_timeout() == 25

    @patch('demistomock.params')
    def test_get_request_timeout_invalid(self, mocker_params):
        """
        Given working integration configuration parameters
        When parameter value of request_timeout is invalid
        Then ValueError should be raised

        :return: None
        """
        mocker_params.return_value = {
            "request_timeout": '25asd'
        }

        from BmcHelixRemedyForce import get_request_timeout
        with pytest.raises(ValueError):
            assert get_request_timeout()

    @patch('demistomock.params')
    def test_get_request_timeout_negative(self, mocker_params):
        """
        Given working integration configuration parameters
        When parameter value of request_timeout is negative
        Then ValueError should be raised

        :return: None
        """
        mocker_params.return_value = {
            "request_timeout": -25
        }

        from BmcHelixRemedyForce import get_request_timeout
        with pytest.raises(ValueError):
            assert get_request_timeout()

    @patch('demistomock.params')
    def test_get_request_timeout_exceeding(self, mocker_params):
        """
        Given working integration configuration parameters
        When parameter value of request_timeout exceeds maximum allowed limit
        Then ValueError should be raised

        :return: None
        """
        mocker_params.return_value = {
            "request_timeout": 92233720361
        }

        from BmcHelixRemedyForce import get_request_timeout
        with pytest.raises(ValueError):
            assert get_request_timeout()

    @patch('BmcHelixRemedyForce.get_service_request_details')
    @patch('demistomock.command')
    @patch('BmcHelixRemedyForce.Client.http_request')
    @patch('BmcHelixRemedyForce.return_results')
    @patch('demistomock.params')
    def test_main_success(self, mocker_params, mocker_return_results,
                          mocker_http_request, mocker_command, mocker_sr_results):
        """
        Given working service integration
        When test-module is called from main()
        Then return_results should be called with 'ok'

        :param mocker_params: mocker object for params
        :param mocker_return_results: mocker object for CommonServerPython.return_results
        :param mocker_http_request: mocker object for Client.http_request
        :param mocker_command: mocker object for demistomock.command
        :return: None
        """

        mocker_sr_results.return_value = {}
        mocker_http_request.return_value = None
        mocker_return_results.return_value = None

        mocker_command.return_value = 'test-module'

        mocker_params.return_value = {
            'request_timeout': 50,
            'credentials': {},
            'url': 'some_base_url',
            'first_fetch': '10 hours'
        }

        from BmcHelixRemedyForce import main
        main()

        mocker_return_results.assert_called_with('ok')

    @patch('demistomock.error')
    @patch('demistomock.command')
    @patch('BmcHelixRemedyForce.Client.http_request')
    @patch('BmcHelixRemedyForce.return_error')
    @patch('demistomock.params')
    def test_main_failure(self, mocker_params, mocker_return_error, mocker_http_request, mocker_command, mocker_error):
        """
        Given non-working service integration
        When test-module is called from main()
        Then return_error should be called with some error details

        :param mocker_params: mocker object for params
        :param mocker_return_error: mocker object for return_error method
        :param mocker_http_request: mocker object for Client.http_request
        :param mocker_command: mocker object for demistomock.command
        :param mocker_error: mocker object for demistomock.error
        :return: None
        """

        mocker_http_request.side_effect = DemistoException('Some error!')
        mocker_return_error.return_value = None

        mocker_command.return_value = 'test-module'

        mocker_params.return_value = {
            'request_timeout': 50,
            'credentials': {},
            'url': 'some_base_url'
        }

        from BmcHelixRemedyForce import main
        main()

        assert mocker_error.called
        assert mocker_return_error.called

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_service_request_definition_get_command_success(self, mocker_http_request):
        """
        Given working service integration
        When bmc_remedy_service_request_definition_get command is called
        Then expected row response should be processed and context data should be set with the same number of items in
            the results field of the response

        :param mocker_http_request: Mocker object for http request call
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.process_single_service_request_definition = MagicMock(
            side_effect=BmcHelixRemedyForce.process_single_service_request_definition)
        BmcHelixRemedyForce.process_single_service_request_definition_output = MagicMock(
            side_effect=BmcHelixRemedyForce.process_single_service_request_definition_output)
        success_resp = {'Success': True, 'Result': [{}, {}]}
        mocker_http_request.return_value = success_resp

        command_resp = BmcHelixRemedyForce.bmc_remedy_service_request_definition_get_command(self.client, {})

        assert command_resp.raw_response == success_resp
        assert len(command_resp.outputs) == 2
        assert BmcHelixRemedyForce.process_single_service_request_definition.call_count == 2
        assert BmcHelixRemedyForce.process_single_service_request_definition_output.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_service_request_definition_get_command_failure(self, mocker_http_request):
        """
        Given non-working service integration
        When bmc_remedy_service_request_definition_get command is called
        Then Demisto exception should be thrown

        :param mocker_http_request: Mocker object for http request call
        :return: None
        """
        failure_resp = {'Success': False}
        mocker_http_request.return_value = failure_resp
        from BmcHelixRemedyForce import bmc_remedy_service_request_definition_get_command
        with pytest.raises(DemistoException) as e:
            bmc_remedy_service_request_definition_get_command(self.client, {})

        assert MESSAGES['FAILED_MESSAGE'].format('get', 'service request definition') == str(e.value)

    def test_prepare_output_for_get_service_request_definitions(self):
        """
        Given single service request definition data
        When prepare_output_for_get_service_request_definitions is called
        Then processed json object should be returned in the expected form

        :return: None
        """
        with open('./TestData/service_request_definition.json', encoding='utf-8') as f:
            data = json.load(f)

        from BmcHelixRemedyForce import prepare_hr_output_for_get_service_request_definitions
        output = prepare_hr_output_for_get_service_request_definitions(data['input_data'])
        assert output == data['expected_output']

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_service_request_def_id_from_name_success(self, mocker_http_request):
        """
        Given working service integration
        When service request id is requested from name
        Then valid name should be returned

        :param mocker_http_request: Mocker object for http request call
        :return: None
        """
        success_resp = {'records': [{'Id': 'ID_FOR_GIVEN_NAME'}]}
        mocker_http_request.return_value = success_resp

        from BmcHelixRemedyForce import get_service_request_def_id_from_name
        assert get_service_request_def_id_from_name("GIVEN_NAME", self.client) == 'ID_FOR_GIVEN_NAME'

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_service_request_def_id_from_name_failure(self, mocker_http_request):
        """
        Given working service integration
        When service request id is requested from name is not found
        Then DemistoException should be raised with proper message

        :param mocker_http_request: Mocker object for http request call
        :return: None
        """
        mocker_http_request.side_effect = DemistoException('ERROR_MSG')

        from BmcHelixRemedyForce import get_service_request_def_id_from_name
        with pytest.raises(DemistoException) as e:
            get_service_request_def_id_from_name("GIVEN_NAME", self.client)

        assert 'ERROR_MSG' in str(e.value)

    def test_validate_max_incidents(self):
        """
        Tests the validation of max_incidents parameter.
        """
        from BmcHelixRemedyForce import validate_max_incidents
        # When non integer.
        with pytest.raises(ValueError):
            validate_max_incidents('test')

        # When blank.
        with pytest.raises(ValueError):
            validate_max_incidents('')

        # When valid integer
        validate_max_incidents('10')

        # When invalid integer
        with pytest.raises(ValueError):
            validate_max_incidents('-1')

    def test_prepare_query_for_fetch_incidents(self):
        """
        Tests the various scenarios related to preparing query based on provided parameters.
        """
        from BmcHelixRemedyForce import prepare_query_for_fetch_incidents, SALESFORCE_QUERIES, timestamp_to_datestring
        # Without query
        params = {
            'category': 'category',
            'impact': 'impact',
            'max_fetch': '10',
            'type': 'Incident'
        }
        fields = 'BMCServiceDesk__Category_ID__c=\'category\' and BMCServiceDesk__Impact_Id__c=\'impact\' and '
        start_time = 1594250101000
        fetch_type = ('true', 'Yes')
        assert prepare_query_for_fetch_incidents(params, start_time) == SALESFORCE_QUERIES[
            'FETCH_INCIDENT_QUERY'].format(
            fields, *fetch_type, timestamp_to_datestring(start_time), '10')

        del params['type']
        with pytest.raises(ValueError):
            prepare_query_for_fetch_incidents(params, start_time)

        # With query

        # Multiple 'where' clause
        params = {'query': 'select Id from table where Id=(select Id from table1 where Id=1)'}
        with pytest.raises(ValueError):
            prepare_query_for_fetch_incidents(params, start_time)

        # No 'where' clause
        params['query'] = 'select id from table order by id'
        expected_query = 'select id from table where LastModifiedDate > 2020-07-08T23:15:01.000Z order by id'
        assert prepare_query_for_fetch_incidents(params, start_time) == expected_query

        params['query'] = 'select id from table'
        expected_query = 'select id from table where LastModifiedDate > 2020-07-08T23:15:01.000Z'
        assert prepare_query_for_fetch_incidents(params, start_time) == expected_query

        # No from found
        with pytest.raises(ValueError):
            params['query'] = 'select id table'
            prepare_query_for_fetch_incidents(params, start_time)

        # With Single 'where' clause
        params['query'] = 'select id from table where id=1'
        expected_query = f'select id from table where LastModifiedDate > {timestamp_to_datestring(start_time)} and id=1'
        assert prepare_query_for_fetch_incidents(params, start_time) == expected_query

    @patch('BmcHelixRemedyForce.get_service_request_details')
    @patch('BmcHelixRemedyForce.get_attachments_for_incident')
    @patch('demistomock.params')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_fetch_incidents(self, http_request, demisto_params_url, mocker_get_attachments, mocker_sr_details):
        """
        Tests the fetch-incidents command.

        :param http_request: mocker object.
        :param demisto_params_url: mocker object for demisto.params()
        :param mocker_get_attachments: mocker object for get_attachments_for_incident()
        """
        from BmcHelixRemedyForce import fetch_incidents

        mocker_sr_details.return_value = {}
        expected_response, expected_incidents = prepare_expected_response_for_fetch_incidents()

        params = {
            'category': 'category',
            'impact': 'impact',
            'max_fetch': 10,
            'type': 'Incident'
        }

        # Mocking http_request
        http_request.return_value = expected_response

        # Mocking demiso.params:
        demisto_params_url.return_value = {'url': 'SOME_URL'}

        mocker_get_attachments.return_value = []

        # With first_fetch
        next_run, incidents = fetch_incidents(client=self.client, params=params, last_run={},
                                              first_fetch=1594250101000)
        assert next_run == {
            'start_time': 1594250101000}

        assert incidents == expected_incidents

        # With last_run
        next_run, incidents = fetch_incidents(client=self.client, params=params, last_run={'start_time': 1582584487},
                                              first_fetch=0)
        assert next_run == {
            'start_time': date_to_timestamp(json.loads(expected_incidents[0]['rawJSON'])['LastModifiedDate'],
                                            date_format='%Y-%m-%dT%H:%M:%S.%f%z')}

        assert incidents == expected_incidents

    @patch('BmcHelixRemedyForce.get_service_request_details')
    @patch('BmcHelixRemedyForce.get_attachments_for_incident')
    @patch('demistomock.getLastRun')
    @patch('demistomock.setLastRun')
    @patch('demistomock.incidents')
    @patch('demistomock.command')
    @patch('BmcHelixRemedyForce.Client.http_request')
    @patch('demistomock.params')
    def test_main_fetch_incidents_success(self, *args):
        """
        Given working service integration
        When fetch-incidents is called from main()
        Then demistomock.incidents and demistomock.setLastRun should be called with respected values.

        :param args: Mocker objects.
        :return: None
        """
        from BmcHelixRemedyForce import main
        expected_response, expected_incidents = prepare_expected_response_for_fetch_incidents()
        args[1].return_value = expected_response

        args[2].return_value = 'fetch-incidents'

        args[0].return_value = {
            'request_timeout': 50,
            'credentials': {},
            'url': 'some_base_url',
            'type': 'Incident',
            'first_fetch': '10 hours'
        }
        args[7].return_value = {}
        args[6].return_value = []

        args[5].return_value = {'start_time': 1594250101000}
        main()
        args[4].assert_called_with({'start_time': 1594250101000})
        args[3].assert_called_with(expected_incidents)

    def test_input_data_create_note(self):
        """
        Given notes and summary as input params return should match expected output
        :return:None
        """
        from BmcHelixRemedyForce import input_data_create_note
        summary = "test summery"
        notes = "test note"
        expected_output = {
            "ActivityLog": [
                {
                    'Summary': summary,
                    'Notes': notes
                }
            ]
        }
        resp = input_data_create_note(summary, notes)
        assert expected_output == resp

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_id_from_incident_number_success(self, mocker_http_request):
        """
        Given input param incident number or service request should return expected id

        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import get_id_from_incident_number
        with open("TestData/get_id_from_name.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mocker_http_request.return_value = expected_res

        resp = get_id_from_incident_number(self.client, '123')

        assert resp == '123456789'

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_id_from_incident_name_failed(self, mocker_http_request):
        """
        Given invalid input param incident number or service request should not  return expected id

        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import get_id_from_incident_number

        mocker_http_request.return_value = {}

        with pytest.raises(ValueError) as e:
            get_id_from_incident_number(self.client, '123')

        assert MESSAGES['NOTE_CREATE_FAIL'].format('123') == str(e.value)

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_id_from_incident_number_failed_value_error(self, mocker_http_request):
        """
        Given invalid input param incident or service request number should not  return expected id

        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import get_id_from_incident_number
        with open("TestData/get_id_from_name_null_id.json", encoding='utf-8') as f:
            expected_res = json.load(f)
        mocker_http_request.return_value = expected_res

        with pytest.raises(ValueError) as e:
            get_id_from_incident_number(self.client, '123')

        assert MESSAGES['NOT_FOUND_ERROR'] == str(e.value)

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_id_from_incident_number_type_incident(self, mocker_http_request):
        """
        Given working salesforce integration API
        When get_id_from_incident_number called with type
        Then query should contain appropriate where clause for getting either SR or IN only

        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import get_id_from_incident_number
        mocker_http_request.return_value = None

        with pytest.raises(Exception):
            get_id_from_incident_number(self.client, '123', 'IN')

        for call in mocker_http_request.call_args_list:
            args, kwargs = call
            assert 'and BMCServiceDesk__isServiceRequest__c=false' in kwargs['params']['q']

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_id_from_incident_number_type_SR(self, mocker_http_request):
        """
        Given working salesforce integration API
        When get_id_from_incident_number called with type
        Then query should contain appropriate where clause for getting either SR or IN only

        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import get_id_from_incident_number
        mocker_http_request.return_value = None

        with pytest.raises(Exception):
            get_id_from_incident_number(self.client, '123', 'SR')

        for call in mocker_http_request.call_args_list:
            args, kwargs = call
            assert 'and BMCServiceDesk__isServiceRequest__c=true' in kwargs['params']['q']

    @patch('BmcHelixRemedyForce.Client.http_request')
    @patch('BmcHelixRemedyForce.get_id_from_incident_number')
    def test_remedy_note_create_command_success(self, mocker_id_from_incident_number, mocker_http_request):
        """
        Given valid param command will run successful

        :param mocker_id_from_incident_number: mocker object for getting valid id from name
        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import bmc_remedy_note_create_command
        with open("TestData/get_create_note_response.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mocker_id_from_incident_number.return_value = 'a123bcd'
        mocker_http_request.return_value = expected_res
        args = {
            "request_number": "IN00000123",
            "summary": "Summary",
            "notes": "Notes"
        }
        result = bmc_remedy_note_create_command(self.client, args)
        assert result.raw_response == expected_res
        assert result.readable_output == HR_MESSAGES['NOTE_CREATE_SUCCESS'].format('IN00000123')
        assert result.outputs_key_field == 'Id'

    @patch('BmcHelixRemedyForce.Client.http_request')
    @patch('BmcHelixRemedyForce.get_id_from_incident_number')
    def test_remedy_note_create_command_failed_raise_exception_with_message(self, mocker_id_from_incident_number,
                                                                            mocker_http_request):
        """
        When command run and DemistoException called
        Then DemistoException should be raised with proper message

        :param mocker_id_from_incident_number: mocker object for getting valid id from name
        :param mocker_http_request: mocker object for Client.http_request
        :return: None
        """
        from BmcHelixRemedyForce import bmc_remedy_note_create_command
        # to cover expected error occurred
        mocker_http_request.side_effect = DemistoException(MESSAGES['UNEXPECTED_ERROR'])
        mocker_id_from_incident_number.return_value = 'a123bcd'
        args = {
            "summary": "Summary",
            "notes": "Notes"
        }

        with pytest.raises(ValueError) as e:
            bmc_remedy_note_create_command(self.client, args)

        assert MESSAGES['EMPTY_REQUIRED_ARGUMENT'].format("request_number") == str(e.value)

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_template_details_get_command_success(self, mock_http_res):
        """
        When bmc_remedy_template_details_get command is called
        Then raw response and method called count should be as expected

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_template_output = MagicMock(
            side_effect=BmcHelixRemedyForce.create_template_output)

        with open("TestData/get_remedy_template_success.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "template_name": "Summary"
        }
        result = BmcHelixRemedyForce.bmc_remedy_template_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_template_output.call_count == 1

        args = {}
        result = BmcHelixRemedyForce.bmc_remedy_template_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_template_output.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_template_details_get_command_no_records_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_template_details_get_command method in case of no records founds in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result
        mock_http_res.return_value = expected_res
        args = {
            "template_name": "tname1"
        }

        result = bmc_remedy_template_details_get_command(self.client, args)

        assert result == MESSAGES['INVALID_ENTITY_NAME'].format('template_name', 'tname1')

        args = {}
        result = bmc_remedy_template_details_get_command(self.client, args)
        assert result == MESSAGES['NO_ENTITY_FOUND'].format('template(s)')

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_update_incident_positive(self, req_obj, mocker_get_session_id):
        """
        Testcase for positive scenario of update_incident method.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        from requests import Session

        date_format = "%Y-%m-%d"
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 204
        resp1.text = ""
        req_obj.side_effect = [resp1]
        with open('./TestData/update_incident.json', encoding='utf-8') as f:
            data = json.load(f)
        expected_output = data["expected_output"]
        params = data["params"]
        actual_response = update_incident(self.client, "123", params=params)
        for call in Session.request.call_args_list:
            args, kwargs = call
            assert kwargs["json"] == expected_output
        assert actual_response["outputs"]["LastUpdatedDate"][:10] == datetime.now().strftime(date_format)

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_update_incident_exception(self, req_obj, mocker_get_session_id):
        """
        Testcase of update_incident method incase of exception scenarios
        and verfying  last_updated_status of context output in this scenarios.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        mocked_http_response = Response()
        mocked_http_response.status_code = 401
        req_obj.side_effect = [mocked_http_response]
        params = {
            "category_id": "abc",
            "broadcast_id": None
        }
        expected_response = {
            'outputs': {},
            'message': MESSAGES["AUTHENTICATION_ERROR"]
        }
        actual_response = update_incident(self.client, "123", params=params)
        assert actual_response == expected_response

    def test_get_valid_arguments(self):
        """
        Testcase of get_valid_arguments method incase of invalid formatted argument
        and verifying exception message.
        """
        try:
            params = "category=abc;broadcast=brdcast;description= ;queue="
            data, exculded_fields = get_valid_arguments(params, "field")
        except Exception as e:
            assert str(e) == "{}".format(MESSAGES["INVALID_DATA_FORMAT"]).format("field")

    def test_get_valid_arguments_empty(self):
        """
        Testcase of get_valid_arguments method incase of empty argument.
        """
        data, exculded_fields = get_valid_arguments("", "field")
        assert data == ""
        assert exculded_fields == []

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_update_service_request_command_invalid_sr_number(self, req_obj, mocker_get_session_id):
        """
        Test-case to update service request in case of invalid service request number
        and verifying  exception message.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_empty_dummy_response
        req_obj.side_effect = [resp1]
        try:
            args = {
                "service_request_number": "345",
                "category_id": "sgs",
                "queue_id": None,
                "staff_id": "afs",
                "status_id": None,
                "urgency_id": ""
            }
            bmc_remedy_update_service_request_command(self.client, args)
        except Exception as e:
            assert str(e) == "{}".format(MESSAGES["NOT_FOUND_SERVICE_REQUEST"]).format("345")

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_update_service_request_command_duplication(self, req_obj, mocker_get_session_id):
        """
        Testcase to update service request incase of default arguments are available in
        additional_fields argument and verfying  exception message.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_empty_dummy_response
        req_obj.side_effect = [resp1]
        try:
            args = {
                "service_request_number": "345",
                "category_id": "sgs",
                "queue_id": None,
                "staff_id": "afs",
                "status_id": None,
                "urgency_id": "",
                "additional_fields": "category_id=dfdg"
            }
            bmc_remedy_update_service_request_command(self.client, args)
        except Exception as e:
            assert str(e) == "{}".format(MESSAGES["INVALID_FIELDS_ERROR"]).format("category_id", "additional_fields")

    @patch('BmcHelixRemedyForce.get_valid_arguments')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_update_service_request_command_invalid_additional_data(
            self, req_obj, mocker_get_session_id, get_mock):
        """
        Testcase to update service request incase of invlaid formatted additional_fields argument
        and verfying  exception message.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param get_mock: mocker object for get_valid_arguments method
        """
        get_mock.return_value = (["category_id", "dfdg"], [])
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_empty_dummy_response
        req_obj.side_effect = [resp1]
        try:
            args = self.incorrect_args
            bmc_remedy_update_service_request_command(self.client, args)
        except Exception as e:
            msg = "{}".format(MESSAGES["INVALID_FORMAT_ERROR"]).format(
                "additional_fields", "field_id1=value_1; field_2=value_2")
            assert str(e) == msg

    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_update_service_request(self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context):
        """
        Testcase to update service request in positive scenarios and verifying context ouput.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        """
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"}
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        args = self.correct_args
        bmc_remedy_update_service_request_command(self.client, args)
        for call in mocker_context.call_args_list:
            args, kwargs = call
            assert args[0].outputs_prefix == OUTPUT_PREFIX["SERVICE_REQUEST"]
            assert args[0].outputs_key_field == 'Number'
            assert args[0].outputs["key"] == "value"
            assert args[0].outputs['Number'] == '345'
            assert args[0].readable_output == "{}".format(HR_MESSAGES["SERVICE_REQUEST_UPDATE_SUCCESS"]).format(
                "345"
            )

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_warning')
    @patch('BmcHelixRemedyForce.get_valid_arguments')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_update_service_request_warning(
            self, req_obj, mocker_get_session_id, mocker_update_incident,
            get_mock, mocker_return_warning, mocker_error):
        """
        Testcase to update service request in case of warning scenarios and verifying
        context data.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param get_mock: mocker object for get_valid_arguments method
        :param mocker_return_warning: mocker object of return_warning method of CommonServerPython
        :param mocker_error: mocker object for demistomock.error
        """
        get_mock.return_value = ([], ["broadcast_id"])
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"}
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        args = self.incorrect_args
        bmc_remedy_update_service_request_command(self.client, args)
        for call in mocker_return_warning.call_args_list:
            args, kwargs = call
            assert kwargs["message"] == '{}'.format(MESSAGES["UPDATE_SERVICE_REQUEST_WARNING"]).format(
                "345", "broadcast_id", MESSAGES["UNEXPECTED_ERROR"])
            assert kwargs["exit"] is True
            assert kwargs["ignore_auto_extract"] is True
            assert kwargs["outputs"]["BmcRemedyforce.ServiceRequest(val.Number === obj.Number)"]["Number"] == '345'
            assert kwargs["outputs"]["BmcRemedyforce.ServiceRequest(val.Number === obj.Number)"]["key"] == 'value'

    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_update_service_request_failure(
            self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context):
        """
        Testcase to update service request in case of failure and verfying exception message.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        """
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"},
            "message": "Failure message"
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        try:
            args = self.incorrect_args
            bmc_remedy_update_service_request_command(self.client, args)
        except Exception as e:
            assert str(e) == self.msg_for_invalid_format

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_create_service_request(self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context,
                                    mocker_error):
        """
        Testcase to create service request in case of positive scenarios and verifying
        context data.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        :param mocker_error: mocker object for demistomock.error
        """
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"}
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        args = self.correct_args
        args["service_request_definition_id"] = "345"
        mocker_context.return_value = None
        bmc_remedy_create_service_request_command(self.client, args)
        for call in mocker_context.call_args_list:
            args, kwargs = call
            assert args[0].outputs_prefix == OUTPUT_PREFIX["SERVICE_REQUEST"]
            assert args[0].outputs_key_field == 'Number'
            assert args[0].outputs['Number'] == '00000132'
            assert args[0].outputs['Id'] == 'adfghjkl'
            assert args[0].readable_output == '{}'.format(HR_MESSAGES["SERVICE_REQUEST_CREATE_SUCCESS"]).format(
                '00000132')
            assert args[0].raw_response == fetch_dummy_response()

    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_create_service_request_failure(
            self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context):
        """
        Testcase to create service request in case of failure and verfying exception message.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        """
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"}
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = get_failure_sr
        req_obj.side_effect = [resp1]
        args = {
            "service_request_definition_id": "345"
        }
        try:
            bmc_remedy_create_service_request_command(self.client, args)
        except Exception as e:
            assert str(e) == MESSAGES["UNEXPECTED_ERROR"]

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_warning')
    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_create_service_request_fail_to_update(
            self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context, mocker_return_warning,
            mocker_error):
        """
        Testcase to update service request in case of warning scenarios and veryfing context data.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        :param mocker_return_warning: mocker object of return_warning method of CommonServerPython
        :param mocker_error: mocker object for demistomock.error
        """
        mock_return_value = {
            "outputs": {"key": "value"},
            "message": "Fail to update"
        }
        mocker_update_incident.return_value = mock_return_value
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        args = {
            "service_request_definition_id": "345",
            "service_request_definition_params": "abc=xyz",
            "category_id": "sd"
        }
        bmc_remedy_create_service_request_command(self.client, args)
        for call in mocker_return_warning.call_args_list:
            args, kwargs = call
            assert kwargs['message'] == "{}".format(MESSAGES["CREATE_SERVICE_REQUEST_WARNING"]).format(
                "00000132", "category_id", mock_return_value["message"])
            assert kwargs['exit'] is True
            assert kwargs['ignore_auto_extract'] is True
            assert kwargs['outputs'][OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']]['Number'] == '00000132'
            assert kwargs['outputs'][OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']]['Id'] == 'adfghjkl'

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.update_incident')
    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_create_service_request_invalid_additional_fields(
            self, req_obj, mocker_get_session_id, mocker_update_incident, mocker_context, mocker_error):
        """
        Testcase to update service request in case of invalid value of additional_fields
        argument.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        :param mocker_update_incident: mocker object for update_incident method
        :param mocker_context: mocker object of return_results method of CommonServerPython
        :param mocker_error: mocker object for demistomock.error
        """
        mocker_update_incident.return_value = {
            "outputs": {"key": "value"}
        }
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_response
        req_obj.side_effect = [resp1]
        args = {
            "service_request_definition_id": "345",
            "additional_fields": "broadcast_id= ;service_id="
        }
        try:
            bmc_remedy_create_service_request_command(self.client, args)
        except Exception as e:
            assert str(e) == MESSAGES["INVALID_DATA_FORMAT"].format("additional_fields")

    def test_remove_prefix(self):
        """
        Testcase remove_prefix method and verfying that is given prefix removed
        from given string or not.
        """
        field = remove_prefix("sr", "SR45678tyty")
        assert field == "45678tyty"

    def test_get_request_params(self):
        """
        Testcase of get_request_params method.
        """
        data = {
            "category_id": "abc",
            "queue_id": "xyz",
            "client_id": "def"
        }
        actual_result = get_request_params(data, {})
        assert actual_result == data

    def test_validate_params_for_fetch_incidents(self):
        """
        Tests, validation of parameters of fetch-incidents.

        :param params_mock: parameter mock object.
        """
        from BmcHelixRemedyForce import validate_params_for_fetch_incidents
        params = {
            'isFetch': True,
            'max_fetch': '10',
        }
        # type validation
        with pytest.raises(ValueError):
            validate_params_for_fetch_incidents(params)

        # query validation
        with pytest.raises(ValueError):
            validate_params_for_fetch_incidents({'query': 'select * from a where where', 'isFetch': True})
        with pytest.raises(ValueError):
            validate_params_for_fetch_incidents({'query': 'select * a', 'isFetch': True})

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_impact_details_get_command(self, req_obj, mocker_get_session_id):
        """
        Testcase for positive scenario of bmc_remedy_impact_details_get_command method.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_get_impacts
        req_obj.side_effect = [resp1]
        args = {"impact_name": "abc"}
        expected_output = fetch_dummy_get_impacts().get("records")
        actual_response = bmc_remedy_impact_details_get_command(self.client, args)
        assert actual_response.outputs_prefix == OUTPUT_PREFIX["IMPACT"]
        assert actual_response.outputs == expected_output
        assert actual_response.raw_response == expected_output
        assert len(actual_response.outputs) == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_impact_details_get_command_no_records_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_impact_details_get_command method in case of no records founds in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result

        mock_http_res.return_value = expected_res
        args = {
            "impact_name": "impact1"
        }

        result = bmc_remedy_impact_details_get_command(self.client, args)

        assert result == MESSAGES['INVALID_ENTITY_NAME'].format('impact_name', 'impact1')

        args = {}
        result = bmc_remedy_impact_details_get_command(self.client, args)
        assert result == MESSAGES['NO_ENTITY_FOUND'].format('impact(s)')

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_service_offering_details_get_command_success(self, mock_http_res):
        """
        Given valid param command will run successful

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_hr_context_output = MagicMock(
            side_effect=BmcHelixRemedyForce.create_hr_context_output)

        with open("TestData/get_service_offering_details.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "service_offering_name": "name"
        }
        result = BmcHelixRemedyForce.bmc_remedy_service_offering_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 1

        args = {}
        result = BmcHelixRemedyForce.bmc_remedy_service_offering_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert len(result.outputs) == 2
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_service_offering_details_get_command_no_record_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_service_offering_details_get_command method in case of no records founds
        in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result

        mock_http_res.return_value = expected_res
        args = {
            "service_offering_name": "sof1"
        }

        result = bmc_remedy_service_offering_details_get_command(self.client, args)

        assert result == MESSAGES['INVALID_ENTITY_NAME'].format('service_offering_name', 'sof1')

        args = {}
        result = bmc_remedy_service_offering_details_get_command(self.client, args)
        assert result == MESSAGES['NO_ENTITY_FOUND'].format('service offering(s)')

    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_create_command_success(self, mocker_http_request, mocker_return_results):
        """
        Given working create and update incident api
        When command to create incident is called
        Then incident should be created and proper context and reatable output should be returned

        :param mocker_http_request: Mocker object for http_request
        :param mocker_return_results: Mocker object for return_results
        :return: None
        """

        with open(INCIDENT_TEST_DATA_FILE) as f:
            api_response = json.load(f)
        success_result = api_response['create_success']['Result']
        mocker_return_results.return_value = None
        mocker_http_request.side_effect = mock_incident_success_response

        from BmcHelixRemedyForce import bmc_remedy_incident_create_command
        bmc_remedy_incident_create_command(self.client, {'client_id': 'SOME_CLIENT_ID', 'description': 'SOME_DESC'})

        assert mocker_return_results.call_count == 1

        for call in mocker_return_results.call_args_list:
            args, kwargs = call
            assert args[0].outputs == success_result
            assert args[0].raw_response == api_response['create_success']
            assert 'SUCCESS_NUMBER' in str(args[0].readable_output)

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_warning')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_create_command_warning(self, mocker_http_request, mocker_return_warning, mocker_error):
        """
            Given working create and but not update incident api
            When command to create incident is called
            Then incident should be created but warning output should be returned with proper context and readable
            output

            :param mocker_http_request: Mocker object for http_request
            :param mocker_return_warning: Mocker object for return_results
            :param mocker_error: mocker object for demistomock.error
            :return: None
        """

        with open(INCIDENT_TEST_DATA_FILE) as f:
            api_response = json.load(f)
        success_result = api_response['create_success']['Result']
        mocker_return_warning.return_value = None
        mocker_http_request.side_effect = mock_incident_warning_response

        from BmcHelixRemedyForce import bmc_remedy_incident_create_command
        bmc_remedy_incident_create_command(self.client,
                                           {'client_id': 'SOME_CLIENT_ID', 'additional_fields': 'service_id=SOME_ID'})

        assert mocker_return_warning.call_count == 1

        for call in mocker_return_warning.call_args_list:
            args, kwargs = call
            expected_msg = HR_MESSAGES['CREATE_INCIDENT_WARNING'].format('SUCCESS_NUMBER', 'client_id, service_id',
                                                                         'SOME_ISSUE_WITH_UPDATE')
            assert expected_msg == str(kwargs['warning'])

            warning_output = {'BmcRemedyforce.Incident(val.Id === obj.Id)': success_result}

            assert warning_output == kwargs['outputs']
            assert mocker_error.called

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_create_command_failure(self, mocker_http_request):
        """
            Given non working create incident api
            When command to create incident is called
            Then error output should be returned with proper error message

            :param mocker_http_request: Mocker object for http_request
            :return: None
        """

        mocker_http_request.return_value = {'ErrorMessage': 'ERROR_MSG'}

        from BmcHelixRemedyForce import bmc_remedy_incident_create_command
        with pytest.raises(DemistoException) as e:
            bmc_remedy_incident_create_command(self.client, {'client_id': 'SOME_CLIENT_ID', 'description': 'SOME_DESC'})

        assert 'ERROR_MSG' in str(e.value)

    def test_bmc_remedy_incident_create_command_input_error(self):
        """
            Given working create and update incident api
            When command to create incident is called with incorrect input
            Then error output should be returned with proper error message
            :return: None
        """

        from BmcHelixRemedyForce import bmc_remedy_incident_create_command
        with pytest.raises(DemistoException) as e:
            bmc_remedy_incident_create_command(self.client,
                                               {'client_id': 'CLIENT_ID', 'additional_fields': 'description=test'})
        assert 'description' in str(e.value)

    @patch('demistomock.error')
    @patch('BmcHelixRemedyForce.return_results')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_update_command_success(self, mocker_http_request, mocker_return_results, mocker_error):
        """
        Given working update incident api
        When command for update incident is called
        Then command should return expected results and set context for update status success

        :param mocker_http_request: Mocker for http request
        :param mocker_return_results: Mocker for return_results
        :param mocker_error: mocker object for demistomock.error
        :return: None
        """
        dummy_response = fetch_dummy_response()
        dummy_response['records'][0]['BMCServiceDesk__isServiceRequest__c'] = False
        mocker_http_request.side_effect = [dummy_response, get_no_content_success_response]

        with open(INCIDENT_TEST_DATA_FILE) as f:
            update_success_context = json.load(f)['update_success']

        from BmcHelixRemedyForce import bmc_remedy_incident_update_command
        bmc_remedy_incident_update_command(self.client, {'incident_number': 'SOME_NUMBER'})

        for call in mocker_return_results.call_args_list:
            args, kwargs = call
            assert args[0].outputs['Id'] == update_success_context['Id']
            assert args[0].outputs['Number'] == update_success_context['Number']
            assert args[0].readable_output == HR_MESSAGES['UPDATE_INCIDENT_SUCCESS'].format('SOME_NUMBER')
            assert mocker_error.called

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_update_command_input_error(self, mocker_http_request):
        """
        Given working update incident api
        When command to create incident is called with incorrect input
        Then error output should be returned with proper error message

        :param mocker_http_request: Mocker for http request
        :return: None
        """
        mocker_http_request.return_value = fetch_dummy_response()
        from BmcHelixRemedyForce import bmc_remedy_incident_update_command
        args = {
            "incident_number": "321"
        }
        with pytest.raises(DemistoException) as e:
            bmc_remedy_incident_update_command(self.client, args)
        assert MESSAGES['NOT_FOUND_INCIDENT'].format('321') == str(e.value)

    def test_remove_extra_space_from_args(self):
        """
        Given a dictionary of arguments
        When remove_extra_space_from_args is called upon them
        Then returned arguments dictionary should not contain any argument value with leading or trailing whitespaces
            and the ones with NoneType should be removed
        :return:
        """

    sample_args = {"bad_1": "", "bad_2": "      ", "can_be_better": " good  ", "good": "good", "very_bad": None}
    sanitized_args = {"can_be_better": "good", "good": "good"}
    from BmcHelixRemedyForce import remove_extra_space_from_args
    assert sanitized_args == remove_extra_space_from_args(sample_args)

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_asset_details_get_command_success(self, mock_http_res):
        """
        When bmc_remedy_asset_details_get_command command is called
        Then raw response and method called count should be as expected

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_asset_output = MagicMock(
            side_effect=BmcHelixRemedyForce.create_asset_output)

        with open("TestData/get_assets_details_records.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "assets_name": "ADP",
            "instance_type": "Asset Classes"
        }
        result = BmcHelixRemedyForce.bmc_remedy_asset_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_asset_output.call_count == 2

        args = {}
        result = BmcHelixRemedyForce.bmc_remedy_asset_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_asset_output.call_count == 4

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_asset_details_get_command_no_record_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_asset_details_get_command method in case of no records founds in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result

        mock_http_res.return_value = expected_res
        args = {
            "asset_name": "aset1",
            "instance_type": "CI Classes"
        }

        result = bmc_remedy_asset_details_get_command(self.client, args)

        assert result == HR_MESSAGES['NOT_FOUND_FOR_ARGUMENTS'].format('asset(s)')

        args = {}
        result = bmc_remedy_asset_details_get_command(self.client, args)

        assert result == MESSAGES['NO_ENTITY_FOUND'].format('asset(s)')

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_account_details_get_command_success(self, mock_http_res):
        """
        Given valid param command will run successful

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_hr_context_output = MagicMock(
            side_effect=BmcHelixRemedyForce.create_hr_context_output)

        with open("TestData/get_accounts_details_success.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "account_name": "name"
        }
        result = bmc_remedy_account_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 1

        args = {}
        result = bmc_remedy_account_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert len(result.outputs) == 2
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_account_details_get_command_no_record_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_account_details_get_command method in case of no records founds in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result

        mock_http_res.return_value = expected_res
        args = {
            "account_name": "acc1"
        }
        result = bmc_remedy_account_details_get_command(self.client, args)
        assert result == MESSAGES['INVALID_ENTITY_NAME'].format('account_name', 'acc1')

        args = {}
        result = bmc_remedy_account_details_get_command(self.client, args)
        assert result == MESSAGES['NO_ENTITY_FOUND'].format('account(s)')

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_status_details_get_command_success(self, mocker_http_request):
        """
        Given working platform integration
        When bmc_remedy_status_details_get_command is called with or without name parameter
        Then proper output and response should be set
        :param mocker_http_request: mocker object for http_request
        :return: None
        """

        with open('TestData/get_status_data.json', encoding='utf-8') as f:
            mock_success_response = json.load(f)

        mocker_http_request.return_value = mock_success_response

        from BmcHelixRemedyForce import bmc_remedy_status_details_get_command
        command_resp = bmc_remedy_status_details_get_command(self.client, {})

        assert len(command_resp.outputs) == 1
        assert command_resp.raw_response == mock_success_response['records']

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_status_details_get_command_failure(self, mocker_http_request):
        """
        Given non-working platform integration
        When bmc_remedy_status_details_get_command is called with or without name parameter
        Then proper error message should be set
        :param mocker_http_request: mocker object for http_request
        :return: None
        """
        mock_empty_response = {}
        mocker_http_request.return_value = mock_empty_response

        from BmcHelixRemedyForce import bmc_remedy_status_details_get_command
        command_resp = bmc_remedy_status_details_get_command(self.client, {})

        assert MESSAGES['NO_ENTITY_FOUND'].format('status') == command_resp.readable_output

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_urgency_details_get_command_success(self, mock_http_res):
        """
        Given valid param command will run successful

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_hr_context_output = MagicMock(
            side_effect=BmcHelixRemedyForce.create_hr_context_output)

        with open("TestData/get_impacts.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "urgency_name": "urg1"
        }
        result = bmc_remedy_urgency_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 1

        args = {}
        result = bmc_remedy_urgency_details_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert len(result.outputs) == 2
        assert BmcHelixRemedyForce.create_hr_context_output.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_urgency_details_get_command_no_record_found(self, mock_http_res):
        """
        Testcase for bmc_remedy_urgency_details_get_command method in case of no records founds in get response.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        expected_res = self.expected_return_null_result

        mock_http_res.return_value = expected_res
        args = {
            "urgency_name": "urg2"
        }

        result = bmc_remedy_urgency_details_get_command(self.client, args)

        assert result == MESSAGES['INVALID_ENTITY_NAME'].format('urgency_name', 'urg2')

        args = {}
        result = bmc_remedy_urgency_details_get_command(self.client, args)
        assert result == MESSAGES['NO_ENTITY_FOUND'].format('urgency')

    def test_bmc_remedy_category_details_get_command_invalid_type(self):
        """
        Testcase for bmc_remedy_category_details_get_command method by passing invalid type argument
        and validating exception.
        """
        args = {'type': 'abc'}
        try:
            bmc_remedy_category_details_get_command(self.client, args)
        except ValueError as e:
            assert str(e) == "{}".format(
                MESSAGES["INVALID_TYPE_FOR_CATEGORIES"]).format("type", "type", ", ".join(POSSIBLE_CATEGORY_TYPES))

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_category_details_get_command_invalid_type_with_category(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch a category mentioned
        in category_name argument but with invalid type and validating exception.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_categories
        req_obj.side_effect = [resp1]
        args = {'type': 'abc',
                'category_name': 'category'}
        try:
            bmc_remedy_category_details_get_command(self.client, args)
        except ValueError as e:
            assert str(e) == "{}".format(
                MESSAGES["INVALID_TYPE_FOR_CATEGORIES"]).format("type", "type", ", ".join(POSSIBLE_CATEGORY_TYPES))

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_category_details_get_command_type_as_service_request(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch a categories
        which is applicable to service request.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_categories
        req_obj.side_effect = [resp1]
        args = {'type': 'Service Request  '}
        actual_result = bmc_remedy_category_details_get_command(self.client, args)
        for call in req_obj.call_args_list:
            _, kwargs = call
        assert SERVICE_REQUEST_CATEGORY_OBJECT in kwargs['params']['q']
        assert actual_result.outputs_prefix == OUTPUT_PREFIX["CATEGORY"]
        assert actual_result.raw_response == fetch_dummy_categories()
        assert actual_result.outputs == self.dummy_categories

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_category_details_get_command_type_as_incident(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch a categories
        which is applicable to incident.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_categories
        req_obj.side_effect = [resp1]
        args = {'type': 'Incident'}
        actual_result = bmc_remedy_category_details_get_command(self.client, args)
        for call in req_obj.call_args_list:
            args, kwargs = call

        assert INCIDENT_CATEGORY_OBJECT in kwargs['params']['q']
        assert actual_result.outputs_prefix == OUTPUT_PREFIX["CATEGORY"]
        assert actual_result.raw_response == fetch_dummy_categories()
        assert actual_result.outputs == self.dummy_categories

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_category_details_get_command_no_record_found(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch a mentioned category
        incase of its not found.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        expected_res = self.expected_return_null_result
        req_obj.return_value = expected_res
        args = {'category_name': 'abc', 'type': 'Incident'}
        actual_result = bmc_remedy_category_details_get_command(self.client, args)
        assert actual_result == HR_MESSAGES['NOT_FOUND_FOR_ARGUMENTS'].format('category')

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_category_details_get_command_no_records_found(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch all categories
        incase of no categories found.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        expected_res = self.expected_return_null_result
        req_obj.return_value = expected_res
        actual_result = bmc_remedy_category_details_get_command(self.client, {'type': 'All'})
        assert actual_result == MESSAGES['NO_ENTITY_FOUND'].format('category')

    @patch('demistomock.args')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_queue_details_get_command(self, http_request, demisto_args):
        """
        Tests the get queue details command.

        :param http_request: mock object of http request.
        :param demisto_args: mock object of demisto.args.
        """
        from BmcHelixRemedyForce import bmc_remedy_queue_details_get_command
        with open('TestData/get_queue_details_response.json') as f:
            expected_response = json.load(f)
        http_request.return_value = expected_response

        args = {
            'type': 'Incident/Service Request'
        }
        demisto_args.return_value = args

        response = bmc_remedy_queue_details_get_command(client=self.client, args=args)

        with open('TestData/get_queue_details_return_entry.json') as f:
            expected_return_entry = json.load(f)
        assert response.to_context() == expected_return_entry

        # No queue
        expected_response['totalSize'] = 0
        http_request.return_value = expected_response
        response = bmc_remedy_queue_details_get_command(client=self.client, args=args)
        assert response == HR_MESSAGES['NO_QUEUE_FOUND']

    @staticmethod
    def test_prepare_query_for_queue_details_get():
        """
         Tests the user details get command query by applying parameters.
        """
        from BmcHelixRemedyForce import prepare_query_for_queue_details_get, SALESFORCE_QUERIES, QUEUE_TYPES

        # Without type and queue_name
        assert prepare_query_for_queue_details_get({}) == SALESFORCE_QUERIES['GET_QUEUE_DETAIL'].format('')

        # With queue name
        assert prepare_query_for_queue_details_get({'queue_name': 'queue1'}) == SALESFORCE_QUERIES[
            'GET_QUEUE_DETAIL'].format(" and name = 'queue1'")

        # With type from option
        queue_type = 'Incident/Service Request'
        assert prepare_query_for_queue_details_get({'type': queue_type}) == SALESFORCE_QUERIES[
            'GET_QUEUE_DETAIL_FOR_SPECIFIC_TYPE'].format(QUEUE_TYPES[queue_type])

        # With type unknown
        queue_type = 'task'
        assert prepare_query_for_queue_details_get({'type': queue_type}) == SALESFORCE_QUERIES[
            'GET_QUEUE_DETAIL_FOR_SPECIFIC_TYPE'].format('task')

        # With type and name
        assert prepare_query_for_queue_details_get({'type': 'type', 'queue_name': 'q1'}) == SALESFORCE_QUERIES[
            'GET_QUEUE_DETAIL_FOR_SPECIFIC_TYPE'].format('type') + " and queue.name = 'q1'"

    @patch('demistomock.args')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_user_details_get_command(self, http_request, demisto_args):
        """
        Tests the get user details command.

        :param http_request: mock object of http request.
        :param demisto_args: mock object of demisto.args.
        """
        from BmcHelixRemedyForce import bmc_remedy_user_details_get_command
        with open('TestData/get_user_details_response.json') as f:
            expected_response = json.load(f)
        http_request.return_value = expected_response

        args = {
            'username': 'username',
            'email': 'email'
        }
        demisto_args.return_value = args

        response = bmc_remedy_user_details_get_command(client=self.client, args=args)

        with open('TestData/get_user_details_return_entry.json') as f:
            expected_return_entry = json.load(f)
        assert response.to_context() == expected_return_entry

        # No users
        expected_response['totalSize'] = 0
        http_request.return_value = expected_response
        response = bmc_remedy_user_details_get_command(client=self.client, args=args)
        assert response == 'No user(s) found for the given argument(s).'

    def test_prepare_query_for_user_details_get(self):
        """
         Tests the user details get command query by applying parameters.
        """
        from BmcHelixRemedyForce import prepare_query_for_user_details_get

        args = {
            'email': 'email',
            'queue_name': 'queue_name',
            'is_staff': 'true',
            'username': 'username'
        }
        expected_query = "select id,name, firstname, lastname, username," \
                         " email, phone, companyname, division, department, title," \
                         " BMCServiceDesk__IsStaffUser__c, BMCServiceDesk__Account_Name__c from user where" \
                         " isactive=true and" \
                         " BMCServiceDesk__User_License__c != null and email='email' and id IN" \
                         " (SELECT userOrGroupId FROM groupmember WHERE group.name ='queue_name') and" \
                         " BMCServiceDesk__IsStaffUser__c=true and username='username'"
        assert prepare_query_for_user_details_get(args) == expected_query

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_broadcast_details_get_command_with_broadcast_name(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_broadcast_details_get_command method to fetch a broadcast
        mentioned in the argument.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_broadcasts
        req_obj.side_effect = [resp1]
        args = {'broadcast_name': 'abc  '}
        actual_result = bmc_remedy_broadcast_details_get_command(self.client, args)
        for call in req_obj.call_args_list:
            args, kwargs = call
        assert args[1] == "https://sample.api.com/services/data/v48.0/query"
        assert actual_result.outputs_prefix == OUTPUT_PREFIX["BROADCAST"]
        assert actual_result.raw_response == fetch_dummy_broadcasts()
        assert actual_result.outputs == self.dummy_broadcasts

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch("requests.Session.request")
    def test_bmc_remedy_broadcast_details_get_command_with_category_name(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_broadcast_details_get_command method to fetch a broadcast with having category
        mentioned in the argument.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        resp1 = Mock(spec=requests.Response)
        resp1.status_code = 200
        resp1.json = fetch_dummy_broadcasts
        req_obj.side_effect = [resp1]
        args = {'category_name': 'abc  '}
        actual_result = bmc_remedy_broadcast_details_get_command(self.client, args)
        for call in req_obj.call_args_list:
            args, kwargs = call

        assert args[1] == "https://sample.api.com/services/data/v48.0/query"
        assert "BMCServiceDesk__Category_ID__c='abc'" in kwargs['params']['q']
        assert actual_result.outputs_prefix == OUTPUT_PREFIX["BROADCAST"]
        assert actual_result.raw_response == fetch_dummy_broadcasts()
        assert actual_result.outputs == self.dummy_broadcasts

    @patch('BmcHelixRemedyForce.Client.get_session_id')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_broadcast_details_get_command_no_records_found(self, req_obj, mocker_get_session_id):
        """
        Testcase for bmc_remedy_category_details_get_command method to fetch all categories
        incase of no categories found.

        :param req_obj: mocker object for making http request call
        :param mocker_get_session_id: mocker object for getting valid session id
        """
        mocker_get_session_id.return_value = self.valid_session_id
        expected_res = self.expected_return_null_result
        req_obj.return_value = expected_res
        actual_result = bmc_remedy_broadcast_details_get_command(self.client, {})
        assert actual_result == HR_MESSAGES["NO_BROADCAST_DETAILS_FOUND"]

    def test_prepare_iso_date_string(self):
        from BmcHelixRemedyForce import prepare_iso_date_string
        assert prepare_iso_date_string('') == ''
        assert prepare_iso_date_string('random string') == ''
        assert prepare_iso_date_string('2020-07-23T07:40:06.000+0000') == '2020-07-23T07:40:06+00:00'

    def test_validate_and_get_date_argument(self):
        """
        Given arguments dictionary and date key
        When validate_and_get_date_argument is called
        Then a valid datetime object should be returned or an exception should be thrown if key exists,
        None should be returned if key does not exist
        :return:None
        """
        from BmcHelixRemedyForce import validate_and_get_date_argument
        assert isinstance(validate_and_get_date_argument({'date_key': '2020-08-23T08:53:00.000Z'}, 'date_key', 'date'),
                          datetime)
        assert isinstance(
            validate_and_get_date_argument({'date1_key': '2020-08-23T08:53:00.000+0530'}, 'date1_key', 'date1'),
            datetime)
        assert isinstance(validate_and_get_date_argument({'date1_key': '2020-08-23'}, 'date1_key', 'date1'), datetime)
        assert not validate_and_get_date_argument({'date_key': '2020-08-23'}, 'date2_key', 'date')

        with pytest.raises(ValueError) as e:
            validate_and_get_date_argument({'wrong_date_key': '2020-08-23asd'}, 'wrong_date_key', 'wrong_date')

        assert 'wrong_date' in str(e.value)

    def test_validate_incident_update_payload(self):
        """
        Given arguments dictionary with incident update details
        When validate_incident_update_payload is called
        Then required validations should take place and an exception should be raised, in case provided payload is
        invalid
        :return: None
        """
        from BmcHelixRemedyForce import MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS, validate_incident_update_payload
        sample_payload = {
            MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['opened_date']: "2020-08-23T08:53:00.000Z",
            MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['due_date']: "2020-08-23T08:54:00.000Z",
            MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['outage_start']: "2020-08-23T08:53:00.000Z",
            MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['outage_end']: "2020-08-23T08:50:00.000Z"
        }

        with pytest.raises(ValueError) as e:
            validate_incident_update_payload(sample_payload)

        assert MESSAGES['DATE_VALIDATION_ERROR'].format('outage_end', 'outage_start') == str(e.value)

        sample_payload[MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['due_date']] = "2020-08-23T08:50:00.000Z"

        with pytest.raises(ValueError) as e:
            validate_incident_update_payload(sample_payload)

        assert MESSAGES['DATE_VALIDATION_ERROR'].format('due_date', 'opened_date') == str(e.value)

    @patch('demistomock.params')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_attachments_for_incident_success(self, mocker_http_request, mocker_params):
        """
        Given working integration instance
        When get_attachments_for_incident() is called
        Then attachments for the passed id, should be returned in the expected format
        :param mocker_http_request: mocker object for http call
        :param mocker_params: mocker object for demisto.params()
        :return: None
        """

        with open('./TestData/get_incident_attachments.json') as f:
            api_response = json.load(f)

        mocker_params.return_value = {'url': 'BASE_URL'}

        mocker_http_request.return_value = api_response

        from BmcHelixRemedyForce import get_attachments_for_incident

        response = get_attachments_for_incident(self.client, 'SOME_ID')

        assert len(response) == 1
        assert 'BASE_URL' + URL_SUFFIX['DOWNLOAD_ATTACHMENT'].format('CONTENT_ID') == response[0].get('Download Link',
                                                                                                      '')
        assert response[0].get('File', '') == 'test_doc'
        assert response[0].get('Created By', '') == 'TEST USER'

    @patch('demistomock.params')
    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_attachments_for_incident_failure(self, mocker_http_request, mocker_params):
        """
        Given non working integration instance
        When get_attachments_for_incident() is called
        Then exception should be thrown with proper message
        :param mocker_http_request: mocker object for http call
        :param mocker_params: mocker object for demisto.params()
        :return: None
        """

        mocker_params.return_value = {'url': 'BASE_URL'}

        mocker_http_request.side_effect = DemistoException('ERROR_MSG')

        from BmcHelixRemedyForce import get_attachments_for_incident

        with pytest.raises(DemistoException) as e:
            get_attachments_for_incident(self.client, 'SOME_ID')

        assert str(e.value) == 'ERROR_MSG'

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_notes_for_incident_success(self, mock_http_res):
        """
        When get_notes_for_incident method is called
        Then return value should be as expected

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.process_notes_record = MagicMock(
            side_effect=BmcHelixRemedyForce.process_notes_record)

        with open("TestData/get_note_from_incident_success.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        date_time = dateparser.parse('2020-07-28T10:44:33.000+0000')
        date = date_time.strftime(DISPLAY_DATE_FORMAT)
        records = [{'Note': 'note_c', 'Date & Time [UTC]': date, 'Incident History ID': '123_0',
                    'Action~': 'action_id', 'Description': 'desc', 'Sender': 'sample_name'}]
        mock_http_res.return_value = expected_res

        result = BmcHelixRemedyForce.get_notes_for_incident(self.client, '33')
        assert result == records
        assert BmcHelixRemedyForce.process_notes_record.call_count == 1

        result2 = BmcHelixRemedyForce.get_notes_for_incident(self.client, '')
        assert result2 == []
        assert BmcHelixRemedyForce.process_notes_record.call_count == 1

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_get_service_request_details(self, mock_http_res):
        """
        When get_service_request_details method is called
        Then return value should be as expected

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        resp1 = {
            "Success": True,
            "Result": {
                "Answers": [
                    {
                        "QuestionText": "question1",
                        "Text": "answer1"
                    },
                    {
                        "QuestionText": "question2",
                        "Text": "answer2"
                    }
                ]
            }
        }
        mock_http_res.return_value = resp1
        actual_response = get_service_request_details(self.client, "abc")
        assert actual_response == {
            "question1": "answer1",
            "question2": "answer2"
        }

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_get_command_success(self, mock_http_res):
        """
        Given valid param command will run successful.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        BmcHelixRemedyForce.create_output_for_incident = MagicMock(
            side_effect=BmcHelixRemedyForce.create_output_for_incident)

        with open("TestData/fetch_incident_response.json", encoding='utf-8') as f:
            expected_res = json.load(f)

        mock_http_res.return_value = expected_res
        args = {
            "time": "1 day",
            "incident_number": '123'
        }

        result = BmcHelixRemedyForce.bmc_remedy_incident_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert BmcHelixRemedyForce.create_output_for_incident.call_count == 1

        args = {}
        result = BmcHelixRemedyForce.bmc_remedy_incident_get_command(self.client, args)
        assert result.raw_response == expected_res
        assert len(result.outputs) == 1
        assert BmcHelixRemedyForce.create_output_for_incident.call_count == 2

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_incident_get_command_no_incident_found(self, mock_http_res):
        """
        Given valid param command will run with message.

        :param mock_http_res: mocker object for Client.http_request
        :return: None
        """
        import BmcHelixRemedyForce
        mock_http_res.return_value = {}
        args = {
            "time": "2 months",
            "incident_number": '321',
            "maximum_incident ": '50'
        }
        result = BmcHelixRemedyForce.bmc_remedy_incident_get_command(self.client, args)
        assert result == HR_MESSAGES['NO_INCIDENT_DETAILS_FOUND']

    def test_bmc_remedy_incident_get_command_invalid_maximum_service_request(self):
        """
        Testcase for bmc_remedy_incident_get_command method to fetch a service request with
        given arguments and verify exception when invalid maximum_service_request is given.

        """
        from BmcHelixRemedyForce import bmc_remedy_incident_get_command
        args = {
            "maximum_incident": 'aaa'
        }
        try:
            bmc_remedy_incident_get_command(self.client, args)
        except ValueError as e:
            assert str(e) == MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_incident')
        args = {
            "maximum_incident": '501'
        }
        try:
            bmc_remedy_incident_get_command(self.client, args)
        except ValueError as e:
            assert str(e) == MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_incident')

    def test_prepare_outputs_for_get_service_request(self):
        """
        Testcase of prepare_outputs_for_get_service_request method
        and verify context and human readable outputs.
        """
        outputs, hr_outputs = prepare_outputs_for_get_service_request(
            self.get_service_request_response["input_records"])
        assert outputs == self.get_service_request_response["expected_records"]
        assert hr_outputs == self.get_service_request_response["expected_records"]

    @patch('BmcHelixRemedyForce.Client.http_request')
    def test_bmc_remedy_service_request_get_command(self, mock_http_res):
        """
        Testcase for bmc_remedy_service_request_get_command method to fetch a service request with
        given arguments.

        :param mock_http_res: mocker object for making http request call
        """
        mock_http_res.return_value = self.get_service_request_response["actual_response"]
        input_args = self.get_service_request_response["input_args"]
        actual_result = bmc_remedy_service_request_get_command(self.client, input_args)
        assert actual_result.outputs_prefix == OUTPUT_PREFIX['SERVICE_REQUEST']
        assert actual_result.outputs_key_field == 'Number'
        assert actual_result.outputs == self.get_service_request_response["expected_records"]
        assert actual_result.raw_response == self.get_service_request_response["actual_response"]

    def test_bmc_remedy_service_request_get_command_invalid_maximum_service_request(self):
        """
        Testcase for bmc_remedy_service_request_get_command method to fetch a service request with
        given arguments and verify exception when invalid maximum_service_request is given.

        :param mock_http_res: mocker object for making http request call
        """
        input_args = self.get_service_request_response["input_args"]
        input_args["maximum_service_request"] = "abc"
        try:
            bmc_remedy_service_request_get_command(self.client, input_args)
        except ValueError as e:
            assert str(e) == MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_service_request')
        input_args["maximum_service_request"] = "1000"
        try:
            bmc_remedy_service_request_get_command(self.client, input_args)
        except ValueError as e:
            assert str(e) == MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_service_request')

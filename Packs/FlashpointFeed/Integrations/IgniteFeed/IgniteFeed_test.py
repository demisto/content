"""Flashpoint Ignite Feed Integration for Cortex XSOAR - Unit Tests file"""

import json
import os
import sys

import pytest
from requests.exceptions import HTTPError

import IgniteFeed
from CommonServerPython import DemistoException
from IgniteFeed import (HTTP_ERRORS, MAX_FETCH, MAX_INDICATORS, MESSAGES,
                        URL_SUFFIX, Client, demisto, fetch_indicators_command,
                        flashpoint_ignite_get_indicators_command, main)
from IgniteFeed import test_module as main_test_module

""" CONSTANTS """

API_KEY = "dummy_api_key"
MOCK_URL = "https://mock_dummy.com"

""" UTILITY FUNCTIONS AND FIXTURES """


def util_load_json(path):
    """
    Load json file into dictionary.

    :param path: Takes file path.

    :return: Dictionary.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    client = Client(url=MOCK_URL, headers={}, proxy=False, verify=False)
    return client


class MockResponse:
    """Creates mock response."""

    def __init__(self, status_code):
        """Initialize class object."""
        self.status_code = status_code

    def raise_for_status(self):
        """Raise status code error."""
        if self.status_code != 200:
            raise HTTPError('test')


""" TEST CASES """


def test_test_module_with_invalid_apikey(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module with invalid apikey.

    Given:
       - mocked client with invalid apikey.
    When:
       - Calling `test_module` function.
    Then:
       - Returns exception.
    """

    indicator_list_response_401: str = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                      'test_data/invalid_apikey_401.json'))
    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]),
                      json=indicator_list_response_401, status_code=401)

    with pytest.raises(DemistoException) as err:
        main_test_module(client=mock_client)

    assert str(err.value) == HTTP_ERRORS[401]


def test_test_module_with_valid_apikey(requests_mock, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client with valid apikey.
    When:
       - Calling `test_module` function.
    Then:
       - Returns an ok message.
    """

    indicator_list_response_200: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                       'test_data/indicator_list_200.json'))
    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]),
                      json=indicator_list_response_200, status_code=200)

    assert main_test_module(client=mock_client) == "ok"


@pytest.mark.parametrize('params, err_msg', [
    ({'url': '', 'credentials': {'password': API_KEY}, 'integrationReliability': 'B - Usually reliable'},
     MESSAGES["NO_PARAM_PROVIDED"].format('Server URL')),
    ({'url': MOCK_URL, 'credentials': '', 'integrationReliability': 'B - Usually reliable'},
     MESSAGES["NO_PARAM_PROVIDED"].format('API Key'))])
def test_test_module_when_invalid_params_provided(params, err_msg, mocker, capfd):
    """
    Test case scenario for execution of test_module when invalid argument provided.

    Given:
        - Params for test_module.
    When:
        - Calling `main` function.
    Then:
        - Returns exception.
    """
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(sys, 'exit', return_value=None)

    return_error = mocker.patch.object(IgniteFeed, "return_error")
    capfd.close()
    main()

    assert err_msg in return_error.call_args[0][0]


@pytest.mark.parametrize("status_code", [
    400, 401, 403, 404, 500
])
def test_http_request_when_error_is_returned(requests_mock, mock_client, status_code):
    """
    Tests http_request method of Client class.

    Given:
        - Status codes of requests.
    When:
        - Calling `http_request` function.
    Then:
        - Returns exception.
    """
    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX['ATTRIBUTES']), status_code=status_code)

    with pytest.raises(DemistoException) as e:
        mock_client.http_request(method='GET', url_suffix=URL_SUFFIX['ATTRIBUTES'], params={})

    assert str(e.value) == HTTP_ERRORS[status_code]


def test_http_request_when_raise_for_status(mock_client):
    """Tests http_request when error raised for status."""
    resp = MockResponse(status_code=503)

    with pytest.raises(HTTPError):
        mock_client.handle_errors(resp)


def test_flashpoint_ignite_get_indicators_command_when_invalid_argument_provided(mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-get-indicators command when invalid argument provided.

    Given:
        - command arguments for flashpoint_ignite_get_indicators_command.
    When:
        - Calling `flashpoint_ignite_get_indicators_command` function.
    Then:
        - Returns a valid error message.
    """
    with pytest.raises(ValueError) as err:
        flashpoint_ignite_get_indicators_command(client=mock_client, params={}, args={'limit': -1})

    assert str(err.value) == MESSAGES['LIMIT_ERROR'].format(-1, MAX_FETCH)


def test_flashpoint_ignite_get_indicators_command_when_valid_response_is_returned(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-get-indicators command when valid response is returned.

    Given:
        - command arguments for flashpoint_ignite_get_indicators_command.
    When:
        - Calling `flashpoint_ignite_get_indicators_command` function.
    Then:
        - Returns a valid output.
    """
    args = {'limit': 2}

    indicator_list_response_200: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                    'test_data/indicator_list_200.json'))

    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json=indicator_list_response_200, status_code=200)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/indicator_list_hr.md")) as file:
        hr_output = file.read()

    indicators: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data/indicators.json'))

    actual = flashpoint_ignite_get_indicators_command(client=mock_client, params={"tlp_color": "AMBER"}, args=args)

    assert actual.raw_response == indicators
    assert actual.readable_output == hr_output


def test_flashpoint_ignite_get_indicators_command_when_create_relationship_is_true(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-get-indicators command when create relationship is true.

    Given:
        - command arguments for flashpoint_ignite_get_indicators_command.
    When:
        - Calling `flashpoint_ignite_get_indicators_command` function.
    Then:
        - Returns a valid output.
    """
    args = {'limit': 2}

    indicator_list_response_200: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                    'test_data/indicator_list_200.json'))

    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json=indicator_list_response_200, status_code=200)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/indicator_list_hr.md")) as file:
        hr_output = file.read()

    indicators: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                   'test_data/indicators_with_relationship.json'))

    actual = flashpoint_ignite_get_indicators_command(client=mock_client, params={'createRelationship': True}, args=args)

    assert actual.raw_response == indicators
    assert actual.readable_output == hr_output


def test_flashpoint_ignite_get_indicators_command_when_empty_response_is_returned(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-get-indicators command when empty response is returned.

    Given:
        - command arguments for flashpoint_ignite_get_indicators_command.
    When:
        - Calling `flashpoint_ignite_get_indicators_command` function.
    Then:
        - Returns a no indicator message.
    """
    args = {'limit': 2}

    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json={}, status_code=200)

    actual = flashpoint_ignite_get_indicators_command(client=mock_client, params={}, args=args)

    assert actual.readable_output == MESSAGES['NO_INDICATORS_FOUND']


def test_fetch_indicators_command_when_valid_response_is_returned(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch-indicators command when valid response is returned.

    Given:
        - command arguments for fetch_indicators_command.
    When:
        - Calling `fetch_indicators_command` function.
    Then:
        - Returns a valid output.
    """
    indicator_list_response_200: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                    'test_data/indicator_list_200.json'))

    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json=indicator_list_response_200,
                      headers={'x-fp-total-hits': '5000'}, status_code=200)

    indicators: dict = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data/indicators.json'))

    assert fetch_indicators_command(client=mock_client, params={"tlp_color": "AMBER"}, last_run={})[0] == indicators


def test_test_module_with_isfetch(requests_mock, mocker, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client of type one with valid apikey.
    When:
       - Calling `test_module` function.
    Then:
       - Returns an ok message.
    """
    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json={},
                      headers={'x-fp-total-hits': '5000'}, status_code=200)
    mocker.patch.object(demisto, 'params', return_value={'feed': True, 'url': MOCK_URL, 'credentials': {'password': API_KEY}})

    assert main_test_module(mock_client) == 'ok'


def test_test_module_with_isfetch_when_error(requests_mock, mocker, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client of type one with valid apikey.
    When:
       - Calling `test_module` function.
    Then:
       - Returns an exception.
    """
    requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["ATTRIBUTES"]), json={},
                      headers={'x-fp-total-hits': f'{MAX_INDICATORS + 1}'}, status_code=200)
    mocker.patch.object(demisto, 'params', return_value={'feed': True, 'url': MOCK_URL, 'credentials': {'password': API_KEY}})

    with pytest.raises(ValueError) as err:
        main_test_module(client=mock_client)

    assert str(err.value) == MESSAGES['TIME_RANGE_ERROR'].format(MAX_INDICATORS + 1)

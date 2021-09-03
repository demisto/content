import json
import io
import pytest
from unittest.mock import patch

from test_data import input_data
from FlashpointFeed import Client, HTTP_ERRORS, MESSAGES, MAX_FETCH
from CommonServerPython import DemistoException
from requests.exceptions import HTTPError

BASE_URL = "https://fp.tools/api/v4"
URL_SUFFIX = "/indicators/attribute?limit=1"
MOCKER_HTTP_METHOD = 'FlashpointFeed.Client.http_request'
PARAMS = {
    'feedTags': 'Flashpoint Indicator',
    'tlp_color': 'AMBER',
    'createRelationship': 'true'
}


def util_load_json(path: str) -> dict:
    """Load a json to python dict."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    client_obj = Client(base_url=BASE_URL)
    return client_obj


class MockResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code != 200:
            raise HTTPError('test')


def test_test_module_success(requests_mock, client):
    """
    Tests test_module.
    """
    from FlashpointFeed import test_module

    requests_mock.get(BASE_URL + URL_SUFFIX, json={"message": "dummy"}, status_code=200)
    response = test_module(client, {})
    assert response == "ok"


@pytest.mark.parametrize("status_code", [
    400, 401, 403, 404, 500
])
def test_http_request_when_error_is_returned(requests_mock, client, status_code):
    """
    Tests http_request method of Client class.
    """
    requests_mock.get(BASE_URL + URL_SUFFIX, status_code=status_code)
    with pytest.raises(DemistoException) as e:
        client.http_request(method='GET', url_suffix=URL_SUFFIX)
    assert str(e.value) == HTTP_ERRORS[status_code]


def test_http_request_when_raise_for_status(client):
    resp = MockResponse(status_code=503)

    with pytest.raises(HTTPError):
        client.handle_errors(resp)


def test_create_indicators_from_response(client):
    """
    Test case scenario when valid response is provided to create_indicators_from_response
    """
    response = util_load_json('test_data/fetch_indicators_response.json')
    indicators = util_load_json('test_data/fetch_indicators.json')

    params = PARAMS
    assert client.create_indicators_from_response(response, '', params, False) == indicators


def test_validate_fetch_indicators_params_when_valid_params_are_provided():
    """
    Test case scenario when the parameters provided are valid.
    """
    from FlashpointFeed import validate_fetch_indicators_params

    params = {
        'types': 'url',
        'first_fetch': '03/07/2021'
    }

    fetch_params = {
        'limit': MAX_FETCH,
        'types': 'url',
        'updated_since': '2021-03-07T00:00:00Z',
        'sort_timestamp': 'asc'
    }
    assert validate_fetch_indicators_params(params) == fetch_params


@pytest.mark.parametrize("params, err_msg", input_data.fetch_indicator_params)
def test_validate_fetch_indicators_params_when_invalid_params_are_provided(params, err_msg):
    """
    Test case scenario when the parameters provided are not valid.
    """
    from FlashpointFeed import validate_fetch_indicators_params

    with pytest.raises(ValueError) as err:
        validate_fetch_indicators_params(params)
    assert str(err.value) == err_msg


@patch(MOCKER_HTTP_METHOD)
def test_fetch_indicators_command_when_valid_response_is_returned(mocker_http_request, client):
    """
    Test case scenario for successful execution of fetch_indicators_command.
    """
    from FlashpointFeed import fetch_indicators_command

    response = util_load_json('test_data/fetch_indicators_response.json')
    mocker_http_request.return_value = response

    indicators = util_load_json('test_data/fetch_indicators.json')

    params = PARAMS
    assert fetch_indicators_command(client, params, {}, False) == indicators


def test_validate_get_indicators_params_when_valid_params_are_provided():
    """
    Test case scenario when the parameters provided are valid.
    """
    from FlashpointFeed import validate_get_indicators_args

    params = {
        'limit': 5,
        'types': 'url',
        'updated_since': '03/07/2021'
    }

    fetch_params = {
        'limit': 5,
        'types': 'url',
        'updated_since': '2021-03-07T00:00:00Z',
        'sort_timestamp': 'asc'
    }
    assert validate_get_indicators_args(params) == fetch_params


@pytest.mark.parametrize("params, err_msg", input_data.get_indicator_params)
def test_validate_get_indicators_params_when_invalid_params_are_provided(params, err_msg):
    """
    Test case scenario when the parameters provided are not valid.
    """
    from FlashpointFeed import validate_get_indicators_args

    with pytest.raises(ValueError) as err:
        validate_get_indicators_args(params)
    assert str(err.value) == err_msg


@patch(MOCKER_HTTP_METHOD)
def test_get_indicators_command_when_valid_response_is_returned(mocker_http_request, client):
    """
    Test case scenario for successful execution of get_indicators_command.
    """
    from FlashpointFeed import get_indicators_command

    mock_response = util_load_json('test_data/fetch_indicators_response.json')
    mocker_http_request.return_value = mock_response

    indicators = util_load_json('test_data/fetch_indicators.json')

    with open('test_data/get_indicators.md') as data:
        expected_hr = data.read()

    params = PARAMS
    result = get_indicators_command(client, params, {})

    assert result.raw_response == indicators
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_get_indicators_command_when_empty_response_is_returned(mocker_http_request, client):
    """
    Test case scenario for successful execution of get_indicators_command with an empty response.
    """
    from FlashpointFeed import get_indicators_command

    mocker_http_request.return_value = {}
    result = get_indicators_command(client, {}, {})

    assert result.readable_output == MESSAGES["NO_INDICATORS_FOUND"]

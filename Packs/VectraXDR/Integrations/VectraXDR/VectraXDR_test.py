import copy
from pathlib import Path
import pytest
from requests.models import Response
from urllib.parse import urlencode
from unittest.mock import patch

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import VectraXDR
from VectraXDR import VectraClient, fetch_incidents, vectra_entity_list_command, vectra_entity_describe_command, \
    vectra_entity_detection_list_command, vectra_detection_describe_command, vectra_entity_note_add_command, \
    vectra_entity_note_update_command, vectra_entity_note_remove_command, vectra_entity_tag_add_command, \
    vectra_entity_tag_remove_command, vectra_detections_mark_fixed_command, vectra_detections_unmark_fixed_command, \
    vectra_entity_assignment_add_command, vectra_entity_assignment_update_command, \
    vectra_entity_assignment_resolve_command, vectra_detection_pcap_download_command, vectra_user_list_command, \
    vectra_entity_detections_mark_fixed_command, vectra_assignment_list_command, vectra_entity_tag_list_command, \
    vectra_assignment_outcome_list_command, vectra_entity_note_list_command, update_remote_system_command, \
    vectra_group_list_command, vectra_group_assign_command, vectra_group_unassign_command, \
    get_modified_remote_data_command, get_remote_data_command
from VectraXDR import ERRORS, VALID_ENTITY_TYPE, VALID_ENTITY_STATE, DETECTION_CATEGORY_TO_ARG, ENDPOINTS, \
    VALID_GROUP_TYPE, VALID_IMPORTANCE_VALUE

# Constants
TEST_DATA_DIR = Path(__file__).parent / 'test_data'
BASE_URL = 'http://serverurl.com'


# Helper Functions
def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client(mocker):
    mocker.patch.object(VectraClient, '_generate_tokens', return_value='test_token')
    return VectraClient(BASE_URL, 'client_id', 'client_secret_key', verify=False, proxy=False)


def add_params_in_url(base_url: str, params: Dict):
    encoded_params = urlencode(params)

    base_url = f'{base_url}?{encoded_params}'
    return base_url


def test_generate_tokens(requests_mock):
    """
    Given
    - Mocked response for generating access tokens.
    - VectraClient instance.

    When
    - Calling the `_generate_tokens` method.

    Then
    - Ensure the generated access token matches the expected access token.
    """
    # Set up
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    requests_mock.post('http://serverurl.com/oauth2/token', json=response_data, status_code=200)
    client = VectraClient('http://serverurl.com', 'client_id', 'client_secret_key', verify=True, proxy=False)
    token = client._generate_tokens()
    assert token == access_token


def test_generate_tokens_failure(requests_mock):
    """
    Given
    - Mocked failed response for generating access tokens.
    - VectraClient instance.

    When
    - Calling the `_generate_tokens` method.

    Then
    - Ensure the method raises an exception.
    """
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    requests_mock.post('http://serverurl.com/oauth2/token', json=response_data, status_code=500)
    client = VectraClient('http://serverurl.com', 'client_id', 'client_secret_key', verify=True, proxy=False)

    # Call the method
    with pytest.raises(Exception):
        client._generate_tokens()


def test_generate_access_token_using_refresh_token(requests_mock, mocker):
    """
    Given
    - Mocked response for generating access token using refresh token.
    - VectraClient instance.
    - Mocked `get_integration_context` method.

    When
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then
    - Ensure the generated access token matches the expected access token.
    """
    # Set up
    access_token = "access_token"
    response_data = {
        "access_token": access_token,
    }
    requests_mock.post('http://serverurl.com/oauth2/token', json=response_data, status_code=200)
    client = VectraClient('http://serverurl.com', 'client_id', 'client_secret_key', verify=True, proxy=False)
    mocker.patch('CommonServerPython.get_integration_context', return_value={'refresh_token': 'refresh_token'})
    token = client._generate_access_token_using_refresh_token()
    assert token == access_token


def test_generate_access_token_using_refresh_token_failure(requests_mock):
    """
    Given
    - Mocked failed response for generating access token using refresh token.
    - VectraClient instance.

    When
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then
    - Ensure the method raises an exception.
    """
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    requests_mock.post('http://serverurl.com/oauth2/token', json=response_data, status_code=500)
    client = VectraClient('http://serverurl.com', 'client_id', 'client_secret_key', verify=True, proxy=False)

    # Call the method
    with pytest.raises(Exception):
        client._generate_access_token_using_refresh_token()


def test_generate_access_token_using_refresh_token_401_status_code(requests_mock, mocker, client):
    """
    Given:
    - A client object.
    - A mocked HTTP POST request to the token endpoint with a status code of 401.
    - A mocked '_generate_tokens' method that raises an exception.

    When:
    - Calling the '_generate_access_token_using_refresh_token' method.

    Then:
    - Assert that an exception is raised.
    - Assert that the '_generate_tokens' method is called once.
    """
    requests_mock.post('http://serverurl.com/oauth2/token', status_code=401)
    generate_token = mocker.patch.object(client, '_generate_tokens', side_effect=Exception())

    # Call the method
    with pytest.raises(Exception):
        client._generate_access_token_using_refresh_token()

    generate_token.assert_called_once()


def test_http_request_with_valid_parameters(mocker, client):
    """
    Given:
    - A mocked `_http_request` method.
    - A client object.

    When:
    - Making a request with valid parameters.

    Then:
    - Assert that the response status code is 200 (indicating a successful request).
    """
    response = Response()
    response.status_code = 200
    mocker.patch.object(BaseClient, "_http_request", return_value=response)

    response = client.http_request(method="GET", url_suffix="/test")

    assert response.status_code == 200


def test_http_request_with_invalid_parameters(mocker, client):
    """
    Given:
    - A mocked `_http_request` method that raises an exception.
    - A client object.

    When:
    - Making a request with invalid parameters.

    Then:
    - Assert that the raised exception matches the expected exception.
    """
    # Mock the `_http_request` method to raise an exception.
    mocker.patch.object(BaseClient, "_http_request", side_effect=Exception())

    # Make a request with invalid parameters.
    with pytest.raises(Exception):
        client.http_request(method="GET", url_suffix="/test")


def test_http_request_with_401_status_code(mocker, client):
    """
     Given:
     - A mocked `_http_request` method that returns a response with a 401 status code.
     - A client object.

     When:
     - Making a request that results in a 401 status code.

     Then:
     - Assert that an exception is raised.
     - Assert that the `_generate_access_token_using_refresh_token` method is called once.
     """
    response = Response()
    response.status_code = 401
    mocker.patch.object(BaseClient, "_http_request", return_value=response)
    generate_token = mocker.patch.object(client, "_generate_access_token_using_refresh_token", side_effect=Exception())
    with pytest.raises(Exception):
        client.http_request(method="GET", url_suffix="/test")
    generate_token.assert_called_once()


def test_test_module(mocker, client):
    """
    Given
    - VectraXDR test module

    When
    - mock the demisto params.
    - mock the VectraClient's generate_tokens.
    - mock the VectraClient.
    - mock the VectraClient's list_entities_request.

    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    from VectraXDR import test_module as module

    mocker.patch.object(demisto, 'params', return_value={})
    entity = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')

    mocker.patch.object(client, 'list_entities_request', return_value=entity)
    result = module(client)

    assert result == 'ok'


def test_test_module_is_fetch_enabled(mocker, client):
    """
    Given
    - VectraXDR test module and fetch incident is enabled

    When
    - mock the VectraClient's generate_tokens.
    - mock the VectraClient.
    - mock the VectraClient's list_entities_request.

    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    from VectraXDR import test_module as module
    params = {
        'isFetch': True,
        'first_fetch': '1 day',
        'max_fetch': '200',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '80'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    entity = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')

    mocker.patch.object(client, 'list_entities_request', return_value=entity)
    result = module(client)

    assert result == 'ok'


def test_test_module_is_fetch_enabled_and_empty_first_fetch(mocker, client):
    """
    Given:
    - VectraXDR test module and fetch incident is enabled

    When:
    - The 'first_fetch' parameter is set to an empty value.

    Then:
    - The `test_module` command should return an error
    """
    from VectraXDR import test_module as module
    params = {
        'isFetch': True,
        'max_fetch': '200',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '80'
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(ValueError):
        module(client)


def test_test_module_is_fetch_enabled_and_invalid_max_fetch(mocker, client):
    """
    Given:
    - VectraXDR test module and fetch incident is enabled

    When:
    - The 'max_fetch' parameter is set to an invalid value.

    Then:
    - The `test_module` command should return an error
    """
    from VectraXDR import test_module as module
    params = {
        'isFetch': True,
        'first_fetch': '1 hour',
        'max_fetch': '-1',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '80'
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(ValueError):
        module(client)


def test_test_module_is_fetch_enabled_and_invalid_urgency_score(mocker, client):
    """
    Given:
    - VectraXDR test module and fetch incident is enabled

    When:
    - The 'urgency_score' parameter is set to an invalid value

    Then:
    - The `test_module` command should return an error
    """
    from VectraXDR import test_module as module
    params = {
        'isFetch': True,
        'first_fetch': '1 hour',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '-1'
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(ValueError):
        module(client)


def test_test_module_is_fetch_enabled_and_invalid_threshold_value_of_urgency_scores(mocker, client):
    """
    Given:
    - VectraXDR test module and fetch incident is enabled

    When:
    - The urgency_scores_threshold parameters is set to an invalid value

    Then:
    - The `test_module` command should return an error
    """
    from VectraXDR import test_module as module
    params = {
        'isFetch': True,
        'first_fetch': '1 hour',
        'max_fetch': '200',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score_high_threshold': '10',
        'urgency_score_medium_threshold': '20',
        'urgency_score_low_threshold': '80'
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    with pytest.raises(ValueError):
        module(client)


def test_fetch_incidents_with_no_params(mocker, client):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method that returns an empty dictionary.
    - A mocked 'list_entities_request' method that returns a sample entity data.

    When:
    - Fetching incidents using the 'fetch_incidents' function with no additional parameters.

    Then:
    - Assert that the number of fetched incidents is equal to the number of entities in the entity data.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    entity_data = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')
    mocker.patch.object(client, 'list_entities_request', return_value=entity_data)
    mocker.patch.object(client, 'list_detections_request', return_value={})
    mocker.patch.object(client, 'list_assignments_request', return_value={})
    params = {
        'isFetch': True,
        'first_fetch': '1 hour',
        'max_fetch': '200',
    }
    incidents = fetch_incidents(client, params)
    assert len(incidents) == len(entity_data.get('results'))


def test_fetch_incidents_with_params(mocker, client):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method that returns an empty dictionary.
    - A mocked 'setLastRun' method.
    - A mocked 'list_entities_request' method that returns a sample entity data.
    - Parameters for fetching incidents.

    When:
    - Fetching incidents using the 'fetch_incidents' function with the provided parameters.

    Then:
    - Assert that the number of fetched incidents is equal to the expected count.
    - Assert the properties of the first fetched incident, such as name, occurred timestamp, raw JSON, and severity.
    """
    last_run = json.dumps({'time': '2023-05-15T09:39:09Z',
                           'next_url': 'https://serverurl.com/api/v3.3/entities'
                                       '?is_prioritized=True'
                                       '&last_detection_timestamp_gte=2023-05'
                                       '-15T09 '
                                       '%3A39%3A09Z&ordering'
                                       '=last_detection_timestamp&page=2'
                                       '&page_size '
                                       '=3&state=active&type=account',
                           'already_fetched': [352, 343]})
    mocker.patch.object(demisto, 'getLastRun', return_value={'value': last_run})
    mocker.patch.object(demisto, 'setLastRun')
    entity_data = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')
    mocker.patch.object(client, 'list_entities_request', return_value=entity_data)
    mocker.patch.object(client, 'list_detections_request', return_value={})
    mocker.patch.object(client, 'list_assignments_request', return_value={})
    params = {
        'isFetch': True,
        'first_fetch': '1 day',
        'max_fetch': '201',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '80'
    }

    incidents = fetch_incidents(client, params)
    assert len(incidents) == 4
    assert incidents[0]['name'] == 'Vectra XDR Entity host_name:334'
    assert incidents[0]['occurred'] == entity_data.get('results')[0].get('last_modified_timestamp')
    assert incidents[0]['rawJSON'] == json.dumps(entity_data.get('results')[0])
    assert incidents[0]['severity'] == 4


def test_fetch_incidents_when_invalid_page_reached(mocker, client, requests_mock):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method.
    - A mocked 'setLastRun' method.
    - A mocked list entities endpoint which returns a 404 error.
    - Parameters for fetching incidents.

    When:
    - Fetching incidents using the 'fetch_incidents' function with the provided parameters.

    Then:
    - Assert that the number of fetched incidents is equal to the expected count.
    """
    last_run = json.dumps({'time': '2023-05-15T09:39:09Z',
                           'next_url': 'https://serverurl.com/api/v3.3/entities'
                                       '?is_prioritized=True'
                                       '&last_detection_timestamp_gte=2023-05'
                                       '-15T09 '
                                       '%3A39%3A09Z&ordering'
                                       '=last_detection_timestamp&page=2'
                                       '&page_size '
                                       '=2&state=active&type=account',
                           'already_fetched': [352, 343]})
    mocker.patch.object(demisto, 'getLastRun', return_value={'value': last_run})
    mocker.patch.object(demisto, 'setLastRun')
    entity_data = util_load_json(f'{TEST_DATA_DIR}/invalid_page_number_404_error.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_ENDPOINT'], json=entity_data, status_code=404)
    params = {
        'isFetch': True,
        'first_fetch': '1 day',
        'max_fetch': '20',
        'entity_type': 'account',
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'entity_importance': 'High',
        'urgency_score': '80'
    }

    incidents = fetch_incidents(client, params)
    assert len(incidents) == 0


def test_fetch_incidents_with_invalid_max_fetch(client):
    """
    Given:
    - A client object.
    - Parameters specifying invalid max fetch value.

    When:
    - Calling the 'fetch_incidents' function with the provided client and parameters.

    Then:
    - The `fetch_incidents` command should return an error
    """
    params = {
        'isFetch': True,
        'first_fetch': '1 day',
        'max_fetch': '-1',
        'entity_type': ['account,host'],
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'urgency_score_low_threshold': '101',
        'urgency_score_medium_threshold': '101',
        'urgency_score_high_threshold': '101',
    }

    with pytest.raises(ValueError) as exception:
        fetch_incidents(client, params)

    assert str(exception.value) == ERRORS["INVALID_MAX_FETCH"].format(-1)


def test_fetch_incidents_with_invalid_urgency_score_threshold_params(capfd, mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'getLastRun' method returning last run data.
    - Mocked 'setLastRun' method.
    - Mocked 'list_entities_request' method returning entity data.
    - Parameters specifying invalid urgency score threshold values.

    When:
    - Calling the 'fetch_incidents' function with the provided client and parameters.

    Then:
    - Assert that the function does not raise any exceptions.
    - Assert that the severity of the fetched incidents matches the expected values.
    """
    last_run = json.dumps({'time': '2023-05-15T09:39:09Z',
                           'next_url': 'https://server.com/api/v3.3/entities'
                                       '?is_prioritized=True'
                                       '&last_detection_timestamp_gte=2023-05'
                                       '-15T09 '
                                       '%3A39%3A09Z&ordering'
                                       '=last_detection_timestamp&page=2'
                                       '&page_size '
                                       '=3&state=active&type=account',
                           'already_fetched': [352, 343]})
    mocker.patch.object(demisto, 'getLastRun', return_value={'value': last_run})
    mocker.patch.object(demisto, 'setLastRun')
    entity_data = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')
    mocker.patch.object(client, 'list_entities_request', return_value=entity_data)
    mocker.patch.object(client, 'list_detections_request', return_value={})
    mocker.patch.object(client, 'list_assignments_request', return_value={})
    params = {
        'isFetch': True,
        'first_fetch': '1 day',
        'max_fetch': '4',
        'entity_type': ['account,host'],
        'is_prioritized': "Yes",
        'tags': 'tag1,tag2',
        'urgency_score_low_threshold': '101',
        'urgency_score_medium_threshold': '101',
        'urgency_score_high_threshold': '101',
    }

    with capfd.disabled():
        incidents = fetch_incidents(client, params)

    assert incidents[0].get('severity') == 4
    assert incidents[1].get('severity') == 3
    assert incidents[2].get('severity') == 2
    assert incidents[3].get('severity') == 1


def test_vectra_user_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_user_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    user_res = util_load_json(f'{TEST_DATA_DIR}/user_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/user_list_context.json')
    with open(f'{TEST_DATA_DIR}/user_list_hr.md') as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS['USER_ENDPOINT'], json=user_res)
    # Call the function
    result = vectra_user_list_command(client, {"last_login_timestamp": "1 year"})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.User'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['user_id']


def test_vectra_user_list_when_response_is_empty(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_users_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_user_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    requests_mock.get(BASE_URL + ENDPOINTS['USER_ENDPOINT'], json=empty_response)

    # Call the function
    result = vectra_user_list_command(client, {})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "##### Got the empty list of users."
    assert result_context.get('EntryContext') == {}


def test_vectra_entity_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity response.
    - Arguments specifying valid parameters for entity listing.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output contains the expected content.
    - Assert that the 'Contents' property in the context matches the entity data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_data = util_load_json(f'{TEST_DATA_DIR}/list_entity_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/list_entity_context.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_ENDPOINT'], json=entity_data)
    with open(f'{TEST_DATA_DIR}/list_entity_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_type': 'account',
        'state': 'active',
        'ordering': 'name',
        'page': '1',
        'page_size': '4',
        'prioritized': 'true',
        'tags': 'test,test1',
        'last_modified_timestamp': '2 days',
        'last_detection_timestamp': '2 days'
    }

    # Call the function
    result = vectra_entity_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == entity_data.get('results')
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['id', 'type']


def test_vectra_entity_list_when_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entities_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    mocker.patch.object(client, 'list_entities_request', return_value=empty_response)
    args = {
        'tags': 'invalid_tag',
    }

    # Call the function
    result = vectra_entity_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "##### Couldn't find any matching entities for provided filters."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'state': 'invalid_state'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('state', ', '.join(VALID_ENTITY_STATE))),
                          ({'page_size': '5001'},
                           ERRORS['INVALID_PAGE_SIZE'])])
def test_vectra_entity_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid values.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for the corresponding invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_describe_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for getting an entity.

    When:
    - Calling the 'vectra_entity_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the entity data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_data = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/get_entity_context.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_ENDPOINT'] + '/21', json=entity_data)
    with open(f'{TEST_DATA_DIR}/get_entity_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '21',
        'entity_type': 'account'
    }

    # Call the function
    result = vectra_entity_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == entity_data
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['id', 'type']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_type': 'account'}, ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': ''},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_describe_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying an invalid entity_type value.

    When:
    - Calling the 'vectra_entity_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for an invalid entity_type value.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_describe_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_detection_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.

    When:
    - A mock entity and detections response.
    - Opening and reading a specific human-readable file.
    - Providing arguments with a valid entity_id, page, and page_size.

    Then:
    - Call the 'vectra_list_entity_detection_command' function with the provided client and arguments.
    - Assert that the CommandResults outputs_prefix is 'Vectra.Entity.Detections'.
    - Assert that the CommandResults HumanReadable matches the content of the read human-readable file.
    - Assert that the CommandResults Contents match the expected detections data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert that the CommandResults outputs_key_field is 'id'.
    """
    detections_data = util_load_json(f'{TEST_DATA_DIR}/entity_detection_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_detection_list_context.json')
    entity_data = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_ENDPOINT'] + '/21', json=entity_data)
    requests_mock.get(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=detections_data)
    with open(f'{TEST_DATA_DIR}/entity_detection_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '21',
        'entity_type': 'account',
        'page': '1',
        'page_size': '50',
        'last_timestamp': '2 days',
        'detection_category': 'Botnet'
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Detections'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == detections_data
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == 'id'


def test_vectra_entity_detection_list_when_detection_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detections_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    entity_data = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    mocker.patch.object(client, 'get_entity_request', return_value=entity_data)
    mocker.patch.object(client, 'list_detections_request', return_value=empty_response)
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'tags': 'invalid_tag',
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Couldn't find any matching entity detections for provided filters."
    assert result_context.get('EntryContext') == {}


def test_vectra_entity_detection_list_when_entity_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'get_entity_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }

    mocker.patch.object(client, 'get_entity_request', return_value={})
    mocker.patch.object(client, 'list_detections_request', return_value=empty_response)
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'tags': 'invalid_tag',
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Couldn't find any matching detections for provided entity ID and type."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': None}, ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({"entity_id": '1', 'entity_type': 'account', 'page': '0'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('page')),
                          ({"entity_id": '1', 'entity_type': 'account', 'page_size': '0'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('page_size')),
                          ({"entity_id": '1', 'entity_type': 'account', 'page_size': '5001'},
                           ERRORS['INVALID_PAGE_SIZE']),
                          ({"entity_id": '1', 'entity_type': 'account', 'detection_category': 'command and control'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('detection_category',
                                                                      ', '.join(DETECTION_CATEGORY_TO_ARG.keys()))),
                          ({'entity_id': '1', 'entity_type': ''}, ERRORS['REQUIRED_ARGUMENT'].format('entity_type')),
                          ({'entity_id': '1', 'entity_type': 'invalid'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE)))])
def test_vectra_entity_detection_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, page, and page_size.

    When:
    - Calling the 'vectra_list_entity_detection_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_detection_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_describe_valid_arguments(mocker, client):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'list_detections_request' method of the client to return a specific detection data.
    - Opening and reading a specific human-readable file.
    - Providing arguments with a valid detection_ids, page, and page_size.

    Then:
    - Call the 'vectra_detection_describe_command' function with the provided client and arguments.
    - Assert that the CommandResults outputs_prefix is 'Vectra.Entity.Detections'.
    - Assert that the CommandResults HumanReadable matches the content of the read human-readable file.
    - Assert that the CommandResults Contents match the expected detection data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert that the CommandResults outputs_key_field is 'id'.
    """
    detections_data = util_load_json(f'{TEST_DATA_DIR}/entity_detection_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_detection_list_context.json')
    mocker.patch.object(client, 'list_detections_request', return_value=detections_data)
    with open(f'{TEST_DATA_DIR}/entity_detection_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'detection_ids': '21',
        'page': '1',
        'page_size': '50'
    }

    # Call the function
    result = vectra_detection_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Detections'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == detections_data
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == 'id'


def test_vectra_detection_describe_when_detection_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detections_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    mocker.patch.object(client, 'list_detections_request', return_value=empty_response)
    args = {
        'detection_ids': '21'
    }

    # Call the function
    result = vectra_detection_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Couldn't find any matching detections for provided detection ID(s)."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'detection_ids': None}, ERRORS['REQUIRED_ARGUMENT'].format('detection_ids')),
                          ({'detection_ids': " "}, ERRORS['REQUIRED_ARGUMENT'].format('detection_ids')),
                          ({'detection_ids': ",   , ,"}, ERRORS['REQUIRED_ARGUMENT'].format('detection_ids')),
                          ({'detection_ids': ",,abc,"}, ERRORS['INVALID_NUMBER'].format('abc')),
                          ({'detection_ids': ",,abc,12"}, ERRORS['INVALID_NUMBER'].format('abc')),
                          ({'detection_ids': ",-12,"}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_ids')),
                          ({'detection_ids': ",12,", 'page': '0'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('page')),
                          ({'detection_ids': ",12,", 'page_size': '0'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('page_size')),
                          ({'detection_ids': ",12,", 'page_size': '5001'},
                           ERRORS['INVALID_PAGE_SIZE'])])
def test_vectra_detection_describe_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_ids, page, and page_size.

    When:
    - Calling the 'vectra_detection_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_describe_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to an entity.

    When:
    - Calling the 'vectra_entity_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f'{TEST_DATA_DIR}/entity_note_add_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_note_add_context.json')
    requests_mock.post(BASE_URL + ENDPOINTS['ADD_AND_LIST_ENTITY_NOTE_ENDPOINT'].format('1'), json=notes_res)
    with open(f'{TEST_DATA_DIR}/entity_note_add_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'note': 'test_note',
    }

    # Call the function
    result = vectra_entity_note_add_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["entity_id"] = 1
    notes_res["entity_type"] = "account"
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Notes'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == notes_res
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['entity_id', 'entity_type', 'note_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': ''}, ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_note_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and note.

    When:
    - Calling the 'vectra_entity_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_update_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock note response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f'{TEST_DATA_DIR}/entity_note_update_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_note_update_context.json')
    requests_mock.patch(BASE_URL + ENDPOINTS['UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT'].format(1, 1), json=notes_res)
    with open(f'{TEST_DATA_DIR}/entity_note_update_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'note_id': '1',
        'note': 'test_note',
    }

    # Call the function
    result = vectra_entity_note_update_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["entity_id"] = 1
    notes_res["entity_type"] = "account"
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Notes'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == notes_res
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['entity_id', 'entity_type', 'note_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type', 'note_id': '1'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': 'account', 'note_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note_id')),
                          ({'entity_id': '0', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'note_id': '0', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id')),
                          ({'note_id': '-1', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id')),
                          ({'note_id': '1.5', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id')),
                          ({'entity_id': '1', 'entity_type': '', 'note_id': '2'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_note_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_remove_valid_arguments(requests_mock, client):
    """
    Tests the 'vectra_entity_note_remove_command' function with valid arguments.

    Ensures that the function removes an entity note and returns the expected CommandResults object.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS['UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT'].format(1, 1), status_code=204)
    with open(f'{TEST_DATA_DIR}/entity_note_remove_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'note_id': '1',
    }

    # Call the function
    result = vectra_entity_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == {}


def test_vectra_entity_note_remove_invalid_status_code(requests_mock, client):
    """
    Tests the 'vectra_entity_note_remove_command' function with valid arguments.

    Ensures that the function gives error in HR for status code.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS['UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT'].format(1, 1), status_code=200)
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'note_id': '1',
    }

    # Call the function
    result = vectra_entity_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == 'Something went wrong.'
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type', 'note_id': '1'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '1', 'note_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type')),
                          ({'entity_id': '1', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note_id')),
                          ({'entity_id': '0', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account', 'note': 'test_note', 'note_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'note_id': '0', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id')),
                          ({'note_id': '-1', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id')),
                          ({'note_id': '1.5', 'entity_type': 'account', 'note': 'test_note', 'entity_id': '1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id'))
                          ])
def test_vectra_entity_note_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_remove_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock get and update tag response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    add_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_add_response.json')
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_tag_add_context.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_TAG_ENDPOINT'].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS['ENTITY_TAG_ENDPOINT'].format(1), json=add_tags_res)
    with open(f'{TEST_DATA_DIR}/entity_tag_add_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag1, tag2',
    }

    # Call the function
    result = vectra_entity_tag_add_command(client, args)
    result_context = result.to_context()
    add_tags_res.update({'entity_id': 1, 'entity_type': 'host'})
    del add_tags_res['status']
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Tags'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == add_tags_res
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['tag_id', 'entity_type', 'entity_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('tags')),
                          ({'entity_id': '1', 'entity_type': 'account', 'tags': ' , '},
                           ERRORS['REQUIRED_ARGUMENT'].format('tags')),
                          ({'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account', 'tags': ' , tag1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account', 'tags': 'tag1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account', 'tags': 'tag1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': '', 'tags': 'tag1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_tag_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_add_when_get_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_invalid_response.json')
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag1, tag2',
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == f'Something went wrong. Message: {get_tags_res.get("message")}.'


def test_vectra_entity_tag_add_when_add_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response.json')
    add_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_add_invalid_response.json')
    mocker.patch.object(client, 'update_entity_tags_request', return_value=add_tags_res)
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag1, tag2',
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == f'Something went wrong. Message: {add_tags_res.get("message")}.'


def test_vectra_entity_tag_remove_valid_arguments(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    add_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_remove_response.json')
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response_2.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_tag_remove_context.json')
    mocker.patch.object(client, 'update_entity_tags_request', return_value=add_tags_res)
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    with open(f'{TEST_DATA_DIR}/entity_tag_remove_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag2'
    }

    # Call the function
    result = vectra_entity_tag_remove_command(client, args)
    result_context = result.to_context()
    add_tags_res.update({'entity_id': 1, 'entity_type': 'host'})
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Tags'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == add_tags_res
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['tag_id', 'entity_type', 'entity_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('tags')),
                          ({'entity_id': '1', 'entity_type': 'account', 'tags': ' , '},
                           ERRORS['REQUIRED_ARGUMENT'].format('tags')),
                          ({'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id'))
                          ])
def test_vectra_entity_tag_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id and entity_type.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_remove_when_get_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_invalid_response.json')
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag2',
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == f'Something went wrong. Message: {get_tags_res.get("message")}.'


def test_vectra_entity_tag_remove_when_add_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response_2.json')
    add_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_add_invalid_response.json')
    mocker.patch.object(client, 'update_entity_tags_request', return_value=add_tags_res)
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag2',
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == f'Something went wrong. Message: {add_tags_res.get("message")}.'


def test_vectra_entity_tag_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response_2.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_tag_list_context.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_TAG_ENDPOINT'].format(1), json=get_tags_res)
    with open(f'{TEST_DATA_DIR}/entity_tag_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'host'
    }

    # Call the function
    result = vectra_entity_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({'entity_id': 1, 'entity_type': 'host'})
    del get_tags_res["status"]
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Tags'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == get_tags_res
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['tag_id', 'entity_type', 'entity_id']


def test_vectra_entity_tag_list_with_empty_tag_response(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'list_entity_tags_request' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_response_2.json')
    get_tags_res["tags"] = []
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_tag_empty_list_context.json')
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    with open(f'{TEST_DATA_DIR}/entity_tag_empty_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'host'
    }

    # Call the function
    result = vectra_entity_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({'entity_id': 1, 'entity_type': 'host'})
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Tags'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == get_tags_res
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['tag_id', 'entity_type', 'entity_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': ''},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_tag_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and tags.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_list_when_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f'{TEST_DATA_DIR}/entity_tag_get_invalid_response.json')
    mocker.patch.object(client, 'list_entity_tags_request', return_value=get_tags_res)
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'tags': 'tag1, tag2',
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_list_command(client, args)

    assert str(exception.value) == f'Something went wrong. Message: {get_tags_res.get("message")}.'


def test_vectra_detections_mark_fixed_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection mark fixed response.
    - The expected human-readable output file.
    - Arguments specifying valid detection IDs to mark as fixed.

    When:
    - Calling the 'vectra_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context is empty.
    """
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    with open(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_hr.md') as f:
        result_hr = f.read()
    result_hr = result_hr.split('\n')
    args = {
        'detection_ids': '1,2,3'
    }

    # Call the function
    result = vectra_detections_mark_fixed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == result_hr[0]
    assert result_context.get('EntryContext') == {}


def test_vectra_detections_mark_fixed_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection mark fixed invalid response.
    - Arguments specifying valid detection IDs to mark as fixed.

    When:
    - Calling the 'vectra_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    response["_meta"]["level"] = "failure"
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    args = {
        'detection_ids': '1,2,3'
    }

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_detections_mark_fixed_command(client, args)

    assert str(exception.value) == "Something went wrong."


@pytest.mark.parametrize('args,error_msg',
                         [({}, ERRORS['REQUIRED_ARGUMENT'].format('detection_ids')),
                          ({'detection_ids': 'as,2'}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_ids'))])
def test_vectra_detections_mark_fixed_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Empty arguments.

    When:
    - Calling the 'vectra_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detections_mark_fixed_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detections_unmark_fixed_valid_arguments(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'mark_or_unmark_detection_fixed_request' method returning response data.
    - The expected human-readable output file.
    - Arguments specifying valid detection IDs to unmark as fixed.

    When:
    - Calling the 'vectra_detections_unmark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context is empty.
    """
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    mocker.patch.object(client, 'mark_or_unmark_detection_fixed_request', return_value=response)
    with open(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_hr.md') as f:
        result_hr = f.read()
    result_hr = result_hr.split('\n')
    args = {
        'detection_ids': '1,2,3'
    }

    # Call the function
    result = vectra_detections_unmark_fixed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == result_hr[1]
    assert result_context.get('EntryContext') == {}


def test_vectra_detections_unmark_fixed_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection unmark fixed invalid response.
    - Arguments specifying valid detection IDs to mark as fixed.

    When:
    - Calling the 'vectra_detections_unmark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    response["_meta"]["level"] = "failure"
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    args = {
        'detection_ids': '1,2,3'
    }

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_detections_unmark_fixed_command(client, args)

    assert str(exception.value) == "Something went wrong."


@pytest.mark.parametrize('args,error_msg',
                         [({}, ERRORS['REQUIRED_ARGUMENT'].format('detection_ids')),
                          ({'detection_ids': 'as,2'}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_ids'))])
def test_vectra_detections_unmark_fixed_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Empty arguments.

    When:
    - Calling the 'vectra_detections_unmark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detections_unmark_fixed_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_assignment_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'add_entity_assignment_request' method returning assignment data.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding an assignment.

    When:
    - Calling the 'vectra_entity_assignment_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_add_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_add_context.json')
    with open(f'{TEST_DATA_DIR}/entity_assignment_add_account_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'account',
        'user_id': '1'
    }
    requests_mock.post(BASE_URL + ENDPOINTS['ASSIGNMENT_ENDPOINT'], json=assignment_res[0])
    # Call the function
    result = vectra_entity_assignment_add_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[0]
    assert result.outputs_key_field == ['assignment_id']
    # For Host
    with open(f'{TEST_DATA_DIR}/entity_assignment_add_host_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'host',
        'user_id': '3'
    }

    requests_mock.post(BASE_URL + ENDPOINTS['ASSIGNMENT_ENDPOINT'], json=assignment_res[1])
    # Call the function
    result = vectra_entity_assignment_add_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[1]
    assert result.outputs_key_field == ['assignment_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type', 'user_id': '1'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('user_id')),
                          ({'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account', 'note': 'test_note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': 'account', 'user_id': '0'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('user_id')),
                          ({'entity_id': '1', 'entity_type': 'account', 'user_id': '-1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('user_id')),
                          ({'entity_id': '1', 'entity_type': 'account', 'user_id': '1.5'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('user_id')),
                          ({'entity_id': '1', 'entity_type': '', 'user_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'),
                           )])
def test_vectra_entity_assignment_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and user_id.

    When:
    - Calling the 'vectra_entity_assignment_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_assignment_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_assignment_update_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity assignment update response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for updating an entity assignment.

    When:
    - Calling the 'vectra_entity_assignment_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_update_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_update_context.json')
    requests_mock.put(BASE_URL + ENDPOINTS['UPDATE_ASSIGNMENT_ENDPOINT'].format(1), json=assignment_res)
    with open(f'{TEST_DATA_DIR}/entity_assignment_update_hr.md') as f:
        result_hr = f.read()
    args = {
        'assignment_id': '1',
        'user_id': '2'
    }

    # Call the function
    result = vectra_entity_assignment_update_command(client, args)
    result_context = result.to_context()
    assignment_res.get('assignment')["assignment_id"] = 1
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == assignment_res.get('assignment')
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['assignment_id']


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'assignment_id': '1'},
                              ERRORS['REQUIRED_ARGUMENT'].format('user_id')),
                             ({'user_id': '2'},
                              ERRORS['REQUIRED_ARGUMENT'].format('assignment_id')),
                             ({'assignment_id': '0', 'user_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                             ({'assignment_id': '-1', 'user_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                             ({'assignment_id': '1.5', 'user_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                             ({'user_id': '0', 'assignment_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('user_id')),
                             ({'user_id': '-1', 'assignment_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('user_id')),
                             ({'user_id': '1.5', 'assignment_id': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('user_id'))
                         ])
def test_vectra_entity_assignment_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for assignment_id and user_id.

    When:
    - Calling the 'vectra_entity_assignment_update_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_assignment_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_assignment_resolve_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked GET request for assignment outcome data.
    - Mocked PUT request for resolving an assignment.
    - The expected response data for assignment resolution, outcome list, and context.
    - Arguments specifying valid parameters for resolving an assignment.

    When:
    - Calling the 'vectra_entity_assignment_resolve_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_resolve_response.json')
    outcome_res = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_outcome_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_resolve_context.json')
    with open(f'{TEST_DATA_DIR}/entity_assignment_resolve_hr.md') as f:
        result_hr = f.read()
    args = {
        "assignment_id": 116,
        "outcome": "Custom outcome",
        "note": "Resolved by XSOAR",
        "triage_as": "Triage by XSOAR",
        "detection_ids": ["1431", "1432", "1433"]
    }
    requests_mock.get(BASE_URL + ENDPOINTS['ASSIGNMENT_OUTCOME_ENDPOINT'], json=outcome_res)
    requests_mock.put(BASE_URL + ENDPOINTS['RESOLVE_ASSIGNMENT_ENDPOINT'].format(args.get('assignment_id')),
                      json=assignment_res)
    # Call the function
    result = vectra_entity_assignment_resolve_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['assignment_id']


@pytest.mark.parametrize('args,error_msg',
                         [({"outcome": "Custom outcome",
                            "note": "Resolved by XSOAR",
                            "triage_as": "Triage by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['REQUIRED_ARGUMENT'].format('assignment_id')),
                          ({"assignment_id": '1',
                            "note": "Resolved by XSOAR",
                            "triage_as": "Triage by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['REQUIRED_ARGUMENT'].format('outcome')),
                          ({"assignment_id": '1',
                            "outcome": "Custom outcome",
                            "note": "Resolved by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['TRIAGE_AS_REQUIRED_WITH_DETECTION_IDS']),
                          ({"assignment_id": '0',
                            "outcome": "Custom outcome",
                            "note": "Resolved by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                          ({"assignment_id": '-1',
                            "outcome": "Custom outcome",
                            "note": "Resolved by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                          ({"assignment_id": '1.5',
                            "outcome": "Custom outcome",
                            "note": "Resolved by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['INVALID_INTEGER_VALUE'].format('assignment_id')),
                          ({"assignment_id": '1',
                            "outcome": "Invalid outcome",
                            "triage_as": "Triage by XSOAR",
                            "note": "Resolved by XSOAR",
                            "detection_ids": ["1431", "1432", "1433"]},
                           ERRORS['INVALID_OUTCOME'].format(
                               ", ".join(
                                   [item["title"] for item in util_load_json(
                                       f'{TEST_DATA_DIR}/entity_assignment_outcome_list_response.json').get(
                                       'results')])))
                          ])
def test_vectra_entity_assignment_resolve_invalid_args(client, args, error_msg, requests_mock):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for 'assignment_id', 'outcome', 'triage_as', and 'detection_ids'.

    When:
    - Calling the 'vectra_entity_assignment_resolve_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    outcome_res = util_load_json(f'{TEST_DATA_DIR}/entity_assignment_outcome_list_response.json')
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        requests_mock.get(BASE_URL + ENDPOINTS['ASSIGNMENT_OUTCOME_ENDPOINT'], json=outcome_res)
        vectra_entity_assignment_resolve_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_pcap_download_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked GET request for downloading PCAP data of a detection.
    - The expected binary file content of the PCAP.
    - Arguments specifying a valid detection ID for downloading PCAP.

    When:
    - Calling the 'vectra_detection_pcap_download_command' function with the provided client and arguments.

    Then:
    - Assert that the result contains the expected binary file content.
    """
    mock_file_content = b"PCAP data of detection id 1431"
    args = {
        "detection_id": "1431"
    }
    requests_mock.get(BASE_URL + ENDPOINTS['DOWNLOAD_DETECTION_PCAP'].format("1431"), content=mock_file_content,
                      headers={
                          "Content-Disposition": 'attachement;filename="IP-1.1.1.1_hidden_dns_tunnel_1431.pcap"'})
    # Call the function
    result = vectra_detection_pcap_download_command(client, args)

    # Assert the CommandResults
    assert result.get('File') == "IP-1.1.1.1_hidden_dns_tunnel_1431.pcap"


@pytest.mark.parametrize('args,error_msg',
                         [({}, ERRORS['REQUIRED_ARGUMENT'].format('detection_id')),
                          ({'detection_id': 'as,2'}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_id')),
                          ({'detection_id': '1.5'}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_id')),
                          ({'detection_id': '-1'}, ERRORS['INVALID_INTEGER_VALUE'].format('detection_id'))])
def test_vectra_detection_pcap_download_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_id.

    When:
    - Calling the 'vectra_detection_pcap_download_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_pcap_download_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_detections_mark_fixed_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked responses for entity data and marking detections as fixed.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for marking detections as fixed for an entity.

    When:
    - Calling the 'vectra_entity_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the content of the expected file.
    """
    entity_response = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    with open(f'{TEST_DATA_DIR}/mark_entity_detections_fixed_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '334',
        'entity_type': 'account'
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['ENTITY_ENDPOINT'], args['entity_id']), json=entity_response)
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    # Call the function
    result = vectra_entity_detections_mark_fixed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == result_hr


def test_vectra_entity_detections_mark_fixed_with_no_detections(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked responses for entity data and marking detections as fixed.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for marking detections as fixed for an entity with no detections.

    When:
    - Calling the 'vectra_entity_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the expected output indicating no detections to mark as fixed.
    """
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    args = {
        'entity_id': '1',
        'entity_type': 'account'
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['ENTITY_ENDPOINT'], args['entity_id']),
                      json={'entity_id': '1', 'type': 'account'})
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    # Call the function
    result = vectra_entity_detections_mark_fixed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "There are no detections to mark as fixed for this entity ID:1."


def test_vectra_entity_detections_mark_fixed_command_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity detection mark fixed invalid response.
    - Arguments specifying valid parameters for marking detections as fixed for an entity.

    When:
    - Calling the 'vectra_entity_detections_mark_fixed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    entity_response = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    response = util_load_json(f'{TEST_DATA_DIR}/mark_or_unmark_detections_fixed_response.json')
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['ENTITY_ENDPOINT'], 334), json=entity_response)
    response["_meta"]["level"] = "failure"
    requests_mock.patch(BASE_URL + ENDPOINTS['DETECTION_ENDPOINT'], json=response)
    args = {
        'entity_id': '334',
        'entity_type': 'account'
    }

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_detections_mark_fixed_command(client, args)

    assert str(exception.value) == "Something went wrong."


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '', 'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_id': '1', 'entity_type': ''},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_detections_mark_fixed_invalid_args(client, args, error_msg):
    """
    Given:
    - Invalid arguments for marking detections as fixed.

    When:
    - Calling the 'vectra_entity_detections_mark_fixed_command' function with the provided invalid arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_detections_mark_fixed_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_assignment_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided client and no additional arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f'{TEST_DATA_DIR}/assignment_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/assignment_list_context.json')
    with open(f'{TEST_DATA_DIR}/assignment_list_hr.md') as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS['ASSIGNMENT_ENDPOINT'], json=assignment_res)
    # Call the function
    result = vectra_assignment_list_command(client, {"entity_type": "host", "entity_ids": "1"})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['assignment_id']


def test_vectra_assignment_list_when_assignment_response_is_empty(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - An empty assignment response.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    args = {
        "resolved": "False",
        "created_after": "1 day",
        "entity_type": "account",
        "entity_ids": "1"
    }
    requests_mock.get(BASE_URL + ENDPOINTS['ASSIGNMENT_ENDPOINT'], json=empty_response)
    # Call the function
    result = vectra_assignment_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Couldn't find any matching assignments for provided filters."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_type': 'account'},
                           ERRORS['ENTITY_IDS_WITHOUT_TYPE']),
                          ({'entity_ids': '1,2'},
                           ERRORS['ENTITY_IDS_WITHOUT_TYPE']),
                          ({'entity_ids': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ])
def test_vectra_assignment_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for listing assignments.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_assignment_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_assignment_outcome_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.
    - A client object.
    - Mocked assignment outcomes response data.
    - Mocked context data.

    When:
    - Calling the 'vectra_assignment_outcome_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment outcomes data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    outcomes = util_load_json(f'{TEST_DATA_DIR}/assignment_outcome_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/assignment_outcome_list_context.json')
    with open(f'{TEST_DATA_DIR}/assignment_outcome_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'page': '1',
        'page_size': '5'
    }
    url = BASE_URL + ENDPOINTS['ASSIGNMENT_OUTCOME_ENDPOINT'] + "?page=1&page_size=5"
    requests_mock.get(url, json=outcomes)
    # Call the function
    result = vectra_assignment_outcome_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Assignments.Outcomes'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['id']


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'page': '1', 'page_size': '-1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('page_size')),
                             ({'page': '1.5', 'page_size': '2'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('page'))
                         ])
def test_vectra_assignment_outcome_invalid_args(client, args, error_msg):
    """
    Given:
    - Invalid arguments containing negative or non-integer values.

    When:
    - Calling the 'vectra_assignment_outcome_list_command' function with the provided client and invalid arguments.

    Then:
    - Assert that calling the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_assignment_outcome_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.
    - A client object.
    - Mocked entity note list response data.
    - Mocked context data.

    When:
    - Calling the 'vectra_entity_note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the entity note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f'{TEST_DATA_DIR}/entity_note_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/entity_note_list_context.json')
    with open(f'{TEST_DATA_DIR}/entity_note_list_hr.md') as f:
        result_hr = f.read()
    args = {
        'entity_id': '1',
        'entity_type': 'account',
    }
    url = BASE_URL + ENDPOINTS['ADD_AND_LIST_ENTITY_NOTE_ENDPOINT'].format(args.get('entity_id'))
    params = {
        'type': args.get('entity_type')
    }
    final_url = add_params_in_url(url, params)
    requests_mock.get(final_url, json=notes_res)
    # Call the function
    result = vectra_entity_note_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Entity.Notes'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('Contents') == notes_res
    assert result_context.get('EntryContext') == remove_empty_elements(context_data)
    assert result.outputs_key_field == ['entity_id', 'entity_type', 'note_id']


@pytest.mark.parametrize('args,error_msg',
                         [({'entity_id': '1', 'entity_type': 'invalid_type'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('entity_type', ', '.join(VALID_ENTITY_TYPE))),
                          ({'entity_type': 'account'},
                           ERRORS['REQUIRED_ARGUMENT'].format('entity_id')),
                          ({'entity_id': '0', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '-1', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1.5', 'entity_type': 'account'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('entity_id')),
                          ({'entity_id': '1', 'entity_type': ''}, ERRORS['REQUIRED_ARGUMENT'].format('entity_type'))
                          ])
def test_vectra_entity_note_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id and entity_type.

    When:
    - Calling the 'vectra_entity_note_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_list_when_note_response_is_empty(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - An empty assignment response.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    empty_response = []
    args = {
        'entity_id': '1',
        'entity_type': 'account',
    }
    url = BASE_URL + ENDPOINTS['ADD_AND_LIST_ENTITY_NOTE_ENDPOINT'].format(args.get('entity_id'))
    params = {
        'type': args.get('entity_type')
    }
    final_url = add_params_in_url(url, params)
    requests_mock.get(final_url, json=empty_response)
    # Call the function
    result = vectra_entity_note_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Couldn't find any notes for provided entity."
    assert result_context.get('EntryContext') == {}


def test_vectra_group_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    group_res = util_load_json(f'{TEST_DATA_DIR}/group_list_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/group_list_context.json')
    with open(f'{TEST_DATA_DIR}/group_list_hr.md') as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS['GROUP_ENDPOINT'], json=group_res)
    args = {
        'group_type': 'account',
        'importance': 'high'
    }
    # Call the function
    result = vectra_group_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == ['group_id']


def test_vectra_group_list_when_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_group_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    mocker.patch.object(client, 'list_group_request', return_value=empty_response)

    # Call the function
    result = vectra_group_list_command(client, {})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "##### Couldn't find any matching groups for provided filters."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'group_type': 'invalid'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('group_type', ', '.join(VALID_GROUP_TYPE))),
                          ({'group_type': 'host', 'account_names': 'account_name'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'account', 'account_names')),
                          ({'group_type': 'host', 'domains': 'domain'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'domain', 'domains')),
                          ({'group_type': 'account', 'host_ids': '1'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_ids')),
                          ({'group_type': 'host', 'host_ids': 'abc'},
                           'Invalid number: "{}"="{}"'.format('host_ids', 'abc')),
                          ({'group_type': 'host', 'host_ids': '-1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('host_ids')),
                          ({'group_type': 'account', 'host_names': 'host_name'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_names')),
                          ({'group_type': 'host', 'ips': '0.0.0.0'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'ip', 'ips')),
                          ({'importance': 'invalid'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('importance', ', '.join(VALID_IMPORTANCE_VALUE))),
                          ])
def test_vectra_group_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid values.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for the corresponding invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_list_command(client, args)

    assert str(exception.value) == error_msg


def test_update_remote_system(client, requests_mock, mocker):
    """
    Given:
    - A client object.
    - A mocked 'requests_mock' to simulate API responses.
    - A mocker for patching client functions.

    When:
    - Calling the 'update_remote_system_command' function with valid arguments.

    Then:
    - Assert that the remote incident ID returned matches the expected value.
    """
    mock_args = util_load_json(f'{TEST_DATA_DIR}/update_remote_system_args.json')

    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})
    mocker.patch.object(client, 'add_entity_note_request', return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args)
    assert remote_incident_id == "123"


def test_update_remote_system_remove_tags(client, mocker):
    """
    Given:
    - A client object.
    - A mocker for patching client functions.
    - Mocked arguments with JSON data from a test file.

    When:
    - Calling the 'update_remote_system_command' function with arguments indicating that all XSOAR tags are removed.

    Then:
    - Assert that the remote incident ID returned matches the expected value.
    """
    mock_args = util_load_json(f'{TEST_DATA_DIR}/update_remote_system_args.json')

    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={'tags': ['tag1', 'tag2']})
    mocker.patch.object(client, 'add_entity_note_request', return_value={})

    # Modify mock_args to remove tags
    mock_args["delta"]["tags"] = []

    remote_incident_id = update_remote_system_command(client, mock_args)
    assert remote_incident_id == "123"


def test_update_remote_system_closing_notes(client, mocker):
    """
    Given:
    - A client object.
    - A mocker for patching client functions.
    - Mocked arguments with JSON data from a test file, including closing notes and related data.

    When:
    - Calling the 'update_remote_system_command' function with arguments indicating the closure of an incident.

    Then:
    - Assert that the remote incident ID returned matches the expected value.
    """
    mock_args = util_load_json(f'{TEST_DATA_DIR}/update_remote_system_args.json')

    mock_args["data"]["closeNotes"] = "Closing notes"
    mock_args["data"]["closeReason"] = "Closed due to testing"
    mock_args["delta"]["closingUserId"] = "user2"

    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})
    mocker.patch.object(client, 'add_entity_note_request', return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args)
    assert remote_incident_id == "123"


def test_vectra_assign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    assign_group_res = util_load_json(f'{TEST_DATA_DIR}/assign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/assign_group_context.json')
    # For Domain group
    with open(f'{TEST_DATA_DIR}/assign_domain_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '1',
        'members': "*.domain3.com,*.domain2.com"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[0])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=assign_group_res[0])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[0]
    assert result.outputs_key_field == ['group_id']


def test_vectra_assign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    assign_group_res = util_load_json(f'{TEST_DATA_DIR}/assign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/assign_group_context.json')
    # For Account group
    with open(f'{TEST_DATA_DIR}/assign_account_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '3',
        'members': "account_3,account_4"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[2])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=assign_group_res[2])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[2]
    assert result.outputs_key_field == ['group_id']


def test_vectra_assign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    assign_group_res = util_load_json(f'{TEST_DATA_DIR}/assign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/assign_group_context.json')
    # For Host group
    with open(f'{TEST_DATA_DIR}/assign_host_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '2',
        'members': "1,2"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[1])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=assign_group_res[1])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[1]
    assert result.outputs_key_field == ['group_id']


def test_vectra_assign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = util_load_json(f'{TEST_DATA_DIR}/assign_group_response.json')

    args = {
        'group_id': '2',
        'members': "1,2"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[1])

    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Member(s) 1, 2 are already in the group."


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'members': 'account1'},
                              ERRORS['REQUIRED_ARGUMENT'].format('group_id')),
                             ({'group_id': '0', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '-1', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1.5', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1'}, ERRORS['REQUIRED_ARGUMENT'].format('members'))
                         ])
def test_vectra_group_assign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_assign_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_unassign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    unassign_group_res = util_load_json(f'{TEST_DATA_DIR}/unassign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/unassign_group_context.json')
    # For Domain group
    with open(f'{TEST_DATA_DIR}/unassign_domain_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '1',
        'members': "*.domain1.net"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[0])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=unassign_group_res[0])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[0]
    assert result.outputs_key_field == ['group_id']


def test_vectra_unassign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    unassign_group_res = util_load_json(f'{TEST_DATA_DIR}/unassign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/unassign_group_context.json')

    with open(f'{TEST_DATA_DIR}/unassign_host_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '2',
        'members': "3"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[1])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=unassign_group_res[1])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[1]
    assert result.outputs_key_field == ['group_id']


def test_vectra_unassign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    unassign_group_res = util_load_json(f'{TEST_DATA_DIR}/unassign_group_response.json')
    groups = util_load_json(f'{TEST_DATA_DIR}/get_groups_response.json')
    context_data = util_load_json(f'{TEST_DATA_DIR}/unassign_group_context.json')

    with open(f'{TEST_DATA_DIR}/unassign_account_group_hr.md') as f:
        result_hr = f.read()
    args = {
        'group_id': '3',
        'members': "account_1"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[2])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')),
                        json=unassign_group_res[2])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[2]
    assert result.outputs_key_field == ['group_id']


def test_vectra_unassign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = util_load_json(f'{TEST_DATA_DIR}/assign_group_response.json')

    args = {
        'group_id': '2',
        'members': "6,7"
    }
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS['GROUP_ENDPOINT'], args.get('group_id')), json=groups[1])

    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Member(s) 6, 7 do not exist in the group."


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'members': 'account1'},
                              ERRORS['REQUIRED_ARGUMENT'].format('group_id')),
                             ({'group_id': '0', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '-1', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1.5', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1'}, ERRORS['REQUIRED_ARGUMENT'].format('members'))
                         ])
def test_vectra_group_unassign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_unassign_command(client, args)

    assert str(exception.value) == error_msg


def test_get_modified_remote_command_successful_retrieval(client):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_last_mirror_run' function to return a specific last mirror run timestamp.
    - Mocking the 'list_entities_request' function to return an empty list of entities.
    - Mocking the 'set_last_mirror_run' function.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    """
    # Mock dateparser, get_last_mirror_run, list_entities_request, and set_last_mirror_run
    with patch('VectraXDR.dateparser.parse', return_value=datetime(2023, 9, 20, 10)):
        with patch('VectraXDR.get_last_mirror_run', return_value={"lastMirrorRun": "2023-09-20T10:00:00+00:00"}):
            with patch('VectraXDR.VectraClient.list_entities_request', return_value={"results": [], "next_url": None}):
                with patch('VectraXDR.set_last_mirror_run'):
                    args = {
                        "lastUpdate": "2023-09-20T10:00:00+00:00"
                    }
                    get_modified_remote_data_command(client, args)

                    # Assertions
                    VectraXDR.dateparser.parse.assert_called_with("2023-09-20T10:00:00+00:00",
                                                                  settings={'TIMEZONE': 'UTC'})
                    VectraXDR.VectraClient.list_entities_request.assert_called_once_with(
                        last_modified_timestamp="2023-09-20T10:00:00Z", page=1, page_size=500, state="")


def test_get_modified_remote_command_max_mirroring_limit_reached(client):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_last_mirror_run' function to return a specific last mirror run timestamp.
    - Mocking the 'list_entities_request' function to return a large number of entities (more than the mirroring limit).
    - Mocking the 'set_last_mirror_run' function.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    """
    # Mock dateparser, get_last_mirror_run, list_entities_request, and set_last_mirror_run
    with patch('VectraXDR.dateparser.parse', return_value=datetime(2023, 9, 20, 10)):
        with patch('VectraXDR.get_last_mirror_run', return_value={"lastMirrorRun": "2023-09-20T10:00:00+00:00"}):
            with patch('VectraXDR.VectraClient.list_entities_request',
                       return_value={"results": [{"id": 1, "type": "account"}] * 10000,
                                     "next_url": "http://serverurl.com/api/v3.3/entities?page=2&page_size=500"
                                                 "&last_modified_timestamp_gte=2023-09-20T10%3A00%3A00Z"}):
                with patch('VectraXDR.set_last_mirror_run'):
                    args = {
                        "lastUpdate": "2023-09-20T10:00:00+00:00"
                    }
                    get_modified_remote_data_command(client, args)

                    # Assertions
                    VectraXDR.dateparser.parse.assert_called_with("2023-09-20T10:00:00+00:00",
                                                                  settings={'TIMEZONE': 'UTC'})
                    VectraXDR.VectraClient.list_entities_request.assert_called_once_with(
                        last_modified_timestamp="2023-09-20T10:00:00Z", page=1, page_size=500, state="")


def test_get_modified_remote_data_command_when_invalid_page_reached(client, requests_mock):
    """
    Given:
    - A client object.
    - A mocked list entities endpoint which returns a 404 error.
    - Parameters for fetching modified incidents.

    When:
    - Fetching modified incidents using the 'get_modified_remote_data_command' function with the provided parameters.

    Then:
    - Assert that the number of modified incidents is equal to the expected count.
    """
    entity_data = util_load_json(f'{TEST_DATA_DIR}/invalid_page_number_404_error.json')
    requests_mock.get(BASE_URL + ENDPOINTS['ENTITY_ENDPOINT'], json=entity_data, status_code=404)
    args = {"lastUpdate": "2023-09-20T10:00:00+00:00"}

    modified_remote_response = get_modified_remote_data_command(client, args)
    assert modified_remote_response.modified_incident_ids == []


def test_get_remote_data_command_when_detections_found(mocker, client):
    """
    Given:
    - A client object.
    - A mocked get entities endpoint.
    - A mocked list detection endpoint.

    When:
    - Fetching modified incident using the 'get_remote_data_command' function with the provided parameters.

    Then:
    - Assert that the reopening entry exists.
    """
    entity_data = util_load_json(f'{TEST_DATA_DIR}/get_entity_response.json')
    mocker.patch("VectraXDR.VectraClient.get_entity_request", return_value=entity_data)
    detection_data = util_load_json(f'{TEST_DATA_DIR}/entity_detection_list_response.json')
    mocker.patch.object(client, 'list_detections_request', return_value=detection_data)
    mocker.patch.object(client, 'list_assignments_request', return_value={})
    args = {
        'id': '334-account',
        'lastUpdate': '2023-06-20T10:00:00+00:00'
    }

    get_remote_response = get_remote_data_command(client, args)
    assert get_remote_response.entries == [{
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    }]


def test_get_remote_data_command_entity_needs_update(capfd, client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying an entity ID and last update timestamp.

    When:
    - Mocking the 'get_entity_request' function to return entity data without any notes.
    - Mocking the 'list_assignments_request' function to return an empty result.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    """
    args = {
        'id': '1-host',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    mocker.patch("VectraXDR.VectraClient.get_entity_request",
                 return_value={"id": 1, "type": "host", "detection_set": ["1"], "urgency_score": 90,
                               "last_modified_timestamp": "2023-09-20T09:00:00+00:00"})
    mocker.patch("VectraXDR.VectraClient.list_detections_request",
                 return_value={"results": []})
    mocker.patch("VectraXDR.VectraClient.list_assignments_request",
                 return_value={"results": [{"host_id": 1}]})

    result = get_remote_data_command(client, args)
    # For Account
    assert result.entries == []
    args = {
        'id': '1-account',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    mocker.patch("demistomock.params", return_value={"urgency_score_low_threshold": "test",
                                                     "urgency_score_medium_threshold": "test",
                                                     "urgency_score_high_threshold": "test"})
    mocker.patch("VectraXDR.VectraClient.get_entity_request",
                 return_value={"id": 1, "type": "account", "urgency_score": 90,
                               "last_modified_timestamp": "2023-09-20T09:00:00+00:00"})
    mocker.patch("VectraXDR.VectraClient.list_assignments_request", return_value={})

    with capfd.disabled():
        result = get_remote_data_command(client, args)

    assert result.entries == []
    assert result.mirrored_object["assignment_details"] == VectraXDR.EMPTY_ASSIGNMENT


def test_get_remote_data_command_entity_needs_update_notes(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying an entity ID and last update timestamp.

    When:
    - Mocking the 'get_entity_request' function to return entity data with a note.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    """
    args = {
        'id': '1-host',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    note_response_1 = {
        "id": 239,
        "date_created": "2023-09-20T10:33:14Z",
        "created_by": "api_client_fb46e7ba9f9c474599f041b4460230ba",
        "note": "test note."
    }
    note_response_2 = copy.deepcopy(note_response_1)
    note_response_2["date_created"] = "2023-08-20T10:33:14Z"
    note_response_3 = copy.deepcopy(note_response_1)
    note_response_3["note"] = "[Mirrored From XSOAR]"
    note_response_4 = copy.deepcopy(note_response_1)
    note_response_4["date_modified"] = "2023-09-20T08:33:14Z"
    mocker.patch("VectraXDR.VectraClient.get_entity_request",
                 return_value={"id": 1, "type": "host", "last_modified_timestamp": "2023-09-20T19:00:00+00:00",
                               "urgency_score": 90,
                               "notes": [note_response_1, note_response_2, note_response_3, note_response_4]})
    mocker.patch("VectraXDR.VectraClient.list_assignments_request", return_value={})

    result = get_remote_data_command(client, args)
    assert len(result.entries) == 1
    assert result.mirrored_object["urgency_score_based_severity"] == 4


def test_get_remote_data_command_entity_not_needs_update(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying an entity ID and last update timestamp.

    When:
    - Mocking the 'get_entity_request' and 'list_assignments_request' functions to return empty data.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    """
    args = {
        'id': '1-host',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    mocker.patch("VectraXDR.VectraClient.get_entity_request",
                 return_value={})
    mocker.patch("VectraXDR.VectraClient.list_assignments_request", return_value={})

    result = get_remote_data_command(client, args)
    assert result == "Incident was not found."

"""Test file for Cofense Vision integration."""

import io
import os
from time import time

import pytest
import json

from CofenseVision import API_ENDPOINTS, ERROR_MESSAGE, STATUS, SUPPORTED_SORT_FORMAT, SUPPORTED_SORT, \
    SUPPORTED_QUARANTINE_EMAILS_FORMAT, SUPPORTED_CRITERIA, SUPPORTED_HASH_VALUE_FORMAT, SUPPORTED_HASH, THREAT_TYPES, \
    SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST, SUPPORTED_HEADERS_FORMAT, QUARANTINE_JOB_OUTPUT_PREFIX, SEARCH_OUTPUT_PREFIX, \
    IOC_OUTPUT_PREFIX
from CommonServerPython import DemistoException, remove_empty_elements

""" CONSTANTS """

MOCK_BASE_URL = "http://127.0.0.1"

OLD_MOCK_RESP_TOKEN = "old_access_token"
NEW_MOCK_RESP_TOKEN = "new_access_token"

VALID_MOCK_INTEGRATION_CONTEXT = {"access_token": OLD_MOCK_RESP_TOKEN, "valid_until": int(time()) + 1800}
INVALID_MOCK_INTEGRATION_CONTEXT = {"access_token": OLD_MOCK_RESP_TOKEN, "valid_until": int(time()) - 1800}

OBJECT_NOT_FOUND_API_ERROR = {
    "status": "NOT_FOUND",
    "message": "Object not found",
    "details": ["Unable to find the requested object"],
}
ACCESS_LIMITATION_API_ERROR = {
    "error": "unauthorized",
    "error_description": "Full authentication is required to access this resource"
}
EXPECTED_ERROR_MSG_FOR_404_ERROR = "Error in API call [404].\nNOT_FOUND : Unable to find the requested object."
EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR = "Error in API call [401].\nunauthorized : Full authentication is " \
                                                 "required to access this resource."
TEST_FILE_NAME = "attachment.txt"
TEST_DAY_DATA = "10 days"


def util_load_json(path):
    """Load a json file located at the given path."""
    with io.open(path, mode="r", encoding="utf-8") as file:
        return json.loads(file.read())


@pytest.fixture()
def mock_client(requests_mock):
    """Create a mock client object to work with."""
    from CofenseVision import VisionClient

    mock_auth_endpoint = MOCK_BASE_URL + API_ENDPOINTS["AUTHENTICATION"]
    mock_auth_resp = {"access_token": NEW_MOCK_RESP_TOKEN, "expires_in": 1799}
    requests_mock.post(mock_auth_endpoint, json=mock_auth_resp)

    client = VisionClient(
        base_url=MOCK_BASE_URL, client_id="test_id", client_secret="test_secret", proxy=False, verify=False,
        threat_levels_good=[], threat_levels_suspicious=[], threat_levels_bad=[]
    )

    return client


def test_get_access_token_method_when_valid_token_found_in_integration_context(mock_client, mocker):
    """
    Test case scenario for successful execution of get_access_token method when valid token found in context.

    Given:
        - mocked_client to call the function.
    When:
        - Token is present in integration context and is valid.
    Then:
        - Returns the same token from the integration context.
    """
    mocker.patch("CofenseVision.get_integration_context", return_value=VALID_MOCK_INTEGRATION_CONTEXT)
    assert mock_client.get_access_token(client_id="test", client_secret="test") == OLD_MOCK_RESP_TOKEN


def test_get_access_token_method_when_invalid_token_found_in_integration_context(mock_client, mocker):
    """
    Test case scenario for successful execution of get_access_token method when invalid token found in context.

    Given:
        - mocked_client to call the function.
    When:
        - Token is present in integration context but it is expired (invalid).
    Then:
        - Return the newly generated token and store it in integration context.
    """
    mocker.patch("CofenseVision.get_integration_context", return_value=INVALID_MOCK_INTEGRATION_CONTEXT)
    assert mock_client.get_access_token(client_id="test", client_secret="test") == NEW_MOCK_RESP_TOKEN


def test_test_module_function_when_valid_credentials_provided(mock_client, requests_mock):
    """
    Test case scenario for successful execution of test_module function when valid credentials are provided.

    Given:
        - mocked_client to call the function.
    When:
        - Valid credentials are provided in integration configuration.
    Then:
        - Return 'ok' string indicating connnection succeeded.
    """
    from CofenseVision import test_module

    mock_get_all_search_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ALL_SEARCHES"]
    requests_mock.get(mock_get_all_search_endpoint, json=[], status_code=200)

    assert test_module(mock_client) == "ok"


def test_test_module_function_when_invalid_credentials_provided(mock_client, requests_mock):
    """
    Test case scenario for successful execution of test_module function when invalid credentials are provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid credentials are provided in integration configuration.
    Then:
        - Raise DemistoException indicating authentication failed.
    """
    from CofenseVision import test_module

    mock_get_all_search_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ALL_SEARCHES"]
    mock_error_response = {"error": "unauthorized", "error_description": "Bad credentials"}
    requests_mock.get(mock_get_all_search_endpoint, json=mock_error_response, status_code=401)

    expected_err_msg = 'Error in API call [401].\nunauthorized : Bad credentials.'

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == expected_err_msg


def test_cofense_message_get_command_when_invalid_token(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-get command when invalid token found.

    Given:
        - command arguments for cofense_message_get_command
    When:
        - Calling `cofense_message_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE"]
    mock_response = {"status": "BAD_REQUEST", "message": "Invalid request parameters",
                     "details": ["Download token is either missing or has already been used: invalid_token"]}
    requests_mock.get(mock_get_message_endpoint, json=mock_response, status_code=400)

    expected_err_msg = (
        'Error in API call [400].\n'
        'BAD_REQUEST : Download token is either missing or has already been used: invalid_token.'
    )

    with pytest.raises(DemistoException) as err:
        cofense_message_get_command(mock_client, {"token": "invalid_token"})

    assert str(err.value) == expected_err_msg


def test_cofense_message_get_command_when_authentication_error(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-get command when authentication error.

    Given:
        - command arguments for cofense_message_get_command
    When:
        - Calling `cofense_message_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE"]
    requests_mock.get(mock_get_message_endpoint, json=ACCESS_LIMITATION_API_ERROR, status_code=401)

    with pytest.raises(DemistoException) as err:
        cofense_message_get_command(mock_client, {"token": "invalid_token"})

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR


def test_cofense_message_get_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-get command.

    Given:
        - command arguments for cofense_message_get_command
    When:
        - Calling `cofense_message_get_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_message_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE"]
    mock_response = "some data"
    requests_mock.get(mock_get_message_endpoint, text=mock_response, status_code=200)

    actual = cofense_message_get_command(mock_client, {"token": "valid_token"})

    assert actual["File"] == "message.zip"


def test_cofense_message_metadata_get_command_when_object_not_found(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-metadata-get command when object not found.

    Given:
        - command arguments for cofense_message_metadata_get_command
    When:
        - Calling `cofense_message_metadata_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_metadata_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_METADATA"]
    requests_mock.get(mock_get_message_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    params = {
        "internet_message_id": "test_id",
        "recipient_address": "test_mail_address"
    }

    with pytest.raises(DemistoException) as err:
        cofense_message_metadata_get_command(mock_client, params)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_message_metadata_get_command_when_authentication_error(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-metadata-get command when authentication error.

    Given:
        - command arguments for cofense_message_metadata_get_command
    When:
        - Calling `cofense_message_metadata_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_metadata_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_METADATA"]
    requests_mock.get(mock_get_message_endpoint, json=ACCESS_LIMITATION_API_ERROR, status_code=401)

    params = {
        "internet_message_id": "test_id",
        "recipient_address": "test_mail_address"
    }

    with pytest.raises(DemistoException) as err:
        cofense_message_metadata_get_command(mock_client, params)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR


def test_cofense_message_metadata_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-metadata-get command.

    Given:
        - command arguments for cofense_message_metadata_get_command
    When:
        - Calling `cofense_message_metadata_get_command` function
    Then:
        - Returns a valid output
    """
    from CofenseVision import cofense_message_metadata_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_message_metadata_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_message_metadata_hr_success.md")) as file:
        hr_output = file.read()

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_METADATA"]
    requests_mock.get(mock_get_message_endpoint, json=mock_response, status_code=200)

    params = {
        "internet_message_id": "test_id",
        "recipient_address": "test_mail_address"
    }

    actual = cofense_message_metadata_get_command(mock_client, params)

    assert actual.outputs_prefix == "Cofense.Message"
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == mock_response
    assert actual.readable_output == hr_output


@pytest.mark.parametrize("args, err_msg", [
    ({"file_name": "", "md5": "11111111111111111111111111111111"},
     ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('file_name')),
    ({"file_name": "attachment.txt", "md5": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('md5')),
    ({"file_name": TEST_FILE_NAME, "md5": "123"}, ERROR_MESSAGE['INVALID_ARGUMENT'].format('123', 'md5 hash')),
    ({"file_name": TEST_FILE_NAME, "md5": "11111111111111111111111111111111", "sha256": "123"},
     ERROR_MESSAGE['INVALID_ARGUMENT'].format('123', 'sha256 hash')),
])
def test_cofense_message_attachment_get_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-message-attachment-get command when invalid arguments provided.

    Given:
        - command arguments for cofense_message_attachment_get_command
    When:
        - Calling `cofense_message_attachment_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_attachment_get_command
    with pytest.raises(ValueError) as err:
        cofense_message_attachment_get_command(mock_client, args)
    assert str(err.value) == err_msg


def test_cofense_message_attachment_get_command_when_valid_response_given(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-attachment-get command when valid response is given.

    Given:
        - command arguments for cofense_message_attachment_get_command
    When:
        - Calling `cofense_message_attachment_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_attachment_get_command

    mock_get_attachment_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ATTACHMENT"]
    mock_response = "some data"
    requests_mock.get(mock_get_attachment_endpoint, text=mock_response, status_code=200)

    params = {"md5": "11111111111111111111111111111111", "file_name": TEST_FILE_NAME}

    actual = cofense_message_attachment_get_command(mock_client, params)

    assert actual['File'] == TEST_FILE_NAME


def test_cofense_message_attachment_get_command_when_404_error_given(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-attachment-get command when object not found.

    Given:
        - command arguments for cofense_message_attachment_get_command
    When:
        - Calling `cofense_message_attachment_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_attachment_get_command

    mock_get_attachment_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ATTACHMENT"]
    requests_mock.get(mock_get_attachment_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    params = {"md5": "11111111111111111111111111111111", "file_name": TEST_FILE_NAME}

    with pytest.raises(DemistoException) as err:
        cofense_message_attachment_get_command(mock_client, params)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_message_attachment_get_command_when_authentication_error(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-attachment-get command when authentication error.

    Given:
        - command arguments for cofense_message_attachment_get_command
    When:
        - Calling `cofense_message_attachment_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_attachment_get_command

    mock_get_message_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ATTACHMENT"]

    requests_mock.get(mock_get_message_endpoint, json=ACCESS_LIMITATION_API_ERROR, status_code=401)

    params = {"md5": "11111111111111111111111111111111", "file_name": TEST_FILE_NAME}

    with pytest.raises(DemistoException) as err:
        cofense_message_attachment_get_command(mock_client, params)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR


@pytest.mark.parametrize(
    "err_msg, args", [
        (ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("internet_message_id"), {"internet_message_id": ""},),
        (ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("recipient_address"),
         {"internet_message_id": "test_id", "recipient_address": ""},),
    ],
)
def test_message_token_get_command_function_when_emtpy_arguments_provided(err_msg, args, mock_client):
    """
    Test case scenario when ValueError is raised by message_token_get function when empty arguments are provided.

    Given:
        - mock_client to call the function.
    When:
        - Empty values are provided to the arguments.
    Then:
        - Raise ValueError indicating that the argument is missing.
    """
    from CofenseVision import cofense_message_token_get_command

    with pytest.raises(ValueError) as err:
        cofense_message_token_get_command(mock_client, args)

    assert str(err.value) == err_msg


def test_message_token_get_command_when_valid_arguments_provided(mock_client, requests_mock):
    """
    Test case scenario for successful execution of test_module function when valid arguments are provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments provided to the command.
    Then:
        - Command should return a one-time token.
    """
    from CofenseVision import cofense_message_token_get_command

    mock_arguments = {"internet_message_id": "test", "recipient_address": "test"}
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_message_token_hr_success.md")) as file:
        expected_hr = file.read()

    expected_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                    "test_data/get_message_token_response_success.json"))

    mock_message_token_get_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_TOKEN"]
    mock_response = "52c80e98-4b8b-4c2a-9c53-b965050a9661"
    requests_mock.post(mock_message_token_get_endpoint, text=mock_response, status_code=200)

    resp = cofense_message_token_get_command(mock_client, mock_arguments)

    assert resp.outputs_prefix == "Cofense.Message"
    assert resp.outputs == expected_response
    assert resp.readable_output == expected_hr
    assert resp.outputs_key_field == "internetMessageId"


@pytest.mark.parametrize(
    'args,error_msg', [({"page": "-5"}, ERROR_MESSAGE['INVALID_PAGE_VALUE']),
                       ({"page": "$"}, '"$" is not a valid number'),
                       ({"size": "0"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
                       ({"size": "2525"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
                       ({"include_status": "dummy"},
                        ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("dummy", 'status', 'status', ', '.join(STATUS))),
                       ({"exclude_status": "dummy"},
                        ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("dummy", 'status', 'status', ', '.join(STATUS))),
                       ({"sort": "modifiedDate:asc:asc"},
                        ERROR_MESSAGE['INVALID_FORMAT'].format("modifiedDate:asc:asc", 'sort', SUPPORTED_SORT_FORMAT)),
                       ({"sort": "modifiedDate:ascq"},
                        ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("ascq", 'sort order', 'sort order',
                                                                  ', '.join(SUPPORTED_SORT['order_by']))),
                       ({"sort": "idq:asc"},
                        ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("idq", 'property name', 'property name',
                                                                  ', '.join(SUPPORTED_SORT['quarantine_jobs_list']))),
                       ({"modified_date_after": "abc"}, 'Invalid date: "modified_date_after"="abc"')])
def test_cofense_quarantine_jobs_list_command_invalid_params_provided(mock_client, args, error_msg):
    """Test case scenario for execution of cofense_quarantine_jobs_list_command  when invalid params are provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid params are provided.
    Then:
        - Raise error.
    """
    from CofenseVision import cofense_quarantine_jobs_list_command
    with pytest.raises(ValueError) as err:
        cofense_quarantine_jobs_list_command(mock_client, args)
    assert str(err.value) == error_msg


def test_cofense_quarantine_jobs_list_command_valid_params_provided(mock_client, requests_mock):
    """Test case scenario for successful execution of cofense_quarantine_jobs_list_command.

    Given:
        - mock_client to call the function.
    When:
        - valid params are provided.
    Then:
        - Return valid output.
    """
    from CofenseVision import cofense_quarantine_jobs_list_command
    args = {
        "auto_quarantine": "True",
        "exclude_quarantine_emails": "True",
        "exclude_status": "NEW",
        "include_status": "FAILED",
        "iocs": "16511",
        "modified_date_after": "2020",
        "page": "0",
        "size": "2",
        "sources": "intelligence",
        "sort": 'id:asc, modifiedDate:desc, createdBy:asc'
    }

    expected_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                    "test_data/list_quarantine_jobs_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_quarantine_jobs_hr_success.md")) as file:
        expected_hr = file.read()

    mock_quarantine_jobs_lst = MOCK_BASE_URL + API_ENDPOINTS["GET_QUARANTINE_JOBS"]
    requests_mock.post(mock_quarantine_jobs_lst, json=expected_response, status_code=200)

    response = cofense_quarantine_jobs_list_command(mock_client, args)

    assert response.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert response.outputs_key_field == "id"
    assert response.raw_response == expected_response
    assert response.outputs == remove_empty_elements(expected_response.get('quarantineJobs'))
    assert response.readable_output == expected_hr


@pytest.mark.parametrize("args, err_msg", [
    ({"quarantine_emails": "<test_id>"},
     ERROR_MESSAGE['INVALID_FORMAT'].format("<test_id>", "quarantine_emails",
                                            SUPPORTED_QUARANTINE_EMAILS_FORMAT)),
    ({"quarantine_emails": "<test_id>:dummy@xyz.com:1"},
     ERROR_MESSAGE['INVALID_FORMAT'].format("<test_id>:dummy@xyz.com:1", "quarantine_emails",
                                            SUPPORTED_QUARANTINE_EMAILS_FORMAT)),
    ({"quarantine_emails": "<test_id1>:dummy@xyz.com,<test_id2>"},
     ERROR_MESSAGE['INVALID_FORMAT'].format("<test_id2>", "quarantine_emails",
                                            SUPPORTED_QUARANTINE_EMAILS_FORMAT)),
    ({"quarantine_emails": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('quarantine_emails'))
])
def test_cofense_quarantine_job_create_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-quarantine-job-create command when invalid arguments provided.

    Given:
        - command arguments for cofense_quarantine_job_create_command
    When:
        - Calling `cofense_quarantine_job_create_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_create_command
    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_create_command(mock_client, args)
    assert str(err.value) == err_msg


def test_cofense_quarantine_job_create_command_when_authentication_error(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-quarantine-job-create command when authentication error.

    Given:
        - command arguments for cofense_quarantine_job_create_command
    When:
        - Calling `cofense_quarantine_job_create_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_create_command

    mock_create_quarantine_job_endpoint = MOCK_BASE_URL + API_ENDPOINTS["QUARANTINE_JOB"]

    requests_mock.post(mock_create_quarantine_job_endpoint, json=ACCESS_LIMITATION_API_ERROR, status_code=401)

    params = {"quarantine_emails": "<test_id>:dummy@xyz.com"}

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_create_command(mock_client, params)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR


def test_cofense_quarantine_job_create_command_when_invalid_data_given(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-quarantine-job-create command when invalid data given.

    Given:
        - command arguments for cofense_quarantine_job_create_command
    When:
        - Calling `cofense_quarantine_job_create_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_create_command

    mock_create_quarantine_job_endpoint = MOCK_BASE_URL + API_ENDPOINTS["QUARANTINE_JOB"]
    mock_response = {"status": "BAD_REQUEST", "message": "Invalid data, please check the request body",
                     "details": ["Invalid request"]}
    requests_mock.post(mock_create_quarantine_job_endpoint, json=mock_response, status_code=404)

    expected_err_msg = (
        'Error in API call [404].\n'
        'BAD_REQUEST : Invalid request.'
    )

    params = {"quarantine_emails": "<test_id>:dummy@xyz.com"}

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_create_command(mock_client, params)

    assert str(err.value) == expected_err_msg


def test_cofense_quarantine_job_create_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-quarantine-job-create command.

    Given:
        - command arguments for cofense_quarantine_job_create_command
    When:
        - Calling `cofense_quarantine_job_create_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_quarantine_job_create_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/create_quarantine_job_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/create_quarantine_job_hr_success.md")) as file:
        hr_output = file.read()

    mock_create_quarantine_job_endpoint = MOCK_BASE_URL + API_ENDPOINTS["QUARANTINE_JOB"]
    requests_mock.post(mock_create_quarantine_job_endpoint, json=mock_response['raw_response'], status_code=200)

    params = {"quarantine_emails": "<test_id>:recipient1@example.com"}

    actual = cofense_quarantine_job_create_command(mock_client, params)

    assert actual.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response['raw_response']
    assert actual.outputs == mock_response['outputs']
    assert actual.readable_output == hr_output


@pytest.mark.parametrize("args, err_msg", [
    ({"size": "0"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
    ({"size": "2001"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
    ({"size": "invalid_size"}, 'Invalid number: "size"="invalid_size"'),
    ({"page": "-1"}, ERROR_MESSAGE['INVALID_PAGE_VALUE']),
    ({"page": "invalid_page"}, 'Invalid number: "page"="invalid_page"'),
    ({"sort": "invalidProperty:asc"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("invalidProperty", "property name", "property name",
                                               ', '.join(SUPPORTED_SORT["message_searches_list"]))),
    ({"sort": "id:desc:test"},
     ERROR_MESSAGE['INVALID_FORMAT'].format("id:desc:test", "sort", SUPPORTED_SORT_FORMAT)),
    ({"sort": "id:invalidOrder"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("invalidOrder", "sort order", "sort order",
                                               ', '.join(SUPPORTED_SORT['order_by']))),
])
def test_cofense_message_searches_list_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-message-searches-list command when invalid arguments provided.

    Given:
        - command arguments for cofense_message_searches_list_command
    When:
        - Calling `cofense_message_searches_list_command` function
    Then:
        - Returns a valid error message.
    """
    from CofenseVision import cofense_message_searches_list_command

    with pytest.raises(ValueError) as err:
        cofense_message_searches_list_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_message_searches_list_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-searches-list command.

    Given:
        - command arguments for cofense_message_searches_list_command
    When:
        - Calling `cofense_message_searches_list_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_message_searches_list_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_message_searches_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_message_searches_hr_success.md")) as file:
        hr_output = file.read()

    mock_message_searches_list_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ALL_SEARCHES"]
    requests_mock.get(mock_message_searches_list_endpoint, json=mock_response['raw_response'])

    actual = cofense_message_searches_list_command(mock_client, {})

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response['raw_response']
    assert actual.outputs == mock_response['outputs']
    assert actual.readable_output == hr_output


def test_cofense_message_searches_list_command_when_empty_response(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-searches-list command when response is empty.

    Given:
        - command arguments for cofense_message_searches_list_command
    When:
        - Calling `cofense_message_searches_list_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_message_searches_list_command

    mock_message_searches_list_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_ALL_SEARCHES"]
    requests_mock.get(mock_message_searches_list_endpoint, json={})

    actual = cofense_message_searches_list_command(mock_client, {})

    expected_hr = "### Message Searches:\n**No entries.**\n"

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == {}
    assert actual.outputs is None
    assert actual.readable_output == expected_hr


@pytest.mark.parametrize("err_msg, args", [
    (ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("id"), {"id": ""}),
    (ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format('id'), {"id": "-1"}),
    ('Invalid number: "id"="test"', {"id": "test"}),
])
def test_quarantine_job_restore_command_when_empty_arguments_provided(err_msg, args, mock_client):
    """
    Test case scenario for execution of quarantine-job-restore command when empty arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - empty arguments are provided to function.
    Then:
        - Value Error should be raised by the function.
    """
    from CofenseVision import cofense_quarantine_job_restore_command

    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_restore_command(mock_client, args)

    assert str(err.value) == err_msg


def test_quarantine_job_restore_command_when_valid_arguments_provided(mock_client, requests_mock):
    """
    Test case scenario for execution of quarantine-job-restore command when valid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments are provided to function.
    Then:
        - Correct context data and HR output should be displayed.
    """
    from CofenseVision import cofense_quarantine_job_restore_command

    mock_arguments = {"id": 1}
    mock_quarantine_job_restore_endpoint = MOCK_BASE_URL + API_ENDPOINTS["RESTORE_QUARANTINE_JOB"].format(1)
    requests_mock.put(mock_quarantine_job_restore_endpoint, json="", status_code=200)

    response = cofense_quarantine_job_restore_command(mock_client, mock_arguments)

    expected_context_data = {"id": 1, "isRestored": True}
    expected_hr_output = "## Emails quarantined by the quarantine job ID 1 have been successfully restored."

    assert response.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert response.outputs_key_field == "id"
    assert response.readable_output == expected_hr_output
    assert response.outputs == expected_context_data


def test_quarantine_job_restore_command_when_404_error_returned(mock_client, requests_mock):
    """
    Test case scenario for execution of quarantine-job-restore command when 404 error code returned.

    Given:
        - mock_client to call the function.
    When:
        - Calling `cofense_quarantine_job_restore_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_restore_command

    mock_arguments = {"id": 1}
    mock_quarantine_job_restore_endpoint = MOCK_BASE_URL + API_ENDPOINTS["RESTORE_QUARANTINE_JOB"].format(1)
    requests_mock.put(mock_quarantine_job_restore_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_restore_command(mock_client, mock_arguments)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_last_ioc_get_command_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of cofense-last-ioc-get command when empty argument provided.

    Given:
        - mock_client to call the function.
    When:
        - empty argument is provided to function.
    Then:
        - Value Error should be raised by the function.
    """
    from CofenseVision import cofense_last_ioc_get_command

    with pytest.raises(ValueError) as err:
        cofense_last_ioc_get_command(mock_client, {"source": ""})

    assert str(err.value) == ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("source")


def test_cofense_last_ioc_get_command_when_422_error(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-last-ioc-get command when 422 error.

    Given:
        - command arguments for cofense_last_ioc_get_command
    When:
        - Calling `cofense_last_ioc_get_command` function
    Then:
        - Returns error message.
    """
    from CofenseVision import cofense_last_ioc_get_command

    mock_response = {"status": "UNPROCESSABLE_ENTITY", "message": "Validation failed for request data",
                     "details": ["X-Cofense-IOC-Source must only have alphanumeric characters and - . _ ~"]}

    mock_get_last_ioc_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_LAST_IOC"]
    requests_mock.get(mock_get_last_ioc_endpoint, json=mock_response, status_code=422)

    expected_err_msg = ('Error in API call [422].\nUNPROCESSABLE_ENTITY : '
                        'X-Cofense-IOC-Source must only have alphanumeric characters and - . _ ~.')

    with pytest.raises(DemistoException) as err:
        cofense_last_ioc_get_command(mock_client, {"source": "test source"})

    assert str(err.value) == expected_err_msg


def test_cofense_last_ioc_get_command_when_empty_response(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-last-ioc-get command when empty response given.

    Given:
        - command arguments for cofense_last_ioc_get_command
    When:
        - Calling `cofense_last_ioc_get_command` function
    Then:`
        - Returns a valid output.
    """
    from CofenseVision import cofense_last_ioc_get_command

    mock_get_last_ioc_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_LAST_IOC"]
    requests_mock.get(mock_get_last_ioc_endpoint, json={})

    expected_hr = "### Last IOC:\n**No entries.**\n"

    actual = cofense_last_ioc_get_command(mock_client, {"source": "test"})

    assert actual.outputs_prefix == IOC_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == {}
    assert actual.outputs is None
    assert actual.readable_output == expected_hr


def test_cofense_last_ioc_get_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-last-ioc-get command.

    Given:
        - command arguments for cofense_last_ioc_get_command
    When:
        - Calling `cofense_last_ioc_get_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_last_ioc_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_last_ioc_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_last_ioc_hr_success.md")) as file:
        hr_output = file.read()

    mock_get_last_ioc_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_LAST_IOC"]
    requests_mock.get(mock_get_last_ioc_endpoint, json=mock_response)

    actual = cofense_last_ioc_get_command(mock_client, {"source": "Vision-UI"})

    assert actual.outputs_prefix == IOC_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == remove_empty_elements(mock_response.get('data'))
    assert actual.readable_output == hr_output


@pytest.mark.parametrize('args, err_msg', [
    ({"id": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
    ({"id": "invalidID"}, 'Invalid number: "id"="invalidID"'),
    ({"id": "-1"}, ERROR_MESSAGE['INVALID_SEARCH_ID']),
    ({"id": "0"}, ERROR_MESSAGE['INVALID_SEARCH_ID']),
])
def test_cofense_message_search_get_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-message-search-get command when invalid arguments provided.

    Given:
        - command arguments for cofense_message_search_get_command
    When:
        - Calling `cofense_message_search_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_search_get_command

    with pytest.raises(ValueError) as err:
        cofense_message_search_get_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_message_search_get_command_when_object_not_found(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-search-get command when object not found error.

    Given:
        - command arguments for cofense_message_search_get_command
    When:
        - Calling `cofense_message_search_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_search_get_command

    mock_message_search_get_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_SEARCH"].format(1)
    requests_mock.get(mock_message_search_get_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_message_search_get_command(mock_client, {"id": 1})

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_message_search_get_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-search-get command.

    Given:
        - command arguments for cofense_message_search_get_command
    When:
        - Calling `cofense_message_search_get_command` function
    Then:
        - Returns a valid output
    """
    from CofenseVision import cofense_message_search_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_message_search_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_message_search_hr_success.md")) as file:
        hr_output = file.read()

    mock_message_search_get_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_MESSAGE_SEARCH"].format(1)
    requests_mock.get(mock_message_search_get_endpoint, json=mock_response)

    actual = cofense_message_search_get_command(mock_client, {"id": 1})

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == remove_empty_elements(mock_response)
    assert actual.readable_output == hr_output


@pytest.mark.parametrize('args, err_msg', [({"id": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
                                           ({"id": "qwe"}, 'Invalid number: "id"="qwe"'),
                                           ({"id": -5}, ERROR_MESSAGE['INVALID_QUARANTINE_JOB_PARAM'].format('id'))])
def test_cofense_quarantine_job_get_command_when_invalid_params_provided(mock_client, args, err_msg):
    """Test case scenario when ValueError is raised by quarantine-job-get when invalid arguments are provided.

    Given:
        - mock_client to call the function.
    When:
        - Empty values are provided to the arguments.
    Then:
        - Raise ValueError indicating that the argument is invalid.
    """
    from CofenseVision import cofense_quarantine_job_get_command

    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_get_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_quarantine_job_get_command_when_404_received(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense_quarantine_job_get_command when error 404 is received.

    Given:
        - command arguments for cofense_quarantine_job_get_command
    When:
        - Calling `cofense_quarantine_job_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_get_command

    mock_arguments = {"id": "265"}
    mock_get_quarantine_job = API_ENDPOINTS['QUARANTINE_JOB'] + '/' + mock_arguments['id']
    requests_mock.get(mock_get_quarantine_job, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_get_command(mock_client, mock_arguments)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_quarantine_job_get_command_when_valid_arguments_provided(mock_client, requests_mock):
    """Test case scenario for execution of quarantine-job-get function when valid arguments are provided.

    Given:
       - mock_client to call the function.
    When:
       - Valid arguments provided to the command.
    Then:
       - Returns a valid output.
    """
    from CofenseVision import cofense_quarantine_job_get_command

    mock_arguments = {"id": "265"}
    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_quarantine_job_response_success.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_quarantine_job_hr_success.md")) as file:
        expected_hr = file.read()
    mock_get_quarantine_job = API_ENDPOINTS['QUARANTINE_JOB'] + '/' + mock_arguments['id']
    requests_mock.get(mock_get_quarantine_job, json=mock_response, status_code=200)
    resp = cofense_quarantine_job_get_command(mock_client, mock_arguments)
    assert resp.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert resp.outputs == remove_empty_elements(mock_response)
    assert resp.readable_output == expected_hr
    assert resp.outputs_key_field == "id"


@pytest.mark.parametrize("err_msg, args", [
    (ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("id"), {"id": ""}),
    (ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("id"), {"id": "-1"}),
    ('Invalid number: "id"="test"', {"id": "test"}),
    (ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("message_count"), {"id": 1, "message_count": 0}),
    (ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("message_count"), {"id": 1, "message_count": -1}),
    ('Invalid number: "message_count"="test"', {"id": 1, "message_count": "test"}),
])
def test_quarantine_job_approve_command_when_invalid_arguments_provided(err_msg, args, mock_client):
    """
    Test case scenario for execution of quarantine-job-approve command when invalid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid arguments are provided.
    Then:
        - Value Error should be raised by the function.
    """
    from CofenseVision import cofense_quarantine_job_approve_command

    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_approve_command(mock_client, args)

    assert str(err.value) == err_msg


def test_quarantine_job_approve_command_when_valid_arguments_provided(mock_client, requests_mock):
    """
    Test case scenario for execution of quarantine-job-approve command when valid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments are provided to function.
    Then:
        - Correct context data and HR output should be displayed.
    """
    from CofenseVision import cofense_quarantine_job_approve_command

    mock_arguments = {"id": 1, "message_count": "10"}
    mock_quarantine_job_approve_endpoint = MOCK_BASE_URL + API_ENDPOINTS["APPROVE_QUARANTINE_JOB"].format(
        1) + "?messageCount=10"
    requests_mock.put(mock_quarantine_job_approve_endpoint, json="", status_code=200)

    response = cofense_quarantine_job_approve_command(mock_client, mock_arguments)

    expected_context_data = {"id": 1, "isApproved": True}
    expected_hr_output = "## Quarantine Job with ID 1 has been approved successfully."

    assert response.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert response.outputs_key_field == "id"
    assert response.readable_output == expected_hr_output
    assert response.outputs == expected_context_data


def test_quarantine_job_approve_command_when_404_error_returned(mock_client, requests_mock):
    """
    Test case scenario for execution of quarantine-job-approve command when 404 error code returned.

    Given:
        - mock_client to call the function.
    When:
        - The quarantine job does not exist.
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_approve_command

    mock_arguments = {"id": "1"}
    mock_quarantine_job_approve_endpoint = MOCK_BASE_URL + API_ENDPOINTS["APPROVE_QUARANTINE_JOB"].format(1)
    requests_mock.put(mock_quarantine_job_approve_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_approve_command(mock_client, mock_arguments)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_quarantine_job_approve_command_when_422_error_returned(mock_client, requests_mock):
    """
    Test case scenario for execution of quarantine-job-approve command when 422 error code returned.

    Given:
        - mock_client to call the function.
    When:
        - Job is not waiting for approval. (Unprocessable Entity)
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_approve_command

    mock_arguments = {"id": "1"}
    mock_quarantine_job_approve_endpoint = MOCK_BASE_URL + API_ENDPOINTS["APPROVE_QUARANTINE_JOB"].format("1")

    mock_response = {"status": "UNPROCESSABLE_ENTITY", "message": "Invalid data, please check the request body",
                     "details": ["Quarantine Job is not Pending Approval"]}

    requests_mock.put(mock_quarantine_job_approve_endpoint, json=mock_response, status_code=422)

    expected_err_msg = (
        'Error in API call [422].\nUNPROCESSABLE_ENTITY : Quarantine Job is not Pending Approval.'
    )

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_approve_command(mock_client, mock_arguments)

    assert str(err.value) == expected_err_msg


@pytest.mark.parametrize("args, err_msg", [({"id": ''}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
                                           ({"id": '-5'}, ERROR_MESSAGE['INVALID_QUARANTINE_JOB_PARAM'].format('id')),
                                           ({"id": "qwe"}, 'Invalid number: "id"="qwe"')])
def test_cofense_quarantine_job_delete_command_when_invalid_arguments_provided(args, err_msg, mock_client):
    """
    Test case scenario when ValueError is raised by cofense_quarantine_job_delete when invalid arguments are provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid values are provided to the arguments.
    Then:
        - Raise ValueError.
    """
    from CofenseVision import cofense_quarantine_job_delete_command
    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_delete_command(mock_client, args)
    assert str(err.value) == err_msg


def test_cofense_quarantine_job_delete_command_when_valid_arguments_provided(mock_client, requests_mock):
    """Test case scenario for execution of quarantine-job-delete function when valid arguments are provided.

    Given:
       - mock_client to call the function.
    When:
       - Valid arguments provided to the command.
    Then:
       - Command should return a one-time token.
    """
    from CofenseVision import cofense_quarantine_job_delete_command

    mock_arguments = {"id": "265"}
    expected_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                    "test_data/delete_quarantine_job_response_success.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/delete_quarantine_job_hr_success.md")) as file:
        expected_hr = file.read()
    mock_delete_quarantine_job = API_ENDPOINTS['QUARANTINE_JOB'] + '/' + mock_arguments['id']
    mock_response = ''
    requests_mock.delete(mock_delete_quarantine_job, text=mock_response, status_code=200)
    resp = cofense_quarantine_job_delete_command(mock_client, mock_arguments)
    assert resp.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert resp.outputs == expected_response
    assert resp.readable_output == expected_hr
    assert resp.outputs_key_field == "id"


def test_cofense_quarantine_job_delete_command_when_404_recived(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense_quarantine_job_delete_command when error 404 is received.

    Given:
        - command arguments for cofense_quarantine_job_delete_command
    When:
        - Calling `cofense_quarantine_job_delete_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_delete_command

    mock_arguments = {"id": "265"}
    mock_delete_quarantine_job = API_ENDPOINTS['QUARANTINE_JOB'] + '/' + mock_arguments['id']
    requests_mock.delete(mock_delete_quarantine_job, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_delete_command(mock_client, mock_arguments)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


@pytest.mark.parametrize("args, err_msg", [
    ({"id": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
    ({"id": "invalidID"}, 'Invalid number: "id"="invalidID"'),
    ({"id": -1}, ERROR_MESSAGE['INVALID_SEARCH_ID']),
    ({"id": 1, "size": "0"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
    ({"id": 1, "size": "2001"}, ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE']),
    ({"id": 1, "size": "invalid_size"}, 'Invalid number: "size"="invalid_size"'),
    ({"id": 1, "page": "-1"}, ERROR_MESSAGE['INVALID_PAGE_VALUE']),
    ({"id": 1, "page": "invalid_page"}, 'Invalid number: "page"="invalid_page"'),
    ({"id": 1, "sort": "invalidProperty:asc"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("invalidProperty", "property name", "property name",
                                               ', '.join(SUPPORTED_SORT["message_search_result_get"]))),
    ({"id": 1, "sort": "id:desc:test"},
     ERROR_MESSAGE['INVALID_FORMAT'].format("id:desc:test", "sort", SUPPORTED_SORT_FORMAT)),
    ({"id": 1, "sort": ","},
     ERROR_MESSAGE['INVALID_FORMAT'].format("None", "sort", SUPPORTED_SORT_FORMAT)),
    ({"id": 1, "sort": "id:invalidOrder"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("invalidOrder", "sort order", "sort order",
                                               ', '.join(SUPPORTED_SORT['order_by']))),
])
def test_cofense_message_search_results_get_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-message-search-results-get command when invalid arguments provided.

    Given:
        - command arguments for cofense_message_search_results_get_command
    When:
        - Calling `cofense_message_search_results_get_command` function
    Then:
        - Returns a valid error message.
    """
    from CofenseVision import cofense_message_search_results_get_command

    with pytest.raises(ValueError) as err:
        cofense_message_search_results_get_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_message_search_results_get_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-search-results-get command.

    Given:
        - command arguments for cofense_message_search_results_get_command
    When:
        - Calling `cofense_message_search_results_get_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_message_search_results_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_message_search_results_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_message_search_results_hr_success.md")) as file:
        hr_output = file.read()

    mock_get_message_search_result_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_SEARCH_RESULTS"].format(1)
    requests_mock.get(mock_get_message_search_result_endpoint, json=mock_response['raw_response'])

    actual = cofense_message_search_results_get_command(mock_client, {"id": 1})

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response['raw_response']
    assert actual.outputs == mock_response['outputs']
    assert actual.readable_output == hr_output


def test_cofense_message_search_results_get_when_object_not_found(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-search-results-get command when object not found.

    Given:
        - command arguments for cofense_message_search_results_get_command
    When:
        - Calling `cofense_message_search_results_get_command` function
    Then:
        - Returns a valid error message.
    """
    from CofenseVision import cofense_message_search_results_get_command

    mock_get_message_search_result_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_SEARCH_RESULTS"].format(1)
    requests_mock.get(mock_get_message_search_result_endpoint, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_message_search_results_get_command(mock_client, {"id": 1})

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_message_search_results_get_command_when_empty_results(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-search-results-get command when empty response.

    Given:
        - command arguments for cofense_message_search_results_get_command
    When:
        - Calling `cofense_message_search_results_get_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_message_search_results_get_command

    mock_response = util_load_json(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "test_data/get_message_search_results_empty_message_search_result.json"))

    mock_get_message_search_result_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_SEARCH_RESULTS"].format(1)
    requests_mock.get(mock_get_message_search_result_endpoint, json=mock_response['raw_response'])

    actual = cofense_message_search_results_get_command(mock_client, {"id": 1})

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_message_search_results_empty_message_search_result_hr.md")) as file:
        hr_output = file.read()

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response['raw_response']
    assert actual.outputs == mock_response['outputs']
    assert actual.readable_output == hr_output


@pytest.mark.parametrize('args, err_msg', [({"source": "", "id": "oxffpd"},
                                            ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('source')),
                                           ({"source": "Vision-UI", "id": ""},
                                            'id is a required parameter. Please provide correct value.'),
                                           ])
def test_cofense_ioc_delete_command_when_invalid_args_provided(mock_client, args, err_msg):
    """
    Test case scenario for execution of cofense-ioc-delete command when invalid arguments provided.

    Given:
        - command arguments for cofense_ioc_delete_command
    When:
        - Calling `cofense_ioc_delete_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_ioc_delete_command
    with pytest.raises(ValueError) as err:
        cofense_ioc_delete_command(mock_client, args)
    assert str(err.value) == err_msg


def test_cofense_ioc_delete_command_when_valid_args_provided(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-ioc-delete command.

    Given:
        - command arguments for cofense_ioc_delete_command
    When:
        - Calling `cofense_ioc_delete_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_ioc_delete_command

    args = {"source": "Vision-UI", "id": "a2fc0f"}
    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/delete_ioc_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/delete_ioc_hr_success.md")) as file:
        hr_output = file.read()

    mock_delete_ioc_endpoint = MOCK_BASE_URL + API_ENDPOINTS['IOC_REPOSITORY'] + '/a2fc0f'

    requests_mock.delete(mock_delete_ioc_endpoint, json=mock_response, status_code=200)

    actual = cofense_ioc_delete_command(mock_client, args)

    assert actual.outputs_prefix == IOC_OUTPUT_PREFIX
    assert actual.readable_output == hr_output


def test_cofense_ioc_delete_command_when_404_received(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-ioc-delete command when invalid data given.

    Given:
        - command arguments for cofense_ioc_delete_command
    When:
        - Calling `cofense_ioc_delete_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_ioc_delete_command

    mock_delete_ioc_endpoint = MOCK_BASE_URL + API_ENDPOINTS['IOC_REPOSITORY'] + '/bc463e'
    mock_response = ''
    requests_mock.delete(mock_delete_ioc_endpoint, text=mock_response, status_code=404)

    expected_err_msg = (
        "Error in API call [404].\n"
    )

    args = {"source": "dummy", "id": "bc463e"}

    with pytest.raises(DemistoException) as err:
        cofense_ioc_delete_command(mock_client, args)

    assert str(err.value) == expected_err_msg


@pytest.mark.parametrize(
    "args, err_msg",
    [
        ({"id": ""}, "id is a required parameter. Please provide correct value."),
        ({"id": "qwe"}, 'Invalid number: "id"="qwe"'),
        ({"id": -5}, "id must be a non-zero positive integer number."),
    ],
)
def test_cofense_quarantine_job_stop_command_when_invalid_params_provided(mock_client, args, err_msg):
    """Test case scenario when ValueError is raised by quarantine-job-stop command when invalid args provided.

    Given:
        - mock_client to call the function.
    When:
        - Empty values are provided to the arguments.
    Then:
        - Raise ValueError indicating that the argument is invalid.
    """
    from CofenseVision import cofense_quarantine_job_stop_command

    with pytest.raises(ValueError) as err:
        cofense_quarantine_job_stop_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_quarantine_job_stop_command_when_404_received(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense_quarantine_job_stop_command when error 404 is received.

    Given:
        - command arguments for cofense_quarantine_job_stop_command
    When:
        - Calling `cofense_quarantine_job_stop_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_quarantine_job_stop_command

    mock_arguments = {"id": "265"}
    mock_get_quarantine_job = MOCK_BASE_URL + API_ENDPOINTS["STOP_QUARANTINE_JOB"].format("265")
    requests_mock.put(mock_get_quarantine_job, json=OBJECT_NOT_FOUND_API_ERROR, status_code=404)

    with pytest.raises(DemistoException) as err:
        cofense_quarantine_job_stop_command(mock_client, mock_arguments)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_404_ERROR


def test_cofense_quarantine_job_stop_command_when_valid_arguments_provided(mock_client, requests_mock):
    """Test case scenario for execution of quarantine-job-stop function when valid arguments are provided.

    Given:
       - mock_client to call the function.
    When:
       - Valid arguments provided to the command.
    Then:
       - Command should return a one-time token.
    """
    from CofenseVision import cofense_quarantine_job_stop_command

    mock_arguments = {"id": "265"}
    mock_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stop_quarantine_job_response_success.json")
    )
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/stop_quarantine_job_hr_success.md")) as file:
        expected_hr = file.read()
    mock_get_quarantine_job = MOCK_BASE_URL + API_ENDPOINTS["STOP_QUARANTINE_JOB"].format("265")

    requests_mock.put(mock_get_quarantine_job, json=mock_response.get("rawResponse"), status_code=200)
    resp = cofense_quarantine_job_stop_command(mock_client, mock_arguments)

    assert resp.outputs_prefix == QUARANTINE_JOB_OUTPUT_PREFIX
    assert resp.outputs == remove_empty_elements(mock_response.get("outputs"))
    assert resp.readable_output == expected_hr
    assert resp.outputs_key_field == "id"


@pytest.mark.parametrize("args, err_msg", [
    ({"subjects": "test1, test2, test3, test4"}, ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('subjects')),
    ({"senders": "test1, test2, test3, test4"}, ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('senders')),
    ({"attachment_names": "test1, test2, test3, test4"},
     ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('attachment_names')),
    ({"attachment_hashes": "test1, test2, test3, test4"},
     ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('attachment_hashes')),
    ({"attachment_mime_types": "test1, test2, test3, test4"},
     ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('attachment_mime_types')),
    ({"attachment_exclude_mime_types": "test1, test2, test3, test4"},
     ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('attachment_exclude_mime_types')),
    ({"domains": "test1, test2, test3, test4"}, ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('domains')),
    ({"whitelist_urls": "test1, test2, test3, test4"},
     ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('whitelist_urls')),
    ({"headers": "test1, test2, test3, test4"}, ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format('headers')),
    ({"attachment_hash_match_criteria": "test"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("test", "attachment_hash_match_criteria",
                                               "attachment_hash_match_criteria", SUPPORTED_CRITERIA)),
    ({"domain_match_criteria": "test"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("test", "domain_match_criteria",
                                               "domain_match_criteria", SUPPORTED_CRITERIA)),
    ({"partial_ingest": "test"}, 'Argument does not contain a valid boolean-like value'),
    ({"received_after_date": "test"}, 'Invalid date: "received_after_date"="test"'),
    ({"received_before_date": "test"}, 'Invalid date: "received_before_date"="test"'),
    ({"attachment_hashes": "test"},
     ERROR_MESSAGE['INVALID_FORMAT'].format('test', 'attachment_hashes', SUPPORTED_HASH_VALUE_FORMAT)),
    ({"headers": "test"},
     ERROR_MESSAGE['INVALID_FORMAT'].format('test', 'headers', SUPPORTED_HEADERS_FORMAT)),
    ({"attachment_hashes": "test_type:test_value"},
     ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("test_type", 'hash', 'hash', SUPPORTED_HASH)),
    ({"attachment_hashes": "MD5:test_value"},
     ERROR_MESSAGE['INVALID_ARGUMENT'].format("test_value", 'MD5'))
])
def test_cofense_message_search_create_command_when_invalid_arguments(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-message-search-create command when invalid arguments provided.

    Given:
        - command arguments for cofense_message_search_create_command
    When:
        - Calling `cofense_message_search_create_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_message_search_create_command

    with pytest.raises(ValueError) as err:
        cofense_message_search_create_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_message_search_create_command_when_422_error_for_header_key(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-message-search-create command when invalid header key provided.

    Given:
        - command arguments for cofense_message_search_create_command
    When:
        - Calling `cofense_message_search_create_command` function
    Then:
        - Returns a valid error message for 422 status code response
    """
    from CofenseVision import cofense_message_search_create_command

    mock_response = {"status": "UNPROCESSABLE_ENTITY", "message": "Validation failed for request data",
                     "details": ["Field error in object 'search' on field 'headers[0]': header 'test' "
                                 "is not configured for search : .search.headers[0]; rejected value: "
                                 "'KeyValue{key='test', values = [test]}';"]}

    mock_message_search_create_endpoint = MOCK_BASE_URL + API_ENDPOINTS['CREATE_MESSAGE_SEARCH']
    requests_mock.post(mock_message_search_create_endpoint, json=mock_response, status_code=422)

    expected_err_msg = ('Error in API call [422].\n'
                        'UNPROCESSABLE_ENTITY : Field error in object \'search\' on field '
                        '\'headers[0]\': header \'test\' is not configured for search : '
                        '.search.headers[0]; rejected value: \'KeyValue{key=\'test\', values = [test]}\';.')

    args = {"headers": "test:test"}

    with pytest.raises(DemistoException) as err:
        cofense_message_search_create_command(mock_client, args)

    assert str(err.value) == expected_err_msg


def test_cofense_message_search_create_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-message-search-create command.

    Given:
        - command arguments for cofense_message_search_create_command
    When:
        - Calling `cofense_message_search_create_command` function
    Then:
        - Returns a valid output
    """
    from CofenseVision import cofense_message_search_create_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/create_message_search_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/create_message_search_hr_success.md")) as file:
        hr_output = file.read()

    mock_message_search_create_endpoint = MOCK_BASE_URL + API_ENDPOINTS['CREATE_MESSAGE_SEARCH']
    requests_mock.post(mock_message_search_create_endpoint, json=mock_response)
    args = {
        "subjects": "test1,test2",
        "senders": "abc@xyz.com",
        "attachment_exclude_mime_types": "image",
        "received_after_date": TEST_DAY_DATA,
        "received_before_date": "5 days",
        "attachment_hashes": "md5:11111111111111111111111111111111"
    }

    actual = cofense_message_search_create_command(mock_client, args=args)

    assert actual.outputs_prefix == SEARCH_OUTPUT_PREFIX
    assert actual.raw_response == mock_response
    assert actual.outputs == remove_empty_elements(mock_response)
    assert actual.outputs_key_field == "id"
    assert actual.readable_output == hr_output


@pytest.mark.parametrize("args, err_msg",
                         [({"source": "", "iocs_json": "{\"threat_type\": \"Domain\", \
                         \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                         \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                         \"requested_expiration\": \"2022-09-09\"}"},
                           ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('source')),
                          ({"source": "Vision-UI"},
                           ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('threat_type')),
                          ({"source": "Vision-UI", "iocs_json": "{\"threat_type\": \"Domain\", \
                         \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                         \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                         \"requested_expiration\": \"2022-09-09\""},
                           '{\"threat_type\": \"Domain\", \
                         \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                         \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                         \"requested_expiration\": \"2022-09-09\" is an invalid JSON format'),
                          ({"source": "Vision-UI", "iocs_json": "{\"threat_type\": \"dummy\", \
                          \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                          \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                          \"requested_expiration\": \"2022-09-09\"}"},
                           ERROR_MESSAGE['UNSUPPORTED_FIELD'].format('dummy', 'threat type',
                                                                     'threat type', THREAT_TYPES)),
                          ({"source": "Vision-UI", "iocs_json": "{\"threat_type\": \"Domain\", \
                          \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                          \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                          \"requested_expiration\": \"abc\"}"},
                           'Invalid date: "requested_expiration"="abc"')])
def test_update_iocs_command_when_invalid_args_provided(mock_client, args, err_msg):
    """
    Test case scenario for execution of cofense-iocs-update command when invalid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid arguments are provided.
    Then:
        - Value Error should be raised by the function.
    """
    from CofenseVision import cofense_iocs_update_command

    with pytest.raises(ValueError) as err:
        cofense_iocs_update_command(mock_client, args)

    assert str(err.value) == err_msg


def test_update_iocs_command_when_valid_args_provided(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-iocs-update command when valid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments are provided to function.
    Then:
        - Correct context data and HR output should be displayed.
    """
    from CofenseVision import cofense_iocs_update_command

    mock_arguments = {"source": "Triage-1", "iocs_json": "{\"threat_type\": \"Domain\", \
                         \"threat_value\": \"abc.com\", \"threat_level\": \"Low\", \"source_id\": \"oxcff\", \
                         \"created_at\": \"2022-07-07\", \"updated_at\": \"2022-07-08\", \
                         \"requested_expiration\": \"2022-09-09\"}"}
    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/update_iocs_response_success.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/update_iocs_hr_success.md")) as file:
        expected_hr = file.read()
    mock_iocs_update_endpoint = API_ENDPOINTS["IOC_REPOSITORY"]
    requests_mock.put(mock_iocs_update_endpoint, json=mock_response, status_code=200)

    response = cofense_iocs_update_command(mock_client, mock_arguments)

    assert response[0].outputs_prefix == IOC_OUTPUT_PREFIX
    assert response[0].outputs_key_field == "id"
    assert response[0].readable_output == expected_hr
    assert response[0].outputs == remove_empty_elements(mock_response.get('data')[0])


@pytest.mark.parametrize("args, err_msg", [({"id": "", "expires_at": "1 day"},
                                            ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
                                           ({"id": "11111111111111111111111111111111", "expires_at": ""},
                                            ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('expires_at')),
                                           ({"id": "11111111111111111111111111111111", "expires_at": "test"},
                                            'Invalid date: "expires_at"="test"')])
def test_update_ioc_command_when_invalid_args_provided(mock_client, args, err_msg):
    """
    Test case scenario for execution of cofense-ioc-update command when invalid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Invalid arguments are provided.
    Then:
        - Value Error should be raised by the function.
    """
    from CofenseVision import cofense_ioc_update_command

    with pytest.raises(ValueError) as err:
        cofense_ioc_update_command(mock_client, args)

    assert str(err.value) == err_msg


def test_update_ioc_command_when_404_received(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-ioc-update command when invalid id given.

    Given:
        - command arguments for cofense_ioc_update_command
    When:
        - Calling `cofense_ioc_update_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_ioc_update_command

    mock_ioc_update_endpoint = API_ENDPOINTS["IOC_REPOSITORY"] + "/test_id"
    requests_mock.put(mock_ioc_update_endpoint, text='', status_code=404)

    expected_err_msg = (
        "Error in API call [404].\n"
    )

    args = {"expires_at": "1 week ago", "id": "test_id"}

    with pytest.raises(DemistoException) as err:
        cofense_ioc_update_command(mock_client, args)

    assert str(err.value) == expected_err_msg


def test_update_ioc_command_when_valid_args_provided(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-ioc-update command when valid arguments provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments are provided to function.
    Then:
        - Correct context data and HR output should be displayed.
    """
    from CofenseVision import cofense_ioc_update_command

    mock_arguments = {"id": "e3026f0c154395767993f34cc71b13e3", "expires_at": "1 day ago"}
    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/update_ioc_response_success.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/update_ioc_hr_success.md")) as file:
        expected_hr = file.read()
    mock_ioc_update_endpoint = API_ENDPOINTS["IOC_REPOSITORY"] + "/e3026f0c154395767993f34cc71b13e3"
    requests_mock.put(mock_ioc_update_endpoint, json=mock_response, status_code=200)

    response = cofense_ioc_update_command(mock_client, mock_arguments)

    assert response.outputs_prefix == IOC_OUTPUT_PREFIX
    assert response.outputs_key_field == "id"
    assert response.readable_output == expected_hr
    assert response.outputs == remove_empty_elements(mock_response.get('data'))


@pytest.mark.parametrize("err_msg, args", [
    (ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format("source"), {"source": ""}),
    (ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE'], {"source": "test", "size": "0"}),
    (ERROR_MESSAGE['INVALID_PAGE_SIZE_RANGE'], {"source": "test", "size": "2001"}),
    ('Invalid number: "size"="invalid_size"', {"source": "test", "size": "invalid_size"}),
    (ERROR_MESSAGE['INVALID_PAGE_VALUE'], {"source": "test", "page": "-1"}),
    ('Invalid number: "page"="invalid_page"', {"source": "test", "page": "invalid_page"}),
    ('Argument is neither a string nor a boolean', {"source": "test", "include_expired": 123}),
    ('Argument does not contain a valid boolean-like value', {"source": "test", "include_expired": 'test'}),
    ('Invalid date: "since"="test"', {"source": "test", "since": 'test'}),
    (ERROR_MESSAGE['UNSUPPORTED_FIELD_FOR_IOCS_LIST'].format("invalidProperty", "property name", "property name",
                                                             ', '.join(SUPPORTED_SORT["iocs_list"])),
     {"source": "test", "sort": "invalidProperty:asc"}),
    (ERROR_MESSAGE['INVALID_FORMAT'].format("id:desc:test", "sort", SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST),
     {"source": "test", "sort": "id:desc:test"}),
    (ERROR_MESSAGE['UNSUPPORTED_FIELD'].format("invalidOrder", "sort order", "sort order",
                                               ', '.join(SUPPORTED_SORT['order_by'])),
     {"source": "test", "sort": "updatedAt:invalidOrder"}),
])
def test_iocs_list_command_when_invalid_arguments_provided(err_msg, args, mock_client):
    """Test case scenario for execution of iocs-list function when invalid arguments are provided.

    Given:
       - mock_client to call the function.
    When:
       - Invalid arguments provided to the command.
    Then:
       - Raises value error.
    """
    from CofenseVision import cofense_iocs_list_command

    with pytest.raises(ValueError) as err:
        cofense_iocs_list_command(mock_client, args)

    assert str(err.value) == err_msg


def test_iocs_list_command_when_empty_response_returned(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-iocs-list command when response is empty.

    Given:
        - command arguments for cofense_iocs_list_command
    When:
        - Calling `cofense_iocs_list_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseVision import cofense_iocs_list_command

    mock_arguments = {"source": "test", "page": "5", "size": "5", "since": TEST_DAY_DATA, "include_expired": "True"}
    mock_request_url = MOCK_BASE_URL + API_ENDPOINTS["GET_IOCS"]
    mock_response = {"data": []}
    requests_mock.get(mock_request_url, json=mock_response, status_code=200)

    expected_hr_output = '### IOC:\n**No entries.**\n'

    response = cofense_iocs_list_command(mock_client, mock_arguments)

    assert response.readable_output == expected_hr_output


def test_iocs_list_command_when_valid_response_returned(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense_iocs_list_command function when valid arguments are provided.

    Given:
        - mock_client to call the function.
    When:
        - Valid arguments provided to the command.
    Then:
        - Command should return valid response.
    """
    from CofenseVision import cofense_iocs_list_command

    mock_arguments = {"source": "test-source-1", "page": "5", "size": "5", "since": TEST_DAY_DATA,
                      "include_expired": "True"}
    mock_request_url = MOCK_BASE_URL + API_ENDPOINTS["GET_IOCS"]
    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_iocs_response_success.json"))
    requests_mock.get(mock_request_url, json=mock_response.get('rawResponse'), status_code=200)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_iocs_hr_success.md")) as file:
        expected_hr_output = file.read()

    response = cofense_iocs_list_command(mock_client, mock_arguments)

    assert response[0].outputs_prefix == IOC_OUTPUT_PREFIX
    assert response[0].outputs_key_field == "id"
    assert response[0].readable_output == expected_hr_output
    assert [resp.outputs for resp in response] == mock_response.get("outputs")


def test_cofense_searchable_headers_list_command_when_authentication_error(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-searchable-headers-get command when authentication error.

    Given:
        - command arguments for cofense_searchable_headers_list_command
    When:
        - Calling `cofense_searchable_headers_list_command` function
    Then:
        - Returns valid error message.
    """
    from CofenseVision import cofense_searchable_headers_list_command

    mock_get_searchable_headers_endpoint = MOCK_BASE_URL + API_ENDPOINTS["GET_SEARCHABLE_HEADERS"]
    requests_mock.get(mock_get_searchable_headers_endpoint, json=ACCESS_LIMITATION_API_ERROR, status_code=401)

    with pytest.raises(DemistoException) as err:
        cofense_searchable_headers_list_command(mock_client)

    assert str(err.value) == EXPECTED_ERROR_MSG_FOR_ACCESS_LIMITATION_ERROR


def test_cofense_searchable_headers_list_command_when_no_searchable_headers(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-searchable-headers-get command when no available headers.

    Given:
        - command arguments for cofense_searchable_headers_list_command
    When:
        - Calling `cofense_searchable_headers_list_command` function
    Then:
        - Returns valid output.
    """
    from CofenseVision import cofense_searchable_headers_list_command

    mock_get_searchable_headers_endpoint = MOCK_BASE_URL + API_ENDPOINTS['GET_SEARCHABLE_HEADERS']
    requests_mock.get(mock_get_searchable_headers_endpoint, json={"headers": []})

    hr_output = "### Available headers to create a search:\n**No entries.**\n"

    actual = cofense_searchable_headers_list_command(mock_client)

    assert actual.outputs_prefix == "Cofense.Config"
    assert actual.outputs_key_field == "name"
    assert actual.outputs == {'name': 'searchableHeaders', 'value': []}
    assert actual.raw_response == {"headers": []}
    assert actual.readable_output == hr_output


def test_cofense_searchable_headers_list_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-searchable-headers-get.

    Given:
        - command arguments for cofense_searchable_headers_list_command
    When:
        - Calling `cofense_searchable_headers_list_command` function
    Then:
        - Returns valid output.
    """
    from CofenseVision import cofense_searchable_headers_list_command

    mock_response = {"headers": ["X-MS-Exchange-Organization-AuthSource"]}

    mock_get_searchable_headers_endpoint = MOCK_BASE_URL + API_ENDPOINTS['GET_SEARCHABLE_HEADERS']
    requests_mock.get(mock_get_searchable_headers_endpoint, json=mock_response)

    expected_output = {"name": "searchableHeaders", "value": ["X-MS-Exchange-Organization-AuthSource"]}

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_searchable_header_hr_success.md")) as file:
        hr_output = file.read()

    actual = cofense_searchable_headers_list_command(mock_client)

    assert actual.outputs_prefix == "Cofense.Config"
    assert actual.outputs_key_field == "name"
    assert actual.outputs == expected_output
    assert actual.raw_response == mock_response
    assert actual.readable_output == hr_output


@pytest.mark.parametrize('args, err_msg', [
    ({"id": ""}, ERROR_MESSAGE['MISSING_REQUIRED_PARAM'].format('id')),
])
def test_cofense_ioc_get_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cofense-ioc-get command when required argument not provided.

    Given:
        - command arguments for cofense_ioc_get_command
    When:
        - Calling `cofense_ioc_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_ioc_get_command

    with pytest.raises(ValueError) as err:
        cofense_ioc_get_command(mock_client, args)

    assert str(err.value) == err_msg


def test_cofense_ioc_get_command_when_object_not_found(mock_client, requests_mock):
    """
    Test case scenario for execution of cofense-ioc-get command when object not found error.

    Given:
        - command arguments for cofense_ioc_get_command
    When:
        - Calling `cofense_ioc_get_command` function
    Then:
        - Returns a valid error message
    """
    from CofenseVision import cofense_ioc_get_command

    mock_ioc_get_endpoint = MOCK_BASE_URL + API_ENDPOINTS['IOC_REPOSITORY'] + '/bc463d'
    mock_response = ''
    requests_mock.get(mock_ioc_get_endpoint, text=mock_response, status_code=404)

    expected_err_msg = (
        "Error in API call [404].\n"
    )

    with pytest.raises(DemistoException) as err:
        cofense_ioc_get_command(mock_client, {"id": "bc463d"})

    assert str(err.value) == expected_err_msg


def test_cofense_ioc_get_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-ioc-get command.

    Given:
        - command arguments for cofense_ioc_get_command
    When:
        - Calling `cofense_ioc_get_command` function
    Then:
        - Returns a valid output
    """
    from CofenseVision import cofense_ioc_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_ioc_response_success.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_ioc_hr_success.md")) as file:
        hr_output = file.read()

    mock_ioc_get_endpoint = MOCK_BASE_URL + API_ENDPOINTS['IOC_REPOSITORY'] + '/bc463d'
    requests_mock.get(mock_ioc_get_endpoint, json=mock_response)

    actual = cofense_ioc_get_command(mock_client, {"id": "bc463d"})

    assert actual.outputs_prefix == IOC_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response.get('data')
    assert actual.outputs == remove_empty_elements(mock_response.get('data'))
    assert actual.readable_output == hr_output

from CrowdStrikeFalconX import Client,\
    send_uploaded_file_to_sandbox_analysis_command, send_url_to_sandbox_analysis_command,\
    get_full_report_command, get_report_summary_command, get_analysis_status_command,\
    check_quota_status_command, find_sandbox_reports_command, find_submission_id_command
from TestsInput.context import SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT, SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT,\
    GET_FULL_REPORT_CONTEXT, GET_REPORT_SUMMARY_CONTEXT, GET_ANALYSIS_STATUS_CONTEXT, CHECK_QUOTA_STATUS_CONTEXT,\
    FIND_SANDBOX_REPORTS_CONTEXT, FIND_SUBMISSION_ID_CONTEXT, MULTIPLE_ERRORS_RESULT
from TestsInput.http_responses import SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_HTTP_RESPONSE,\
    SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, GET_FULL_REPORT_HTTP_RESPONSE, GET_REPORT_SUMMARY_HTTP_RESPONSE,\
    CHECK_QUOTA_STATUS_HTTP_RESPONSE, FIND_SANDBOX_REPORTS_HTTP_RESPONSE, FIND_SUBMISSION_ID_HTTP_RESPONSE,\
    GET_ANALYSIS_STATUS_HTTP_RESPONSE, MULTI_ERRORS_HTTP_RESPONSE, NO_ERRORS_HTTP_RESPONSE
import pytest


class ResMocker:
    def __init__(self, http_response):
        self.http_response = http_response
        self.ok = False

    def json(self):
        return self.http_response


SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS = {
    "sha256": "sha256",
    "environment_id": "160: Windows 10",
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "enable_tor": "false",
    "submit_name": "",
    "system_date": "",
    "system_time": ""
}


SEND_URL_TO_SANDBOX_ANALYSIS_ARGS = {
    "url": "https://www.google.com",
    "environment_id": "160: Windows 10",
    "enable_tor": "False",
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "submit_name": "",
    "system_date": "",
    "system_time": ""
}

GET_FULL_REPORT_ARGS = {
    "ids": "ids",
}

GET_REPORT_SUMMARY_ARGS = {
    "ids": "ids",
}

GET_ANALYSIS_STATUS_ARGS = {
    "ids": "ids",
}

FIND_SANDBOX_REPORTS_ARGS = {
    "offset": "",
    "limit": "",
    "sort": "",
    "filter": "",
}

FIND_SUBMISSION_ID_ARGS = {
    "offset": "",
    "limit": "",
    "sort": "",
    "filter": "",
}


@pytest.mark.parametrize('command, args, http_response, context', [
    (send_uploaded_file_to_sandbox_analysis_command, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS,
     SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_HTTP_RESPONSE, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT),
    (send_url_to_sandbox_analysis_command, SEND_URL_TO_SANDBOX_ANALYSIS_ARGS,
     SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT),
    (get_full_report_command, GET_FULL_REPORT_ARGS, GET_FULL_REPORT_HTTP_RESPONSE, GET_FULL_REPORT_CONTEXT),
    (get_report_summary_command, GET_REPORT_SUMMARY_ARGS, GET_REPORT_SUMMARY_HTTP_RESPONSE, GET_REPORT_SUMMARY_CONTEXT),
    (get_analysis_status_command, GET_ANALYSIS_STATUS_ARGS, GET_ANALYSIS_STATUS_HTTP_RESPONSE,
     GET_ANALYSIS_STATUS_CONTEXT),
    (check_quota_status_command, {}, CHECK_QUOTA_STATUS_HTTP_RESPONSE, CHECK_QUOTA_STATUS_CONTEXT),
    (find_sandbox_reports_command, FIND_SANDBOX_REPORTS_ARGS, FIND_SANDBOX_REPORTS_HTTP_RESPONSE,
     FIND_SANDBOX_REPORTS_CONTEXT),
    (find_submission_id_command, FIND_SUBMISSION_ID_ARGS, FIND_SUBMISSION_ID_HTTP_RESPONSE, FIND_SUBMISSION_ID_CONTEXT),
])
def test_cs_falconx_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    _, outputs, _ = command(client, **args)
    assert outputs == context


@pytest.mark.parametrize('http_response, output', [
    (MULTI_ERRORS_HTTP_RESPONSE, MULTIPLE_ERRORS_RESULT),
    (NO_ERRORS_HTTP_RESPONSE, "")
])
def test_handle_errors(http_response, output, mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - there are or there are no errors
    Then
    - show the exception content
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False)
    try:
        mocker.patch.object(client._session, 'request', return_value=ResMocker(http_response))
        _, output, _ = check_quota_status_command(client)
    except Exception as e:
        assert (str(e) == str(output))

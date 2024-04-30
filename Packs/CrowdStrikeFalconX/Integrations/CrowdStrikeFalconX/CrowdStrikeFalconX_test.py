import pytest

from CommonServerPython import *

from CrowdStrikeFalconX import Client, \
    send_uploaded_file_to_sandbox_analysis_command, send_url_to_sandbox_analysis_command, \
    get_full_report_command, get_report_summary_command, get_analysis_status_command, \
    check_quota_status_command, find_sandbox_reports_command, find_submission_id_command, run_polling_command, \
    pop_polling_related_args, is_new_polling_search, arrange_args_for_upload_func, remove_polling_related_args, \
    DBotScoreReliability, parse_indicator, upload_file_with_polling_command
from test_data.context import SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT, SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT, \
    GET_FULL_REPORT_CONTEXT, GET_REPORT_SUMMARY_CONTEXT, GET_ANALYSIS_STATUS_CONTEXT, CHECK_QUOTA_STATUS_CONTEXT, \
    FIND_SANDBOX_REPORTS_CONTEXT, FIND_SUBMISSION_ID_CONTEXT, MULTIPLE_ERRORS_RESULT, GET_FULL_REPORT_CONTEXT_EXTENDED, \
    FIND_SANDBOX_REPORTS_HASH_CONTEXT, FIND_SANDBOX_REPORTS_NOT_FOUND_HASH_CONTEXT
from test_data.http_responses import SEND_UPLOADED_FILE_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, \
    SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, GET_FULL_REPORT_HTTP_RESPONSE, GET_REPORT_SUMMARY_HTTP_RESPONSE, \
    CHECK_QUOTA_STATUS_HTTP_RESPONSE, FIND_SANDBOX_REPORTS_HTTP_RESPONSE, FIND_SUBMISSION_ID_HTTP_RESPONSE, \
    GET_ANALYSIS_STATUS_HTTP_RESPONSE, MULTI_ERRORS_HTTP_RESPONSE, NO_ERRORS_HTTP_RESPONSE, \
    GET_FULL_REPORT_HTTP_RESPONSE_EMPTY, FIND_SANDBOX_REPORTS_NOT_FOUND_HTTP_RESPONSE, \
    GET_FULL_REPORT_HTTP_RESPONSE_ERROR_MESSAGE, UPLOAD_FILE_HTTP_RESPONSE


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

SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS_POLLING = {
    "sha256": "sha256",
    "environment_id": "160: Windows 10",
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "enable_tor": "false",
    "submit_name": "",
    "system_date": "",
    "system_time": "",
    "polling": True,
    "interval_in_seconds": "60",
    "extended_data": "true"
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

SEND_URL_TO_SANDBOX_ANALYSIS_ARGS_POLLING = {
    "url": "https://www.google.com",
    "environment_id": "160: Windows 10",
    "enable_tor": "False",
    "action_script": "",
    "command_line": "",
    "document_password": "",
    "submit_name": "",
    "system_date": "",
    "system_time": "",
    "polling": "true",
    "interval_in_seconds": "10",
    "extended_data": "true"
}

GET_FULL_REPORT_ARGS = {
    "ids": ["ids"],
    "extended_data": "false"
}
GET_FULL_REPORT_ARGS_EXTENDED = {
    "ids": "ids",
    "extended_data": "true"
}

GET_REPORT_SUMMARY_ARGS = {
    "ids": ["ids"],
}

GET_ANALYSIS_STATUS_ARGS = {
    "ids": ["ids"],
}

FIND_SANDBOX_REPORTS_ARGS = {
    "offset": "",
    "limit": "",
    "sort": "",
    "filter": "",
}
FIND_SANDBOX_REPORTS_HASHES_ARGS = {
    "offset": "",
    "limit": "",
    "sort": "",
    "filter": "",
    "hashes": "hash1",
}

FIND_SUBMISSION_ID_ARGS = {
    "offset": "",
    "limit": "",
    "sort": "",
    "filter": "",
}


def test_running_polling_command_upload_file_error(mocker):
    """
    Given
    - A client object
    - IDs of files that have been uploaded as part of the polling command
    When
    - Running the 'cs-fx-upload-file' command with polling
    Then
    - Validate that we return an error when the report contains an error object, meaning
    that the sandbox analysis was not able to run properly
    """
    args = {'ids': '1234', 'extended_data': 'true'}
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)
    mocker.patch.object(Client, 'upload_file', return_value=UPLOAD_FILE_HTTP_RESPONSE)
    mocker.patch.object(Client, 'send_uploaded_file_to_sandbox_analysis', return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE_ERROR_MESSAGE)
    with pytest.raises(DemistoException) as e:
        upload_file_with_polling_command(client, args)
    assert 'Sandbox was not able to analyze one of the files, failing with error' in str(e)


@pytest.mark.parametrize('command', [(get_full_report_command), (get_report_summary_command)])
def test_get_report_commands_error(mocker, command):
    """
    Given
    - A client object
    When
    - Running the commands 'cs-fx-get-full-report' and 'cs-fx-get-report-summary'
    Then
    - Validate that we return a warning when the report contains an error object
    """
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, '_http_request', return_value=GET_FULL_REPORT_HTTP_RESPONSE_ERROR_MESSAGE)
    command(client, '1')
    # Entry type '11' means warning
    assert demisto_results_mocker.call_args_list[0][0][0].get('Type') == 11
    assert 'Sandbox report for resource id resource_id returned an error of type FILE_TYPE_BAD_ERROR with content' \
        in demisto_results_mocker.call_args_list[0][0][0].get('Contents')


@pytest.mark.parametrize('command, args, http_response, context', [
    (get_report_summary_command, GET_REPORT_SUMMARY_ARGS, GET_REPORT_SUMMARY_HTTP_RESPONSE, GET_REPORT_SUMMARY_CONTEXT),
    (get_analysis_status_command, GET_ANALYSIS_STATUS_ARGS, GET_ANALYSIS_STATUS_HTTP_RESPONSE,
     GET_ANALYSIS_STATUS_CONTEXT),
    (check_quota_status_command, {}, CHECK_QUOTA_STATUS_HTTP_RESPONSE, CHECK_QUOTA_STATUS_CONTEXT),
    (find_sandbox_reports_command, FIND_SANDBOX_REPORTS_ARGS, FIND_SANDBOX_REPORTS_HTTP_RESPONSE,
     FIND_SANDBOX_REPORTS_CONTEXT),
    (find_sandbox_reports_command, FIND_SANDBOX_REPORTS_HASHES_ARGS, FIND_SANDBOX_REPORTS_HTTP_RESPONSE,
     FIND_SANDBOX_REPORTS_HASH_CONTEXT),
    (find_sandbox_reports_command, FIND_SANDBOX_REPORTS_HASHES_ARGS, FIND_SANDBOX_REPORTS_NOT_FOUND_HTTP_RESPONSE,
     FIND_SANDBOX_REPORTS_NOT_FOUND_HASH_CONTEXT),
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
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    command_results = command(client, **args)
    if not isinstance(command_results, list):  # some command only return a single CommandResults objects
        command_results = [command_results]

    outputs = [cr.to_context()['EntryContext'] for cr in command_results]
    if isinstance(context, dict) and len(outputs) == 1:
        outputs = outputs[0]

    assert outputs == context


@pytest.mark.parametrize('command, args, http_response, context', [
    (send_uploaded_file_to_sandbox_analysis_command, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS,
     SEND_UPLOADED_FILE_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT),
    (send_url_to_sandbox_analysis_command, SEND_URL_TO_SANDBOX_ANALYSIS_ARGS,
     SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE, SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT),
    (get_full_report_command, GET_FULL_REPORT_ARGS, GET_FULL_REPORT_HTTP_RESPONSE, GET_FULL_REPORT_CONTEXT),
    (get_full_report_command, GET_FULL_REPORT_ARGS_EXTENDED, GET_FULL_REPORT_HTTP_RESPONSE,
     GET_FULL_REPORT_CONTEXT_EXTENDED)
])
def test_cs_falcon_x_polling_related_commands(command, args, http_response, context, mocker):
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
    mocker.patch.object(Client, '_get_access_token')
    mocker.patch.object(demisto, 'get', return_value={'sha256': 'sha256', 'file_name': 'test.pdf'})
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    if command == get_full_report_command:
        command_res, status = command(client, **args)
    else:
        command_res = command(client, **args)
    if isinstance(command_res, list):
        assert len(command_res) == 1
    else:
        command_res = [command_res]

    assert command_res[0].outputs == context


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
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)
    try:
        mocker.patch.object(client._session, 'request', return_value=ResMocker(http_response))
        _, output, _ = check_quota_status_command(client)
    except Exception as e:
        assert (str(e) == str(output))


def test_running_polling_command_success_for_url(mocker):
    """
    Given:
        An upload request of a url or a file using the polling flow, that was already initiated priorly and is now
         complete.
    When:
        When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         already complete.
    Then:
        Return a command results object, without scheduling a new command.
    """
    args = {'ids': "1234", "extended_data": "true"}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_url_to_sandbox_analysis', return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE)

    expected_outputs = GET_FULL_REPORT_CONTEXT_EXTENDED
    command_results = run_polling_command(client, args, 'cs-fx-submit-url', send_url_to_sandbox_analysis_command,
                                          get_full_report_command, 'URL')
    assert isinstance(command_results, list)
    assert len(command_results) == 1

    assert command_results[0].outputs == expected_outputs
    assert command_results[0].scheduled_command is None


def test_running_polling_command_success_for_file(mocker):
    """
    Given:
        An upload request of a url or a file using the polling flow, that was already initiated priorly and is now
         complete.
    When:
        When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         already complete.
    Then:
        Return a command results object, without scheduling a new command.
    """
    args = {'ids': "1234", "extended_data": "true"}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_url_to_sandbox_analysis', return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE)

    expected_outputs = GET_FULL_REPORT_CONTEXT_EXTENDED
    command_results = run_polling_command(client, args, 'cs-fx-submit-uploaded-file',
                                          send_uploaded_file_to_sandbox_analysis_command,
                                          get_full_report_command, 'FILE')
    assert isinstance(command_results, list)
    assert len(command_results) == 1
    assert command_results[0].outputs == expected_outputs
    assert command_results[0].scheduled_command is None


def test_running_polling_command_pending_for_url(mocker):
    """
    Given:
         An upload request of a url or a file using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = {'ids': "1234", "extended_data": "true"}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_url_to_sandbox_analysis', return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE_EMPTY)
    command_results = run_polling_command(client, args, 'cs-fx-submit-url', send_url_to_sandbox_analysis_command,
                                          get_full_report_command, 'URL')
    assert command_results.outputs is None
    assert command_results.scheduled_command is not None


def test_running_polling_command_pending_for_file(mocker):
    """
    Given:
         An upload request of a url or a file using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = {'ids': "1234", "extended_data": "true"}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_url_to_sandbox_analysis', return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE_EMPTY)
    command_results = run_polling_command(client, args, 'cs-fx-submit-uploaded-file',
                                          send_uploaded_file_to_sandbox_analysis_command,
                                          get_full_report_command, 'FILE')
    assert command_results.outputs is None
    assert command_results.scheduled_command is not None


def test_running_polling_command_new_search_for_url(mocker):
    """
    Given:
         An upload request of a url using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = SEND_URL_TO_SANDBOX_ANALYSIS_ARGS_POLLING
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_url_to_sandbox_analysis',
                        return_value=SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE)

    expected_outputs = SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT
    command_results = run_polling_command(client, args, 'cs-fx-submit-url', send_url_to_sandbox_analysis_command,
                                          get_full_report_command, 'URL')

    assert command_results.outputs == expected_outputs
    assert command_results.scheduled_command is not None


def test_running_polling_command_new_search_for_file(mocker):
    """
    Given:
         An upload request of a file  using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_ARGS_POLLING
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch.object(Client, '_get_access_token')
    mocker.patch.object(demisto, 'get', return_value={'sha256': 'sha256', 'file_name': 'test.pdf'})
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)

    mocker.patch.object(Client, 'send_uploaded_file_to_sandbox_analysis',
                        return_value=SEND_UPLOADED_FILE_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE)
    mocker.patch.object(Client, 'get_full_report', return_value=GET_FULL_REPORT_HTTP_RESPONSE)

    expected_outputs = SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT
    command_results = run_polling_command(client, args, 'cs-fx-submit-uploaded-file',
                                          send_uploaded_file_to_sandbox_analysis_command,
                                          get_full_report_command, 'FILE')

    assert command_results.outputs == expected_outputs
    assert command_results.scheduled_command is not None


def test_pop_polling_related_args():
    args = {
        'submit_file': 'submit_file',
        'enable_tor': 'enable_tor',
        'interval_in_seconds': 'interval_in_seconds',
        'polling': 'polling',
        'ids': 'ids'
    }
    pop_polling_related_args(args)
    assert 'submit_file' not in args
    assert 'enable_tor' not in args
    assert 'interval_in_seconds' not in args
    assert 'polling' not in args
    assert 'ids' in args


def test_is_new_polling_search():
    assert not is_new_polling_search({'ids': 'a'})
    assert is_new_polling_search({'polling': 'a'})


def test_arrange_args_for_upload_func():
    args = {
        'submit_file': 'submit_file',
        'enable_tor': 'enable_tor',
        'interval_in_seconds': 'interval_in_seconds',
        'polling': 'polling',
        'ids': 'ids',
        'extended_data': 'extended_data'
    }

    extended_data = arrange_args_for_upload_func(args)
    assert extended_data == 'extended_data'
    assert 'interval_in_seconds' not in args
    assert 'polling' not in args
    assert 'extended_data' not in args


def test_remove_polling_related_args():
    args = {
        'interval_in_seconds': 'interval_in_seconds',
        'polling': 'polling',
        'ids': 'ids',
        'extended_data': 'extended_data'
    }
    remove_polling_related_args(args)
    assert 'interval_in_seconds' not in args
    assert 'extended_data' not in args


def test_parse_indicator():
    sandbox = {
        'sha256': 'sha256',
        'verdict': 'suspicious',
        'submit_name': 'submit_name',
        'file_size': 123,
        'file_type': 'foo type',
        'version_info': [{'id': k, 'value': k} for k in
                         ('CompanyName', 'ProductName', 'LegalCopyright', 'FileDescription', 'FileVersion',
                          'InternalName', 'OriginalFilename')
                         ],
        'submission_type': 'file',
        'dns_requests': [{'address': 'example0.com/foo', 'domain': 'example0.com'}],
        'contacted_hosts': [{'address': 'example1.com'},
                            {'address': 'example2.com'}]
    }
    indicator = parse_indicator(sandbox=sandbox, reliability_str=DBotScoreReliability.A_PLUS)
    expected_context = {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || '
        'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || '
        'val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || '
        'val.SSDeep && val.SSDeep == obj.SSDeep)': {
            'Name': 'submit_name', 'Size': 123, 'SHA256': 'sha256', 'Type': 'foo type', 'Company': 'CompanyName',
            'Hashes': [{'type': 'SHA256', 'value': 'sha256'}],
            'ProductName': 'ProductName',
            'Signature': {'Authentihash': '', 'Copyright': 'LegalCopyright', 'Description': 'FileDescription',
                          'FileVersion': 'FileVersion', 'InternalName': 'InternalName',
                          'OriginalName': 'OriginalFilename'},
            'Relationships': [{'Relationship': 'communicates-with', 'EntityA': 'sha256', 'EntityAType': 'File',
                               'EntityB': 'example0.com/foo', 'EntityBType': 'IP'},
                              {'Relationship': 'communicates-with', 'EntityA': 'sha256', 'EntityAType': 'File',
                               'EntityB': 'example0.com', 'EntityBType': 'Domain'},
                              {'Relationship': 'communicates-with', 'EntityA': 'sha256', 'EntityAType': 'File',
                               'EntityB': 'example1.com', 'EntityBType': 'IP'},
                              {'Relationship': 'communicates-with', 'EntityA': 'sha256', 'EntityAType': 'File',
                               'EntityB': 'example2.com', 'EntityBType': 'IP'}]
        },
        'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
        'val.Vendor == obj.Vendor && val.Type == obj.Type)': {
            'Indicator': 'sha256', 'Type': 'file', 'Vendor': '', 'Score': 2,  # Vendor is auto-populated on XSOAR
            'Reliability': 'A+ - 3rd party enrichment'
        }
    }

    assert indicator.to_context() == expected_context


@pytest.mark.parametrize('file,mocked_address,mocked_response', (('file',
                                                                  'https://api.crowdstrike.com/falconx/queries/reports'
                                                                  '/v1?filter=sandbox.sha256%3A%22file%22',
                                                                  {'resources': ['id_1']}),
                                                                 ('file1, file2',
                                                                  'https://api.crowdstrike.com/falconx/queries/reports/'
                                                                  'v1?filter=sandbox.sha256%3A%22file1%22%2C'
                                                                  'sandbox.sha256%3A%22file2%22',
                                                                  {'resources': ['id_1', 'id_2']})
                                                                 ))
def test_file_command(requests_mock, mocker, file: str, mocked_address: str, mocked_response: dict):
    """
    Given
            files to check
    When
            Calling the !file command
    Then
            Make sure the api calls are made correctly.
            Parsing is not tested as it's equivalent in other commands.
    """
    mocker.patch.object(Client, '_get_access_token', return_value='token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)
    file_ids = mocked_response['resources']

    from CrowdStrikeFalconX import file_command
    args = {'file': file}
    id_query_mock = requests_mock.get(mocked_address, json=mocked_response)
    search_query_mocks = [requests_mock.get(f'https://api.crowdstrike.com/falconx/entities/reports/v1?ids={file_id}',
                                            json={}) for file_id in file_ids]

    command_results = file_command(client, **args)

    assert id_query_mock.call_count == 1
    assert all(mocked_search.call_count == 1 for mocked_search in search_query_mocks)
    assert isinstance(command_results, list)
    assert len(command_results) == len(file_ids)


@pytest.mark.parametrize('mocked_address,ioc_id,mocked_response,command_results_output',
                         (('https://api.crowdstrike.com/falconx/entities/artifacts/v1',
                           '123',
                           {'headers': {'Content-Type': 'image/png',
                                        'Content-Disposition': 'attachment; filename=screen_0.png'}},
                           'screen_0.png'),
                          ('https://api.crowdstrike.com/falconx/entities/artifacts/v1',
                           '123',
                           {'headers': {'Content-Type': 'application/json'}},
                           None),
                          ))
def test_download_ioc_command(requests_mock, mocker, mocked_address, ioc_id, mocked_response, command_results_output):
    """
    Given
            IOCs to download
    When
            Calling the cs-fx-download-ioc command
    Then
            - Verify that when the response includes an image a file is returned
            - Verify that when the response includes a json the output is a table
    """
    mocker.patch.object(Client, '_get_access_token', return_value='token')
    client = Client(server_url="https://api.crowdstrike.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False, reliability=DBotScoreReliability.B)
    from CrowdStrikeFalconX import download_ioc_command
    requests_mock.get(mocked_address, headers=mocked_response.get('headers'), json={})
    command_results = download_ioc_command(client, ioc_id)
    if isinstance(command_results, dict):
        assert command_results.get('File') == command_results_output
    else:
        assert command_results.outputs.get('File') == command_results_output


def test_get_new_access_token(mocker):
    """
    Given
     - no access token in the integration context at all

    When
     - trying to get the access token

    Then
     - make sure the integration creates a new access token
    """
    mocker.patch.object(Client, '_get_token_request', return_value=('123', '100'))
    client = Client(
        server_url="https://api.crowdstrike.com/",
        username="user1",
        password="12345",
        use_ssl=False,
        proxy=False,
        reliability=DBotScoreReliability.B
    )
    access_token = client._get_access_token()
    assert access_token == '123'


def test_get_existing_access_token(mocker):
    """
    Given
     - existing access token saved in integration context that its time is not expired yet

    When
     - trying to get the access token

    Then
     - make sure the integration gets the token from context.
    """
    mocker.patch.object(
        demisto,
        'getIntegrationContextVersioned',
        return_value={
            'context': {
                'access_token': '123', 'token_initiate_time': '10000.941587', 'token_expiration_seconds': '7200'
            }
        }
    )
    mocker.patch.object(time, 'time', return_value=16999.941587)
    client = Client(
        server_url="https://api.crowdstrike.com/",
        username="user1",
        password="12345",
        use_ssl=False,
        proxy=False,
        reliability=DBotScoreReliability.B
    )
    access_token = client._get_access_token()
    assert access_token == '123'


def test_parse_indicator_bug_fix():
    """
    Given:
        A dictionary of indicator data from Sandbox, with a version_info item without a "value" field.
    When:
        Running parse_indicator()
    Then:
        Make sure no KeyError is raised and the command succeeds.
    """
    sandbox = {
        "sha256": "xxx",
        "version_info": [{"id": "xxx"}],
    }
    assert parse_indicator(sandbox, DBotScoreReliability.A_PLUS)

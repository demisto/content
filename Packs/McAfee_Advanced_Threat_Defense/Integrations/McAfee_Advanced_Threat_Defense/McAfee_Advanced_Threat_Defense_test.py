import tempfile

import pytest

import demistomock as demisto

integration_params = {
    'baseUrl': ' http://demi.demi.com',
    'username': 'bark',
    'password': 'my_password'
}

FILE_UPLOAD_ERROR_ONLY_ONE_ARG = 'You must submit one and only one of the following: url, entryID'
FILE_UPLOAD_ERROR_MUST_GIVE_BOTH_ARGS = 'When submitType is 2 You must submit both url and entryID'
FILE_UPLOAD_ERROR_WRONG_ARGS = 'In order to detonate a file submitType must be 0 ' \
                               'and an entryID of a file must be given.\n' \
                               'In order to detonate a url submitType must be 1 or 3' \
                               ' and a url must be given.' \
                               'In order to submit file with a url submitType must be 2' \
                               ' and both entryID and a url must be given.'
FILE_UPLOAD_ERROR_INVALID_ARG = 'This is not a valid submitType. Should be one of : 0, 1, 2, 3'


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@pytest.mark.parametrize('args, expected_error', [
    ({'submitType': '2', 'entryID': 'entry_id'}, FILE_UPLOAD_ERROR_MUST_GIVE_BOTH_ARGS),
    ({'submitType': '2', 'url': 'url'}, FILE_UPLOAD_ERROR_MUST_GIVE_BOTH_ARGS),
    ({'submitType': '0', 'entryID': 'entry_id', 'url': 'url'}, FILE_UPLOAD_ERROR_ONLY_ONE_ARG),
    ({'submitType': '1', 'entryID': 'entry_id', 'url': 'url'}, FILE_UPLOAD_ERROR_ONLY_ONE_ARG),
    ({'submitType': '3', 'entryID': 'entry_id', 'url': 'url'}, FILE_UPLOAD_ERROR_ONLY_ONE_ARG),
    ({'submitType': '1', 'entryID': 'entry_id'}, FILE_UPLOAD_ERROR_WRONG_ARGS),
    ({'submitType': '3', 'entryID': 'entry_id'}, FILE_UPLOAD_ERROR_WRONG_ARGS),
    ({'submitType': '0', 'url': 'url'}, FILE_UPLOAD_ERROR_WRONG_ARGS),
    ({'submitType': '4'}, FILE_UPLOAD_ERROR_INVALID_ARG),
])
def test_handling_errors_with_file_upload_command(mocker, args, expected_error):
    """
    Given:
        submitType , submitType , url arguments

    When:
        Execute command atd-file-upload

    Then:
        Arguments' validation - returns error if one of the given
        arguments does not fit the command's structure
    """
    from McAfee_Advanced_Threat_Defense import handling_errors_with_file_upload_command
    mocker.patch.object(demisto, 'results')
    with pytest.raises(SystemExit):
        handling_errors_with_file_upload_command(args)
    contents = demisto.results.call_args[0][0]
    assert contents['Contents'] == expected_error


@pytest.mark.parametrize('given_url, expected_output', [
    ('google.com', 'http://www.google.com'),
    ('http://www.google.com', 'http://www.google.com'),
    ('www.google.com', 'http://www.google.com'),
    ("", "http://www."),
])
def test_add_prefix_to_given_url(given_url, expected_output):
    """
    Given:
        url argument

    When:
        Execute command atd-file-upload with submitType that is one of : 1,2,3

    Then:
        Returns the given url argument with a prefix of http://
    """
    from McAfee_Advanced_Threat_Defense import add_prefix_to_given_url
    assert add_prefix_to_given_url(given_url) == expected_output


def test_prettify_current_user_res():
    from McAfee_Advanced_Threat_Defense import prettify_current_user_res
    expected_user_dict = {'APIVersion': "1.0", 'IsAdmin': "True", 'SessionId': "42", 'UserId': 101}
    prettify_user_res = prettify_current_user_res(
        {'apiVersion': "1.0", 'isAdmin': "1", 'session': "42", 'userId': 101})
    assert expected_user_dict == prettify_user_res


def test_prettify_task_status_by_taskId_res():
    from McAfee_Advanced_Threat_Defense import prettify_task_status_by_task_id
    expected_rtask_status = {
        'taskId': "41", 'jobId': "42", 'status': "finished", 'filename': "my_name", 'MD5': "my_md5",
        'submitTime': "010101"}
    prettify_task_status_res = prettify_task_status_by_task_id(
        {'taskid': "41", 'jobid': "42", 'status': "finished", 'filename': "my_name", 'md5': "my_md5",
         'submitTime': "010101"})
    assert expected_rtask_status == prettify_task_status_res


def test_get_report_command(mocker, requests_mock):
    """
    Given:
        - The script args.
    When:
        - Running get report command.
    Then:
        - Validating the outputs as expected.
    """
    from McAfee_Advanced_Threat_Defense import get_report_command
    mocker.patch.object(demisto, 'args', return_value={'taskId': 1,
                                                       'threshold': 1,
                                                       'type': 'json'})
    requests_mock.get(
        'http://demi.demi.com/php/samplestatus.php?iTaskId=1',
        json={'results': {'taskid': '1',
                          'jobid': '1',
                          'status': 'Completed',
                          'filename': 'filename',
                          'md5': 'some_hash',
                          'submitTime': '01.09.2022'}}
    )
    requests_mock.get(
        'http://demi.demi.com/php/showreport.php?iTaskId=1&iType=json',
        json={'Summary': {'Verdict': {'Description': 'desc',
                                      'Severity': 5},
                          'Subject': {'Type': 'application/url',
                                      'md5': 'some_hash',
                                      'sha-1': 'some_hash',
                                      'sha-256': 'some_hash',
                                      'size': 50,
                                      'Name': 'name',
                                      'FileType': 'type'},
                          'Ips': [{'Ipv4': '1.1.1.1'}]

                          }}
    )
    results_mock = mocker.patch.object(demisto, 'results')
    get_report_command()
    assert 'McAfee ATD Sandbox Report' in results_mock.call_args[0][0]['HumanReadable']


def test_detonate_file_command(mocker, requests_mock):
    """
    Given:
        - The script args.
    When:
        - Running detonate-file command.
    Then:
        - Validating the outputs as expected.
    """
    from McAfee_Advanced_Threat_Defense import detonate
    requests_mock.post(
        'http://demi.demi.com/php/fileupload.php?',
        json={'success': 'True',
              'results': [{'taskId': '1',
                           'messageId': '1',
                           'url': 'url.com',
                           'status': 'Completed',
                           'filename': 'filename',
                           'md5': 'some_hash',
                           'sha1': 'some_hash',
                           'sha256': 'some_hash',
                           'srcIp': '1.1.1.1',
                           'destIp': '1.1.1.1',
                           'submitTime': '01.09.2022'}]}
    )
    requests_mock.get(
        'http://demi.demi.com/php/samplestatus.php?iTaskId=1',
        json={'results': {'taskid': '1',
                          'jobid': '1',
                          'status': 'Completed',
                          'filename': 'filename',
                          'md5': 'some_hash',
                          'submitTime': '01.09.2022'}}
    )
    requests_mock.get(
        'http://demi.demi.com/php/showreport.php?iTaskId=1&iType=json',
        json={'Summary': {'Verdict': {'Description': 'desc',
                                      'Severity': 5},
                          'Subject': {'Type': 'application/url',
                                      'md5': 'some_hash',
                                      'sha-1': 'some_hash',
                                      'sha-256': 'some_hash',
                                      'size': 50,
                                      'Name': 'name',
                                      'FileType': 'type'},
                          'Ips': [{'Ipv4': '1.1.1.1'}]
                          }}
    )
    requests_mock.get(
        'http://demi.demi.com/php/showreport.php?iTaskId=1&iType=sample',
        json={'Summary': {'Verdict': {'Description': 'desc',
                                      'Severity': 5}
                          }}
    )
    results_mock = mocker.patch.object(demisto, 'results')
    f = tempfile.TemporaryFile(mode='w')
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': f.name})
    detonate(0, 'sample', '100', 'sample', 1, 'fileName')
    assert '1.zip' in results_mock.call_args[0][0]['File']


def test_list_users_command(mocker, requests_mock):
    """
        Given:
            - The script args.
        When:
            - Running list_users command.
        Then:
            - Validating the outputs as expected.
        """
    from McAfee_Advanced_Threat_Defense import list_users_command
    mocker.patch.object(demisto, 'args', return_value={'userType': 'userType'})
    requests_mock.get(
        'http://demi.demi.com/php/briefUserList.php?userType=userType',
        json={'results': [{'fullName': 'fullName',
                           'idx': 'idx',
                           'loginId': 'loginId',
                           'userType': 'userType'}]}
    )
    results_mock = mocker.patch.object(demisto, 'results')
    list_users_command()
    assert 'ATD User List' in results_mock.call_args[0][0]['HumanReadable']


def test_detonate_url_command(mocker, requests_mock):
    """
    Given:
        - The script args.
    When:
        - Running detonate url command.
    Then:
        - Validating the outputs as expected.
    """
    from McAfee_Advanced_Threat_Defense import detonate
    requests_mock.post(
        'http://demi.demi.com/php/fileupload.php?',
        json={'success': 'True',
              'results': [{'taskId': '1',
                           'messageId': '1',
                           'url': 'url.com',
                           'status': 'Completed',
                           'filename': 'filename',
                           'md5': 'some_hash',
                           'sha1': 'some_hash',
                           'sha256': 'some_hash',
                           'srcIp': '1.1.1.1',
                           'destIp': '1.1.1.1',
                           'submitTime': '01.09.2022'}]}
    )
    requests_mock.get(
        'http://demi.demi.com/php/samplestatus.php?iTaskId=1',
        json={'results': {'taskid': '1',
                          'jobid': '1',
                          'status': 'Completed',
                          'filename': 'filename',
                          'md5': 'some_hash',
                          'submitTime': '01.09.2022'}}
    )
    requests_mock.get(
        'http://demi.demi.com/php/showreport.php?iTaskId=1&iType=json',
        json={'Summary': {'Verdict': {'Description': 'desc',
                                      'Severity': 5},
                          'Subject': {'Type': 'application/url',
                                      'md5': 'some_hash',
                                      'sha-1': 'some_hash',
                                      'sha-256': 'some_hash',
                                      'size': 50,
                                      'Name': 'name',
                                      'FileType': 'type'},
                          'Ips': [{'Ipv4': '1.1.1.1'}]
                          }}
    )
    requests_mock.get(
        'http://demi.demi.com/php/showreport.php?iTaskId=1&iType=pdf',
        json={'Summary': {'Verdict': {'Description': 'desc',
                                      'Severity': 5}
                          }}
    )
    results_mock = mocker.patch.object(demisto, 'results')
    f = tempfile.TemporaryFile(mode='w')
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': f.name})
    detonate(1, 'url.com', '100', 'pdf', 1, 'fileName')
    assert '1.pdf' in results_mock.call_args[0][0]['File']


def test_list_profiles_command(mocker, requests_mock):
    """
        Given:
            - The script args.
        When:
            - Running list_profiles command.
        Then:
            - Validating the outputs as expected.
        """
    from McAfee_Advanced_Threat_Defense import list_profiles_command
    requests_mock.get(
        'http://demi.demi.com/php/vmprofiles.php',
        json={'results': [{'name': 'name',
                           'vmProfileid': 'vmProfileid',
                           'vmDesc': 'vmDesc',
                           'sandbox': 0,
                           'internet': 0,
                           'locBlackList': 0}]}
    )
    results_mock = mocker.patch.object(demisto, 'results')
    list_profiles_command()
    assert 'ATD Analyzers Profile List' in results_mock.call_args[0][0]['HumanReadable']


def test_get_headers(requests_mock):
    """
        Given:
            - The script args.
        When:
            - Running get_headers function.
        Then:
            - Validating the outputs as expected.
        """
    from McAfee_Advanced_Threat_Defense import get_headers
    requests_mock.get(
        'http://demi.demi.com/php/session.php',
        json={'results': {'session': 'session',
                          'userId': 'userId'}}
    )
    res = get_headers()
    assert res.get('VE-SDK-API') == b'c2Vzc2lvbjp1c2VySWQ='

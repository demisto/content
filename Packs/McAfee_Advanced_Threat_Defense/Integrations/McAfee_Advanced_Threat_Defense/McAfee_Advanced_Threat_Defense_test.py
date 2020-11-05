import pytest

import demistomock as demisto

integration_params = {
    'baseUrl': 'demi.demi.com',
    'username': 'bark',
    'password': 'my_password'
}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@pytest.mark.parametrize('args', [
    ({'submitType': '2', 'entryID': 'entry_id'}),
    ({'submitType': '2', 'url': 'url'}),
    ({'submitType': '0', 'entry_id': 'entry_id', 'url': 'url'}),
    ({'submitType': '1', 'entryID': 'entry_id', 'url': 'url'}),
    ({'submitType': '3', 'entryID': 'entry_id', 'url': 'url'}),
    ({'submitType': '1', 'entryID': 'entry_id'}),
    ({'submitType': '3', 'entryID': 'entry_id'}),
    ({'submitType': '0', 'url': 'url'}),
    ({'submitType': '4'}),
])
def test_handling_errors_with_file_upload_command(args):
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
    with pytest.raises(SystemExit) as e:
        handling_errors_with_file_upload_command(args)
    assert e


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
    expected_user_dict = dict({
        'APIVersion': "1.0", 'IsAdmin': "True", 'SessionId': "42", 'UserId': 101})
    prettify_user_res = prettify_current_user_res(
        {'apiVersion': "1.0", 'isAdmin': "1", 'session': "42", 'userId': 101})
    assert expected_user_dict == prettify_user_res


def test_prettify_task_status_by_taskId_res():
    from McAfee_Advanced_Threat_Defense import prettify_task_status_by_task_id
    expected_rtask_status = dict({
        'taskId': "41", 'jobId': "42", 'status': "finished", 'filename': "my_name", 'MD5': "my_md5",
        'submitTime': "010101"})
    prettify_task_status_res = prettify_task_status_by_task_id(
        {'taskid': "41", 'jobid': "42", 'status': "finished", 'filename': "my_name", 'md5': "my_md5",
         'submitTime': "010101"})
    assert expected_rtask_status == prettify_task_status_res

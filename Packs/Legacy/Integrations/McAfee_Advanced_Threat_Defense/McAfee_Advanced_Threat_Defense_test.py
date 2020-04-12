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
        'taskId': "41", 'jobId': "42", 'status': "finished", 'filename': "my_name", 'MD5': "my_md5", 'submitTime': "010101"})
    prettify_task_status_res = prettify_task_status_by_task_id(
        {'taskid': "41", 'jobid': "42", 'status': "finished", 'filename': "my_name", 'md5': "my_md5", 'submitTime': "010101"})
    assert expected_rtask_status == prettify_task_status_res

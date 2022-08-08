import duo_client


def test_modify_user(mocker):
    from DuoAdminApi import modify_user
    args = {'user_id': '1', 'status': 'active'}
    mocker.patch.object(duo_client.Admin, 'update_user', return_value=None)
    result = modify_user(**args)
    assert result.readable_output == 'Status for user id ' + '1' + ' Successfully updated to ' + 'active'


def test_modify_admin_user(mocker):
    from DuoAdminApi import modify_admin_user
    args = {'user_id': '1', 'status': 'active'}
    mocker.patch.object(duo_client.Admin, 'update_admin', return_value=None)
    result = modify_admin_user(**args)
    assert result.readable_output == 'Status for user id ' + '1' + ' Successfully updated to ' + 'active'

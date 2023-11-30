import duo_client
import json
import demistomock as demisto


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    from DuoAdminApi import create_api_call
    return create_api_call()


def test_modify_user(mocker):
    """
        Given
        - A user id and status.

        When
        - Calling modify_user method.

        Then
        - Validate that the user were successfully update.
    """
    from DuoAdminApi import modify_user
    args = {'user_id': '1', 'status': 'active'}
    user_id = args.get('user_id')
    client = mock_client()
    mocker.patch.object(duo_client.Admin, 'update_user', return_value=None)
    result = modify_user(client, **args)
    assert result.readable_output == f'The user id {user_id} successfully updated'


def test_modify_admin_user(mocker):
    """
        Given
        - An admin id and name.

        When
        - Calling modify_admin_user method.

        Then
        - Validate that the admin were successfully update.
    """
    from DuoAdminApi import modify_admin_user
    args = {'admin_id': '1', 'name': 'test'}
    admin_id = args.get('admin_id')
    client = mock_client()
    mocker.patch.object(duo_client.Admin, 'update_admin', return_value=None)
    result = modify_admin_user(client, **args)
    assert result.readable_output == f'The admin id {admin_id} successfully updated'


def test_get_users(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling get_all_users method.

        Then
        - Validate that all users were successfully retrieve.
    """
    from DuoAdminApi import get_all_users
    client = mock_client()
    mock_res = util_load_json('test_data/get_users.json')
    mocker.patch.object(duo_client.Admin, 'get_users', return_value=mock_res)
    mocker.patch.object(demisto, 'results')

    get_all_users(client)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')
    assert content.get('alias1') == 'test.1'
    assert content.get('email') == 'test.1@test.com'
    assert content.get('status') == 'active'


def test_get_bypass_codes(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling get_all_bypass_codes method.

        Then
        - Validate that all bypass codes were successfully retrieve.
    """
    from DuoAdminApi import get_all_bypass_codes
    client = mock_client()
    mock_res = util_load_json('test_data/get_all_bypass_codes.json')
    mocker.patch.object(duo_client.Admin, 'get_bypass_codes', return_value=mock_res)
    mocker.patch.object(demisto, 'results')

    get_all_bypass_codes(client)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')
    assert content.get('bypass_code_id') == '1'


def test_get_authentication_logs_by_user(mocker):
    """
        Given
        - A duo admin client user name and from date time.

        When
        - Calling get_authentication_logs_by_user method.

        Then
        - Validate that all the logs were successfully retrieve.
    """
    from DuoAdminApi import get_authentication_logs_by_user
    client = mock_client()
    args = {'username': 'test@demisto.com', 'from': '10_years_ago'}
    mock_res = util_load_json('test_data/get_authentication_logs_by_user.json')

    mocker.patch.object(duo_client.Admin, 'get_authentication_log', return_value=mock_res)
    mocker.patch.object(duo_client.Admin, 'get_users_by_name', return_value=[{'user_id': '1'}])
    mocker.patch.object(demisto, 'results')

    get_authentication_logs_by_user(client, args)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')[0]
    assert content.get('user').get('name') == args.get('username')
    assert content.get('auth_device').get('ip') == '1.1.1.1'
    assert content.get('auth_device').get('location').get('city') == 'test_city'


def test_get_all_devices(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling get_all_devices method.

        Then
        - Validate that all the devices were successfully retrieve.
    """
    from DuoAdminApi import get_all_devices
    client = mock_client()
    mock_res = util_load_json('test_data/get_all_devices.json')

    mocker.patch.object(duo_client.Admin, 'get_phones', return_value=mock_res)
    mocker.patch.object(demisto, 'results')

    get_all_devices(client)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')
    assert content.get('activated')
    assert content.get('phone_id') == '1'
    assert content.get('type') == 'Mobile'


def test_dissociate_device_by_user(mocker):
    """
        Given
        - A duo admin client user name and device id.

        When
        - Calling dissociate_device_by_user method.

        Then
        - Validate that the phone id was successfully dissociated.
    """
    from DuoAdminApi import dissociate_device_by_user
    client = mock_client()
    args = {'username': 'test@demisto.com', 'device_id': '1'}
    mock_res = util_load_json('test_data/get_authentication_logs_by_user.json')

    mocker.patch.object(duo_client.Admin, 'delete_user_phone', return_value=mock_res)
    mocker.patch.object(duo_client.Admin, 'get_users_by_name', return_value=[{'user_id': '1'}])
    mocker.patch.object(demisto, 'results')

    dissociate_device_by_user(client, args)
    res = demisto.results
    hr = res.call_args[0][0]
    assert hr == f"Phone with ID {args.get('device_id')} was dissociated to user {args.get('username')}"


def test_associate_device_to_user(mocker):
    """
        Given
        - A duo admin client user name and device id.

        When
        - Calling associate_device_by_user method.

        Then
        - Validate that the phone id was successfully associated.
    """
    from DuoAdminApi import associate_device_to_user
    client = mock_client()
    args = {'username': 'test@demisto.com', 'device_id': '1'}
    mock_res = util_load_json('test_data/get_authentication_logs_by_user.json')

    mocker.patch.object(duo_client.Admin, 'add_user_phone', return_value=mock_res)
    mocker.patch.object(duo_client.Admin, 'get_users_by_name', return_value=[{'user_id': '1'}])
    mocker.patch.object(demisto, 'results')

    associate_device_to_user(client, args)
    res = demisto.results
    hr = res.call_args[0][0]
    assert hr == f"Phone with ID {args.get('device_id')} was associated to user {args.get('username')}"


def test_get_all_admins(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling get_all_admins method.

        Then
        - Validate that all admins were successfully retrieve.
    """
    from DuoAdminApi import get_all_admins
    client = mock_client()
    mock_res = {
        "admin_id": "1",
        "created": None,
        "email": "test.1@test.com",
        "last_login": 1662468518,
        "name": "test1-Demisto",
        "phone": "+972111111111"
    }

    mocker.patch.object(duo_client.Admin, 'get_admins', return_value=mock_res)
    mocker.patch.object(demisto, 'results')

    get_all_admins(client)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')
    assert content.get('admin_id') == mock_res.get('admin_id')
    assert content.get('email') == mock_res.get('email')


def test_get_u2f_tokens_by_user(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling get_u2f_tokens_by_user method.

        Then
        - Validate that all u2f tokens were successfully retrieve.
    """
    from DuoAdminApi import get_u2f_tokens_by_user
    client = mock_client()
    mock_res = util_load_json('test_data/get_users.json')
    mock_res.update({
        "credential_name": "test_credential",
        "date_added": 1662468518,
        "label": "Security Key"
    })
    mock_res = [mock_res]
    args = {'username': 'test1'}

    mocker.patch.object(duo_client.Admin, 'get_user_u2ftokens', return_value=mock_res)
    mocker.patch.object(duo_client.Admin, 'get_users_by_name', return_value=[{'user_id': '1'}])
    mocker.patch.object(demisto, 'results')
    get_u2f_tokens_by_user(client, args)
    res = demisto.results
    content = res.call_args[0][0].get('Contents')[0]
    assert content.get('credential_name') == 'test_credential'


def test_delete_u2f_token(mocker):
    """
        Given
        - A duo admin client.

        When
        - Calling delete_u2f_token method.

        Then
        - Validate that u2f token was successfully deleted.
    """
    from DuoAdminApi import delete_u2f_token
    client = mock_client()
    args = {'token_id': 'test_token'}

    mocker.patch.object(duo_client.Admin, 'delete_u2ftoken')
    mocker.patch.object(demisto, 'results')
    delete_u2f_token(client, args)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == f"Token with ID {args.get('token_id')} deleted successfully"

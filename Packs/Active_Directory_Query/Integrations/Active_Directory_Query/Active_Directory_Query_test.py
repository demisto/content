import demistomock as demisto
from Active_Directory_Query import main, group_dn
import socket
import ssl
from threading import Thread
import time
import os
import pytest
import json
from IAMApiModule import *
from unittest.mock import patch


BASE_TEST_PARAMS = {
    'server_ip': '127.0.0.1',
    'secure_connection': 'None',
    'page_size': '500',
    'credentials': {'identifier': 'bad', 'password': 'bad'}
}

RETURN_ERROR_TARGET = 'Active_Directory_Query.return_error'


def test_bad_host_no_ssl(mocker):
    mocker.patch.object(demisto, 'params',
                        return_value=BASE_TEST_PARAMS)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('server_ip') == '127.0.0.1'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg


@pytest.mark.filterwarnings("ignore::ResourceWarning")
def test_bad_ssl(mocker):
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '185.199.108.153'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['port'] = 443
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    demisto_info_mock = mocker.patch.object(demisto, "info")
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'SSL error' in err_msg
    # call_args_list holds all calls (we need the first) with a tuple of args list and kwargs
    info_msg = demisto_info_mock.call_args_list[0][0][0]
    # ip is not in the certificate. so it should fail on host match
    assert "doesn't match any name" in info_msg


def ssl_bad_socket_server(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # cert and keyfile generated with
    # openssl req -x509 -nodes -days 3000 -newkey rsa:2048 -keyout key.pem -out cert.pem
    try:
        context.load_cert_chain('cert.pem', 'key.pem')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', port))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                try:
                    conn, addr = ssock.accept()
                except ssl.SSLError as err:
                    if 'TLSV1_ALERT_UNKNOWN_CA' in str(err):
                        # all is ok. client refused our cert
                        return
                    raise
                conn.recv(32)
                msg = b'THIS IS A TEST SERVER WHICH IGNORES PROTOCOL\n\n'
                for x in range(10):
                    msg += msg
                conn.send(msg)
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
    except Exception as ex:
        pytest.fail("Failed starting ssl_bad_socket_server: {}".format(ex))
        raise


@pytest.mark.filterwarnings("ignore::ResourceWarning")
def test_faulty_server(mocker):
    port = 9638
    t = Thread(target=ssl_bad_socket_server, args=(port,))
    t.start()
    time.sleep(1)  # wait for socket server to startup
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '127.0.0.1'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['unsecure'] = True
    params['port'] = port
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    t.join(5)
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg


def test_ssl_custom_cert(mocker, request):
    ENV_KEY = 'SSL_CERT_FILE'
    os.environ[ENV_KEY] = 'cert.pem'

    def cleanup():
        os.environ.pop(ENV_KEY)

    request.addfinalizer(cleanup)
    port = 9637
    t = Thread(target=ssl_bad_socket_server, args=(port,))
    t.start()
    time.sleep(1)  # wait for socket server to startup
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '127.0.0.1'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['port'] = port
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    t.join(5)
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'SSL error' not in err_msg


def test_endpoint_entry():
    """
    Given:
         Custom attributes to filter the computer object entry.
    When:
        The function filters the computer object according to the custom attributes.
    Then:
        The function will return all the computer object entry because custom attributes contain '*'.

    """
    from Active_Directory_Query import endpoint_entry
    custom_attributes_with_asterisk = endpoint_entry({'dn': 'dn', 'name': 'name', 'memberOf': 'memberOf'}, ['*'])
    assert custom_attributes_with_asterisk == {'Groups': 'memberOf', 'Hostname': 'name', 'ID': 'dn', 'Type': 'AD'}


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')

    return outputs


def mock_demisto_map_object(object, mapper_name, incident_type):
    email = object.get('email')
    email_prefix = email.split('@')[0]
    return {
        'cn': email_prefix,
        'mail': email,
        'sAMAccountName': email_prefix,
        'userPrincipalName': email_prefix,
        "ou": "OU=Americas,OU=Demisto"
    }


def test_get_iam_user_profile(mocker):
    from Active_Directory_Query import get_iam_user_profile
    mocker.patch.object(demisto, 'mapObject', side_effect=mock_demisto_map_object)

    user_profile = {"email": "test2@paloaltonetworks.com", "username": "test",
                    "locationregion": "Americas",
                    "olduserdata": {"email": "test@paloaltonetworks.com", "username": "test",
                                    "locationregion": "Americas"}}
    _, ad_user, sam_account_name = get_iam_user_profile(user_profile, 'mock_mapper_out')
    assert sam_account_name == 'test'
    assert ad_user


def test_update_user_iam__username_change(mocker):
    """
    Given:
         A valid user profile with valid mapping
    When:
        Running the `create_user_iam` command
    Then:
        The user was created successfully in AD.

    """
    import Active_Directory_Query
    add_args, add_kwargs = [], {}

    class ConnectionMocker:
        entries = []
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

        def search(self, *args, **kwargs):
            return

        def add(self, *args, **kwargs):
            nonlocal add_args, add_kwargs
            add_args, add_kwargs = args, kwargs
            return True

        def modify(self, *args, **kwargs):
            return True

        def modify_dn(self, *args, **kwargs):
            return True

    Active_Directory_Query.conn = ConnectionMocker()
    args = {"user-profile": json.dumps({"email": "test2@paloaltonetworks.com", "username": "test",
                                        "locationregion": "Americas",
                                        "olduserdata": {"email": "test@paloaltonetworks.com", "username": "test",
                                                        "locationregion": "Americas"}})}

    mocker.patch.object(demisto, 'mapObject', side_effect=mock_demisto_map_object)
    mocker.patch('Active_Directory_Query.check_if_user_exists_by_attribute', return_value=True)
    mocker.patch('Active_Directory_Query.get_user_activity_by_samaccountname', return_value=True)
    mocker.patch('Active_Directory_Query.user_dn', return_value='mock_dn')

    user_profile = Active_Directory_Query.update_user_iam(
        default_base_dn='mock_base_dn',
        args=args,
        create_if_not_exists=False,
        mapper_out='mock_mapper_out',
        disabled_users_group_cn='mock_disabled_users_group_cn'
    )
    outputs = get_outputs_from_user_profile(user_profile)
    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('email') == 'test2@paloaltonetworks.com'
    assert outputs.get('username') == 'test2'


def test_create_user_iam(mocker):
    """
    Given:
         A valid user profile with valid mapping
    When:
        Running the `create_user_iam` command
    Then:
        The user was created successfully in AD.

    """
    import Active_Directory_Query
    add_args, add_kwargs = [], {}

    class ConnectionMocker:
        entries = []
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

        def search(self, *args, **kwargs):
            return

        def add(self, *args, **kwargs):
            nonlocal add_args, add_kwargs
            add_args, add_kwargs = args, kwargs
            return True

    Active_Directory_Query.conn = ConnectionMocker()
    args = {"user-profile": json.dumps({"email": "test@paloaltonetworks.com", "username": "test",
                                        "locationregion": "Americas"})}

    mocker.patch('Active_Directory_Query.check_if_user_exists_by_attribute', return_value=False)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={'cn': 'test', 'mail': 'test@paloaltonetworks.com',
                                                                    'sAMAccountName': 'test',
                                                                    'userPrincipalName': 'test',
                                                                    "ou": "OU=Americas,OU=Demisto"})

    user_profile = Active_Directory_Query.create_user_iam('', args, 'mapper_out', '')
    outputs = get_outputs_from_user_profile(user_profile)
    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is False
    assert outputs.get('email') == 'test@paloaltonetworks.com'


def test_unseccsseful_create_user_iam_missing_ou(mocker):
    """
    Given:
         A valid user profile with missing ou in the mapping
    When:
        Running the `create_user_iam` command
    Then:
        - The user was not created in AD.
        - An error message was returned.

    """
    import Active_Directory_Query
    add_args, add_kwargs = [], {}

    class ConnectionMocker:
        entries = []
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

        def search(self, *args, **kwargs):
            return

        def add(self, *args, **kwargs):
            nonlocal add_args, add_kwargs
            add_args, add_kwargs = args, kwargs
            return True

    Active_Directory_Query.conn = ConnectionMocker()
    args = {"user-profile": json.dumps({"email": "test@paloaltonetworks.com", "username": "test",
                                        "locationregion": "Americas"})}

    mocker.patch('Active_Directory_Query.check_if_user_exists_by_attribute', return_value=False)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={'cn': 'test', 'mail': 'test@paloaltonetworks.com',
                                                                    'sAMAccountName': 'test',
                                                                    'userPrincipalName': 'test'})

    user_profile = Active_Directory_Query.create_user_iam('', args, 'mapper_out', '')
    outputs = get_outputs_from_user_profile(user_profile)
    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is False
    assert outputs.get('email') == 'test@paloaltonetworks.com'
    assert 'User must have an Organizational Unit (OU)' in outputs.get('errorMessage')


def test_unseccsseful_create_user_iam_missing_samaccountname(mocker):
    """
    Given:
         A valid user profile with missing samaccountname in the mapping
    When:
        Running the `create_user_iam` command
    Then:
        - The user was not created in AD.
        - An error message was returned.

    """
    import Active_Directory_Query
    add_args, add_kwargs = [], {}

    class ConnectionMocker:
        entries = []
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

        def search(self, *args, **kwargs):
            return

        def add(self, *args, **kwargs):
            nonlocal add_args, add_kwargs
            add_args, add_kwargs = args, kwargs
            return True

    Active_Directory_Query.conn = ConnectionMocker()
    args = {"user-profile": json.dumps({"email": "test@paloaltonetworks.com", "username": "test",
                                        "locationregion": "Americas"})}

    mocker.patch('Active_Directory_Query.check_if_user_exists_by_attribute', return_value=False)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={'cn': 'test', 'mail': 'test@paloaltonetworks.com',
                                                                    "ou": "OU=Americas,OU=Demisto",
                                                                    'userPrincipalName': 'test'})

    user_profile = Active_Directory_Query.create_user_iam('', args, 'mapper_out', '')
    outputs = get_outputs_from_user_profile(user_profile)
    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is False
    assert outputs.get('email') == 'test@paloaltonetworks.com'
    assert 'User must have a sAMAccountName' in outputs.get('errorMessage')


def test_group_entry_no_custom_attributes():
    """
    Given:
         Custom attributes to filter the group object entry.
    When:
        The function filters the group object according to the custom attributes.
    Then:
        The function will return all the group object entry because custom attributes contain '*'.

    """
    from Active_Directory_Query import group_entry
    custom_attributes_with_asterisk = group_entry({'dn': 'dn', 'name': 'name', 'memberOf': 'memberOf'}, ['*'])
    assert custom_attributes_with_asterisk == {'Groups': 'memberOf', 'ID': 'dn', 'Name': 'name', 'Type': 'AD'}


def test_group_entry():
    """
    Given:
         Custom attributes to filter the group object entry.
    When:
        The function filters the group object according to the custom attributes.
    Then:
        The function will return all the group object entry because custom attributes contain '*'.

    """
    from Active_Directory_Query import group_entry
    custom_attributes_with_asterisk = group_entry({'dn': 'dn', 'name': 'name', 'memberOf': 'memberOf',
                                                   'displayName': 'display name'}, ['displayName'])
    assert custom_attributes_with_asterisk == {'Groups': 'memberOf', 'ID': 'dn', 'Name': 'name', 'Type': 'AD',
                                               'displayName': 'display name'}


def test_search_group_members(mocker):
    """
    sanity test for search_group_members method
    """
    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return '{"dn": "dn","attributes": {"memberOf": ["memberOf"], "name": ["name"]}}'

    class ConnectionMocker:
        entries = [EntryMocker()]
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

        def search(self, *args, **kwargs):
            return

    expected_results = {'ContentsFormat': 'json', 'Type': 1,
                        'Contents': [{'dn': 'dn', 'attributes': {'memberOf': ['memberOf'], 'name': ['name']}}],
                        'ReadableContentsFormat': 'markdown',
                        'HumanReadable': '### Active Directory - Get Group Members\n|'
                                         'dn|memberOf|name|\n|---|---|---|\n| dn | memberOf | name |\n',
                        'EntryContext': {'ActiveDirectory.Groups(obj.dn ==dn)': {'dn': 'dn', 'members': [
                                        {'dn': 'dn', 'category': 'group'}]}, 'ActiveDirectory.Groups(obj.dn == val.dn)':
                                            [{'dn': 'dn', 'memberOf': ['memberOf'], 'name': ['name']}], 'Group':
                                            [{'Type': 'AD', 'ID': 'dn', 'Name': ['name'], 'Groups': ['memberOf']}]}}

    expected_results = f'demisto results: {json.dumps(expected_results, indent=4, sort_keys=True)}'

    mocker.patch.object(demisto, 'args',
                        return_value={'member-type': 'group', 'group-dn': 'dn'})

    Active_Directory_Query.conn = ConnectionMocker()

    with patch('logging.Logger.info') as mock:
        Active_Directory_Query.search_group_members('dc', 1)
        mock.assert_called_with(expected_results)


def test_group_dn_escape_characters():
    """
    Given:
         Group name with parentheses
    When:
        Running the function group_dn
    Then:
        The function search gets the group name after escape special characters.

    """
    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return '{"dn": "dn","attributes": {"memberOf": ["memberOf"], "name": ["name"]}}'

    class ConnectionMocker:
        entries = [EntryMocker()]
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': '<cookie>'}}}}

    Active_Directory_Query.conn = ConnectionMocker()

    with patch('Active_Directory_Query.search', return_value=[EntryMocker()]) as mock:
        group_dn('group(group)', '')

        mock.assert_called_with('(&(objectClass=group)(cn=group\\28group\\29))', '')


def test_search__no_control_exist(mocker):
    """
    Given:
         No control key in the result
    When:
        Run any search query
    Then:
        The result return 'no entries' instead of throw exception

    """
    import Active_Directory_Query

    class ConnectionMocker:
        entries = []
        result = {}

        def search(self, *args, **kwargs):
            return

    mocker.patch.object(demisto, 'results')
    Active_Directory_Query.conn = ConnectionMocker()
    Active_Directory_Query.search_users('dc=test,dc=test_1', page_size=20)

    assert '**No entries.**' in demisto.results.call_args[0][0]['HumanReadable']


def test_user_account_to_boolean_fields():
    """
    Given:
        a userAccountControl value
    When:
        parsing the userAccountControl fields
    Then:
        Only the relevant fields will be marked as true
    """
    import Active_Directory_Query

    fields = Active_Directory_Query.user_account_to_boolean_fields(0x50)
    assert {k for k, v in fields.items() if v} == {'LOCKOUT', 'PASSWD_CANT_CHANGE'}

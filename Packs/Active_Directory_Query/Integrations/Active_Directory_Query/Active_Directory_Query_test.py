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
    """
        Given:
            - Demisto.params() with an invalid server (host), and insecure connection type (None).
        When:
            - Running the 'main()' function.
        Then:
            - Verify that the expected error message was raised.
    """
    params = BASE_TEST_PARAMS
    params['server_ip'] = '127.0.0.'
    mocker.patch.object(demisto, 'params',
                        return_value=BASE_TEST_PARAMS)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('server_ip') == '127.0.0.'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'invalid server address' in err_msg


@pytest.mark.filterwarnings("ignore::ResourceWarning")
def test_bad_ssl(mocker):
    """
        Given:
            - Demisto.params() with an ssl connection type (SSL) and a server (host) that will cause
              an SSL socket error.
        When:
            - Running the 'main()' function.
        Then:
            - Verify that the expected error message was raised.
    """
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '185.199.108.153'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['port'] = 443
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    mocker.patch.object(demisto, "info")
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Failed to access' in err_msg
    assert 'Try using: "Trust any certificate" option.' in err_msg


def ssl_bad_socket_server(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # cert and keyfile generated with
    # openssl req -x509 -nodes -days 3000 -newkey rsa:2048 -keyout key.pem -out cert.pem
    try:
        context.load_cert_chain('test_data/cert.pem', 'test_data/key.pem')
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
                for _x in range(10):
                    msg += msg
                conn.send(msg)
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
    except Exception as ex:
        pytest.fail(f"Failed starting ssl_bad_socket_server: {ex}")
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
    assert len(err_msg) < 125
    assert 'Failed to access' in err_msg
    assert 'Try using: "Trust any certificate" option.' not in err_msg


def test_ssl_custom_cert(mocker, request):
    ENV_KEY = 'SSL_CERT_FILE'
    os.environ[ENV_KEY] = 'test_data/cert.pem'

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

    Active_Directory_Query.connection = ConnectionMocker()
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

    Active_Directory_Query.connection = ConnectionMocker()
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

    Active_Directory_Query.connection = ConnectionMocker()
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

    Active_Directory_Query.connection = ConnectionMocker()
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
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': b'<cookie>'}}}}

        def search(self, *args, **kwargs):
            time.sleep(1)

    expected_entry = {
        'ActiveDirectory.Groups(obj.dn ==dn)': {'dn': 'dn', 'members': [{'dn': 'dn', 'category': 'group'}]},
        'ActiveDirectory.Groups(obj.dn == val.dn)': [{'dn': 'dn', 'memberOf': ['memberOf'], 'name': ['name']}],
        'Group': [{'Type': 'AD', 'ID': 'dn', 'Name': ['name'], 'Groups': ['memberOf']}],
        'ActiveDirectory(true)': {"GroupsPageCookie": base64.b64encode(b'<cookie>').decode('utf-8')}}

    expected_results = {'ContentsFormat': 'json', 'Type': 1,
                        'Contents': [{'dn': 'dn', 'attributes': {'memberOf': ['memberOf'], 'name': ['name']}}],
                        'ReadableContentsFormat': 'markdown',
                        'HumanReadable': '### Active Directory - Get Group Members\n|'
                                         'dn|memberOf|name|\n|---|---|---|\n| dn | memberOf | name |\n',
                        'EntryContext': expected_entry}
    expected_results = f'demisto results: {json.dumps(expected_results, indent=4, sort_keys=True)}'

    mocker.patch.object(demisto, 'args',
                        return_value={'member-type': 'group', 'group-dn': 'dn', 'time_limit': '1'})

    Active_Directory_Query.connection = ConnectionMocker()

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

    Active_Directory_Query.connection = ConnectionMocker()

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
    Active_Directory_Query.connection = ConnectionMocker()
    Active_Directory_Query.search_users('dc=test,dc=test_1', page_size=20)

    assert '**No entries.**' in demisto.results.call_args[0][0]['HumanReadable']


def test_search_attributes_to_exclude(mocker):
    """
    Given:
        attributes_to_exclude
    When:
        Run any search query
    Then:
        The given arguments where excluded from human_readable and context_data
    """
    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return '{"dn": "dn"}'

    class ConnectionMocker:
        entries = [EntryMocker()]
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': b'<cookie>'}}}}

        def search(self, *args, **kwargs):
            time.sleep(1)

    expected_results = {'ContentsFormat': 'json', 'Type': 1,
                        'Contents': [{'dn': 'dn'}],
                        'ReadableContentsFormat': 'markdown',
                        'HumanReadable': '### Active Directory - Get Users\n|dn|\n|---|\n| dn |\n',
                        'EntryContext': {'ActiveDirectory.Users(obj.dn == val.dn)': [{'dn': 'dn'}],
                                         'Account(obj.ID == val.ID)':
                                             [{'Type': 'AD', 'ID': 'dn', 'Email': None, 'Username': None,
                                               'DisplayName': None, 'Managr': None, 'Manager': None, 'Groups': None}],
                                         'ActiveDirectory(true)':
                                             {"UsersPageCookie": base64.b64encode(b'<cookie>').decode('utf-8')}}}

    expected_results = f'demisto results: {json.dumps(expected_results, indent=4, sort_keys=True)}'

    mocker.patch.object(demisto, 'args',
                        return_value={'attributes-to-exclude': "memberOf,name,mail,displayName,"
                                                               "manager,sAMAccountName,userAccountControl",
                                      'page-size': '1'})

    Active_Directory_Query.connection = ConnectionMocker()

    with patch('logging.Logger.info') as mock:
        Active_Directory_Query.search_users('dc', 1)
        mock.assert_called_with(expected_results)


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


@pytest.mark.parametrize('flags', [512, 0, 544])
def test_restore_user(mocker, flags):
    """
    Given:
        A disabled user.
    When:
        Calling restore_user method.
    Then:
        Verify the existing flag is returned.
    """
    from Active_Directory_Query import restore_user

    re_val = {'flat': [{'userAccountControl': [flags]}]}
    mocker.patch('Active_Directory_Query.search_with_paging', return_value=re_val)
    mocker.patch.object(demisto, 'args')

    assert restore_user('test_user', 0) == flags


def test_enable_user_with_restore_user_option(mocker):
    """
    Given:
        A disabled user.
    When:
        Calling enable_user method.
    Then:
        Verify the existing flag is returned with the disable bit off.
    """
    from Active_Directory_Query import enable_user
    disabled_account_with_properties = 546
    enabled_account_with_properties = 544
    mocker.patch('Active_Directory_Query.restore_user', return_value=disabled_account_with_properties)
    mocker.patch('Active_Directory_Query.user_dn', return_value='test_dn')
    modify_data = mocker.patch('Active_Directory_Query.modify_object')
    mocker.patch.object(demisto, 'args')

    enable_user('test_user', 0)

    assert modify_data.call_args.args[1].get('userAccountControl')[0][1] == enabled_account_with_properties


def test_search_with_paging_bug(mocker):
    """
     Given:
        page size larger than 1.
    When:
        running get-group-members command.
    Then:
        time_limit results returned.

    """
    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return '{"dn": "dn","attributes": {"memberOf": ["memberOf"], "name": ["name"]}}'

    class ConnectionMocker:
        entries = []
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': b'<cookie>'}}}}

        def search(self, *args, **kwargs):
            page_size = kwargs.get('paged_size')
            if page_size:
                self.entries = [EntryMocker() for i in range(page_size)]
                time.sleep(1)

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args',
                        return_value={'member-type': 'group', 'group-dn': 'dn', 'time_limit': '3'})

    Active_Directory_Query.connection = ConnectionMocker()

    with patch('logging.Logger.info'):
        Active_Directory_Query.search_group_members('dc', 1)
        assert len(demisto.results.call_args[0][0]['Contents']) == 3


def test_password_not_expire_missing_username(mocker):
    """
     Given:
        A demisto args object with missing username and a valid value.
    When:
        running set_password_not_expire command.
    Then:
        Verify that a a missing username exception is raised.

    """
    from Active_Directory_Query import set_password_not_expire
    mocker.patch.object(demisto, 'args', return_value={'username': None, 'value': True})
    default_base_dn = {}

    with pytest.raises(Exception) as err:
        set_password_not_expire(default_base_dn)
    assert err.value.args[0] == 'Missing argument - You must specify a username (sAMAccountName).'


@pytest.mark.parametrize('connection_type, unsecure, expected_auto_bind_value', [
    ('Start TLS', True, 'TLS_BEFORE_BIND'),
    ('Start TLS', False, 'TLS_BEFORE_BIND'),
    ('TLS', False, 'TLS_BEFORE_BIND'),
    ('TLS', True, 'NO_TLS'),
    ('SSL', True, 'NO_TLS'),
    ('SSL', False, 'NO_TLS'),
    ('None', True, 'NO_TLS'),
    ('None', False, 'NO_TLS')
])
def test_get_auto_bind_value(connection_type, unsecure, expected_auto_bind_value):
    """
        Given:
            - A connection type:
                1. Start TLS
                2. TLS
                3. SSL
                4. None
        When:
            - Running the 'get_auto_bind_value()' function.
        Then:
            - Verify that the returned auto_bind value is as expected:
                1. 'TLS_BEFORE_BIND' - which means that connection should upgrade it's secure level to TLS before
                                       the bind itself (STARTTLS command is executed).

                2. 'TLS_BEFORE_BIND' - for unsecure=False and 'NO_TLS' for unsecure=True

                3. 'NO_TLS' - The connection is secured from the beginning,
                              thus STARTTLS command shouldn't be executed.

                4. 'NO_TLS' - Connection is insecure (cleartext) and shouldn't be upgraded to TLS.
    """
    from Active_Directory_Query import get_auto_bind_value
    auto_bind_value = get_auto_bind_value(connection_type, unsecure)
    assert auto_bind_value == expected_auto_bind_value


@pytest.mark.parametrize('ssl_version, expected_ssl_version', [
    ('TLS', 2), ('TLSv1', 3), ('TLSv1_1', 4), ('TLSv1_2', 5), ('TLS_CLIENT', 16), (None, None), ('None', None)
])
def test_get_ssl_version(ssl_version, expected_ssl_version):
    """
        Given:
            - An ssl protocol version:
                1. TLS
                2. TLSv1
                3. TLSv1_1
                4. TLSv1_2
                5. TLS_CLIENT
                6. None
                7. 'None'
        When:
            - Running the 'get_ssl_version()' function.
        Then:
            - Verify that the returned ssl version value is as expected:
                1. TLS - 2
                2. TLSv1 - 3
                3. TLSv1_1 - 4
                4. TLSv1_2 - 5
                5. TLS_CLIENT - 16
                6. None - None
                7. 'None' - None
    """
    from Active_Directory_Query import get_ssl_version
    ssl_version_value = get_ssl_version(ssl_version)
    assert ssl_version_value == expected_ssl_version


def test_search_users_empty_userAccountControl(mocker):
    """
    Given:
        The 'userAccountControl' attribute was returned empty
    When:
        Run the 'ad-get-user' command
    Then:
        The result returns without raise IndexError: list index out of range
    """

    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return '{"attributes": {"displayName": [], "mail": [], "manager": [], "memberOf": ["memberOf"], ' \
                   '"name": ["Guest"], "sAMAccountName": ["Guest"], "userAccountControl": []}, "dn": "test_dn"}'

    class ConnectionMocker:
        entries = [EntryMocker()]
        result = {'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': b'<cookie>'}}}}

        def search(self, *args, **kwargs):
            time.sleep(1)

    expected_results = {'ContentsFormat': 'json',
                        'Type': 1,
                        'Contents': [{'attributes': {'displayName': [], 'mail': [], 'manager': [],
                                                     'memberOf': ['memberOf'], 'name': ['Guest'],
                                                     'sAMAccountName': ['Guest'],
                                                     'userAccountControl': []}, 'dn': 'test_dn'}],
                        'ReadableContentsFormat': 'markdown',
                        'HumanReadable': '### Active Directory - Get Users\n|displayName|dn|mail|manager|memberOf|name'
                                         '|sAMAccountName|userAccountControl|\n|---|---|---|---|---|---|---|---|\n|  |'
                                         ' test_dn |  |  | memberOf | Guest | Guest |  |\n',
                        'EntryContext': {'ActiveDirectory.Users(obj.dn == val.dn)': [{'dn': 'test_dn',
                                                                                      'displayName': [], 'mail': [],
                                                                                      'manager': [],
                                                                                      'memberOf': ['memberOf'],
                                                                                      'name': ['Guest'],
                                                                                      'sAMAccountName': ['Guest'],
                                                                                      'userAccountControl': []}],
                                         'Account(obj.ID == val.ID)': [{'Type': 'AD', 'ID': 'test_dn', 'Email': [],
                                                                        'Username': ['Guest'], 'DisplayName': [],
                                                                        'Managr': [], 'Manager': [],
                                                                        'Groups': ['memberOf']}],
                                         'ActiveDirectory(true)':
                                             {'UsersPageCookie': base64.b64encode(b'<cookie>').decode('utf-8')}}}

    expected_results = f'demisto results: {json.dumps(expected_results, indent=4, sort_keys=True)}'

    mocker.patch.object(demisto, 'args', return_value={'page-size': '1'})

    Active_Directory_Query.connection = ConnectionMocker()

    with patch('logging.Logger.info') as mock:
        Active_Directory_Query.search_users('dc', 1)
        mock.assert_called_with(expected_results)


def test_test_credentials_command(mocker):
    """
    Given:
        A demisto args object with username and password
    When:
        Run the 'ad-test-credentials' command
    Then:
        The result returns with successful connection
    """
    import Active_Directory_Query
    args = {'username': 'username_test_credentials', 'password': 'password_test_credentials'}
    mocker.patch.object(demisto, 'args', return_value=args)

    class MockConnection:
        def unbind(self):
            pass

    def mock_create_connection(server, server_ip, username, password, ntlm_connection, auto_bind):
        return MockConnection()

    with patch("Active_Directory_Query.create_connection", side_effect=mock_create_connection), \
            patch("Active_Directory_Query.Connection.unbind", side_effect=MockConnection.unbind):
        command_results = Active_Directory_Query.test_credentials_command(
            BASE_TEST_PARAMS['server_ip'], "server", ntlm_connection='true', auto_bind="auto_bind")
        assert command_results.readable_output == 'Credential test with username username_test_credentials succeeded.'


@pytest.mark.parametrize('dn,expected', [
    ('CN=name, lastname,OU=Test1,DC=dc1,DC=dc2', 'CN=name, lastname'),
    ('CN=name\\ lastname,OU=Test1,DC=dc1,DC=dc2', 'CN=name lastname'),
    ('CN=name,DC=dc1,DC=dc2', 'CN=name')])
def test_modify_user_ou(mocker, dn, expected):
    """
       Given:
            - user with CN contains //
            - user with CN contains comma
            - user without ou
       When:
           Run the 'ad-modify-ou' command
       Then:
            Validate the cn extracted as expected
       """
    import Active_Directory_Query

    class MockConnection:
        def modify_dn(self, dn, cn, new_superior):
            pass

    Active_Directory_Query.connection = MockConnection()
    new_ou = 'OU=Test2'
    connection_mocker = mocker.patch.object(Active_Directory_Query.connection, 'modify_dn', return_value=True)
    Active_Directory_Query.modify_user_ou(dn, new_ou)
    assert connection_mocker.call_args[0][1] == expected


def test_search_users_with_msDSUserAccountControlComputed(mocker):
    """
    Given:
        The 'msDSUserAccountControlComputed' was returned.
    When:
        Run the 'ad-get-user' command
    Then:
        The user_account_to_boolean_fields_msDS_user_account_control_computed was called.
    """

    import Active_Directory_Query

    class EntryMocker:
        def entry_to_json(self):
            return (
                '{"attributes": {"displayName": [], "mail": [], "manager": [], "memberOf": ["memberOf"], '
                '"name": ["Guest"], "sAMAccountName": ["Guest"], "userAccountControl": [0], \
                   "msDS-User-Account-Control-Computed": [0]},"dn": "test_dn"}'
            )

    class ConnectionMocker:
        entries = [EntryMocker()]
        result = {"controls": {"": {"value": {"cookie": b"<cookie>"}}}}

        def search(self, *args, **kwargs):
            time.sleep(1)

    mocker.patch.object(demisto, "args", return_value={"page-size": "1"})
    mocker.patch.object(demisto, "results")
    mocker_msDSUserAccountControlComputed = mocker.patch.object(
        Active_Directory_Query,
        "user_account_to_boolean_fields_msDS_user_account_control_computed",
        return_value={"PASSWORD_EXPIRED": True, "LOCKOUT": True},
    )

    Active_Directory_Query.connection = ConnectionMocker()

    Active_Directory_Query.search_users("dc", 1)
    mocker_msDSUserAccountControlComputed.assert_called_once()
    assert "msDS-User-Account-Control-Computed" in demisto.results.call_args[0][0][
        "Contents"
    ][0].get("attributes")
    assert (
        demisto.results.call_args[0][0]["EntryContext"]
        .get("ActiveDirectory.Users(obj.dn == val.dn)", {})[0]
        .get("userAccountControlFields")
        .get("PASSWORD_EXPIRED") is True
    )

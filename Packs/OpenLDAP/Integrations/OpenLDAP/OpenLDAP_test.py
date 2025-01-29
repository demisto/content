"""
Tests module for the LDAP Authentication integration
"""
from unittest.mock import MagicMock, patch
import unittest
import json

import pytest
from OpenLDAP import LdapClient, entries_paged_search


class Entry:
    def __init__(self):
        self.value = 'OpenLDAProotDSE'


class Connection:

    def __init__(self, vendor):
        if vendor == OPENLDAP:
            self.entries = [{'objectClass': Entry()}]
        else:
            self.entries = [{}]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @staticmethod
    def search(search_base, search_filter, search_scope, attributes):
        return None


OPENLDAP = 'OpenLDAP'
ACTIVE_DIRECTORY = 'Active Directory'


class TestLDAPClient:
    @pytest.mark.parametrize('vendor', [OPENLDAP, ACTIVE_DIRECTORY])
    def test_ldap_vendor(self, mocker, vendor):
        mocker.patch('OpenLDAP.Connection', return_value=Connection(vendor))
        client = LdapClient({'ldap_server_vendor': 'Auto', 'host': 'server_ip'})
        assert client._ldap_server_vendor == vendor


class TestsActiveDirectory:
    """
        Contains unit tests for functions that deal with Active directory server only.
    """

    def test_parse_ldap_group_entries_and_referrals(self):
        """
            Given:
                - A raw response of a groups paged search in an Active directory server
                (received during the execution of ad-groups command).
            When:
                - Running the 'parse_ldap_group_entries_and_referrals()' function.
            Then:
                - Verify that the raw response parsed correctly and that the referrals and entries lists
                  returned as expected.
        """
        client = LdapClient({'ldap_server_vendor': 'Active Directory', 'host': 'server_ip'})

        ldap_group_entries = [
            {'uri': ['ldap://domain1/CN=test,DC=demisto,DC=test'], 'type': 'searchResRef'},
            {'uri': ['ldap://domain2/DC=test,DC=demisto,DC=test'], 'type': 'searchResRef'},
            {'raw_dn': b'CN=test,CN=Users,DC=demisto,DC=test', 'dn': 'CN=test,CN=Users,DC=demisto,DC=test',
             'raw_attributes': {'primaryGroupToken': [b'11111']}, 'attributes': {'primaryGroupToken': 11111},
             'type': 'searchResEntry'},
            {'raw_dn': b'CN=DisabledUsers,DC=demisto,DC=test', 'dn': 'CN=DisabledUsers,DC=demisto,DC=test',
             'raw_attributes': {'primaryGroupToken': [b'22222']}, 'attributes': {'primaryGroupToken': 22222},
             'type': 'searchResEntry'}]

        expected_referrals = ['ldap://domain1/CN=test,DC=demisto,DC=test', 'ldap://domain2/DC=test,DC=demisto,DC=test']
        expected_entries = [{'DN': 'CN=test,CN=Users,DC=demisto,DC=test',
                             'Attributes': [{'Name': 'primaryGroupToken', 'Values': ['11111']}]},
                            {'DN': 'CN=DisabledUsers,DC=demisto,DC=test',
                             'Attributes': [{'Name': 'primaryGroupToken', 'Values': ['22222']}]}]

        referrals, entries = client._parse_ldap_group_entries_and_referrals(ldap_group_entries)

        assert referrals == expected_referrals
        assert entries == expected_entries

    def test_parse_and_authenticate_ldap_group_entries_and_referrals(self, mocker):
        """
            Given:
                - A raw response of a user paged search in an Active directory server.
                (received during the execution of ad-authenticate-and-roles command).
            When:
                - Running the 'parse_and_authenticate_ldap_group_entries_and_referrals()' function.
            Then:
                - Verify that the raw response parsed correctly and that the referrals and entries lists
                  returned as expected.
        """
        client = LdapClient({'ldap_server_vendor': 'Active Directory', 'host': 'server_ip'})

        password = '123456'

        ldap_group_entries = [
            {'uri': ['ldap://domain1/CN=test,DC=demisto,DC=test'], 'type': 'searchResRef'},
            {'uri': ['ldap://domain2/DC=test,DC=demisto,DC=test'], 'type': 'searchResRef'},
            {'raw_dn': b'CN=username,CN=Users,DC=demisto,DC=test', 'dn': 'CN=username,CN=Users,DC=demisto,DC=test',
             'raw_attributes': {'memberOf': [b'CN=test-group,CN=Users,DC=demisto,DC=test'],
                                'name': [b'username'], 'primaryGroupID': [b'111'], 'mail': [b'user@mail.com'],
                                'mobile': [b'050-1111111']},
             'attributes': {'memberOf': ['CN=test-group,CN=Users,DC=demisto,DC=test'], 'name': 'username',
                            'primaryGroupID': 111, 'mail': 'user@mail.com', 'mobile': '050-1111111'},
             'type': 'searchResEntry'}]

        expected_referrals = ['ldap://domain1/CN=test,DC=demisto,DC=test', 'ldap://domain2/DC=test,DC=demisto,DC=test']
        expected_entries = [
            {'DN': 'CN=username,CN=Users,DC=demisto,DC=test',
             'Attributes': [
                 {'Name': 'memberOf', 'Values': ['CN=test-group,CN=Users,DC=demisto,DC=test']},
                 {'Name': 'name', 'Values': ['username']},
                 {'Name': 'primaryGroupID', 'Values': ['111']},
                 {'Name': 'mail', 'Values': ['user@mail.com']},
                 {'Name': 'mobile', 'Values': ['050-1111111']}
             ]}]

        mocker.patch('OpenLDAP.LdapClient.authenticate_ldap_user', return_value='Done')
        referrals, entries = client._parse_and_authenticate_ldap_group_entries_and_referrals(ldap_group_entries,
                                                                                             password)

        assert referrals == expected_referrals
        assert entries == expected_entries

    @pytest.mark.parametrize('user_logon_name, expected_ad_username', [
        ('DEMISTO\\test1user', 'test1user'),
        ('test2user@demisto.ad', 'test2user'),
    ])
    def test_get_ad_username(self, user_logon_name, expected_ad_username):
        """
            Given:
                - A user logon name (a username to login to XSOAR with).
            When:
                - Running the 'get_ad_username()' function.
            Then:
                - Verify that the returned Active Directory username is as expected.
        """
        client = LdapClient({'ldap_server_vendor': 'Active Directory', 'host': 'server_ip'})

        ad_username = client._get_ad_username(user_logon_name)
        assert ad_username == expected_ad_username

    @pytest.mark.parametrize('connection_type, expected_auto_bind_value', [
        ('Start TLS', 'TLS_BEFORE_BIND'),
        ('SSL', 'NO_TLS'),
        ('None', 'NO_TLS')
    ])
    def test_get_auto_bind_value(self, connection_type, expected_auto_bind_value):
        """
            Given:
                - A connection type:
                    1. Start TLS
                    2. SSL
                    3. None
            When:
                - Running the '_get_auto_bind_value()' function.
            Then:
                - Verify that the returned auto_bind value is as expected:
                    1. 'TLS_BEFORE_BIND' - which means that connection should upgrade it's secure level to TLS before
                                           the bind itself (STARTTLS command is executed).
                    2. 'NO_TLS' - The connection is secured from the beginning,
                                  thus STARTTLS command shouldn't be executed.
                    3. 'NO_TLS' - Connection is insecure (cleartext) and shouldn't be upgraded to TLS.
        """
        client = LdapClient({'ldap_server_vendor': 'Active Directory', 'host': 'server_ip',
                             'connection_type': connection_type})

        auto_bind_value = client._get_auto_bind_value()
        assert auto_bind_value == expected_auto_bind_value


class TestsOpenLDAP:
    """
       Contains unit tests for functions that deal with OpenLDAP server only.
    """

    @pytest.mark.parametrize('dn, user_identifier_attribute, expected_result', [
        ('uid=user_test,cn=users_test,dc=openldap_test,dc=test,dc=int', 'uid', (True, 'user_test')),
        ('not_a_valid_dn_test', 'uid', (False, 'not_a_valid_dn_test'))
    ])
    def test_is_valid_dn(self, dn, user_identifier_attribute, expected_result):
        """
             Given:
                 - A DN and a user identifier attribute:
                   1. A valid DN.
                   2. Invalid DN.
             When:
                 - Running the '_is_valid_dn()' function.
             Then:
                 - Verify that the DN is parsed correctly and that the user returned as expected.
         """
        client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
                             'connection_type': 'SSL', 'user_identifier_attribute': user_identifier_attribute})

        actual_result, dn = client._is_valid_dn(dn, client.USER_IDENTIFIER_ATTRIBUTE)

        assert (actual_result, dn) == expected_result

    @pytest.mark.parametrize('dn, user_identifier_attribute', [
        ('cn=users_test,dc=openldap_test,dc=test,dc=int', 'uid'),
        ('uid=user_test,cn=users_test,dc=openldap_test,dc=test,dc=int', 'new_uid')
    ])
    def test_is_valid_dn_user_id_not_in_dn(self, dn, user_identifier_attribute):
        """
             Given:
                 1. A DN without a user identifier attribute.
                 2. A DN with a wrong user identifier attribute.
             When:
                 - Running the '_is_valid_dn()' function.
             Then:
                 - Verify that the expected err message is raised.
         """
        client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
                             'connection_type': 'SSL', 'user_identifier_attribute': user_identifier_attribute})

        with pytest.raises(Exception) as e:
            client._is_valid_dn(dn, client.USER_IDENTIFIER_ATTRIBUTE)
        assert e.value.args[0] == f'OpenLDAP {user_identifier_attribute} attribute was not found in user DN : {dn}'


class TestLDAPAuthentication:
    """
       Contains unit tests for general functions that deal with both OpenLDAP and Active Directory servers.
    """

    @pytest.mark.parametrize('ssl_version, expected_ssl_version', [
        ('TLS', 2), ('TLSv1', 3), ('TLSv1_1', 4), ('TLSv1_2', 5), ('TLS_CLIENT', 16), (None, None), ('None', None)
    ])
    def test_get_ssl_version(self, ssl_version, expected_ssl_version):
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
                - Running the '_get_ssl_version()' function.
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
        client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
                             'connection_type': 'SSL', 'ssl_version': ssl_version})

        ssl_version_value = client._get_ssl_version()
        assert ssl_version_value == expected_ssl_version

    @pytest.mark.parametrize('custom_attributes, expected_formatted_attributes', [
        ('attr1=val1,attr2=val2,attr3=val3', '(attr1=val1)(attr2=val2)(attr3=val3)'),
        ('', '')
    ])
    def test_get_formatted_custom_attributes(self, custom_attributes, expected_formatted_attributes):
        """
             Given:
                 - Custom attributes:
                   1. A valid comma separated list of attributes.
                   2. An empty string of attributes.
             When:
                 - Running the '_get_formatted_custom_attributes()' function.
             Then:
                 - Verify that the attributed parsed correctly.
         """
        client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
                             'connection_type': 'SSL', 'custom_attributes': custom_attributes})

        formatted_attributes = client._get_formatted_custom_attributes()
        assert formatted_attributes == expected_formatted_attributes

    def test_get_formatted_custom_attributes_invalid_attributes_input(self):
        """
             Given:
                 - Invalid Custom attributes.
             When:
                 - Running the '_get_formatted_custom_attributes()' function.
             Then:
                 - Verify that the expected error message is raised.
         """
        client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
                             'connection_type': 'SSL', 'custom_attributes': 'attr1val1,attr2=val2,attr3=val3'})

        with pytest.raises(Exception) as e:
            client._get_formatted_custom_attributes()
        assert e.value.args[0] == (f'User defined attributes must be of the form "attrA=valA,attrB=valB,...", but got: '
                                   f'{client.CUSTOM_ATTRIBUTE}')

    @pytest.mark.parametrize('user_logon_name', [
        ('test*'),
        ('test?test'),
    ])
    def test_has_wildcards_in_user_logon(self, user_logon_name):
        """
            Given:
                1. A user logon name contains the "*" symbol.
                2. A user logon name contains the "?" symbol.
            When:
                - Running the 'has_wildcards_in_user_logon()' function.
            Then:
                - Verify that an exception is raised due to the use of wildcards in the logon name.
        """
        client = LdapClient({'ldap_server_vendor': 'Active Directory', 'host': 'server_ip'})

        with pytest.raises(Exception) as e:
            client._has_wildcards_in_user_logon(user_logon_name)
        assert 'Wildcards were detected in the user logon name' in e.value.args[0]
        assert user_logon_name in e.value.args[0]


class TestEntriesPagedSearch(unittest.TestCase):

    def setUp(self):
        """
        Set up the test by creating a mock connection and search parameters.
        """
        self.connection = MagicMock()
        self.search_params = {'search_base': 'dc=example,dc=com', 'search_filter': '(objectClass=person)'}
        self.page_size = 10

    def test_first_page(self):
        """
        when running the entries_paged_search function with a page number of 1 then the search method should be called with
        the correct parameters and the results should be returned.
        """
        self.connection.search.return_value = [{'name': 'John Doe'}]

        results = entries_paged_search(self.connection, self.search_params, page=1, page_size=self.page_size)

        self.connection.search.assert_called_once_with(**self.search_params, paged_size=self.page_size)
        assert results == [{'name': 'John Doe'}]

    def test_subsequent_page(self):
        """
        when running the entries_paged_search function with a page number greater than 1 then the search method should be called
        with the correct parameters and the results should be returned. The search method should be called twice, once to skip
        the results and once to get the actual results.
        """
        # Mock the connection's search method for the first search (to skip results)
        self.connection.search.side_effect = [
            None,  # First call returns None to simulate the skip search
            [{'name': 'Jane Doe'}]  # Second call returns the actual results
        ]
        # Mock the result of the first search to include the cookie
        self.connection.result = {
            'controls': {
                '1.2.840.113556.1.4.319': {
                    'value': {
                        'cookie': b'cookie_value'
                    }
                }
            }
        }

        results = entries_paged_search(self.connection, self.search_params, page=2, page_size=self.page_size)

        # Assert the search method was called twice with the correct parameters
        assert self.connection.search.call_count == 2
        self.connection.search.assert_any_call(**self.search_params, paged_size=self.page_size * 1)
        self.connection.search.assert_any_call(**self.search_params, paged_size=self.page_size, paged_cookie=b'cookie_value')
        assert results == [{'name': 'Jane Doe'}]


class TestEntriesSearchCommand(unittest.TestCase):
    """
    Test class for the entries_search_command function.
    """

    def setUp(self):
        """
        Set up the test by creating an instance of the LdapClient class and mocking the _get_auto_bind_value method.
        """
        self.instance = LdapClient({
            'host': 'server_ip',
            'port': '636',
            'credentials': {'identifier': 'username', 'password': 'password'},
            'base_dn': 'dc=example,dc=com',
            'connection_type': 'SSL',
            'ssl_version': 'TLSv1_2',
            'fetch_groups': True,
            'insecure': False,
            'ldap_server_vendor': 'OpenLDAP',
        })

        self.instance._get_auto_bind_value = MagicMock(return_value=True)

    @patch('OpenLDAP.Connection')
    @patch('OpenLDAP.create_entries_search_filter', return_value='(objectClass=*)')
    @patch('OpenLDAP.get_search_attributes', return_value=['cn', 'mail'])
    def test_entries_search_command_first_page(self, mock_get_search_attributes, mock_create_entries_search_filter,
                                               mock_connection):
        """
        when running the entries_search_command function with a page number of 1 then the search method should be called with
        the correct parameters and the results should be returned.
        """
        # Mock the LDAP connection
        mock_conn_instance = mock_connection.return_value.__enter__.return_value
        mock_conn_instance.entries = [MagicMock(entry_to_json=MagicMock(return_value=json.dumps({
            'attributes': {'cn': ['John Doe'], 'mail': ['john.doe@example.com']},
            'dn': 'cn=John Doe,dc=example,dc=com'
        })))]

        args = {
            'search_base': 'dc=example,dc=com',
            'search_scope': 'SUBTREE',
            'page': '1',
            'page_size': '50'
        }

        result = self.instance.entries_search_command(args)

        self.instance._get_auto_bind_value.assert_called_once()
        mock_create_entries_search_filter.assert_called_once_with(args)
        mock_get_search_attributes.assert_called_once_with('all')
        mock_connection.assert_called_once_with(
            self.instance._ldap_server, self.instance._username, self.instance._password, auto_bind=True)

        assert len(result.outputs) == 1
        assert result.outputs[0]['cn'] == ['John Doe']
        assert result.outputs[0]['mail'] == ['john.doe@example.com']
        assert result.outputs[0]['dn'] == 'cn=John Doe,dc=example,dc=com'

    @patch('OpenLDAP.Connection')
    @patch('OpenLDAP.create_entries_search_filter', return_value='(objectClass=*)')
    @patch('OpenLDAP.get_search_attributes', return_value=['cn', 'mail'])
    def test_entries_search_command_subsequent_page(self, mock_get_search_attributes, mock_create_entries_search_filter,
                                                    mock_connection):
        """
        when running the entries_search_command function with a page number greater than 1 then the search method should be
        called with the correct parameters and the results should be returned. The search method should be called twice, once
        to skip the results and once to get the actual results.
        """
        # Mock the LDAP connection
        mock_conn_instance = mock_connection.return_value.__enter__.return_value
        mock_conn_instance.entries = [MagicMock(entry_to_json=MagicMock(return_value=json.dumps({
            'attributes': {'cn': ['Jane Doe'], 'mail': ['jane.doe@example.com']},
            'dn': 'cn=Jane Doe,dc=example,dc=com'
        })))]

        args = {
            'search_base': 'dc=example,dc=com',
            'search_scope': 'SUBTREE',
            'page': '2',
            'page_size': '50'
        }

        result = self.instance.entries_search_command(args)

        self.instance._get_auto_bind_value.assert_called_once()
        mock_create_entries_search_filter.assert_called_once_with(args)
        mock_get_search_attributes.assert_called_once_with('all')
        mock_connection.assert_called_once_with(
            self.instance._ldap_server, self.instance._username, self.instance._password, auto_bind=True)

        assert len(result.outputs) == 1
        assert result.outputs[0]['cn'] == ['Jane Doe']
        assert result.outputs[0]['mail'] == ['jane.doe@example.com']
        assert result.outputs[0]['dn'] == 'cn=Jane Doe,dc=example,dc=com'

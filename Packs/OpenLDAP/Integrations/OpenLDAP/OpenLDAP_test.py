"""
Tests module for the LDAP Authentication integration
"""
import pytest
from OpenLDAP import LdapClient


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

    # def test_get_user_data(self):
    #     client = LdapClient({'ldap_server_vendor': 'OpenLDAP', 'host': 'server_ip',
    #                          'connection_type': 'SSL', 'user_identifier_attribute': 'uid'})
    #
    #     mocker.patch('OpenLDAP.LdapClient.search_user_data', return_value=)


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

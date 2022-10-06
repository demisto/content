"""
Tests module for the LDAP Authentication integration
"""
import pytest
from OpenLDAP import LdapClient


class TestsActiveDirectory:
    """
        Contains unit tests for functions that deal with Active directory server.
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
       Contains unit tests for functions that deal with OpenLDAP server.
    """

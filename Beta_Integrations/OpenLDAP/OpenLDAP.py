import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from ldap3 import Server, Connection, Tls, BASE
from ldap3.utils.dn import parse_dn
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidDnError, LDAPSocketOpenError, LDAPInvalidPortError
from ssl import CERT_REQUIRED

''' OpenLDAP CLIENT '''


class LdapClient:
    GROUPS_TOKEN = 'primaryGroupToken'
    GROUPS_MEMBER = 'memberOf'
    GROUPS_PRIMARY_ID = 'primaryGroupID'
    TIMEOUT = 120
    DEV_BUILD_NUMBER = 'REPLACE_THIS_WITH_CI_BUILD_NUM'
    SUPPORTED_BUILD_NUMBER = 57352

    def __init__(self, kwargs):
        self._host = kwargs.get('host')
        self._port = int(kwargs.get('port')) if kwargs.get('port') else None
        self._username = kwargs.get('credentials', {}).get('identifier', '')
        self._password = kwargs.get('credentials', {}).get('password', '')
        self._base_dn = kwargs.get('base_dn', '').strip()
        self._connection_type = kwargs.get('connection_type', 'none').lower()
        self._fetch_groups = kwargs.get('fetch_groups', True)
        self._verify = not kwargs.get('insecure', False)
        self._ldap_server = self._initialize_ldap_server()
        self._page_size = int(kwargs.get('page_size', 500))
        self._groups_filter_class = kwargs.get('group_filter_class', 'posixGroup').strip()
        self._group_identifier_attribute = kwargs.get('group_identifier_attribute', 'gidNumber').strip()
        self._member_identifier_attribute = kwargs.get('member_identifier_attribute', 'memberUid').strip()
        self._user_filter_class = kwargs.get('user_filter_class', 'posixAccount')
        self._user_identifier_attribute = kwargs.get('user_identifier_attribute', 'uid')

    @property
    def GROUPS_OBJECT_CLASS(self):
        return self._groups_filter_class

    @property
    def GROUPS_IDENTIFIER_ATTRIBUTE(self):
        return self._group_identifier_attribute

    @property
    def GROUPS_MEMBERSHIP_IDENTIFIER_ATTRIBUTE(self):
        return self._member_identifier_attribute

    @property
    def USER_OBJECT_CLASS(self):
        return self._user_filter_class

    @property
    def USER_IDENTIFIER_ATTRIBUTE(self):
        return self._user_identifier_attribute

    def _initialize_ldap_server(self):
        if self._connection_type == 'ssl':
            # todo get ca certs file
            tls = Tls(validate=CERT_REQUIRED,
                      ca_certs_file=os.environ.get('SSL_CERT_FILE')) if self._verify else None

            return Server(host=self._host, port=self._port, use_ssl=True, tls=tls, connect_timeout=LdapClient.TIMEOUT)
        else:
            return Server(host=self._host, port=self._port, connect_timeout=LdapClient.TIMEOUT)

    @staticmethod
    def _parse_ldap_group_entries(ldap_group_entries, groups_identifier_attribute):
        return [{'DN': ldap_group.get('dn'), 'Attributes': [{'Name': LdapClient.GROUPS_TOKEN,
                                                             'Values': [str(ldap_group.get('attributes', {}).get(
                                                                 groups_identifier_attribute))]}]}
                for ldap_group in ldap_group_entries]

    @staticmethod
    def _parse_ldap_users_groups_entries(ldap_group_entries):
        return [ldap_group.get('dn') for ldap_group in ldap_group_entries]

    @staticmethod
    def _build_entry_for_user(user_groups, user_data, mail_attribute, name_attribute):
        parsed_ldap_groups = {'Name': LdapClient.GROUPS_MEMBER, 'Values': user_groups}
        parsed_group_id = {'Name': LdapClient.GROUPS_PRIMARY_ID, 'Values': user_data['gid_number']}
        attributes = [parsed_ldap_groups, parsed_group_id]

        if 'name' in user_data:
            attributes.append({'Name': name_attribute, 'Values': [user_data['name']]})
        if 'email' in user_data:
            attributes.append({'Name': name_attribute, 'Values': [user_data['email']]})

        return {
            'DN': user_data['dn'],
            'Attributes': attributes
        }

    @staticmethod
    def _is_valid_dn(dn, user_identifier_attribute):
        try:
            parsed_dn = parse_dn(dn, strip=False)
            for attribute_and_value in parsed_dn:
                if attribute_and_value[0].lower() == user_identifier_attribute.lower():
                    return True, attribute_and_value[1]

            raise Exception(f'OpenLDAP {user_identifier_attribute} attribute was not found in user DN : {dn}')
        except LDAPInvalidDnError as e:
            demisto.debug(f'OpenLDAP failed parsing DN with error: {str(e)}. Fallback for unique id activated')
            return False, dn
        except Exception:
            raise

    def _fetch_all_groups(self):
        with Connection(self._ldap_server, self._username, self._password) as ldap_conn:
            search_filter = f'(objectClass={self.GROUPS_OBJECT_CLASS})'
            ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                        search_filter=search_filter,
                                                                        attributes=[self.GROUPS_IDENTIFIER_ATTRIBUTE],
                                                                        paged_size=self._page_size)

            return {
                'Controls': None,
                'Referrals': ldap_conn.result.get('referrals'),
                'Entries': LdapClient._parse_ldap_group_entries(ldap_group_entries, self.GROUPS_IDENTIFIER_ATTRIBUTE)
            }

    def _fetch_specific_groups(self, specific_groups):
        dn_list = [group.strip() for group in argToList(specific_groups, separator="#")]
        with Connection(self._ldap_server, self._username, self._password) as ldap_conn:
            parsed_ldap_entries = []

            for dn in dn_list:
                search_filter = f'(objectClass={self.GROUPS_OBJECT_CLASS})'
                ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=dn,
                                                                            search_filter=search_filter,
                                                                            attributes=[
                                                                                self.GROUPS_IDENTIFIER_ATTRIBUTE],
                                                                            paged_size=self._page_size,
                                                                            search_scope=BASE)
                parsed_ldap_entries.append(
                    self._parse_ldap_group_entries(ldap_group_entries, self.GROUPS_IDENTIFIER_ATTRIBUTE))

            return {
                'Controls': None,
                'Referrals': ldap_conn.result.get('referrals'),
                'Entries': parsed_ldap_entries
            }

    def get_ldap_groups(self, specific_group=None):
        instance_name = demisto.integrationInstance()  # noqa # pylint: disable no-member # type: ignore
        if not self._fetch_groups and not specific_group:
            demisto.info(f'Instance [{instance_name}] configured not to fetch groups')
            sys.exit()

        searched_results = self._fetch_specific_groups(
            specific_group) if not self._fetch_groups else self._fetch_all_groups()
        demisto.info(f'Retrieved {len(searched_results["Entries"])} groups from OpenLDAP {instance_name}')

        return searched_results

    def authenticate_ldap_user(self, username, password):
        ldap_conn = Connection(server=self._ldap_server, user=username, password=password, auto_bind=True)

        if ldap_conn.bound:
            ldap_conn.unbind()
            return "Done"
        else:
            raise Exception("OpenLDAP authentication connection failed")

    def get_user_data(self, username, pull_name, pull_mail, name_attribute, mail_attribute, search_user_by_dn=False):
        with Connection(self._ldap_server, self._username, self._password) as ldap_conn:
            attributes = [self.GROUPS_IDENTIFIER_ATTRIBUTE]

            if pull_name:
                attributes.append(name_attribute)
            if pull_mail:
                attributes.append(mail_attribute)

            if search_user_by_dn:
                search_filter = f'(objectClass={self.USER_OBJECT_CLASS})'
                ldap_conn.search(search_base=username, search_filter=search_filter, size_limit=1,
                                 attributes=attributes, search_scope=BASE)
            else:
                search_filter = (f'(&(objectClass={self.USER_OBJECT_CLASS})'
                                 f'({self.USER_IDENTIFIER_ATTRIBUTE}={username}))')
                ldap_conn.search(search_base=self._base_dn, search_filter=search_filter, size_limit=1,
                                 attributes=attributes)

            if not ldap_conn.entries:
                raise Exception("OpenLDAP user not found")
            entry = ldap_conn.entries[0]

            if self.GROUPS_IDENTIFIER_ATTRIBUTE not in entry \
                    or not entry[self.GROUPS_IDENTIFIER_ATTRIBUTE].value:
                raise Exception(f"OpenLDAP user's {self.GROUPS_IDENTIFIER_ATTRIBUTE} not found")

            user_data = {'dn': entry.entry_dn, 'gid_number': [str(entry[self.GROUPS_IDENTIFIER_ATTRIBUTE].value)],
                         'referrals': ldap_conn.result.get('referrals')}

            if name_attribute in entry and entry[name_attribute].value:
                user_data['name'] = ldap_conn.entries[0][name_attribute].value
            if mail_attribute in entry and entry[mail_attribute].value:
                user_data['email'] = ldap_conn.entries[0][mail_attribute].value

            return user_data

    def get_user_groups(self, user_identifier):
        with Connection(self._ldap_server, self._username, self._password) as ldap_conn:
            search_filter = (f'(&(objectClass={self.GROUPS_OBJECT_CLASS})'
                             f'({self.GROUPS_MEMBERSHIP_IDENTIFIER_ATTRIBUTE}={user_identifier}))')
            ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                        search_filter=search_filter,
                                                                        attributes=[
                                                                            self.GROUPS_IDENTIFIER_ATTRIBUTE],
                                                                        paged_size=self._page_size)
            return LdapClient._parse_ldap_users_groups_entries(ldap_group_entries)

    def authenticate_and_roles(self, username, password, pull_name=True, pull_mail=True, mail_attribute='mail',
                               name_attribute='name'):
        search_user_by_dn, user_identifier = LdapClient._is_valid_dn(username, self.USER_IDENTIFIER_ATTRIBUTE)
        user_data = self.get_user_data(username=username, search_user_by_dn=search_user_by_dn, pull_name=pull_name,
                                       pull_mail=pull_mail, mail_attribute=mail_attribute,
                                       name_attribute=name_attribute)
        self.authenticate_ldap_user(user_data['dn'], password)
        user_groups = self.get_user_groups(user_identifier)

        return {
            'Controls': None,
            'Referrals': user_data['referrals'],
            'Entries': [LdapClient._build_entry_for_user(user_groups=user_groups, user_data=user_data,
                                                         mail_attribute=mail_attribute, name_attribute=name_attribute)]
        }

    def test_module(self):
        build_number = get_demisto_version().get('buildNumber', LdapClient.DEV_BUILD_NUMBER)

        if build_number != LdapClient.DEV_BUILD_NUMBER \
                and LdapClient.SUPPORTED_BUILD_NUMBER > int(build_number):
            raise Exception(f'OpenLDAP integration is supported from build number: {LdapClient.SUPPORTED_BUILD_NUMBER}')

        try:
            parse_dn(self._username)
        except LDAPInvalidDnError:
            raise Exception("Invalid credentials input. Credentials must be full DN.")
        self.authenticate_ldap_user(username=self._username, password=self._password)
        demisto.results('ok')


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    LOG(f'Command being called is {command}')
    try:
        # initialized OpenLDAP client
        client = LdapClient(params)

        if command == 'test-module':
            client.test_module()
        elif command == 'ad-authenticate':
            username = args.get('username')
            password = args.get('password')
            authentication_result = client.authenticate_ldap_user(username, password)
            demisto.results(authentication_result)
        elif command == 'ad-groups':
            specific_group = args.get('specific-groups')
            searched_results = client.get_ldap_groups(specific_group)
            demisto.results(searched_results)
        elif command == 'ad-authenticate-and-roles':
            username = args.get('username')
            password = args.get('password')
            mail_attribute = args.get('attribute-mail', 'mail')
            name_attribute = args.get('attribute-name', 'name')
            pull_name = args.get('attribute-name-pull', True)
            pull_mail = args.get('attribute-mail-pull', True)
            entry_result = client.authenticate_and_roles(username=username, password=password, pull_name=pull_name,
                                                         pull_mail=pull_mail, mail_attribute=mail_attribute,
                                                         name_attribute=name_attribute)
            demisto.results(entry_result)

    # Log exceptions
    except Exception as e:
        msg = str(e)
        if isinstance(e, LDAPBindError):
            msg = f'OpenLDAP authentication connection failed. Additional details: {msg}'
        elif isinstance(e, LDAPSocketOpenError):
            msg = f'Failed to connect to OpenLDAP server. Additional details: {msg}'
        elif isinstance(e, LDAPInvalidPortError):
            msg = f'Not valid ldap server input. Check that server input is of form: ip or ldap://ip'
        return_error(str(msg))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

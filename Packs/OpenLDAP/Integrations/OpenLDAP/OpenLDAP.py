import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import ssl
from ldap3 import Server, Connection, Tls, BASE, AUTO_BIND_TLS_BEFORE_BIND, AUTO_BIND_NO_TLS, ALL_ATTRIBUTES, SUBTREE, \
    ALL_OPERATIONAL_ATTRIBUTES
from ldap3.utils.dn import parse_dn
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidDnError, LDAPSocketOpenError, LDAPInvalidPortError, \
    LDAPSocketReceiveError, LDAPStartTLSError

'''CONSTANTS'''

MAX_PAGE_SIZE = 2000

''' LDAP Authentication CLIENT '''


def listArgToLdapFilterSyntax(arg: str, prefix: str) -> str:
    """
    Converts a list argument to an LDAP filter syntax.
    Args:
        arg (str): The argument to convert.
        prefix (str): The prefix to use in the filter syntax.
    Returns:
        str: The LDAP filter syntax.
    """
    arg_list = argToList(arg)
    joined_list = ''.join([f'({prefix}={item})' for item in arg_list])
    if len(arg_list) > 1:
        return f'(&{joined_list})'
    return joined_list if arg_list else ''


def create_entries_search_filter(args: dict) -> str:
    """
    Creates the search filter according to the user's selection. Merges all the search filters into one filter.
    Args:
        args (dict): The command arguments.
    Returns:
        str: The search filter.
    """
    cn_filter = listArgToLdapFilterSyntax(args.get('cn', ''), 'cn')
    description_filter = listArgToLdapFilterSyntax(args.get('description', ''), 'description')
    object_class = listArgToLdapFilterSyntax(args.get('object_class', ''), 'objectClass')
    uid = listArgToLdapFilterSyntax(args.get('uid', ''), 'uid')
    search_filter = args.get('search_filter', '')
    if not any([cn_filter, description_filter, object_class, uid, search_filter]):
        return '(objectClass=*)'
    return f'(|{cn_filter}{description_filter}{object_class}{uid}{search_filter})'


def get_search_attributes(attributes: str) -> Optional[list[str] | str]:
    """
    Returns the search attributes according to the user's selection.
    Args:
        attributes (str): The attributes to search for.
    Returns:
        list[str] | str: The search attributes.
    """
    if attributes == 'all':
        return [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
    return {
        'none': None,
        'all_user_attributes': ALL_ATTRIBUTES,
        'all_operational_attributes': ALL_OPERATIONAL_ATTRIBUTES

    }.get(attributes, argToList(attributes))


def entries_paged_search(connection: Connection, search_params: dict, page: int, page_size: int) -> list[dict]:
    """
    preforms search on the ldap server with the given page and page size parameters.
    Args:
        connection (Connection): Connection object
        search_params (dict): search parameters
        page (int): page number
        page_size (int): page size
    Returns:
        list[dict]: search results
    """
    if page == 1:
        return connection.search(**search_params, paged_size=page_size)

    results_to_skip = page_size * (page - 1)
    connection.search(**search_params, paged_size=results_to_skip)
    # After the first search you must send back the cookie you get with each response in each subsequent search.
    # https://ldap3.readthedocs.io/en/latest/searches.html#simple-paged-search
    cookie = connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
    return connection.search(**search_params, paged_size=page_size, paged_cookie=cookie)


class LdapClient:
    """
        Base client for Ldap authentication.

        :type kwargs: ``dict``
        :param kwargs: Initialize params for ldap client
    """

    OPENLDAP = 'OpenLDAP'
    ACTIVE_DIRECTORY = 'Active Directory'
    AUTO = 'Auto'
    GROUPS_TOKEN = 'primaryGroupToken'
    GROUPS_MEMBER = 'memberOf'
    GROUPS_PRIMARY_ID = 'primaryGroupID'
    TIMEOUT = 120  # timeout for ssl/tls socket
    DEV_BUILD_NUMBER = 'REPLACE_THIS_WITH_CI_BUILD_NUM'  # is used only in dev mode
    SUPPORTED_BUILD_NUMBER = 57352  # required server build number
    CIPHERS_STRING = '@SECLEVEL=1:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:' \
                     'ECDH+AES:DH+AES:RSA+ANESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS'  # Allowed ciphers for SSL/TLS
    SSL_VERSIONS = {
        'None': None,
        'TLS': ssl.PROTOCOL_TLS,
        'TLSv1': ssl.PROTOCOL_TLSv1,  # guardrails-disable-line
        'TLSv1_1': ssl.PROTOCOL_TLSv1_1,  # guardrails-disable-line
        'TLSv1_2': ssl.PROTOCOL_TLSv1_2,
        'TLS_CLIENT': ssl.PROTOCOL_TLS_CLIENT
    }

    def __init__(self, kwargs):
        self._host = kwargs.get('host')
        self._port = int(kwargs.get('port')) if kwargs.get('port') else None
        self._username = kwargs.get('credentials', {}).get('identifier', '')
        self._password = kwargs.get('credentials', {}).get('password', '')
        self._base_dn = kwargs.get('base_dn', '').strip()
        self._connection_type = kwargs.get('connection_type', 'none').lower()
        self._ssl_version = kwargs.get('ssl_version', 'None')
        self._fetch_groups = kwargs.get('fetch_groups', True)
        self._verify = not kwargs.get('insecure', False)
        self._ldap_server = self._initialize_ldap_server()
        self._ldap_server_vendor = kwargs.get('ldap_server_vendor', self.AUTO)  # OpenLDAP or Active Directory
        if self._ldap_server_vendor == self.AUTO:
            self._determine_ldap_vendor_automatically()
        self._page_size = int(kwargs.get('page_size', 500))

        # OpenLDAP only fields:
        self._groups_filter_class = kwargs.get('group_filter_class', 'posixGroup').strip()
        self._group_identifier_attribute = kwargs.get('group_identifier_attribute', 'gidNumber').strip()
        self._member_identifier_attribute = kwargs.get('member_identifier_attribute', 'memberUid').strip()
        self._user_filter_class = kwargs.get('user_filter_class', 'posixAccount')
        self._user_identifier_attribute = kwargs.get('user_identifier_attribute', 'uid')
        self._custom_attributes = kwargs.get('custom_attributes', '')

    @property
    def GROUPS_OBJECT_CLASS(self):
        """
        :rtype: ``str``
        :return: Group's base class object name.
        """
        return self._groups_filter_class

    @property
    def GROUPS_IDENTIFIER_ATTRIBUTE(self):
        """
        :rtype: ``str``
        :return: Groups identifier attribute.
        """
        return self._group_identifier_attribute

    @property
    def GROUPS_MEMBERSHIP_IDENTIFIER_ATTRIBUTE(self):
        """
        :rtype: ``str``
        :return: Groups membership attribute.
        """
        return self._member_identifier_attribute

    @property
    def USER_OBJECT_CLASS(self):
        """
        :rtype: ``str``
        :return: User's base class object name.
        """
        return self._user_filter_class

    @property
    def USER_IDENTIFIER_ATTRIBUTE(self):
        """
        rtype: ``str``
        :return: Users identifier attribute.
        """
        return self._user_identifier_attribute

    @property
    def CUSTOM_ATTRIBUTE(self):
        """
        rtype: ``str``
        :return: User defined attributes.
        """
        return self._custom_attributes

    def _get_ssl_version(self):
        """
            Returns the ssl version object according to the user's selection.
        """
        version = self.SSL_VERSIONS.get(self._ssl_version)
        if version:
            demisto.info(f"SSL/TLS protocol version is {self._ssl_version} ({version}).")
        else:  # version is None
            demisto.info("SSL/TLS protocol version is None (the default value of the ldap3 Tls object).")

        return version

    def _get_tls_object(self):
        """
            Returns a TLS object according to the user's selection of the 'Trust any certificate' checkbox.
        """
        if self._verify:  # Trust any certificate is unchecked
            # Trust any certificate = False means that the LDAP server's certificate must be valid -
            # i.e if the server's certificate is not valid the connection will fail.
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get('SSL_CERT_FILE'),
                      version=self._get_ssl_version())

        else:  # Trust any certificate is checked
            # Trust any certificate = True means that we do not require validation of the LDAP server's certificate,
            # and allow the use of all possible ciphers.
            tls = Tls(validate=ssl.CERT_NONE, ca_certs_file=None, version=self._get_ssl_version(),
                      ciphers=self.CIPHERS_STRING)

        return tls

    def _initialize_ldap_server(self):
        """
        Initializes ldap server object with given parameters. Supports both encrypted and non encrypted connection.

        :rtype: ldap3.Server
        :return: Initialized ldap server object.
        """
        if self._connection_type == 'ssl':  # Secure connection (SSL\TLS)
            demisto.info(f"Initializing LDAP sever with SSL/TLS (unsecure: {not self._verify})."
                         f" port: {self._port or 'default(636)'}")
            tls = self._get_tls_object()
            server = Server(host=self._host, port=self._port, use_ssl=True, tls=tls, connect_timeout=LdapClient.TIMEOUT)

        elif self._connection_type == 'start tls':  # Secure connection (STARTTLS)
            demisto.info(f"Initializing LDAP sever without a secure connection - Start TLS operation will be executed"
                         f" during bind. (unsecure: {not self._verify}). port: {self._port or 'default(389)'}")
            tls = self._get_tls_object()
            server = Server(host=self._host, port=self._port, use_ssl=False, tls=tls, connect_timeout=LdapClient.TIMEOUT)

        else:  # Unsecure (non encrypted connection initialized) - connection type is None
            demisto.info(f"Initializing LDAP sever without a secure connection. port: {self._port or 'default(389)'}")
            server = Server(host=self._host, port=self._port, connect_timeout=LdapClient.TIMEOUT)

        return server

    def _determine_ldap_vendor_automatically(self):
        """
            Determines the LDAP vendor automatically
        """
        try:
            with Connection(self._ldap_server) as conn:
                conn.search(search_base='',
                            search_filter='(objectClass=*)',
                            search_scope=BASE,
                            attributes=[ALL_ATTRIBUTES])
                entry = conn.entries[0]
                if 'objectClass' in entry and 'OpenLDAProotDSE' in entry['objectClass'].value:
                    self._ldap_server_vendor = self.OPENLDAP
                else:
                    # There is no way to determine the AD vendor. As we support only 2 vendors,
                    # we can assume the AD vendor by saying that it is not OpenLDAP
                    self._ldap_server_vendor = self.ACTIVE_DIRECTORY
                demisto.info(f'Determining LDAP vendor is {self._ldap_server_vendor}')
        except Exception as e:
            raise DemistoException(f'Could not parse LDAP vendor automatically. Try to choose the vendor manually. '
                                   f'Error: str({e})')

    @staticmethod
    def _parse_ldap_group_entries(ldap_group_entries: list[dict], groups_identifier_attribute: str) -> list[dict]:
        """
            Returns parsed ldap groups entries.
        """
        return [{'DN': ldap_group.get('dn'), 'Attributes': [{'Name': LdapClient.GROUPS_TOKEN,
                                                             'Values': [str(ldap_group.get('attributes', {}).get(
                                                                 groups_identifier_attribute))]}]}
                for ldap_group in ldap_group_entries]

    @staticmethod
    def _parse_ldap_group_entries_and_referrals(ldap_group_entries: list[dict]) -> tuple[list[str], list[dict]]:
        """
            Returns parsed ldap groups entries and referrals.
        """
        referrals: list[str] = []
        entries: list[dict] = []

        for ldap_group in ldap_group_entries:
            if ldap_group_type := ldap_group.get('type'):
                if ldap_group_type == 'searchResRef':  # a referral
                    referrals.extend(ldap_group.get('uri') or [])

                elif ldap_group_type == 'searchResEntry':  # an entry
                    entries.append(
                        {'DN': ldap_group.get('dn'),
                         'Attributes': [{'Name': LdapClient.GROUPS_TOKEN,
                                         'Values': [str(ldap_group.get('attributes', {}).get(LdapClient.GROUPS_TOKEN))]}
                                        ]
                         })
        return referrals, entries

    def _parse_and_authenticate_ldap_group_entries_and_referrals(self, ldap_group_entries: list[dict],
                                                                 password: str) -> tuple[list[str], list[dict]]:
        """
            Returns parsed ldap groups entries and referrals.
            Authenticate - performs simple bind operation on the ldap server with the given user and password.
        """

        referrals: list[str] = []
        entries: list[dict] = []

        for entry in ldap_group_entries:
            if entry_type := entry.get('type'):
                if entry_type == 'searchResRef':  # a referral
                    referrals.extend(entry.get('uri') or [])

                elif entry_type == 'searchResEntry':  # an entry
                    # (should be only one searchResEntry to authenticate)
                    entry_dn = entry.get('dn', '')
                    entry_attributes = entry.get('attributes', {})
                    relevant_entry_attributes = []
                    for attr in entry_attributes:
                        if attr_value := entry_attributes.get(attr, []):
                            if not isinstance(attr_value, list):
                                attr_value = [str(attr_value)]  # handle numerical values
                            relevant_entry_attributes.append({'Name': attr, 'Values': attr_value})

                    entries.append({'DN': entry_dn, 'Attributes': relevant_entry_attributes})
                    self.authenticate_ldap_user(entry_dn, password)

        return referrals, entries

    @staticmethod
    def _parse_ldap_users_groups_entries(ldap_group_entries: list[dict]) -> list[Optional[Any]]:
        """
            Returns parsed user's group entries.
        """
        return [ldap_group.get('dn') for ldap_group in ldap_group_entries]

    @staticmethod
    def _build_entry_for_user(user_groups: str, user_data: dict,
                              mail_attribute: str, name_attribute: str, phone_attribute: str) -> dict:
        """
            Returns entry for specific ldap user.
        """
        parsed_ldap_groups = {'Name': LdapClient.GROUPS_MEMBER, 'Values': user_groups}
        parsed_group_id = {'Name': LdapClient.GROUPS_PRIMARY_ID, 'Values': user_data['gid_number']}
        attributes = [parsed_ldap_groups, parsed_group_id]

        if 'name' in user_data:
            attributes.append({'Name': name_attribute, 'Values': [user_data['name']]})
        if 'email' in user_data:
            attributes.append({'Name': mail_attribute, 'Values': [user_data['email']]})
        if 'mobile' in user_data:
            attributes.append({'Name': phone_attribute, 'Values': [user_data['mobile']]})

        return {
            'DN': user_data['dn'],
            'Attributes': attributes
        }

    @staticmethod
    def _is_valid_dn(dn: str, user_identifier_attribute: str) -> tuple[bool, str]:
        """
            Validates whether given input is valid ldap DN. Returns flag indicator and user's identifier value from DN
            (if exists).
        """
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
        """
            Fetches all ldap groups under given base DN.
        """
        auto_bind = self._get_auto_bind_value()
        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            demisto.info(f'LDAP Connection Details: {ldap_conn}')

            if self._ldap_server_vendor == self.ACTIVE_DIRECTORY:
                search_filter = '(&(objectClass=group)(objectCategory=group))'

                referrals, entries = self._get_ldap_groups_entries_and_referrals_ad(ldap_conn=ldap_conn,
                                                                                    search_filter=search_filter)

                return {
                    'Controls': None,
                    'Referrals': referrals,
                    'Entries': entries
                }

            else:  # ldap server is OpenLDAP
                search_filter = f'(objectClass={self.GROUPS_OBJECT_CLASS})'
                ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                            search_filter=search_filter,
                                                                            attributes=[
                                                                                self.GROUPS_IDENTIFIER_ATTRIBUTE],
                                                                            paged_size=self._page_size)

                return {
                    'Controls': None,
                    'Referrals': ldap_conn.result.get('referrals'),
                    'Entries': LdapClient._parse_ldap_group_entries(ldap_group_entries,
                                                                    self.GROUPS_IDENTIFIER_ATTRIBUTE)
                }

    def _get_formatted_custom_attributes(self) -> str:
        """
        :return: custom attributes parsed to the form (att_name1=value1)(attname2=value2)
        """
        if not self.CUSTOM_ATTRIBUTE:
            return ''
        formatted_attributes = ''
        for att in self.CUSTOM_ATTRIBUTE.split(','):
            if len(att.split('=')) != 2:
                raise Exception(f'User defined attributes must be of the form'
                                f' \"attrA=valA,attrB=valB,...\", but got: {self.CUSTOM_ATTRIBUTE}')
            formatted_attributes = formatted_attributes + f'({att})'
        return formatted_attributes

    def _get_ldap_groups_entries_and_referrals_ad(self, ldap_conn: Connection,
                                                  search_filter: str) -> tuple[list[str], list[dict]]:
        """
            Returns parsed ldap groups entries and referrals.
        """

        ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                    search_filter=search_filter,
                                                                    attributes=[LdapClient.GROUPS_TOKEN],
                                                                    paged_size=self._page_size,
                                                                    generator=False)

        referrals, entries = LdapClient._parse_ldap_group_entries_and_referrals(ldap_group_entries)

        return referrals, entries

    def _create_search_filter(self, filter_prefix: str) -> str:
        return filter_prefix + self._get_formatted_custom_attributes()

    def _fetch_specific_groups(self, specific_groups: str) -> dict:
        """
            Fetches specific ldap groups under given base DN.
        """
        auto_bind = self._get_auto_bind_value()
        dn_list = [group.strip() for group in argToList(specific_groups, separator="#")]

        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            demisto.info(f'LDAP Connection Details: {ldap_conn}')

            if self._ldap_server_vendor == self.ACTIVE_DIRECTORY:
                dns_filter = ''
                for dn in dn_list:
                    dns_filter += f'(distinguishedName={dn})'
                search_filter = f'(&(objectClass=group)(objectCategory=group)(|{dns_filter}))'

                referrals, entries = self._get_ldap_groups_entries_and_referrals_ad(ldap_conn=ldap_conn,
                                                                                    search_filter=search_filter)

                return {
                    'Controls': None,
                    'Referrals': referrals,
                    'Entries': entries
                }

            else:  # ldap server is OpenLDAP
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

    @staticmethod
    def _get_ad_username(logon_name: str) -> str:
        """
            Gets a User logon name (the username that is used for log in to XSOAR)
            and returns the Active Directory username.
        """
        ad_username = logon_name
        if '\\' in logon_name:
            ad_username = logon_name.split('\\')[1]
        elif '@' in logon_name:
            ad_username = logon_name.split('@')[0]

        return ad_username

    @staticmethod
    def _has_wildcards_in_user_logon(logon_name: str):
        """
            Gets a User logon name (the username that is used for log in to XSOAR) and checks if it includes wildcards.
            Raises exception if wildcards are found in the logon name.

            Background:
                LDAP servers support the use of wildcards primarily through the '*' and the '?' symbols for searching entries in
                the directory.
                Since the authentication process relies on exact username for login, the login attempt will be denied if the
                user logon name includes wildcards.

            Note:
                Wildcards are illegal characters for active directory logon names, however they are valid characters
                for OpenLdap usernames.
                Since we believe usernames include '*' or '?' symbols are rare, we fail the authentication when a user logon name
                includes one of them.
        """
        err_msg = f"Wildcards were detected in the user logon name - Input Username: '{logon_name}'."\
            f" Wildcards are not permitted for user authentication."

        wildcards = ['*', '?']
        for wildcard in wildcards:
            if wildcard in logon_name:
                demisto.debug(f"LDAP Authentication - User login attempt failed - {err_msg}")
                raise Exception(f"LDAP Authentication - Authentication failed - {err_msg}")

    def _get_auto_bind_value(self) -> str:
        """
            Returns the proper auto bind value according to the desirable connection type.
            The 'TLS' in the auto_bind parameter refers to the STARTTLS LDAP operation, that can be performed only on a
            cleartext connection (unsecure connection - port 389).

            If the Client's connection type is Start TLS - the secure level will be upgraded to TLS during the
            connection bind itself and thus we use the AUTO_BIND_TLS_BEFORE_BIND constant.

            If the Client's connection type is SSL - the connection is already secured (server was initialized with
            use_ssl=True and port 636) and therefore we use the AUTO_BIND_NO_TLS constant.

            Otherwise, the Client's connection type is None - the connection is unsecured and should stay unsecured,
            thus we use the AUTO_BIND_NO_TLS constant here as well.
        """
        if self._connection_type == 'start tls':
            auto_bind = AUTO_BIND_TLS_BEFORE_BIND
        else:
            auto_bind = AUTO_BIND_NO_TLS

        return auto_bind

    def get_ldap_groups(self, specific_group: str = '') -> dict:
        """
            Implements ldap groups command.
        """
        instance_name = demisto.integrationInstance()
        if not self._fetch_groups and not specific_group:
            demisto.info(f'Instance [{instance_name}] configured not to fetch groups')
            sys.exit()

        searched_results = self._fetch_specific_groups(
            specific_group) if not self._fetch_groups else self._fetch_all_groups()
        demisto.info(f'Retrieved {len(searched_results["Entries"])} groups from LDAP Authentication {instance_name}')

        return searched_results

    def authenticate_ldap_user(self, username: str, password: str) -> str:
        """
            Performs simple bind operation on ldap server.
        """
        auto_bind = self._get_auto_bind_value()
        ldap_conn = Connection(server=self._ldap_server, user=username, password=password, auto_bind=auto_bind)
        demisto.info(f'LDAP Connection Details: {ldap_conn}')

        if ldap_conn.bound:
            ldap_conn.unbind()
            return "Done"
        else:
            raise Exception(f"LDAP Authentication - authentication connection failed,"
                            f" server type is: {self._ldap_server_vendor}")

    def search_user_data(self, username: str, attributes: list, search_user_by_dn: bool = False) -> tuple:
        """
             Returns data for given ldap user.
             Raises error if the user is not found in the ldap server.
        """
        auto_bind = self._get_auto_bind_value()
        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            demisto.info(f'LDAP Connection Details: {ldap_conn}')

            if search_user_by_dn:
                search_filter = f'(&(objectClass={self.USER_OBJECT_CLASS})' + \
                                self._get_formatted_custom_attributes() + ')'
                ldap_conn.search(search_base=username, search_filter=search_filter, size_limit=1,
                                 attributes=attributes, search_scope=BASE)
            else:
                custom_attributes = self._get_formatted_custom_attributes()
                search_filter = (f'(&(objectClass={self.USER_OBJECT_CLASS})'
                                 f'({self.USER_IDENTIFIER_ATTRIBUTE}={username}){custom_attributes})')
                ldap_conn.search(search_base=self._base_dn, search_filter=search_filter, size_limit=1,
                                 attributes=attributes)

            if not ldap_conn.entries:
                raise Exception("LDAP Authentication - LDAP user not found")
            entry = ldap_conn.entries[0]
            referrals = ldap_conn.result.get('referrals')

            if self.GROUPS_IDENTIFIER_ATTRIBUTE not in entry \
                    or not entry[self.GROUPS_IDENTIFIER_ATTRIBUTE].value:
                raise Exception(f"LDAP Authentication - OpenLDAP user's {self.GROUPS_IDENTIFIER_ATTRIBUTE} not found")

            return entry, referrals

    def get_user_data(self, username: str, pull_name: bool, pull_mail: bool, pull_phone: bool,
                      name_attribute: str, mail_attribute: str, phone_attribute: str,
                      search_user_by_dn: bool = False) -> dict:
        """
            Returns data for given ldap user.
        """

        attributes = [self.GROUPS_IDENTIFIER_ATTRIBUTE]

        if pull_name:
            attributes.append(name_attribute)
        if pull_mail:
            attributes.append(mail_attribute)
        if pull_phone:
            attributes.append(phone_attribute)

        user_data_entry, referrals = self.search_user_data(username, attributes, search_user_by_dn)

        user_data = {'dn': user_data_entry.entry_dn,
                     'gid_number': [str(user_data_entry[self.GROUPS_IDENTIFIER_ATTRIBUTE].value)],
                     'referrals': referrals}

        if name_attribute in user_data_entry and user_data_entry[name_attribute].value:
            user_data['name'] = user_data_entry[name_attribute].value
        if mail_attribute in user_data_entry and user_data_entry[mail_attribute].value:
            user_data['email'] = user_data_entry[mail_attribute].value
        if phone_attribute in user_data_entry and user_data_entry[phone_attribute].value:
            user_data['mobile'] = user_data_entry[phone_attribute].value

        return user_data

    def get_user_groups(self, user_identifier: str):
        """
            Returns user's group.
        """
        auto_bind = self._get_auto_bind_value()
        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            demisto.info(f'LDAP Connection Details: {ldap_conn}')

            search_filter = (f'(&(objectClass={self.GROUPS_OBJECT_CLASS})'
                             f'({self.GROUPS_MEMBERSHIP_IDENTIFIER_ATTRIBUTE}={user_identifier}))')
            ldap_group_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                        search_filter=search_filter,
                                                                        attributes=[
                                                                            self.GROUPS_IDENTIFIER_ATTRIBUTE],
                                                                        paged_size=self._page_size)
            return LdapClient._parse_ldap_users_groups_entries(ldap_group_entries)

    def authenticate_and_roles_openldap(self, username: str, password: str, pull_name: bool = True,
                                        pull_mail: bool = True, pull_phone: bool = False, mail_attribute: str = 'mail',
                                        name_attribute: str = 'name', phone_attribute: str = 'mobile') -> dict:
        """
            Implements authenticate and roles command for OpenLDAP.
        """
        search_user_by_dn, user_identifier = LdapClient._is_valid_dn(username, self.USER_IDENTIFIER_ATTRIBUTE)
        user_data = self.get_user_data(username=username, search_user_by_dn=search_user_by_dn, pull_name=pull_name,
                                       pull_mail=pull_mail, pull_phone=pull_phone, mail_attribute=mail_attribute,
                                       name_attribute=name_attribute, phone_attribute=phone_attribute)

        self.authenticate_ldap_user(user_data['dn'], password)
        user_groups = self.get_user_groups(user_identifier)

        return {
            'Controls': None,
            'Referrals': user_data['referrals'],
            'Entries': [LdapClient._build_entry_for_user(user_groups=user_groups, user_data=user_data,
                                                         mail_attribute=mail_attribute, name_attribute=name_attribute,
                                                         phone_attribute=phone_attribute)]
        }

    def authenticate_and_roles_active_directory(self, username: str, password: str, pull_name: bool = True,
                                                pull_mail: bool = True, pull_phone: bool = False,
                                                mail_attribute: str = 'mail', name_attribute: str = 'name',
                                                phone_attribute: str = 'mobile') -> dict:
        """
            Implements authenticate and roles command for Active Directory.
        """
        ad_username = self._get_ad_username(username)
        auto_bind = self._get_auto_bind_value()

        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            demisto.info(f'LDAP Connection Details: {ldap_conn}')

            attributes = [self.GROUPS_MEMBER, self.GROUPS_PRIMARY_ID]
            if pull_name:
                attributes.append(name_attribute)
            if pull_mail:
                attributes.append(mail_attribute)
            if pull_phone:
                attributes.append(phone_attribute)

            search_filter = f'(|(sAMAccountName={ad_username})(userPrincipalName={username}))'
            ldap_conn_entries = ldap_conn.extend.standard.paged_search(search_base=self._base_dn,
                                                                       search_filter=search_filter,
                                                                       attributes=attributes,
                                                                       paged_size=self._page_size,
                                                                       generator=False)

            referrals, entries = \
                self._parse_and_authenticate_ldap_group_entries_and_referrals(ldap_group_entries=ldap_conn_entries,
                                                                              password=password)

            if not entries:  # if the user not exist in AD the query returns no entries
                raise Exception("LDAP Authentication - LDAP user not found")

        return {
            'Controls': [],
            'Referrals': referrals,
            'Entries': entries
        }

    def authenticate_and_roles(self, username: str, password: str, pull_name: bool = True, pull_mail: bool = True,
                               pull_phone: bool = False, mail_attribute: str = 'mail', name_attribute: str = 'name',
                               phone_attribute: str = 'mobile') -> dict:
        """
            Implements authenticate and roles command.
        """
        self._has_wildcards_in_user_logon(username)  # fail login attempt when wildcards are used

        if self._ldap_server_vendor == self.ACTIVE_DIRECTORY:
            return self.authenticate_and_roles_active_directory(username=username, password=password,
                                                                pull_name=pull_name, pull_mail=pull_mail,
                                                                pull_phone=pull_phone, mail_attribute=mail_attribute,
                                                                name_attribute=name_attribute,
                                                                phone_attribute=phone_attribute)
        else:  # ldap server is OpenLDAP
            return self.authenticate_and_roles_openldap(username=username, password=password,
                                                        pull_name=pull_name, pull_mail=pull_mail, pull_phone=pull_phone,
                                                        mail_attribute=mail_attribute, name_attribute=name_attribute,
                                                        phone_attribute=phone_attribute)

    def entries_search_command(self, args: dict[str, Any]) -> CommandResults:
        """
        Implements entries search command.
        """

        search_params = {'search_base': args.get('search_base', self._base_dn),
                         'search_scope': args.get('search_scope', SUBTREE),
                         'search_filter': create_entries_search_filter(args),
                         'attributes': get_search_attributes(args.get('attributes', 'all')),
                         }

        auto_bind = self._get_auto_bind_value()
        with Connection(self._ldap_server, self._username, self._password, auto_bind=auto_bind) as ldap_conn:
            if page := arg_to_number(args.get('page')):
                page_size = int(args.get('page_size', 50))
                if page_size > MAX_PAGE_SIZE:
                    raise Exception('The page size must be less than or equal to 2000')
            else:
                page = 1
                page_size = int(args.get('limit', 50))
            entries_paged_search(connection=ldap_conn,
                                 search_params=search_params,
                                 page=page,
                                 page_size=page_size)

            outputs = [
                {**json.loads(entry.entry_to_json()).get('attributes', {}), 'dn': json.loads(entry.entry_to_json()).get('dn')}
                for entry in ldap_conn.entries
            ]
            total = len(outputs)

        return CommandResults(
            outputs_prefix='LDAP.Search',
            outputs=outputs,
            raw_response=outputs,
            readable_output=tableToMarkdown(f'LDAP Entries Search Results - {total} Found', outputs),
        )

    def ad_authenticate(self, username: str, password: str) -> str:
        """
            Search for the user in the ldap server.
            Performs simple bind operation on ldap server.
        """
        self._has_wildcards_in_user_logon(username)  # fail authentication when wildcards are used

        if self._ldap_server_vendor == self.OPENLDAP:
            # If the given username is not a full DN, search for it in the ldap server and find it's full DN
            search_user_by_dn, _ = LdapClient._is_valid_dn(username, self.USER_IDENTIFIER_ATTRIBUTE)
            user_data_entry, _ = self.search_user_data(username, [self.GROUPS_IDENTIFIER_ATTRIBUTE], search_user_by_dn)
            username = user_data_entry.entry_dn

        return self.authenticate_ldap_user(username, password)

    def test_module(self):
        """
            Basic test connection and validation of the Ldap integration.
        """
        build_number = get_demisto_version().get('buildNumber', LdapClient.DEV_BUILD_NUMBER)
        self._get_formatted_custom_attributes()

        if build_number != LdapClient.DEV_BUILD_NUMBER \
                and int(build_number) < LdapClient.SUPPORTED_BUILD_NUMBER:
            raise Exception(f'LDAP Authentication integration is supported from build number:'
                            f' {LdapClient.SUPPORTED_BUILD_NUMBER}')

        if self._ldap_server_vendor == self.OPENLDAP:
            try:
                parse_dn(self._username)
            except LDAPInvalidDnError:
                raise Exception("Invalid credentials input. User DN must be a full DN.")
        self.authenticate_ldap_user(username=self._username, password=self._password)
        return 'ok'


def main():  # pragma: no coverage
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.info(f'Command being called is {command}')
    try:
        # initialized LDAP Authentication client
        client = LdapClient(params)

        if command == 'test-module':
            test_result = client.test_module()
            return_results(test_result)
        elif command == 'ad-authenticate':
            username = args.get('username')
            password = args.get('password')
            authentication_result = client.ad_authenticate(username, password)
            demisto.info(f'ad-authenticate command - authentication result: {authentication_result}')
            return_results(authentication_result)
        elif command == 'ad-groups':
            specific_group = args.get('specific-groups')
            searched_results = client.get_ldap_groups(specific_group)
            demisto.info(f'ad-groups command - searched results: {searched_results}')
            return_results(searched_results)
        elif command == 'ad-authenticate-and-roles':
            username = args.get('username')
            password = args.get('password')
            mail_attribute = args.get('attribute-mail', 'mail')
            name_attribute = args.get('attribute-name', 'name')
            phone_attribute = args.get('attribute-phone', 'mobile')
            pull_name = argToBoolean(args.get('attribute-name-pull', True))
            pull_mail = argToBoolean(args.get('attribute-mail-pull', True))
            pull_phone = argToBoolean(args.get('attribute-phone-pull', False))
            entry_result = client.authenticate_and_roles(username=username, password=password, pull_name=pull_name,
                                                         pull_mail=pull_mail, pull_phone=pull_phone,
                                                         mail_attribute=mail_attribute, name_attribute=name_attribute,
                                                         phone_attribute=phone_attribute)
            demisto.info(f'ad-authenticate-and-roles command - entry results: {entry_result}')
            return_results(entry_result)
        elif command == 'ad-entries-search':
            return_results(client.entries_search_command(args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions
    except Exception as e:
        msg = str(e)
        if isinstance(e, LDAPBindError):
            msg = f'LDAP Authentication - authentication connection failed. Additional details: {msg}'
        elif isinstance(e, LDAPSocketOpenError | LDAPSocketReceiveError | LDAPStartTLSError):
            msg = f'LDAP Authentication - Failed to connect to LDAP server. Additional details: {msg}'
            if not params.get('insecure', False):
                msg += ' Try using: "Trust any certificate" option.\n'
        elif isinstance(e, LDAPInvalidPortError):
            msg = 'LDAP Authentication - Not valid ldap server input.' \
                  ' Check that server input is of form: ip or ldap://ip'
        return_error(str(msg))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.log import (set_library_log_detail_level, get_library_log_detail_level,
                             set_library_log_hide_sensitive_data, EXTENDED)
import os
from datetime import datetime
import ssl
from ldap3.extend import microsoft
from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES, Tls, Entry, Reader, ObjectDef, \
    AUTO_BIND_TLS_BEFORE_BIND, AUTO_BIND_NO_TLS
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPStartTLSError, LDAPSocketReceiveError
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' GLOBAL VARS '''

CIPHERS_STRING = '@SECLEVEL=1:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:' \
                 'DH+AESGCM:ECDH+AES:DH+AES:RSA+ANESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS'  # Allowed ciphers for SSL/TLS
DEFAULT_TIMEOUT = 120  # timeout for ssl/tls socket
START_TLS = 'Start TLS'
TLS = 'TLS'
SSL = 'SSL'
SSL_VERSIONS = {
    'None': None,
    'TLS': ssl.PROTOCOL_TLS,
    'TLSv1': ssl.PROTOCOL_TLSv1,  # guardrails-disable-line
    'TLSv1_1': ssl.PROTOCOL_TLSv1_1,  # guardrails-disable-line
    'TLSv1_2': ssl.PROTOCOL_TLSv1_2,
    'TLS_CLIENT': ssl.PROTOCOL_TLS_CLIENT
}
# global connection
connection: Connection | None = None

# userAccountControl is a bitmask used to store a number of settings.
# find more at:
# https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
DEFAULT_OUTGOING_MAPPER = "User Profile - Active Directory (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Active Directory (Incoming)"

COMMON_ACCOUNT_CONTROL_FLAGS = {
    512: "Enabled Account",
    514: "Disabled account",
    544: "Password Not Required",
    4096: "Workstation/server",
    66048: "Enabled, password never expires",
    66050: "Disabled, password never expires",
    66080: "Enables, password never expires, password not required.",
    532480: "Domain controller"
}
NORMAL_ACCOUNT = 512
DISABLED_ACCOUNT = 514
PASSWORD_NOT_REQUIRED = 544
INACTIVE_LIST_OPTIONS = [514, 546, 66050, 66082, 262658, 262690, 328226]
DEFAULT_LIMIT = 20

# common attributes for specific AD objects
DEFAULT_PERSON_ATTRIBUTES = [
    'name',
    'displayName',
    'memberOf',
    'mail',
    'sAMAccountName',
    'manager',
    'userAccountControl'
]
DEFAULT_COMPUTER_ATTRIBUTES = [
    'name',
    'memberOf'
]
DEFAULT_GROUP_ATTRIBUTES = [
    'name',
    'memberOf'
]
FIELDS_THAT_CANT_BE_MODIFIED = [
    "dn", "cn", "ou"
]

''' HELPER FUNCTIONS '''


def get_ssl_version(ssl_version):
    """
        Returns the ssl version object according to the user's selection.
    """
    version = SSL_VERSIONS.get(ssl_version)
    if version:
        demisto.info(f"SSL/TLS protocol version is {ssl_version} ({version}).")
    else:  # version is None
        demisto.info("SSL/TLS protocol version is None (the default value of the ldap3 Tls object).")

    return version


def get_tls_object(unsecure, ssl_version):
    """
        Returns a TLS object according to the user's selection of the 'Trust any certificate' checkbox.
    """
    if unsecure:  # Trust any certificate is checked
        # Trust any certificate = True means that we do not require validation of the LDAP server's certificate,
        # and allow the use of all possible ciphers.
        tls = Tls(validate=ssl.CERT_NONE, ca_certs_file=None, ciphers=CIPHERS_STRING,
                  version=get_ssl_version(ssl_version))

    else:  # Trust any certificate is unchecked
        # Trust any certificate = False means that the LDAP server's certificate must be valid -
        # i.e if the server's certificate is not valid the connection will fail.
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get('SSL_CERT_FILE'),
                  version=get_ssl_version(ssl_version))

    return tls


def initialize_server(host, port, secure_connection, unsecure, ssl_version):
    """
    Uses the instance configuration to initialize the LDAP server.
    Supports both encrypted and non encrypted connection.

    :param host: host or ip
    :type host: string
    :param port: port or None
    :type port: number
    :param secure_connection: SSL, TLS, Start TLS or None
    :type secure_connection: string
    :param unsecure: trust any certificate
    :type unsecure: boolean
    :param ssl_version: ssl version
    :type unsecure: string
    :return: ldap3 Server
    :rtype: Server
    """
    if secure_connection == TLS:
        # Kept the TLS option for backwards compatibility only.
        # For establishing a secure connection via SSL/TLS protocol - use the 'SSL' option.
        # For establishing a secure connection via Start TLS - use the 'Start TLS' option.
        demisto.debug(f"initializing sever with TLS (unsecure: {unsecure}). port: {port or 'default(636)'}")
        if unsecure:
            # Add support for all CIPHERS_STRING
            tls = Tls(validate=ssl.CERT_NONE, ciphers=CIPHERS_STRING, version=get_ssl_version(ssl_version))
        else:
            tls = Tls(validate=ssl.CERT_NONE, version=get_ssl_version(ssl_version))
        if port:
            return Server(host, port=port, use_ssl=unsecure, tls=tls)
        return Server(host, use_ssl=unsecure, tls=tls)

    if secure_connection == SSL:  # Secure connection (SSL\TLS)
        demisto.info(f"Initializing LDAP sever with SSL/TLS (unsecure: {unsecure})."
                     f" port: {port or 'default(636)'}")
        tls = get_tls_object(unsecure, ssl_version)
        return Server(host=host, port=port, use_ssl=True, tls=tls, connect_timeout=DEFAULT_TIMEOUT)

    elif secure_connection == START_TLS:  # Secure connection (STARTTLS)
        demisto.info(f"Initializing LDAP sever without a secure connection - Start TLS operation will be executed"
                     f" during bind. (unsecure: {unsecure}). port: {port or 'default(389)'}")
        tls = get_tls_object(unsecure, ssl_version)
        return Server(host=host, port=port, use_ssl=False, tls=tls, connect_timeout=DEFAULT_TIMEOUT)

    else:  # Unsecure (non encrypted connection initialized) - connection type is None
        demisto.info(f"Initializing LDAP sever without a secure connection. port: {port or 'default(389)'}")
        return Server(host=host, port=port, connect_timeout=DEFAULT_TIMEOUT)


def user_account_to_boolean_fields(user_account_control):
    """
    parse the userAccountControl into boolean values.
    following the values from:
    https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    """
    return {
        'SCRIPT': bool(user_account_control & 0x0001),
        'ACCOUNTDISABLE': bool(user_account_control & 0x0002),
        'HOMEDIR_REQUIRED': bool(user_account_control & 0x0008),
        'LOCKOUT': bool(user_account_control & 0x0010),
        'PASSWD_NOTREQD': bool(user_account_control & 0x0020),
        'PASSWD_CANT_CHANGE': bool(user_account_control & 0x0040),
        'ENCRYPTED_TEXT_PWD_ALLOWED': bool(user_account_control & 0x0080),
        'TEMP_DUPLICATE_ACCOUNT': bool(user_account_control & 0x0100),
        'NORMAL_ACCOUNT': bool(user_account_control & 0x0200),
        'INTERDOMAIN_TRUST_ACCOUNT': bool(user_account_control & 0x0800),
        'WORKSTATION_TRUST_ACCOUNT': bool(user_account_control & 0x1000),
        'SERVER_TRUST_ACCOUNT': bool(user_account_control & 0x2000),
        'DONT_EXPIRE_PASSWORD': bool(user_account_control & 0x10000),
        'MNS_LOGON_ACCOUNT': bool(user_account_control & 0x20000),
        'SMARTCARD_REQUIRED': bool(user_account_control & 0x40000),
        'TRUSTED_FOR_DELEGATION': bool(user_account_control & 0x80000),
        'NOT_DELEGATED': bool(user_account_control & 0x100000),
        'USE_DES_KEY_ONLY': bool(user_account_control & 0x200000),
        'DONT_REQ_PREAUTH': bool(user_account_control & 0x400000),
        'PASSWORD_EXPIRED': bool(user_account_control & 0x800000),
        'TRUSTED_TO_AUTH_FOR_DELEGATION': bool(user_account_control & 0x1000000),
        'PARTIAL_SECRETS_ACCOUNT': bool(user_account_control & 0x04000000),
    }


def user_account_to_boolean_fields_msDS_user_account_control_computed(user_account_control):
    """
    parse the msDS-User-Account-Control-Computed into boolean values.
    following the values from:
    https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed
    """
    return {
        'PASSWORD_EXPIRED': bool(user_account_control & 0x800000),
        'LOCKOUT': bool(user_account_control & 0x0010),
    }


def account_entry(person_object, custom_attributes):
    # create an account entry from a person objects
    account = {
        'Type': 'AD',
        'ID': person_object.get('dn'),
        'Email': person_object.get('mail'),
        'Username': person_object.get('sAMAccountName'),
        'DisplayName': person_object.get('displayName'),
        'Managr': person_object.get('manager'),
        'Manager': person_object.get('manager'),
        'Groups': person_object.get('memberOf')
    }

    lower_cased_person_object_keys = {
        person_object_key.lower(): person_object_key for person_object_key in person_object
    }

    for attr in custom_attributes:
        try:
            account[attr] = person_object[attr]
        except KeyError as e:
            lower_cased_custom_attr = attr.lower()
            if lower_cased_custom_attr in lower_cased_person_object_keys:
                cased_custom_attr = lower_cased_person_object_keys.get(lower_cased_custom_attr, '')
                account[cased_custom_attr] = person_object[cased_custom_attr]
            else:
                demisto.error(f'Failed parsing custom attribute {attr}, error: {e}')

    return account


def endpoint_entry(computer_object, custom_attributes):
    # create an endpoint entry from a computer object
    endpoint = {
        'Type': 'AD',
        'ID': computer_object.get('dn'),
        'Hostname': computer_object.get('name'),
        'Groups': computer_object.get('memberOf')
    }

    lower_cased_person_object_keys = {
        person_object_key.lower(): person_object_key for person_object_key in computer_object
    }

    for attr in custom_attributes:
        if attr == '*':
            continue
        try:
            endpoint[attr] = computer_object[attr]
        except KeyError as e:
            lower_cased_custom_attr = attr.lower()
            if lower_cased_custom_attr in lower_cased_person_object_keys:
                cased_custom_attr = lower_cased_person_object_keys.get(lower_cased_custom_attr, '')
                endpoint[cased_custom_attr] = computer_object[cased_custom_attr]
            else:
                demisto.error(f'Failed parsing custom attribute {attr}, error: {e}')

    return endpoint


def group_entry(group_object, custom_attributes):
    # create an group entry from a group object
    group = {
        'Type': 'AD',
        'ID': group_object.get('dn'),
        'Name': group_object.get('name'),
        'Groups': group_object.get('memberOf'),
    }

    lower_cased_person_object_keys = {
        person_object_key.lower(): person_object_key for person_object_key in group_object
    }

    for attr in custom_attributes:
        if attr == '*':
            continue
        try:
            group[attr] = group_object[attr]
        except KeyError as e:
            lower_cased_custom_attr = attr.lower()
            if lower_cased_custom_attr in lower_cased_person_object_keys:
                cased_custom_attr = lower_cased_person_object_keys.get(lower_cased_custom_attr, '')
                group[cased_custom_attr] = group_object[cased_custom_attr]
            else:
                demisto.error(f'Failed parsing custom attribute {attr}, error: {e}')

    return group


def base_dn_verified(base_dn):
    # search AD with a simple query to test base DN is configured correctly
    try:
        search(
            "(objectClass=*)",
            base_dn,
            size_limit=1
        )
    except Exception as e:
        demisto.info(str(e))
        return False
    return True


def generate_unique_cn(default_base_dn, cn):
    changing_cn = cn
    i = 1
    while check_if_user_exists_by_attribute(default_base_dn, "cn", changing_cn):
        changing_cn = cn + str(i)
        i += 1
        if i == 30:
            raise Exception("User CN couldn't be generated")
    return changing_cn


def generate_dn_and_remove_from_user_profile(default_base_dn, user):
    """Generates a user dn, in case user dn is included in the user, will return it, otherwise
    will generate one using the cn and ou values
    :param default_base_dn: The location in the DIT where the search will start
    :param user: The user dict including his values
    :return: The user's dn.
    """
    user_dn = user.get("dn")

    if user_dn:
        user.pop("dn")
        return user_dn
    user_cn = user.get("cn")
    if not user_cn:
        raise Exception("User must have cn, please provide a valid value")

    valid_cn = generate_unique_cn(default_base_dn, user.get("cn"))
    ou = user.get("ou")

    return 'CN=' + str(valid_cn) + ',' + str(ou)


def check_if_user_exists_by_attribute(default_base_dn, attr, val):
    """Check if user exists base on a specific attribute
    :param default_base_dn: The location in the DIT where the search will start
    :param attr: The attribute to search by
    :param val: The attribute's value
    :return: True if the user exists, False otherwise.
    """
    query = f'(&(objectClass=User)(objectCategory=person)({attr}={val}))'
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=[attr],
        size_limit=1,
        page_size=1
    )
    if entries.get('flat'):
        return True
    return False


def get_user_activity_by_samaccountname(default_base_dn, samaccountname):
    """Get if user is active or not by samaccountname
    :param default_base_dn: The location in the DIT where the search will start
    :param samaccountname: The user's unique samaccountname
    :return: True if the user active, False otherwise.
    """
    active = False
    query = f'(&(objectClass=User)(objectCategory=person)(sAMAccountName={samaccountname}))'
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=["userAccountControl"],
        size_limit=1,
        page_size=1
    )

    if entries.get('flat'):
        user = entries.get('flat')[0]
        activity = user.get('userAccountControl')[0]
        active = activity not in INACTIVE_LIST_OPTIONS

    return active


def get_user_dn_by_email(default_base_dn, email):
    """Get's user dn by it's email, this function assumes that user's unique sameaccountname it the email prefix
    :param default_base_dn: The location in the DIT where the search will start
    :param email: The user's email
    :return: the user's dn
    """
    dn = ''
    samaccountname = email.split('@')[0]
    query = f'(&(objectClass=User)(objectCategory=person)(sAMAccountName={samaccountname}))'
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=["sAMAccountName"],
        size_limit=1,
        page_size=1
    )

    if entries.get('flat'):
        user = entries.get('flat')[0]
        dn = user.get('dn')

    return dn


def modify_user_ou(dn, new_ou):
    assert connection is not None
    cn = dn.split(',OU=', 1)[0]
    cn = cn.split(',DC=', 1)[0]
    # removing // to fix customers bug
    cn = cn.replace('\\', '')
    dn = dn.replace('\\', '')

    success = connection.modify_dn(dn, cn, new_superior=new_ou)
    return success


def get_all_attributes(search_base):
    obj_inetorgperson = ObjectDef('user', connection)
    r = Reader(connection, obj_inetorgperson, search_base)
    r.search()
    if not r:
        return []
    if not r[0]:
        return []
    attributes = r[0].allowedAttributes
    return list(attributes)


''' COMMANDS '''

''' SEARCH '''


def search(search_filter, search_base, attributes=None, size_limit=0, time_limit=0):
    """
    find entries in the DIT

    Args:
        search_base: the location in the DIT where the search will start
        search_filter: LDAP query string
        attributes: the attributes to specify for each entry found in the DIT

    """
    assert connection is not None
    success = connection.search(
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
        size_limit=size_limit,
        time_limit=time_limit
    )

    if not success:
        raise Exception("Search failed")
    return connection.entries


def search_with_paging(search_filter, search_base, attributes=None, page_size=100, size_limit=0,
                       time_limit=0, page_cookie=None):
    """
    find entries in the DIT

    Args:
        search_base: the location in the DIT where the search will start
        search_filter: LDAP query string
        attributes: the attributes to specify for each entry found in the DIT
    """
    assert connection is not None
    total_entries = 0
    cookie = base64.b64decode(page_cookie) if page_cookie else None
    start = datetime.now()

    entries: list[Entry] = []
    entries_left_to_fetch = size_limit
    while True:
        if 0 < entries_left_to_fetch < page_size:
            page_size = entries_left_to_fetch
        connection.search(
            search_base,
            search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            paged_cookie=cookie
        )
        entries_left_to_fetch -= len(connection.entries)
        total_entries += len(connection.entries)
        cookie = dict_safe_get(connection.result, ['controls', '1.2.840.113556.1.4.319', 'value', 'cookie'])
        time_diff = (datetime.now() - start).seconds

        entries.extend(connection.entries)

        # stop when: 1.reached size limit 2.reached time limit 3. no cookie
        if (size_limit and size_limit <= total_entries) or (time_limit and time_diff >= time_limit) or (not cookie):
            break

    # keep the raw entry for raw content (backward compatibility)
    raw = []
    # flatten the entries
    flat = []

    for entry in entries:
        entry = json.loads(entry.entry_to_json())

        flat_entry = {
            'dn': entry['dn']
        }

        for attr in entry.get('attributes', {}):
            flat_entry[attr] = entry['attributes'][attr]

        raw.append(entry)
        flat.append(flat_entry)
    encode_cookie = b64_encode(cookie) if cookie else None
    return {
        "raw": raw,
        "flat": flat,
        "page_cookie": encode_cookie
    }


def user_dn(sam_account_name, search_base):
    search_filter = f'(&(objectClass=user)(sAMAccountName={sam_account_name}))'
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception(f"Could not get full DN for user with sAMAccountName '{sam_account_name}'")
    entry = json.loads(entries[0].entry_to_json())
    return entry['dn']


def computer_dn(compuer_name, search_base):
    search_filter = f'(&(objectClass=user)(objectCategory=computer)(name={compuer_name}))'
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception(f"Could not get full DN for computer with name '{compuer_name}'")
    entry = json.loads(entries[0].entry_to_json())
    return entry['dn']


def group_dn(group_name, search_base):
    group_name = escape_filter_chars(group_name)
    search_filter = f'(&(objectClass=group)(cn={group_name}))'
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception(f"Could not get full DN for group with name '{group_name}'")
    entry = json.loads(entries[0].entry_to_json())
    return entry['dn']


def convert_special_chars_to_unicode(search_filter):
    # We allow users to use special chars without explicitly typing their unicode values
    chars_to_replace = {
        '\\(': '\\28',
        '\\)': '\\29',
        '\\*': '\\2a',
        '\\/': '\\2f',
        '\\\\': '\\5c'
    }
    for i, j in chars_to_replace.items():
        search_filter = search_filter.replace(i, j)

    return search_filter


def free_search(default_base_dn, page_size):
    args = demisto.args()

    search_filter = args.get('filter')
    size_limit = int(args.get('size-limit', '0'))
    time_limit = int(args.get('time-limit', '0'))
    search_base = args.get('base-dn') or default_base_dn
    attributes = args.get('attributes')
    context_output = args.get('context-output')

    search_filter = convert_special_chars_to_unicode(search_filter)

    # if ALL was specified - get all the object's attributes, else expect a string of comma separated values
    if attributes:
        attributes = ALL_ATTRIBUTES if attributes == 'ALL' else attributes.split(',')

    page_cookie = args.get('page-cookie')
    if args.get('page-size'):
        page_size = arg_to_number(args['page-size'])
        size_limit = page_size

    entries = search_with_paging(
        search_filter,
        search_base,
        attributes=attributes,
        size_limit=size_limit,
        time_limit=time_limit,
        page_size=page_size,
        page_cookie=page_cookie
    )
    ec = {} if context_output == 'no' else {'ActiveDirectory.Search(obj.dn == val.dn)': entries['flat'],
                                            'ActiveDirectory(true)': {
                                                'SearchPageCookie': entries['page_cookie']}
                                            }
    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory Search", entries['flat']),
        'EntryContext': ec
    }
    demisto.results(demisto_entry)


def search_users(default_base_dn, page_size):
    # this command is equivalent to script ADGetUser
    # will preform a custom search to find users by a specific (one) attribute specified by the user

    args = demisto.args()

    attributes: list[str] = []
    custom_attributes: list[str] = []

    # zero is actually no limitation, default is 20
    limit = int(args.get('limit', '20'))
    if limit <= 0:
        limit = 20

    page_cookie = args.get('page-cookie')
    if args.get('page-size'):
        page_size = arg_to_number(args['page-size'])
        limit = page_size

    # default query - list all users
    query = "(&(objectClass=User)(objectCategory=person))"
    # query by user DN
    if args.get('dn'):
        dn = escape_filter_chars(args['dn'])
        query = f"(&(objectClass=User)(objectCategory=person)(distinguishedName={dn}))"

    # query by name
    if args.get('name'):
        name = escape_filter_chars(args['name'])
        query = f"(&(objectClass=User)(objectCategory=person)(cn={name}))"

    # query by email
    if args.get('email'):
        email = escape_filter_chars(args['email'])
        query = f"(&(objectClass=User)(objectCategory=person)(mail={email}))"

    # query by sAMAccountName
    if args.get('username') or args.get('sAMAccountName'):
        username = escape_filter_chars(args['username']) if args.get('username') else escape_filter_chars(args['sAMAccountName'])
        query = f"(&(objectClass=User)(objectCategory=person)(sAMAccountName={username}))"

    # query by custom object attribute
    if args.get('custom-field-type'):
        if not args.get('custom-field-data'):
            raise Exception('Please specify "custom-field-data" as well when quering by "custom-field-type"')
        field_type = escape_filter_chars(args['custom-field-type'])
        field_data = escape_filter_chars(args['custom-field-data'])
        query = "(&(objectClass=User)(objectCategory=person)({}={}))".format(
            field_type, field_data)

    if args.get('attributes'):
        custom_attributes = args['attributes'].split(",")

    attributes = list(set(custom_attributes + DEFAULT_PERSON_ATTRIBUTES)
                      - set(argToList(args.get('attributes-to-exclude'))))
    if 'userAccountControl' in attributes:
        attributes.append('msDS-User-Account-Control-Computed')
    entries = search_with_paging(
        query,
        default_base_dn,
        page_cookie=page_cookie,
        attributes=attributes,
        size_limit=limit,
        page_size=page_size
    )

    accounts = [account_entry(entry, custom_attributes) for entry in entries['flat']]
    if 'userAccountControl' in attributes:
        for user in entries['flat']:
            if user.get('userAccountControl'):
                user_account_control = user.get('userAccountControl')[0]
                user['userAccountControlFields'] = user_account_to_boolean_fields(user_account_control)

                # display a literal translation of the numeric account control flag
                if args.get('user-account-control-out', '') == 'true':
                    user['userAccountControl'] = COMMON_ACCOUNT_CONTROL_FLAGS.get(
                        user_account_control) or user_account_control

            if user.get("msDS-User-Account-Control-Computed"):
                user_account_control_msDS = user.get("msDS-User-Account-Control-Computed")[0]
                user_account_to_boolean_dict = user_account_to_boolean_fields_msDS_user_account_control_computed(
                    user_account_control_msDS)
                user.setdefault("userAccountControlFields", {}).update(user_account_to_boolean_dict)

    entry_context = {
        'ActiveDirectory.Users(obj.dn == val.dn)': entries['flat'],
        # 'backward compatability' with ADGetUser script
        'Account(obj.ID == val.ID)': accounts,
        'ActiveDirectory(true)': {'UsersPageCookie': entries['page_cookie']} if entries['page_cookie'] else None
    }
    remove_nulls_from_dictionary(entry_context)

    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory - Get Users", entries['flat']),
        'EntryContext': entry_context
    }
    demisto.results(demisto_entry)


def get_user_iam(default_base_dn, args, mapper_in, mapper_out):
    """Gets an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param args: Demisto args.
    :param mapper_in: Mapping AD user to User Profiles
    :param mapper_out: Mapping User Profiles to AD users.
    :return: User Profile of the AD user
    """
    try:
        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        default_attribute = "sAMAccountName"

        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta,
                                          mapper=mapper_out,
                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)

        # we use the outgoing mapper to get all the AD attributes which will be later passed to search_with_paging()
        ad_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                              incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)

        value = ad_user.get(default_attribute)

        # removing keys with no values
        user = {k: v for k, v in ad_user.items() if v}
        attributes = list(user.keys())

        query = f'(&(objectClass=User)(objectCategory=person)({default_attribute}={value}))'
        entries = search_with_paging(
            query,
            default_base_dn,
            attributes=attributes,
            size_limit=1,
            page_size=1
        )

        if not entries.get('flat'):
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(action=IAMActions.GET_USER,
                                        success=False,
                                        error_code=error_code,
                                        error_message=error_message)
        else:
            user_account_control = get_user_activity_by_samaccountname(default_base_dn, value)
            ad_user["userAccountControl"] = user_account_control
            iam_user_profile.update_with_app_data(ad_user, mapper_in)
            iam_user_profile.set_result(success=True,
                                        email=ad_user.get('email'),
                                        username=ad_user.get('name'),
                                        action=IAMActions.GET_USER,
                                        details=ad_user,
                                        active=user_account_control)

        return iam_user_profile

    except Exception as e:
        error_code, _ = IAMErrors.BAD_REQUEST
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=str(e),
                                    action=IAMActions.GET_USER
                                    )
        return iam_user_profile


def search_computers(default_base_dn, page_size):
    # this command is equivalent to ADGetComputer script

    args = demisto.args()
    attributes: list[str] = []
    custom_attributes: list[str] = []

    # default query - list all users (computer category)
    query = "(&(objectClass=user)(objectCategory=computer))"

    # query by user DN
    if args.get('dn'):
        query = "(&(objectClass=user)(objectCategory=computer)(distinguishedName={}))".format(args['dn'])

    # query by name
    if args.get('name'):
        query = "(&(objectClass=user)(objectCategory=computer)(name={}))".format(args['name'])

    # query by custom object attribute
    if args.get('custom-field-type'):
        if not args.get('custom-field-data'):
            raise Exception('Please specify "custom-field-data" as well when quering by "custom-field-type"')
        query = "(&(objectClass=user)(objectCategory=computer)({}={}))".format(
            args['custom-field-type'], args['custom-field-data'])

    size_limit = int(args.get('limit', '0'))
    page_cookie = args.get('page-cookie')
    if args.get('page-size'):
        page_size = arg_to_number(args['page-size'])
        size_limit = page_size

    if args.get('attributes'):
        custom_attributes = args['attributes'].split(",")
    attributes = list(set(custom_attributes + DEFAULT_COMPUTER_ATTRIBUTES))
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        page_size=page_size,
        size_limit=size_limit,
        page_cookie=page_cookie
    )

    endpoints = [endpoint_entry(entry, custom_attributes) for entry in entries['flat']]
    readable_output = tableToMarkdown("Active Directory - Get Computers", entries['flat'])

    if endpoints:
        results = CommandResults(
            readable_output=readable_output,
            outputs={
                'ActiveDirectory.Computers(obj.dn == val.dn)': entries['flat'],
                # 'backward compatability' with ADGetComputer script
                'Endpoint(obj.ID == val.ID)': endpoints,
                'ActiveDirectory(true)': {'ComputersPageCookie': entries['page_cookie']}
            },
            raw_response=entries['raw'],
        )
    else:
        results = CommandResults(
            readable_output=readable_output,
        )

    return_results(results)


def search_group_members(default_base_dn, page_size):
    # this command is equivalent to ADGetGroupMembers script

    args = demisto.args()
    member_type = args.get('member-type')
    group_dn = args.get('group-dn')
    nested_search = '' if args.get('disable-nested-search') == 'true' else ':1.2.840.113556.1.4.1941:'
    time_limit = int(args.get('time_limit', 180))
    account_name = args.get('sAMAccountName')
    custom_attributes: list[str] = []

    default_attribute_mapping = {
        'person': DEFAULT_PERSON_ATTRIBUTES,
        'group': DEFAULT_GROUP_ATTRIBUTES,
        'computer': DEFAULT_COMPUTER_ATTRIBUTES,
    }
    default_attributes = default_attribute_mapping.get(member_type, DEFAULT_COMPUTER_ATTRIBUTES)

    if args.get('attributes'):
        custom_attributes = args['attributes'].split(",")

    attributes = list(set(custom_attributes + default_attributes))

    if member_type == 'group':
        query = "(&(objectCategory={})(memberOf{}={})(sAMAccountName={}))".format(member_type, nested_search, group_dn,
                                                                                  account_name)
    else:
        query = "(&(objectCategory={})(objectClass=user)(memberOf{}={})(sAMAccountName={}))"\
            .format(member_type, nested_search, group_dn, account_name)

    size_limit = int(args.get('limit', '0'))
    page_cookie = args.get('page-cookie')
    if args.get('page-size'):
        page_size = arg_to_number(args['page-size'])
        size_limit = page_size

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        page_size=page_size,
        time_limit=time_limit,
        size_limit=size_limit,
        page_cookie=page_cookie
    )
    members = [{'dn': entry['dn'], 'category': member_type} for entry in entries['flat']]
    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory - Get Group Members", entries['flat']),
        'EntryContext': {
            'ActiveDirectory.Groups(obj.dn ==' + group_dn + ')': {
                'dn': group_dn,
                'members': members
            },
            'ActiveDirectory(true)': {'GroupsPageCookie': entries['page_cookie']}
        }
    }

    if member_type == 'person':
        demisto_entry['EntryContext']['ActiveDirectory.Users(obj.dn == val.dn)'] = entries['flat']
        demisto_entry['EntryContext']['Account'] = [account_entry(
            entry, custom_attributes) for entry in entries['flat']]
    elif member_type == 'computer':
        demisto_entry['EntryContext']['ActiveDirectory.Computers(obj.dn == val.dn)'] = entries['flat']
        demisto_entry['EntryContext']['Endpoint'] = [endpoint_entry(
            entry, custom_attributes) for entry in entries['flat']]
    elif member_type == 'group':
        demisto_entry['EntryContext']['ActiveDirectory.Groups(obj.dn == val.dn)'] = entries['flat']
        demisto_entry['EntryContext']['Group'] = [group_entry(
            entry, custom_attributes) for entry in entries['flat']]

    demisto.results(demisto_entry)


''' DATABASE OPERATIONS '''

''' CREATE OBJECT'''


def create_user():
    assert connection is not None
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "user"]
    user_dn = args.get('user-dn')
    username = args.get("username")
    password = args.get("password")
    custom_attributes = args.get('custom-attributes')
    attributes = {
        "sAMAccountName": username
    }

    # set common user attributes
    if args.get('display-name'):
        attributes['displayName'] = args['display-name']
    if args.get('description'):
        attributes['description'] = args['description']
    if args.get('email'):
        attributes['mail'] = args['email']
    if args.get('telephone-number'):
        attributes['telephoneNumber'] = args['telephone-number']
    if args.get('title'):
        attributes['title'] = args['title']

    # set user custom attributes
    if custom_attributes:
        try:
            custom_attributes = json.loads(custom_attributes)
        except Exception as e:
            demisto.info(str(e))
            raise Exception(
                "Failed to parse custom attributes argument. Please see an example of this argument in the description."
            )
        for attribute_name, attribute_value in custom_attributes.items():
            # can run default attribute setting
            attributes[attribute_name] = attribute_value

    # add user
    success = connection.add(user_dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create user")

    # set user password
    success = connection.extend.microsoft.modify_password(user_dn, password)
    if not success:
        raise Exception("Failed to reset user password")

    # enable user and expire password
    modification = {
        # enable user
        'userAccountControl': [('MODIFY_REPLACE', NORMAL_ACCOUNT)],
        # set to 0, to force password change on next login
        "pwdLastSet": [('MODIFY_REPLACE', "0")]
    }
    modify_object(user_dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Created user with DN: {user_dn}"
    }
    demisto.results(demisto_entry)


def create_user_iam(default_base_dn, args, mapper_out, disabled_users_group_cn):
    """Creates an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param args: Demisto args.
    :param mapper_out: Mapping User Profiles to AD users.
    :param disabled_users_group_cn: The disabled group cn, the user will be removed from this group when enabled
    :return: The user that was created
    """
    assert connection is not None
    try:

        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta,
                                          mapper=mapper_out, incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
        ad_user = iam_user_profile.map_object(mapper_name=mapper_out, incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)

        sam_account_name = ad_user.get("sAMAccountName")

        if not sam_account_name:
            raise DemistoException("User must have a sAMAccountName, please make sure a mapping "
                                   "exists in \"" + mapper_out + "\" outgoing mapper.")
        if not ad_user.get('ou'):
            raise DemistoException("User must have an Organizational Unit (OU). Please make sure you've added a "
                                   "transformer script which determines the OU of the user "
                                   "in \"" + mapper_out + "\" outgoing mapper, in the User Profile incident type "
                                                          "and schema type, under the \"ou\" field.")

        user_exists = check_if_user_exists_by_attribute(default_base_dn, "sAMAccountName", sam_account_name)

        if user_exists:
            iam_user_profile = update_user_iam(default_base_dn, args, False, mapper_out, disabled_users_group_cn)

        else:
            user_dn = generate_dn_and_remove_from_user_profile(default_base_dn, ad_user)
            object_classes = ["top", "person", "organizationalPerson", "user"]
            # ou and cn are updated from the dn, updating them seperatly can cause conflicts
            ad_user.pop('ou')
            ad_user.pop('cn')
            if manager_email := ad_user.get('manageremail'):
                manager_dn = get_user_dn_by_email(default_base_dn, manager_email)
                ad_user['manager'] = manager_dn
            success = connection.add(user_dn, object_classes, ad_user)
            if success:
                iam_user_profile.set_result(success=True,
                                            email=ad_user.get('mail'),
                                            username=ad_user.get('sAMAccountName'),
                                            details=ad_user,
                                            action=IAMActions.CREATE_USER,
                                            active=False)  # the user should be activated with the IAMInitADUser script

            else:
                error_msg = 'Please validate your instance configuration and make sure all of the ' \
                            'required attributes are mapped correctly in "' + mapper_out + '" outgoing mapper.'
                raise DemistoException(error_msg)

        return iam_user_profile

    except Exception as e:
        error_code, _ = IAMErrors.BAD_REQUEST
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=str(e),
                                    action=IAMActions.CREATE_USER,
                                    )
        return iam_user_profile


def get_iam_user_profile(user_profile, mapper_out):
    iam_user_profile = IAMUserProfile(user_profile=user_profile, mapper=mapper_out,
                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    ad_user = iam_user_profile.map_object(mapper_name=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    sam_account_name = ad_user.get("sAMAccountName")

    old_user_data = iam_user_profile.get_attribute('olduserdata')
    if old_user_data:
        iam_old_user_profile = IAMUserProfile(user_profile=old_user_data, mapper=mapper_out,
                                              incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        ad_old_user = iam_old_user_profile.map_object(mapper_name=mapper_out,
                                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        sam_account_name = ad_old_user.get("sAMAccountName") or sam_account_name

    return iam_user_profile, ad_user, sam_account_name


def update_user_iam(default_base_dn, args, create_if_not_exists, mapper_out, disabled_users_group_cn):
    """Update an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param args: Demisto args.
    :param create_if_not_exists: Created the user if it does not exists.
    :param mapper_out: Mapping User Profiles to AD users.
    :param disabled_users_group_cn: The disabled group cn, the user will be removed from this group when enabled
    :return: Updated User
    """
    assert connection is not None
    try:
        user_profile = args.get("user-profile")
        allow_enable = args.get('allow-enable') == 'true'

        iam_user_profile, ad_user, sam_account_name = get_iam_user_profile(user_profile, mapper_out)

        if not sam_account_name:
            raise DemistoException("User must have a sAMAccountName, please make sure a mapping "
                                   "exists in \"" + mapper_out + "\" outgoing mapper.")
        if not ad_user.get('ou'):
            raise DemistoException("User must have an Organizational Unit (OU). Please make sure you've added a "
                                   "transformer script which determines the OU of the user "
                                   "in \"" + mapper_out + "\" outgoing mapper, in the User Profile incident type "
                                                          "and schema type, under the \"ou\" field.")

        new_ou = ad_user.get("ou")
        user_exists = check_if_user_exists_by_attribute(default_base_dn, "sAMAccountName", sam_account_name)

        if not user_exists:
            if create_if_not_exists:
                iam_user_profile = create_user_iam(default_base_dn, args, mapper_out, disabled_users_group_cn)
            else:
                _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                            skip=True,
                                            skip_reason=error_message)
        else:
            dn = user_dn(sam_account_name, default_base_dn)

            if allow_enable:
                enable_user_iam(default_base_dn, dn, disabled_users_group_cn)

            # fields that can't be modified
            # notice that we are changing the ou and that effects the dn and cn
            for field in FIELDS_THAT_CANT_BE_MODIFIED:
                if ad_user.get(field):
                    ad_user.pop(field)

            fail_to_modify = []
            if manager_email := ad_user.get('manageremail'):
                manager_dn = get_user_dn_by_email(default_base_dn, manager_email)
                ad_user['manager'] = manager_dn
                ad_user.pop('manageremail')

            for key in ad_user:
                modification = {key: [('MODIFY_REPLACE', ad_user.get(key))]}
                success = connection.modify(dn, modification)
                if not success:
                    fail_to_modify.append(key)

            ou_modified_succeed = modify_user_ou(dn, new_ou)
            if not ou_modified_succeed:
                fail_to_modify.append("ou")

            if fail_to_modify:
                error_list = '\n'.join(fail_to_modify)
                error_message = f"Failed to modify the following attributes: {error_list}"
                raise DemistoException(error_message)

            else:
                active = get_user_activity_by_samaccountname(default_base_dn, sam_account_name)
                iam_user_profile.set_result(success=True,
                                            email=ad_user.get('mail'),
                                            username=ad_user.get('sAMAccountName'),
                                            action=IAMActions.UPDATE_USER,
                                            details=ad_user,
                                            active=active)
        return iam_user_profile

    except Exception as e:
        error_code, _ = IAMErrors.BAD_REQUEST
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=str(e),
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def create_contact():
    assert connection is not None
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "contact"]
    contact_dn = args.get('contact-dn')

    # set contact attributes
    attributes: dict = {}
    if args.get('custom-attributes'):
        try:
            attributes = json.loads(args['custom-attributes'])
        except Exception as e:
            demisto.info(str(e))
            raise Exception(
                'Failed to parse custom attributes argument. Please see an example of this argument in the argument.'
            )

    # set common user attributes
    if args.get('display-name'):
        attributes['displayName'] = args['display-name']
    if args.get('description'):
        attributes['description'] = args['description']
    if args.get('email'):
        attributes['mail'] = args['email']
    if args.get('telephone-number'):
        attributes['telephoneNumber'] = args['telephone-number']
    if args.get('title'):
        attributes['title'] = args['title']

    # add contact

    success = connection.add(contact_dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create contact")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Created contact with DN: {contact_dn}"
    }
    demisto.results(demisto_entry)


def create_group():
    assert connection is not None
    args = demisto.args()

    object_classes = ["top", "group"]
    dn = args.get('dn')
    group_name = args.get('name')
    group_type_map = {"security": "2147483650", "distribution": "2"}
    group_type = group_type_map[args.get("group-type")]
    if args.get('members'):
        members = args.get('members')
        attributes = {
            "samAccountName": group_name,
            "groupType": group_type,
            "member": members
        }
    else:
        attributes = {
            "samAccountName": group_name,
            "groupType": group_type
        }

    # create group
    success = connection.add(dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create group")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Created group with DN: {dn}"
    }
    demisto.results(demisto_entry)


''' UPDATE OBJECT '''


def modify_object(dn, modification):
    """
    modifies object in the DIT
    """
    assert connection is not None
    success = connection.modify(dn, modification)
    if not success:
        raise Exception("Failed to update object {} with the following modification: {}".format(
            dn, json.dumps(modification)))


def update_user(default_base_dn):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    attribute_name = args.get('attribute-name')
    attribute_value = args.get('attribute-value')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    modification = {}
    modification[attribute_name] = [('MODIFY_REPLACE', attribute_value)]

    # modify user
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Updated user's {attribute_name} to {attribute_value} "
    }
    demisto.results(demisto_entry)


def update_group(default_base_dn):
    args = demisto.args()

    sam_account_name = args.get('groupname')
    attribute_name = args.get('attributename')
    attribute_value = args.get('attributevalue')
    search_base = args.get('basedn') or default_base_dn
    dn = group_dn(sam_account_name, search_base)

    modification = {attribute_name: [('MODIFY_REPLACE', attribute_value)]}
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Updated group's {attribute_name} to {attribute_value} "
    }
    demisto.results(demisto_entry)


def update_contact():
    args = demisto.args()

    contact_dn = args.get('contact-dn')
    modification = {}
    modification[args.get('attribute-name')] = [('MODIFY_REPLACE', args.get('attribute-value'))]

    # modify
    modify_object(contact_dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Updated contact's {} to: {} ".format(args.get('attribute-name'), args.get('attribute-value'))
    }
    demisto.results(demisto_entry)


def modify_computer_ou(default_base_dn):
    assert connection is not None
    args = demisto.args()

    computer_name = args.get('computer-name')
    dn = computer_dn(computer_name, args.get('base-dn') or default_base_dn)

    success = connection.modify_dn(dn, f"CN={computer_name}", new_superior=args.get('full-superior-dn'))
    if not success:
        raise Exception("Failed to modify computer OU")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Moved computer {} to {}".format(computer_name, args.get('full-superior-dn'))
    }
    demisto.results(demisto_entry)


def modify_user_ou_command(default_base_dn):
    assert connection is not None
    args = demisto.args()

    user_name = args.get('user-name')
    dn = user_dn(user_name, args.get('base-dn') or default_base_dn)
    success = modify_user_ou(dn, new_ou=args.get('full-superior-dn'))
    if not success:
        raise Exception("Failed to modify user OU")

    return f'Moved user {user_name} to {args.get("full-superior-dn")}'


def expire_user_password(default_base_dn):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    modification = {
        # set to 0, to force password change on next login
        "pwdLastSet": [('MODIFY_REPLACE', "0")]
    }

    # modify user
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Expired password successfully"
    }
    demisto.results(demisto_entry)


def set_user_password(default_base_dn, port):
    assert connection is not None
    args = demisto.args()

    if port != 636:
        raise DemistoException('Port 636 is required for this action.')

    # get user DN
    sam_account_name = args.get('username')
    password = args.get('password')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    # set user password
    success = connection.extend.microsoft.modify_password(dn, password)
    if not success:
        raise Exception("Failed to reset user password")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "User password successfully set"
    }
    demisto.results(demisto_entry)


def restore_user(default_base_dn: str, page_size: int) -> int:
    """
         Restore the user UserAccountControl flags.
         Args:
             default_base_dn (str): The default base dn.
             page_size (int): The page size to query.
         Returns:
             flags (int): The UserAccountControl flags.
     """
    args = demisto.args()

    # default query - list all users
    query = "(&(objectClass=User)(objectCategory=person))"

    # query by sAMAccountName
    if args.get('username') or args.get('sAMAccountName'):
        username = escape_filter_chars(args['username']) if args.get('username') else escape_filter_chars(args['sAMAccountName'])
        query = f"(&(objectClass=User)(objectCategory=person)(sAMAccountName={username}))"

    attributes = list(set(DEFAULT_PERSON_ATTRIBUTES))

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        size_limit=0,
        page_size=page_size
    )
    if entries.get('flat'):
        return entries.get('flat')[0].get('userAccountControl')[0]
    return 0


def turn_disable_flag_off(flags: int) -> int:
    """
        Turn off the ACCOUNTDISABLE flag in UserAccountControl flags.
        https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
         Args:
             flags (int): The UserAccountControl flags to update.
         Returns:
             flags (int): The UserAccountControl flags with the ACCOUNTDISABLE turned off.
     """
    return flags & ~(1 << (2 - 1))


def enable_user(default_base_dn, default_page_size):
    args = demisto.args()
    account_options = NORMAL_ACCOUNT
    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    if args.get('restore_user'):
        account_options = restore_user(search_base, default_page_size)

    # modify user
    modification = {
        'userAccountControl': [('MODIFY_REPLACE', turn_disable_flag_off(account_options))]
    }
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"User {sam_account_name} was enabled"
    }
    demisto.results(demisto_entry)


def disable_user(default_base_dn, default_page_size):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)
    account_options = restore_user(search_base, default_page_size)

    # modify user
    modification = {
        'userAccountControl': [('MODIFY_REPLACE', (account_options | DISABLED_ACCOUNT))]
    }
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"User {sam_account_name} was disabled"
    }
    demisto.results(demisto_entry)


def enable_user_iam(default_base_dn, dn, disabled_users_group_cn):
    """Enables an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param dn: The users unique dn
    :param disabled_users_group_cn: The disabled group cn, the user will be removed from this group when enabled
    """
    modification = {
        'userAccountControl': [('MODIFY_REPLACE', PASSWORD_NOT_REQUIRED)]
    }
    modify_object(dn, modification)
    if disabled_users_group_cn:
        grp_dn = group_dn(disabled_users_group_cn, default_base_dn)
        success = microsoft.removeMembersFromGroups.ad_remove_members_from_groups(connection, [dn], [grp_dn], True)
        if not success:
            raise Exception(f'Failed to remove user from {disabled_users_group_cn} group')


def disable_user_iam(default_base_dn, disabled_users_group_cn, args, mapper_out):
    """Disables an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param disabled_users_group_cn: The disabled group cn, the user will be added from this group when enabled
    :param args: Demisto args.
    :param mapper_out: Mapping User Profiles to AD users.
    :return: The disabled user
    """
    try:
        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta,
                                          mapper=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
        ad_user = iam_user_profile.map_object(mapper_name=mapper_out, incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)

        sam_account_name = ad_user.get("sAMAccountName")
        if not sam_account_name:
            raise DemistoException("User must have a sAMAccountName, please make sure a mapping "
                                   "exists in \"" + mapper_out + "\" outgoing mapper.")

        user_exists = check_if_user_exists_by_attribute(default_base_dn, "sAMAccountName", sam_account_name)
        if not user_exists:
            iam_user_profile.set_result(success=True, action=IAMActions.DISABLE_USER,
                                        skip=True, skip_reason="User doesn't exist")
            return iam_user_profile

        dn = user_dn(sam_account_name, default_base_dn)

        # modify user
        modification = {
            'userAccountControl': [('MODIFY_REPLACE', DISABLED_ACCOUNT)]
        }

        try:
            modify_object(dn, modification)
        except Exception as e:
            error_msg = 'Please validate your instance configuration and make sure all of the ' \
                        'required attributes are mapped correctly in "' + mapper_out + '" outgoing mapper.\n' \
                                                                                       'Error is: ' + str(e)
            raise DemistoException(error_msg)

        if disabled_users_group_cn:

            grp_dn = group_dn(disabled_users_group_cn, default_base_dn)
            success = microsoft.addMembersToGroups.ad_add_members_to_groups(connection, [dn], [grp_dn])
            if not success:
                raise DemistoException('Failed to remove user from the group "' + disabled_users_group_cn + '".')

        iam_user_profile.set_result(success=True,
                                    email=ad_user.get('mail'),
                                    username=ad_user.get('sAMAccountName'),
                                    action=IAMActions.DISABLE_USER,
                                    details=ad_user,
                                    active=False)

        return iam_user_profile

    except Exception as e:
        error_code, _ = IAMErrors.BAD_REQUEST
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=str(e),
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


def add_member_to_group(default_base_dn):
    args = demisto.args()

    search_base = args.get('base-dn') or default_base_dn

    # get the  dn of the member - either user or computer
    args_err = "Please provide either username, computer-name, or nested_group_cn"
    member_dn = ''

    if args.get('username') and args.get('computer-name'):
        # both arguments passed
        raise Exception(args_err)
    if args.get('username'):
        usernames = argToList(args.get('username'))
        demisto.debug(f"Usernames collected are {usernames}")
        member_dns = []
        for u in usernames:
            member_dn = user_dn(u, search_base)
            demisto.debug(f"Member DNs after formatting are: {member_dn}")
            member_dns.append(member_dn)
    elif args.get('computer-name'):
        computers = argToList('computer-name')
        member_dns = []
        for c in computers:
            member_dn = computer_dn(c, search_base)
            member_dns.append(member_dn)
    # added option to pass a Group CN to be added to the Group as a nested group
    elif args.get('nested_group_cn'):
        member_dn = group_dn(args['nested_group_cn'], search_base)
        member_dns = [member_dn]
    else:
        # none of the arguments passed
        raise Exception(args_err)

    grp_dn = group_dn(args.get('group-cn'), search_base)

    # Updated to take an array of member DNs to add to the group. Not detailed in the ldap3 documentation but per the function
    # hints https://github.com/cannatag/ldap3/blob/dev/ldap3/extend/microsoft/addMembersToGroups.py
    # def ad_add_members_to_groups(connection, members_nd, groups_dn, fixe=True, raise_error=False):
    # """
    # :param connection: a bound Connection object
    # :param members_dn: the list of members to add to groups
    # :param groups_dn: the list of groups where members are to be added
    # :param fix: checks for group existence and already assigned members
    # :param raise_error: If the operation fails it raises an error instead of returning False
    # :return: a boolean where True means that the operation was successful and False means an error has happened
    # Establishes users-groups relations following the Active Directory rules: users are added to the member attribute of groups.
    # Raises LDAPInvalidDnError if members or groups are not found in the DIT.
    # """
    success = microsoft.addMembersToGroups.ad_add_members_to_groups(
        connection=connection, members_dn=member_dns, groups_dn=[grp_dn], raise_error=True)
    demisto.debug(f'addMembersToGroups: {success}')
    if not success:
        raise Exception(success)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Object(s) with dn(s) {member_dns} were added to group {args.get('group-cn')}"
    }
    demisto.results(demisto_entry)


def remove_member_from_group(default_base_dn):
    args = demisto.args()

    search_base = args.get('base-dn') or default_base_dn

    # get the dn of the member - either user or computer
    args_err = "Pleade provide either username or computer-name"
    member_dn = ''

    if args.get('username') and args.get('computer-name'):
        # both arguments passed
        raise Exception(args_err)
    if args.get('username'):
        member_dn = user_dn(args['username'], search_base)
    elif args.get('computer-name'):
        member_dn = computer_dn(args['computer-name'], search_base)
    else:
        # none of the arguments passed
        raise Exception(args_err)

    grp_dn = group_dn(args.get('group-cn'), search_base)

    success = microsoft.removeMembersFromGroups.ad_remove_members_from_groups(connection, [member_dn], [grp_dn], True)
    if not success:
        raise Exception("Failed to remove {} from group {}".format(
            args.get('username') or args.get('computer-name'),
            args.get('group-cn')
        ))

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Object with dn {} removed from group {}".format(member_dn, args.get('group-cn'))
    }
    demisto.results(demisto_entry)


def unlock_account(default_base_dn):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    success = microsoft.unlockAccount.ad_unlock_account(connection, dn)
    if not success:
        raise Exception(f"Failed to unlock user {sam_account_name}")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Unlocked user {sam_account_name}"
    }
    demisto.results(demisto_entry)


''' DELETE OBJECT '''


def delete_user():
    # can actually delete any object...
    assert connection is not None
    success = connection.delete(demisto.args().get('user-dn'))
    if not success:
        raise Exception('Failed to delete user')

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Deleted object with dn {}".format(demisto.args().get('user-dn'))
    }
    demisto.results(demisto_entry)


def delete_group():
    assert connection is not None
    args = demisto.args()

    dn = args.get('dn')

    # delete group
    success = connection.delete(dn)
    if not success:
        raise Exception("Failed to delete group")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': f"Deleted group with DN: {dn}"
    }
    demisto.results(demisto_entry)


def get_mapping_fields_command(search_base):
    ad_attributes = get_all_attributes(search_base)
    # add keys that are not attributes but can be used in mapping
    ad_attributes.extend(("dn", "manageremail"))

    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

    for field in ad_attributes:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


'''
    TEST CONFIGURATION
    authenticate user credentials while initializing connection with AD server
    verify base DN is configured correctly
'''


def set_password_not_expire(default_base_dn):
    args = demisto.args()
    sam_account_name = args.get('username')
    pwd_n_exp = argToBoolean(args.get('value'))

    if not sam_account_name:
        raise Exception("Missing argument - You must specify a username (sAMAccountName).")

    # Query by sAMAccountName
    sam_account_name = escape_filter_chars(sam_account_name)
    query = f"(&(objectClass=User)(objectCategory=person)(sAMAccountName={sam_account_name}))"
    entries = search_with_paging(query, default_base_dn, attributes='userAccountControl')

    if not check_if_user_exists_by_attribute(default_base_dn, "sAMAccountName", sam_account_name):
        return_error(f"sAMAccountName {sam_account_name} was not found.")

    if user := entries.get('flat'):
        user = user[0]
        if user_account_control := user.get('userAccountControl'):
            user_account_control = user_account_control[0]

        # Check if UAC flag for "Password Never Expire" (0x10000) is set to True or False:
        if pwd_n_exp:
            # Sets the bit 16 to 1
            user_account_control |= 1 << 16
            content_output = (f"AD account {sam_account_name} has set \"password never expire\" attribute. "
                              f"Value is set to True")
        else:
            # Clears the bit 16 to 0
            user_account_control &= ~(1 << 16)
            content_output = (f"AD account {sam_account_name} has cleared \"password never expire\" attribute. "
                              f"Value is set to False")

        attribute_name = 'userAccountControl'
        attribute_value = user_account_control
        dn = user_dn(sam_account_name, default_base_dn)
        modification = {attribute_name: [('MODIFY_REPLACE', attribute_value)]}

        # Modify user
        modify_object(dn, modification)
        demisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': content_output
        }
        demisto.results(demisto_entry)

    else:
        raise DemistoException(f"Unable to fetch attribute 'userAccountControl' for user {sam_account_name}.")


def test_credentials_command(server_ip, server, ntlm_connection, auto_bind):
    args = demisto.args()
    username = args.get('username')
    try:
        connection = create_connection(
            server=server,
            server_ip=server_ip,
            username=username,
            password=args.get('password'),
            ntlm_connection=argToBoolean(ntlm_connection),
            auto_bind=auto_bind,
        )
        connection.unbind()
    except LDAPBindError:
        raise DemistoException(f"Credential test with username {username} was not successful.")
    return CommandResults(
        outputs_prefix='ActiveDirectory.ValidCredentials',
        outputs_key_field='username',
        outputs=username,
        readable_output=f"Credential test with username {username} succeeded."
    )


def create_connection(server: Server, server_ip: str, username: str, password: str, ntlm_connection: bool, auto_bind: str | bool):
    domain_name = server_ip + '\\' + username if '\\' not in username else username
    # open socket and bind to server
    return Connection(server, domain_name, password=password, authentication=NTLM, auto_bind=auto_bind) if ntlm_connection \
        else Connection(server, user=username, password=password, auto_bind=auto_bind)


def get_auto_bind_value(secure_connection, unsecure) -> str:
    """
        Returns the proper auto bind value according to the desirable connection type.
        The 'TLS' in the auto_bind parameter refers to the STARTTLS LDAP operation, that can be performed only on a
        cleartext connection (unsecure connection - port 389).

        If the Client's connection type is Start TLS - the secure level will be upgraded to TLS during the
        connection bind itself, and thus we use the AUTO_BIND_TLS_BEFORE_BIND constant.

        If the Client's connection type is Start TLS and the 'Trust any certificate' is unchecked -
        For backwards compatibility - we use the AUTO_BIND_TLS_BEFORE_BIND constant as well.

        If the Client's connection type is SSL - the connection is already secured (server was initialized with
        use_ssl=True and port 636) and therefore we use the AUTO_BIND_NO_TLS constant.

        Otherwise, the Client's connection type is None - the connection is unsecured and should stay unsecured,
        thus we use the AUTO_BIND_NO_TLS constant here as well.
    """
    if secure_connection == START_TLS:
        auto_bind = AUTO_BIND_TLS_BEFORE_BIND

    elif secure_connection == TLS and not unsecure:  # BC
        auto_bind = AUTO_BIND_TLS_BEFORE_BIND

    else:
        auto_bind = AUTO_BIND_NO_TLS

    return auto_bind


def main():
    """ INSTANCE CONFIGURATION """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    server_ip = params.get('server_ip')
    username = params.get('credentials')['identifier']
    password = params.get('credentials')['password']
    default_base_dn = params.get('base_dn')
    secure_connection = params.get('secure_connection')
    ssl_version = params.get('ssl_version', 'None')
    default_page_size = int(params.get('page_size'))
    ntlm_auth = params.get('ntlm')
    insecure = params.get('unsecure', False)
    port = params.get('port')

    disabled_users_group_cn = params.get('group-cn')
    create_if_not_exists = params.get('create-if-not-exists')
    mapper_in = params.get('mapper-in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper-out', DEFAULT_OUTGOING_MAPPER)

    if port:
        # port was configured, cast to int
        port = int(port)
    last_log_detail_level = None
    try:
        set_library_log_hide_sensitive_data(True)
        if is_debug_mode():
            demisto.info('debug-mode: setting library log detail to EXTENDED')
            last_log_detail_level = get_library_log_detail_level()
            set_library_log_detail_level(EXTENDED)

        server = initialize_server(server_ip, port, secure_connection, insecure, ssl_version)

        global connection
        auto_bind = get_auto_bind_value(secure_connection, insecure)

        try:
            # user example: domain\user
            connection = create_connection(
                server=server,
                server_ip=server_ip,
                username=username,
                password=password,
                ntlm_connection=ntlm_auth,
                auto_bind=auto_bind)
        except Exception as e:
            err_msg = str(e)
            demisto.info(f"Failed connect to: {server_ip}:{port}. {type(e)}:{err_msg}\n"
                         f"Trace:\n{traceback.format_exc()}")
            if isinstance(e, LDAPBindError):
                message = (f'Failed to bind server. Please validate that the credentials are configured correctly.\n'
                           f'Additional details: {err_msg}.\n')
            elif isinstance(e, LDAPSocketOpenError | LDAPSocketReceiveError | LDAPStartTLSError):
                message = f'Failed to access LDAP server. \n Additional details: {err_msg}.\n'
                if not insecure and secure_connection in (SSL, START_TLS):
                    message += ' Try using: "Trust any certificate" option.\n'
            else:
                message = ("Failed to access LDAP server. Please validate the server host and port are configured "
                           "correctly.\n")
            return_error(message)
            return None

        demisto.info(f'Established connection with AD LDAP server.\nLDAP Connection Details: {connection}')

        if not base_dn_verified(default_base_dn):
            message = (f"Failed to verify the base DN configured for the instance.\n"
                       f"Last connection result: {json.dumps(connection.result)}\n"
                       f"Last error from LDAP server: {json.dumps(connection.last_error)}")
            return_error(message)
            return None

        demisto.info(f'Verified base DN "{default_base_dn}"')

        ''' COMMAND EXECUTION '''

        if command == 'test-module':
            if connection.user == '':
                # Empty response means you have no authentication status on the server, so you are an anonymous user.
                raise Exception("Failed to authenticate user")
            demisto.results('ok')

        elif command == 'ad-search':
            free_search(default_base_dn, default_page_size)

        elif command == 'ad-modify-password-never-expire':
            set_password_not_expire(default_base_dn)

        elif command == 'ad-expire-password':
            expire_user_password(default_base_dn)

        elif command == 'ad-set-new-password':
            set_user_password(default_base_dn, port)

        elif command == 'ad-unlock-account':
            unlock_account(default_base_dn)

        elif command == 'ad-disable-account':
            disable_user(default_base_dn, default_page_size)

        elif command == 'ad-enable-account':
            enable_user(default_base_dn, default_page_size)

        elif command == 'ad-remove-from-group':
            remove_member_from_group(default_base_dn)

        elif command == 'ad-add-to-group':
            add_member_to_group(default_base_dn)

        elif command == 'ad-create-user':
            create_user()

        elif command == 'ad-delete-user':
            delete_user()

        elif command == 'ad-update-user':
            update_user(default_base_dn)

        elif command == 'ad-update-group':
            update_group(default_base_dn)

        elif command == 'ad-modify-computer-ou':
            modify_computer_ou(default_base_dn)

        elif command == 'ad-modify-user-ou':
            return_results(modify_user_ou_command(default_base_dn))

        elif command == 'ad-create-contact':
            create_contact()

        elif command == 'ad-update-contact':
            update_contact()

        elif command == 'ad-get-user':
            search_users(default_base_dn, default_page_size)

        elif command == 'ad-get-computer':
            search_computers(default_base_dn, default_page_size)

        elif command == 'ad-get-group-members':
            search_group_members(default_base_dn, default_page_size)

        elif command == 'ad-create-group':
            create_group()

        elif command == 'ad-delete-group':
            delete_group()

        elif command == 'ad-test-credentials':
            return return_results(test_credentials_command(server_ip, server, ntlm_connection=ntlm_auth, auto_bind=auto_bind))

        # IAM commands
        elif command == 'iam-get-user':
            user_profile = get_user_iam(default_base_dn, args, mapper_in, mapper_out)
            return return_results(user_profile)

        elif command == 'iam-create-user':
            user_profile = create_user_iam(default_base_dn, args, mapper_out, disabled_users_group_cn)
            return return_results(user_profile)

        elif command == 'iam-update-user':
            user_profile = update_user_iam(default_base_dn, args, create_if_not_exists, mapper_out,
                                           disabled_users_group_cn)
            return return_results(user_profile)

        elif command == 'iam-disable-user':
            user_profile = disable_user_iam(default_base_dn, disabled_users_group_cn, args, mapper_out)
            return return_results(user_profile)

        elif command == 'get-mapping-fields':
            mapping_fields = get_mapping_fields_command(default_base_dn)
            return return_results(mapping_fields)

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        message = str(e)
        if connection:
            message += (f"\nLast connection result: {json.dumps(connection.result)}\n"
                        f"Last error from LDAP server: {connection.last_error}")
        return_error(message)
        return None

    finally:
        # disconnect and close the connection
        if connection:
            connection.unbind()
        if last_log_detail_level:
            set_library_log_detail_level(last_log_detail_level)


from IAMApiModule import *  # noqa: E402

# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

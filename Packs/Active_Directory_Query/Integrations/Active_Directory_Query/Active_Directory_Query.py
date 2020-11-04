import demistomock as demisto
from CommonServerPython import *
from typing import List, Dict, Optional
from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES, Tls, Entry, Reader, ObjectDef
from ldap3.extend import microsoft
import ssl
from datetime import datetime
import traceback
import os
from ldap3.utils.log import (set_library_log_detail_level, get_library_log_detail_level,
                             set_library_log_hide_sensitive_data, EXTENDED)

# global connection
conn: Optional[Connection] = None

''' GLOBAL VARS '''

# userAccountControl is a bitmask used to store a number of settings.
# find more at:
# https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
DEFAULT_OUTGOING_MAPPER = "User Profile - Active Directory (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Active Directory (Incoming)"

COOMON_ACCOUNT_CONTROL_FLAGS = {
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
FIELDS_THAT_CANT_BE_MODIFIED = [
    "dn", "samaccountname", "cn", "ou"
]

''' HELPER FUNCTIONS '''


def initialize_server(host, port, secure_connection, unsecure):
    """
    uses the instance configuration to initialize the LDAP server

    :param host: host or ip
    :type host: string
    :param port: port or None
    :type port: number
    :param secure_connection: SSL or None
    :type secure_connection: string
    :param unsecure: trust any cert
    :type unsecure: boolean
    :return: ldap3 Server
    :rtype: Server
    """

    if secure_connection == "SSL":
        # intialize server with ssl
        # port is configured by default as 389 or as 636 for LDAPS if not specified in configuration
        demisto.debug("initializing sever with ssl (unsecure: {}). port: {}". format(unsecure, port or 'default(636)'))
        if not unsecure:
            demisto.debug("will require server certificate.")
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get('SSL_CERT_FILE'))
            if port:
                return Server(host, port=port, use_ssl=True, tls=tls)
            return Server(host, use_ssl=True, tls=tls)
        if port:
            return Server(host, port=port, use_ssl=True)
        return Server(host, use_ssl=True)
    demisto.debug("initializing server without secure connection. port: {}". format(port or 'default(389)'))
    if port:
        return Server(host, port=port)
    return Server(host)


def account_entry(person_object, custome_attributes):
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
        person_object_key.lower(): person_object_key for person_object_key in person_object.keys()
    }

    for attr in custome_attributes:
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


def endpoint_entry(computer_object, custome_attributes):
    # create an endpoint entry from a computer object
    endpoint = {
        'Type': 'AD',
        'ID': computer_object.get('dn'),
        'Hostname': computer_object.get('name'),
        'Groups': computer_object.get('memberOf')
    }

    lower_cased_person_object_keys = {
        person_object_key.lower(): person_object_key for person_object_key in computer_object.keys()
    }

    for attr in custome_attributes:
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


def base_dn_verified(base_dn):
    # serch AD with a simple query to test base DN is configured correctly
    try:
        search(
            "(objectClass=user)",
            base_dn,
            size_limit=1
        )
    except Exception as e:
        demisto.info(str(e))
        return False
    return True


def generate_dn_and_remove_from_user_profile(user):
    """Generates a user dn, in case user dn is included in the user, will return it, otherwise
    will generate one using the cn and ou values
    :param user: The user dict including his values
    :return: The user's dn.
    """
    user_dn = user.get("dn")
    if user_dn:
        user.pop("dn")
        return user_dn

    cn = user.get("cn")
    ou = user.get("ou")

    return 'CN=' + str(cn) + ',' + str(ou)


def check_if_user_exists_by_samaccountname(default_base_dn, samaccountname):
    """Check if user exists base on his samaccountname
    :param default_base_dn: The location in the DIT where the search will start
    :param samaccountname: The user's unique samaccountname
    :return: True if the user exists, False otherwise.
    """
    query = f'(&(objectClass=User)(objectCategory=person)(samaccountname={samaccountname}))'
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=["samaccountname"],
        size_limit=1,
        page_size=1
    )

    if entries.get('flat'):
        return True

    return False


def modify_user_ou(dn, new_ou):
    assert conn is not None
    cn = dn.split(',', 1)[0]

    success = conn.modify_dn(dn, cn, new_superior=new_ou)
    return success


def get_all_attributes(search_base):
    obj_inetorgperson = ObjectDef('user', conn)
    r = Reader(conn, obj_inetorgperson, search_base)
    r.search()
    if not r:
        return []
    if not r[0]:
        return []
    attributes = r[0].entry_attributes
    return attributes


''' COMMANDS '''

''' SEARCH '''


def search(search_filter, search_base, attributes=None, size_limit=0, time_limit=0):
    """
    find entries in the DIT

    Args:
        search_base: the location in the DIT where the search will start
        search_filte: LDAP query string
        attributes: the attributes to specify for each entry found in the DIT

    """
    assert conn is not None
    success = conn.search(
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
        size_limit=size_limit,
        time_limit=time_limit
    )

    if not success:
        raise Exception("Search failed")
    return conn.entries


def search_with_paging(search_filter, search_base, attributes=None, page_size=100, size_limit=0, time_limit=0):
    """
    find entries in the DIT

    Args:
        search_base: the location in the DIT where the search will start
        search_filter: LDAP query string
        attributes: the attributes to specify for each entrxy found in the DIT

    """
    assert conn is not None
    total_entries = 0
    cookie = None
    start = datetime.now()

    entries: List[Entry] = []
    entries_left_to_fetch = size_limit
    while True:
        if 0 < entries_left_to_fetch < page_size:
            page_size = entries_left_to_fetch

        conn.search(
            search_base,
            search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            paged_cookie=cookie
        )

        entries_left_to_fetch -= len(conn.entries)
        total_entries += len(conn.entries)
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        time_diff = (start - datetime.now()).seconds

        entries.extend(conn.entries)

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

    return {
        "raw": raw,
        "flat": flat
    }


def user_dn(sam_account_name, search_base):
    search_filter = '(&(objectClass=user)(sAMAccountName={}))'.format(sam_account_name)
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception("Could not get full DN for user with sAMAccountName '{}'".format(sam_account_name))
    entry = json.loads(entries[0].entry_to_json())
    return entry['dn']


def computer_dn(compuer_name, search_base):
    search_filter = '(&(objectClass=user)(objectCategory=computer)(name={}))'.format(compuer_name)
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception("Could not get full DN for computer with name '{}'".format(compuer_name))
    entry = json.loads(entries[0].entry_to_json())
    return entry['dn']


def group_dn(group_name, search_base):
    search_filter = '(&(objectClass=group)(cn={}))'.format(group_name)
    entries = search(
        search_filter,
        search_base
    )
    if not entries:
        raise Exception("Could not get full DN for group with name '{}'".format(group_name))
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

    entries = search_with_paging(
        search_filter,
        search_base,
        attributes=attributes,
        size_limit=size_limit,
        time_limit=time_limit,
        page_size=page_size
    )

    ec = {} if context_output == 'no' else {'ActiveDirectory.Search(obj.dn == val.dn)': entries['flat']}
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

    attributes: List[str] = []
    custom_attributes: List[str] = []

    # zero is actually no limitation, default is 20
    limit = int(args.get('limit', '20'))
    if limit <= 0:
        limit = 20

    # default query - list all users
    query = "(&(objectClass=User)(objectCategory=person))"

    # query by user DN
    if args.get('dn'):
        query = "(&(objectClass=User)(objectCategory=person)(distinguishedName={}))".format(args['dn'])

    # query by name
    if args.get('name'):
        query = "(&(objectClass=User)(objectCategory=person)(cn={}))".format(args['name'])

    # query by email
    if args.get('email'):
        query = "(&(objectClass=User)(objectCategory=person)(mail={}))".format(args['email'])

    # query by sAMAccountName
    if args.get('username'):
        query = "(&(objectClass=User)(objectCategory=person)(sAMAccountName={}))".format(args['username'])

    # query by custom object attribute
    if args.get('custom-field-type'):
        if not args.get('custom-field-data'):
            raise Exception('Please specify "custom-field-data" as well when quering by "custom-field-type"')
        query = "(&(objectClass=User)(objectCategory=person)({}={}))".format(
            args['custom-field-type'], args['custom-field-data'])

    if args.get('attributes'):
        custom_attributes = args['attributes'].split(",")

    attributes = list(set(custom_attributes + DEFAULT_PERSON_ATTRIBUTES))

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        size_limit=limit,
        page_size=page_size
    )

    accounts = [account_entry(entry, custom_attributes) for entry in entries['flat']]

    if args.get('user-account-control-out', '') == 'true':
        # display a literal translation of the numeric account control flag
        for i, user in enumerate(entries['flat']):
            flag_no = user.get('userAccountControl')[0]
            entries['flat'][i]['userAccountControl'] = COOMON_ACCOUNT_CONTROL_FLAGS.get(flag_no) or flag_no

    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory - Get Users", entries['flat']),
        'EntryContext': {
            'ActiveDirectory.Users(obj.dn == val.dn)': entries['flat'],
            # 'backward compatability' with ADGetUser script
            'Account(obj.ID == val.ID)': accounts
        }
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
        default_attribute = "samaccountname"

        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta)

        ad_user = iam_user_profile.map_object(mapper_name=mapper_out)

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
            iam_user_profile.set_result(success=False,
                                        error_message="No user was found",
                                        action=IAMActions.GET_USER
                                        )
        else:
            ad_user = entries.get('flat')[0]
            user_account_control = ad_user.get('userAccountControl') not in INACTIVE_LIST_OPTIONS
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
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.GET_USER
                                    )
        return iam_user_profile


def search_computers(default_base_dn, page_size):
    # this command is equivalent to ADGetComputer script

    args = demisto.args()
    attributes: List[str] = []
    custome_attributes: List[str] = []

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

    if args.get('attributes'):
        custome_attributes = args['attributes'].split(",")
    attributes = list(set(custome_attributes + DEFAULT_COMPUTER_ATTRIBUTES))
    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        page_size=page_size
    )

    endpoints = [endpoint_entry(entry, custome_attributes) for entry in entries['flat']]

    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory - Get Computers", entries['flat']),
        'EntryContext': {
            'ActiveDirectory.Computers(obj.dn == val.dn)': entries['flat'],
            # 'backward compatability' with ADGetComputer script
            'Endpoint(obj.ID == val.ID)': endpoints
        }
    }
    demisto.results(demisto_entry)


def search_group_members(default_base_dn, page_size):
    # this command is equivalent to ADGetGroupMembers script

    args = demisto.args()
    member_type = args.get('member-type')
    group_dn = args.get('group-dn')
    nested_search = '' if args.get('disable-nested-search') == 'true' else ':1.2.840.113556.1.4.1941:'
    time_limit = int(args.get('time_limit', 180))

    custome_attributes: List[str] = []
    default_attributes = DEFAULT_PERSON_ATTRIBUTES if member_type == 'person' else DEFAULT_COMPUTER_ATTRIBUTES

    if args.get('attributes'):
        custome_attributes = args['attributes'].split(",")

    attributes = list(set(custome_attributes + default_attributes))

    query = "(&(objectCategory={})(objectClass=user)(memberOf{}={}))".format(member_type, nested_search, group_dn)

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        page_size=page_size,
        time_limit=time_limit
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
            }
        }
    }

    if member_type == 'person':
        demisto_entry['EntryContext']['ActiveDirectory.Users(obj.dn == val.dn)'] = entries['flat']
        demisto_entry['EntryContext']['Account'] = [account_entry(
            entry, custome_attributes) for entry in entries['flat']]
    else:
        demisto_entry['EntryContext']['ActiveDirectory.Computers(obj.dn == val.dn)'] = entries['flat']
        demisto_entry['EntryContext']['Endpoint'] = [endpoint_entry(
            entry, custome_attributes) for entry in entries['flat']]

    demisto.results(demisto_entry)


''' DATABASE OPERATIONS '''

''' CREATE OBJECT'''


def create_user():
    assert conn is not None
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "user"]
    user_dn = args.get('user-dn')
    username = args.get("username")
    password = args.get("password")
    custome_attributes = args.get('custom-attributes')
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

    # set user custome attributes
    if custome_attributes:
        try:
            custome_attributes = json.loads(custome_attributes)
        except Exception as e:
            demisto.info(str(e))
            raise Exception(
                "Failed to parse custom attributes argument. Please see an example of this argument in the description."
            )
        for attribute_name, attribute_value in custome_attributes.items():
            # can run default attribute stting
            attributes[attribute_name] = attribute_value

    # add user
    success = conn.add(user_dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create user")

    # set user password
    success = conn.extend.microsoft.modify_password(user_dn, password)
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
        'Contents': "Created user with DN: {}".format(user_dn)
    }
    demisto.results(demisto_entry)


def create_user_iam(default_base_dn, args, mapper_out):
    """Creates an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param args: Demisto args.
    :param mapper_out: Mapping User Profiles to AD users.
    :return: The user that was created
    """
    assert conn is not None
    try:

        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta)
        ad_user = iam_user_profile.map_object(mapper_name=mapper_out)

        sam_account_name = ad_user.get("samaccountname")
        if not sam_account_name:
            raise DemistoException("User must have SAMAccountName")
        user_exists = check_if_user_exists_by_samaccountname(default_base_dn, sam_account_name)
        if user_exists:
            iam_user_profile.set_result(success=True, action=IAMActions.CREATE_USER,
                                        skip=True, skip_reason="User already exists")

        else:
            user_dn = generate_dn_and_remove_from_user_profile(ad_user)

            object_classes = ["top", "person", "organizationalPerson", "user"]

            success = conn.add(user_dn, object_classes, ad_user)
            if success:
                iam_user_profile.set_result(success=True,
                                            email=ad_user.get('email'),
                                            username=ad_user.get('name'),
                                            details=ad_user,
                                            action=IAMActions.CREATE_USER,
                                            active=True)

            else:
                iam_user_profile.set_result(success=False,
                                            error_message="Failed to create user",
                                            action=IAMActions.CREATE_USER
                                            )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.CREATE_USER,
                                    )
        return iam_user_profile


def update_user_iam(default_base_dn, args, create_if_not_exists, mapper_out):
    """Update an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param args: Demisto args.
    :param create_if_not_exists: Created the user if it does not exists.
    :param mapper_out: Mapping User Profiles to AD users.
    :return: Updated User
    """
    assert conn is not None
    try:
        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta)

        ad_user = iam_user_profile.map_object(mapper_name=mapper_out)

        # check it user exists and if it doesn't, create it
        sam_account_name = ad_user.get("samaccountname")
        if not sam_account_name:
            raise DemistoException("User must have SAMAccountName")

        new_ou = ad_user.get("ou")
        user_exists = check_if_user_exists_by_samaccountname(default_base_dn, sam_account_name)

        if not user_exists and create_if_not_exists:
            return create_user_iam(default_base_dn, args, mapper_out)

        elif user_exists:

            dn = user_dn(sam_account_name, default_base_dn)

            # fields that can't be modified
            # notice that we are changing the ou and that effects the dn and cn
            for field in FIELDS_THAT_CANT_BE_MODIFIED:
                if ad_user.get(field):
                    ad_user.pop(field)

            fail_to_modify = []

            for key in ad_user:
                modification = {key: [('MODIFY_REPLACE', ad_user.get(key))]}
                success = conn.modify(dn, modification)
                if not success:
                    fail_to_modify.append(key)

            ou_modified_succeed = modify_user_ou(dn, new_ou)
            if not ou_modified_succeed:
                fail_to_modify.append("ou")

            if fail_to_modify:
                error_list = '\n'.join(fail_to_modify)
                error_message = f"Fail to modify the following attributes: {error_list}"
                iam_user_profile.set_result(success=False,
                                            error_message=error_message,
                                            action=IAMActions.UPDATE_USER,
                                            )

            else:
                active = ad_user.get('userAccountControl') not in INACTIVE_LIST_OPTIONS
                iam_user_profile.set_result(success=True,
                                            email=ad_user.get('email'),
                                            username=ad_user.get('name'),
                                            action=IAMActions.UPDATE_USER,
                                            details=ad_user,
                                            active=active)
        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def create_contact():
    assert conn is not None
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "contact"]
    contact_dn = args.get('contact-dn')

    # set contact attributes
    attributes: Dict = {}
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

    success = conn.add(contact_dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create contact")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Created contact with DN: {}".format(contact_dn)
    }
    demisto.results(demisto_entry)


def create_group():
    assert conn is not None
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
    success = conn.add(dn, object_classes, attributes)
    if not success:
        raise Exception("Failed to create group")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Created group with DN: {}".format(dn)
    }
    demisto.results(demisto_entry)


''' UPDATE OBJECT '''


def modify_object(dn, modification):
    """
    modifies object in the DIT
    """
    assert conn is not None
    success = conn.modify(dn, modification)
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
        'Contents': "Updated user's {} to {} ".format(attribute_name, attribute_value)
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
    assert conn is not None
    args = demisto.args()

    computer_name = args.get('computer-name')
    dn = computer_dn(computer_name, args.get('base-dn') or default_base_dn)

    success = conn.modify_dn(dn, "CN={}".format(computer_name), new_superior=args.get('full-superior-dn'))
    if not success:
        raise Exception("Failed to modify computer OU")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Moved computer {} to {}".format(computer_name, args.get('full-superior-dn'))
    }
    demisto.results(demisto_entry)


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


def set_user_password(default_base_dn):
    assert conn is not None
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    password = args.get('password')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    # set user password
    success = conn.extend.microsoft.modify_password(dn, password)
    if not success:
        raise Exception("Failed to reset user password")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "User password successfully set"
    }
    demisto.results(demisto_entry)


def enable_user(default_base_dn):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    # modify user
    modification = {
        'userAccountControl': [('MODIFY_REPLACE', NORMAL_ACCOUNT)]
    }
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "User {} was enabled".format(sam_account_name)
    }
    demisto.results(demisto_entry)


def disable_user(default_base_dn):
    args = demisto.args()

    # get user DN
    sam_account_name = args.get('username')
    search_base = args.get('base-dn') or default_base_dn
    dn = user_dn(sam_account_name, search_base)

    # modify user
    modification = {
        'userAccountControl': [('MODIFY_REPLACE', DISABLED_ACCOUNT)]
    }
    modify_object(dn, modification)

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "User {} was disabled".format(sam_account_name)
    }
    demisto.results(demisto_entry)


def enable_user_iam(default_base_dn, disabled_users_group_cn, args, create_if_not_exists, mapper_out):
    """Enables an AD user by User Profile.
    :param default_base_dn: The location in the DIT where the search will start
    :param disabled_users_group_cn: The disabled group cn, the user will be removed from this group when enabled
    :param args: Demisto args.
    :param create_if_not_exists: Created the user if it does not exists.
    :param mapper_out: Mapping User Profiles to AD users.
    :return: The enabled user
    """
    try:
        user_profile = args.get("user-profile")
        user_profile_delta = args.get('user-profile-delta')
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta)

        ad_user = iam_user_profile.map_object(mapper_name=mapper_out)

        # check it user exists and if it doesn't, create it
        sam_account_name = ad_user.get("samaccountname")
        if not sam_account_name:
            raise DemistoException("User must have SAMAccountName")

        user_exists = check_if_user_exists_by_samaccountname(default_base_dn, sam_account_name)

        if not user_exists and create_if_not_exists:
            return create_user_iam(default_base_dn, iam_user_profile, mapper_out)

        dn = user_dn(sam_account_name, default_base_dn)

        # modify user to enable account
        modification = {
            'userAccountControl': [('MODIFY_REPLACE', NORMAL_ACCOUNT)]
        }

        # Enable account and update with attributes if any
        command_failed = False
        modify_object(dn, modification)
        if disabled_users_group_cn:
            grp_dn = group_dn(disabled_users_group_cn, default_base_dn)
            success = microsoft.removeMembersFromGroups.ad_remove_members_from_groups(conn, [dn], [grp_dn], True)
            if not success:
                command_failed = True
                e = 'Failed to add user to {} group'.format(disabled_users_group_cn)
                iam_user_profile.set_result(success=False,
                                            error_message=e,
                                            action=IAMActions.ENABLE_USER,
                                            )
        if not command_failed:
            iam_user_profile.set_result(success=True,
                                        email=ad_user.get('email'),
                                        username=ad_user.get('name'),
                                        action=IAMActions.ENABLE_USER,
                                        details=ad_user,
                                        active=True)

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.ENABLE_USER,
                                    )
        return iam_user_profile


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
        iam_user_profile = IAMUserProfile(user_profile=user_profile, user_profile_delta=user_profile_delta)
        ad_user = iam_user_profile.map_object(mapper_name=mapper_out)

        sam_account_name = ad_user.get("samaccountname")
        if not sam_account_name:
            raise DemistoException("User must have SAMAccountName")

        user_exists = check_if_user_exists_by_samaccountname(default_base_dn, sam_account_name)
        if not user_exists:
            iam_user_profile.set_result(success=True, action=IAMActions.DISABLE_USER,
                                        skip=True, skip_reason="User doesn't exists")
            return iam_user_profile

        dn = user_dn(sam_account_name, default_base_dn)

        # modify user
        modification = {
            'userAccountControl': [('MODIFY_REPLACE', DISABLED_ACCOUNT)]
        }

        command_failed = False
        modify_object(dn, modification)
        if disabled_users_group_cn:

            grp_dn = group_dn(disabled_users_group_cn, default_base_dn)
            success = microsoft.addMembersToGroups.ad_add_members_to_groups(conn, [dn], [grp_dn])
            if not success:
                command_failed = True
                e = 'Failed to remove user from {} group'.format(disabled_users_group_cn)
                iam_user_profile.set_result(success=False,
                                            error_message=e,
                                            action=IAMActions.DISABLE_USER,
                                            )
        if not command_failed:
            iam_user_profile.set_result(success=True,
                                        email=ad_user.get('email'),
                                        username=ad_user.get('name'),
                                        action=IAMActions.DISABLE_USER,
                                        details=ad_user,
                                        active=False)

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


def add_member_to_group(default_base_dn):

    args = demisto.args()

    search_base = args.get('base-dn') or default_base_dn

    # get the  dn of the member - either user or computer
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

    success = microsoft.addMembersToGroups.ad_add_members_to_groups(conn, [member_dn], [grp_dn])
    if not success:
        raise Exception("Failed to add {} to group {}".format(
            args.get('username') or args.get('computer-name'),
            args.get('group_name')
        ))

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Object with dn {} was added to group {}".format(member_dn, args.get('group-cn'))
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

    success = microsoft.removeMembersFromGroups.ad_remove_members_from_groups(conn, [member_dn], [grp_dn], True)
    if not success:
        raise Exception("Failed to remove {} from group {}".format(
            args.get('username') or args.get('computer-name'),
            args.get('group_name')
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

    success = microsoft.unlockAccount.ad_unlock_account(conn, dn)
    if not success:
        raise Exception("Failed to unlock user {}".format(sam_account_name))

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Unlocked user {}".format(sam_account_name)
    }
    demisto.results(demisto_entry)


''' DELETE OBJECT '''


def delete_user():
    # can actually delete any object...
    assert conn is not None
    success = conn.delete(demisto.args().get('user-dn'))
    if not success:
        raise Exception('Failed to delete user')

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Deleted object with dn {}".format(demisto.args().get('user-dn'))
    }
    demisto.results(demisto_entry)


def delete_group():
    assert conn is not None
    args = demisto.args()

    dn = args.get('dn')

    # delete group
    success = conn.delete(dn)
    if not success:
        raise Exception("Failed to delete group")

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Deleted group with DN: {}".format(dn)
    }
    demisto.results(demisto_entry)


def get_mapping_fields_command(search_base):
    ad_attributes = get_all_attributes(search_base)
    # add keys that are not attributes but can be used in mapping
    ad_attributes.extend(("dn", "samaccountname"))

    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field in ad_attributes:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


'''
    TEST CONFIGURATION
    authenticate user credentials while initializing connection with AD server
    verify base DN is configured correctly
'''


def main():
    ''' INSTANCE CONFIGURATION '''
    params = demisto.params()

    SERVER_IP = params.get('server_ip')
    USERNAME = params.get('credentials')['identifier']
    PASSWORD = params.get('credentials')['password']
    DEFAULT_BASE_DN = params.get('base_dn')
    SECURE_CONNECTION = params.get('secure_connection')
    DEFAULT_PAGE_SIZE = int(params.get('page_size'))
    NTLM_AUTH = params.get('ntlm')
    UNSECURE = params.get('unsecure', False)
    PORT = params.get('port')

    disabled_users_group_cn = params.get('group-cn')
    create_if_not_exists = params.get('create-if-not-exists')
    mapper_in = params.get('mapper-in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper-out', DEFAULT_OUTGOING_MAPPER)

    if PORT:
        # port was configured, cast to int
        PORT = int(PORT)
    last_log_detail_level = None
    try:
        try:
            set_library_log_hide_sensitive_data(True)
            if is_debug_mode():
                demisto.info('debug-mode: setting library log detail to EXTENDED')
                last_log_detail_level = get_library_log_detail_level()
                set_library_log_detail_level(EXTENDED)
            server = initialize_server(SERVER_IP, PORT, SECURE_CONNECTION, UNSECURE)
        except Exception as e:
            return_error(str(e))
            return
        global conn
        if NTLM_AUTH:
            # intialize connection to LDAP server with NTLM authentication
            # user example: domain\user
            domain_user = SERVER_IP + '\\' + USERNAME if '\\' not in USERNAME else USERNAME
            conn = Connection(server, user=domain_user, password=PASSWORD, authentication=NTLM)
        else:
            # here username should be the user dn
            conn = Connection(server, user=USERNAME, password=PASSWORD)

        # bind operation is the “authenticate” operation.
        try:
            # open socket and bind to server
            if not conn.bind():
                message = "Failed to bind to server. Please validate the credentials configured correctly.\n{}".format(
                    json.dumps(conn.result))
                return_error(message)
                return
        except Exception as e:
            exc_msg = str(e)
            demisto.info("Failed bind to: {}:{}. {}: {}".format(SERVER_IP, PORT, type(e), exc_msg
                         + "\nTrace:\n{}".format(traceback.format_exc())))
            message = "Failed to access LDAP server. Please validate the server host and port are configured correctly"
            if 'ssl wrapping error' in exc_msg:
                message = "Failed to access LDAP server. SSL error."
                if not UNSECURE:
                    message += ' Try using: "Trust any certificate" option.'
            return_error(message)
            return

        demisto.info('Established connection with AD LDAP server')

        if not base_dn_verified(DEFAULT_BASE_DN):
            message = "Failed to verify the base DN configured for the instance.\n" \
                "Last connection result: {}\n" \
                "Last error from LDAP server: {}".format(json.dumps(conn.result), json.dumps(conn.last_error))
            return_error(message)
            return

        demisto.info('Verfied base DN "{}"'.format(DEFAULT_BASE_DN))

        ''' COMMAND EXECUTION '''

        if demisto.command() == 'test-module':
            if conn.user == '':
                # Empty response means you have no authentication status on the server, so you are an anonymous user.
                raise Exception("Failed to authenticate user")
            demisto.results('ok')

        args = demisto.args()

        if demisto.command() == 'ad-search':
            free_search(DEFAULT_BASE_DN, DEFAULT_PAGE_SIZE)

        if demisto.command() == 'ad-expire-password':
            expire_user_password(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-set-new-password':
            set_user_password(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-unlock-account':
            unlock_account(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-disable-account':
            disable_user(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-enable-account':
            enable_user(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-remove-from-group':
            remove_member_from_group(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-add-to-group':
            add_member_to_group(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-create-user':
            create_user()

        if demisto.command() == 'ad-delete-user':
            delete_user()

        if demisto.command() == 'ad-update-user':
            update_user(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-modify-computer-ou':
            modify_computer_ou(DEFAULT_BASE_DN)

        if demisto.command() == 'ad-create-contact':
            create_contact()

        if demisto.command() == 'ad-update-contact':
            update_contact()

        if demisto.command() == 'ad-get-user':
            search_users(DEFAULT_BASE_DN, DEFAULT_PAGE_SIZE)

        if demisto.command() == 'ad-get-computer':
            search_computers(DEFAULT_BASE_DN, DEFAULT_PAGE_SIZE)

        if demisto.command() == 'ad-get-group-members':
            search_group_members(DEFAULT_BASE_DN, DEFAULT_PAGE_SIZE)

        if demisto.command() == 'ad-create-group':
            create_group()

        if demisto.command() == 'ad-delete-group':
            delete_group()

        # IAM commands
        if demisto.command() == 'iam-get-user':
            user_profile = get_user_iam(DEFAULT_BASE_DN, args, mapper_in, mapper_out)
            return return_results(user_profile)

        if demisto.command() == 'iam-create-user':
            user_profile = create_user_iam(DEFAULT_BASE_DN, args, mapper_out)
            return return_results(user_profile)

        if demisto.command() == 'iam-update-user':
            user_profile = update_user_iam(DEFAULT_BASE_DN, args, create_if_not_exists, mapper_out)
            return return_results(user_profile)

        if demisto.command() == 'iam-enable-user':
            user_profile = enable_user_iam(DEFAULT_BASE_DN, disabled_users_group_cn, args, create_if_not_exists, mapper_out)
            return return_results(user_profile)

        if demisto.command() == 'iam-disable-user':
            user_profile = disable_user_iam(DEFAULT_BASE_DN, disabled_users_group_cn, args, mapper_out)
            return return_results(user_profile)

        elif demisto.command() == 'get-mapping-fields':
            mapping_fields = get_mapping_fields_command(DEFAULT_BASE_DN)
            return return_results(mapping_fields)

    except Exception as e:
        message = str(e)
        if conn:
            message += "\nLast connection result: {}\nLast error from LDAP server: {}".format(
                json.dumps(conn.result), conn.last_error)
        return_error(message)
        return
    finally:
        # disconnect and close the connection
        if conn:
            conn.unbind()
        if last_log_detail_level:
            set_library_log_detail_level(last_log_detail_level)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()

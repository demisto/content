import demistomock as demisto
from CommonServerPython import *
from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES, Tls
from ldap3.core.exceptions import LDAPSocketOpenError
from ldap3.extend import microsoft
import ssl
from datetime import datetime


# global connection
conn = None

''' GLOBAL VARS '''

# userAccountControl is a bitmask used to store a number of settings.
# find more at:
# https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro

COOMON_ACCOUNT_CONTROL_FLAGS = {
    512: "Enabled Account",
    514: "Disabled account",
    544: "Account Enabled - Require user to change password at first logon",
    4096: "Workstation/server",
    66048: "Enabled, password never expires",
    66050: "Disabled, password never expires",
    66080: "Enables, password never expires, password not required.",
    532480: "Domain controller"
}
NORMAL_ACCOUNT = 512
DISABLED_ACCOUNT = 514

# common attributes for specific AD objects
DEFAULT_PERSON_ATTRIBUTES = [
    'name',
    'displayName',
    'memberOf',
    'mail',
    'samAccountName',
    'manager',
    'userAccountControl'
]
DEFAULT_COMPUTER_ATTRIBUTES = [
    'name',
    'memberOf'
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
            tls = Tls(validate=ssl.CERT_REQUIRED)
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
        'Email': person_object.get('email'),
        'Username': person_object.get('samAccountName'),
        'DisplayName': person_object.get('displayName'),
        'Managr': person_object.get('manager'),
        'Groups': person_object.get('memberOf')
    }

    for attr in custome_attributes:
        account[attr] = person_object[attr]

    return account


def endpoint_entry(computer_object, custome_attributes):
    # create an endpoint entry from a computer object
    endpoint = {
        'Type': 'AD',
        'ID': computer_object.get('dn'),
        'Hostname': computer_object.get('name'),
        'Groups': computer_object.get('memberOf')
    }

    for attr in custome_attributes:
        endpoint[attr] = computer_object[attr]

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
    success = conn.search(
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
        size_limit=size_limit,
        time_limit=time_limit
    )

    if not success:
        raise("Search failed")
    return conn.entries


def search_with_paging(search_filter, search_base, attributes=None, page_size=100, size_limit=0, time_limit=0):
    """
    find entries in the DIT

    Args:
        search_base: the location in the DIT where the search will start
        search_filte: LDAP query string
        attributes: the attributes to specify for each entrxy found in the DIT

    """

    total_entries = 0
    cookie = None
    start = datetime.now()

    entries = []

    while True:
        if size_limit and size_limit < page_size:
            page_size = size_limit

        conn.search(
            search_base,
            search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            paged_cookie=cookie
        )

        total_entries += len(conn.entries)
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        time_diff = (start - datetime.now()).seconds

        entries.extend(conn.entries)

        # stop when: 1.reached size limit 2.reached time limit 3. no cookie
        if (size_limit and size_limit >= total_entries) or (time_limit and time_diff >= time_limit) or (not cookie):
            break

    # keep the raw entry for raw content (backward compatability)
    raw = []
    # flaten the entries
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


def free_search(default_base_dn, page_size):

    args = demisto.args()

    search_filter = args.get('filter')
    size_limit = int(args.get('size-limit', '0'))
    time_limit = int(args.get('time-limit', '0'))
    search_base = args.get('base-dn') or default_base_dn
    attributes = args.get('attributes')

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

    demisto_entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': entries['raw'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Active Directory Search", entries['flat']),
        'EntryContext': {
            'ActiveDirectory.Search(obj.dn == val.dn)': entries['flat']
        }
    }
    demisto.results(demisto_entry)


def search_users(default_base_dn, page_size):
    # this command is equivalant to script ADGetUser
    # will preform a custom search to find users by a specific (one) attribute specified by the user

    args = demisto.args()

    attributes = []
    custome_attributes = []

    # zero is actually no limitation
    limit = int(args.get('limit', '0'))

    # default query - list all users
    query = "(objectClass=User)(objectCategory=person)"

    # query by user DN
    if args.get('dn'):
        query = "(&(objectClass=User)(objectCategory=person)(dn={}))".format(args['dn'])

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
            args['custom-field-type'], args['ustom-field-data'])

    if args.get('attributes'):
        custome_attributes = args['attributes'].split(",")

    attributes = set(custome_attributes + DEFAULT_PERSON_ATTRIBUTES)

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        size_limit=limit,
        page_size=page_size
    )

    accounts = [account_entry(entry, custome_attributes) for entry in entries['flat']]

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


def search_computers(default_base_dn, page_size):
    # this command is equivalent to ADGetComputer script

    args = demisto.args()

    attributes = []
    custome_attributes = []

    # default query - list all users (computer category)
    query = "(&(objectClass=user)(objectCategory=computer))"

    # query by user DN
    if args.get('dn'):
        query = "(&(objectClass=user)(objectCategory=computer)(dn={}))".format(args['dn'])

    # query by name
    if args.get('name'):
        query = "(&(objectClass=user)(objectCategory=computer)(name={}))".format(args['name'])

    # query by custom object attribute
    if args.get('custom-field-type'):
        if not args.get('custom-field-data'):
            raise Exception('Please specify "custom-field-data" as well when quering by "custom-field-type"')
        query = "(&(objectClass=user)(objectCategory=computer)({}={}))".format(
            args['custom-field-type'], args['ustom-field-data'])

    if args.get('attributes'):
        custome_attributes = args['attributes'].split(",")

    attributes = set(custome_attributes + DEFAULT_COMPUTER_ATTRIBUTES)

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

    custome_attributes = []
    default_attributes = DEFAULT_PERSON_ATTRIBUTES if member_type == 'person' else DEFAULT_COMPUTER_ATTRIBUTES

    if args.get('attributes'):
        custome_attributes = args['attributes'].split(",")

    attributes = set(custome_attributes + default_attributes)

    # neasted search
    query = "(&(objectCategory={})(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={}))".format(member_type,
                                                                                                    group_dn)

    entries = search_with_paging(
        query,
        default_base_dn,
        attributes=attributes,
        page_size=page_size
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
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "user"]
    user_dn = args.get('user-dn')
    username = args.get("username")
    password = args.get("password")
    custome_attributes = args.get('custom-attributes')
    attributes = {
        "samAccountName": username
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


def create_contact():
    args = demisto.args()

    object_classes = ["top", "person", "organizationalPerson", "contact"]
    contact_dn = args.get('contact-dn')

    # set contact attributes
    attributes = {}
    if args.get('custom-attributes'):
        try:
            attributes = json.loads(args['custom-attributes'])
        except Exception as e:
            demisto.info(str(e))
            raise Exception(
                'Failed to parse custom attributes argument. Please see an example of this argument in the argument.'
            )

    # set common user attributes
    if args.get('diaply-name'):
        attributes['displayName'] = args['diaply-name']
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


''' UPDATE OBJECT '''


def modify_object(dn, modification):
    """
    modifys object in the DIT
    """
    success = conn.modify(dn, modification)
    if not success:
        raise Exception("Failed to update object {} with the following modofication: {}".format(
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
        raise Exception("Failed to add {} to group {]}".format(
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
        raise Exception("Failed to remove {member} from group {group_name}".format({
            "member": args.get('username') or args.get('computer-name'),
            "group_name": args.get('group_name')
        }))

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
    # can acually delete any object...
    success = conn.delete(demisto.args().get('user-dn'))
    if not success:
        raise Exception('Failed to delete user')

    demisto_entry = {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Deleted object with dn {}".format(demisto.args().get('user-dn'))
    }
    demisto.results(demisto_entry)


'''
    TEST CONFIGURATION
    authenticate user credentials while initializing connection wiith AD server
    verify base DN is configured correctly
'''


def main():
    ''' INSTANCE CONFIGURATION '''
    SERVER_IP = demisto.params().get('server_ip')
    USERNAME = demisto.params().get('credentials')['identifier']
    PASSWORD = demisto.params().get('credentials')['password']
    DEFAULT_BASE_DN = demisto.params().get('base_dn')
    SECURE_CONNECTION = demisto.params().get('secure_connection')
    DEFAULT_PAGE_SIZE = int(demisto.params().get('page_size'))
    NTLM_AUTH = demisto.params().get('ntlm')
    UNSECURE = demisto.params().get('unsecure', False)
    PORT = demisto.params().get('port')

    try:
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
            demisto.info(message)
            return_error(message)
            return
    except LDAPSocketOpenError as e:
        exc_msg = str(e)
        demisto.info(exc_msg)
        message = "Failed to access LDAP server. Please validate the server host and port are configured correctly"
        if 'ssl wrapping error' in exc_msg:
            message = "Failed to access LDAP server. SSL error."
            if not UNSECURE:
                message += ' Try using: "Trust any certificate" option.'
        demisto.info(message)
        return_error(message)
        return

    demisto.info('Established connection with AD LDAP server')

    if not base_dn_verified(DEFAULT_BASE_DN):
        message = "Failed to verify the base DN configured for the instance.\n" \
            "Last connection result: {}\n" \
            "Last error from LDAP server: {}".format(json.dumps(conn.result), json.dumps(conn.last_error))
        demisto.info(message)
        return_error(message)
        return

    demisto.info('Verfied base DN "{}"'.format(DEFAULT_BASE_DN))

    ''' COMMAND EXECUTION '''

    try:
        if demisto.command() == 'test-module':
            if conn.user == '':
                # Empty response means you have no authentication status on the server, so you are an anonymous user.
                raise Exception("Failed to authenticate user")
            demisto.results('ok')

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

    except Exception as e:
        message = "{}\nLast connection result: {}\nLast error from LDAP server: {}".format(
            str(e), json.dumps(conn.result), conn.last_error)
        demisto.info(message)
        return_error(message)
        return
    finally:
        # disconnect and close the connection
        conn.unbind()


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

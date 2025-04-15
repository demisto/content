import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from datetime import datetime, timedelta
from random import randrange, choice, randint
from copy import deepcopy
import json


''' SAMPLE EVENTS '''

SAMPLE_EVENT = {
    "type": "url allowed",
    "eventID": "007",
    "urlCategory": "MALWARE",
    "sourceIP": "10.8.8.8",
                "occurred": "2023-01-01T00:00:01.000Z",
                "sourceUser": "james.bond@xsoar.local",
                "url": "https://xsoar.pan.dev/login.zip",
                "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
}

TYPES = ["url allowed", "url blocked"]
CATEGORIES = ["PHISH", "MALWARE", "SPAM"]

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

''' ACTIVE DIRECTORY QUERY V2 INTEGRATION '''

USERS = [
    {
        "email": "james.bond@xsoar.local",
        "displayname": "James Bond",
        "samaccountname": "XSOAR007",
        "dn": "CN=James Bond,CN=Users,DC=xsoar,DC=local",
        "group": "CN=Agents,CN=Users,DC=xsoar,DC=local",
        "manager": "CN=M,CN=Users,DC=xsoar,DC=local"
    },
    {
        "email": "eve.moneypenny@xsoar.local",
        "displayname": "Eve Moneypenny",
        "samaccountname": "XSOAR002",
        "dn": "CN=Eve Moneypenny,CN=Users,DC=xsoar,DC=local",
        "group": "CN=Administration,CN=Users,DC=xsoar,DC=local",
        "manager": "CN=M,CN=Users,DC=xsoar,DC=local"
    },
    {
        "email": "m@xsoar.local",
        "displayname": "M",
        "samaccountname": "XSOAR001",
        "dn": "CN=M,CN=Users,DC=xsoar,DC=local",
        "group": "CN=Managers,CN=Users,DC=xsoar,DC=local",
        "manager": "CN=James Bond,CN=Users,DC=xsoar,DC=local"
    },
    {
        "email": "q@xsoar.local",
        "displayname": "Q",
        "samaccountname": "XSOAR003",
        "dn": "CN=Q,CN=Users,DC=xsoar,DC=local",
        "group": "CN=Gadgets,CN=Users,DC=xsoar,DC=local",
        "manager": "CN=James Bond,CN=Users,DC=xsoar,DC=local"
    }
]


""" Helper functions """


def get_now():
    """
    A wrapper function of datetime.now
    helps handle tests

    Returns:
        datetime: time right now
    """
    return datetime.now()


def mock_data(total):
    """
    Changes mocks the data to randomize the alerts a bit.
    """
    now = get_now()
    data = []
    count = 0

    users = [x['email'] for x in USERS]
    while count < total:
        item = deepcopy(SAMPLE_EVENT)
        item['occurred'] = (now - timedelta(minutes=randrange(6, 60))).strftime('%Y-%m-%dT%H:%M:%SZ')
        item['eventID'] = str(randrange(100, 10000))
        item['type'] = choice(TYPES)
        if item['type'] == 'url blocked':
            item['urlCategory'] = choice(CATEGORIES)
        else:
            item['urlCategory'] = choice(CATEGORIES)
        item['sourceUser'] = choice(users)
        item['sourceIP'] = f"10.8.8.{randrange(2,250)}"

        if item["urlCategory"] == "MALWARE":
            item["url"] = f"https://xsoar.pan.dev/{randrange(1,88)}/download.zip"
        if item["urlCategory"] == "PHISH":
            item["url"] = f"https://xsoar.pan.dev/{randrange(1,88)}/login.php"
        if item["urlCategory"] == "SPAM":
            item["url"] = f"https://xsoar.pan.dev/{randrange(1,88)}/getnewbike"

        data.append(item)
        count += 1
    return data


def lookup_ad_user(lookup, attribute):
    """
    Returns the user details from the USERS global var
    """
    found_user = False
    for u in USERS:
        if u[attribute] == lookup:
            found_user = True
            user: Dict | None = u
            break

    if not found_user:
        user = None
    return user


def create_ad_user_output(user):
    """
    returns the user object for using the USER_TEMPLATE
    """
    user_template = {
        "attributes": {
            "displayName": [
                f"{user['displayname']}"
            ],
            "mail": [
                f"{user['email']}"
            ],
            "manager": [
                f"{user['manager']}"
            ],
            "memberOf": [
                f"{user['group']}"
            ],
            "name": [
                f"{user['displayname']}"
            ],
            "sAMAccountName": [
                f"{user['samaccountname']}"
            ],
            "userAccountControl": [
                512
            ],
            "dn": f"{user['dn']}"
        },
        "account": {
            "DisplayName": [
                f"{user['displayname']}"
            ],
            "Email": [
                f"{user['email']}"
            ],
            "Manager": [
                f"{user['manager']}"
            ],
            "Groups": [
                f"{user['group']}"
            ],
            "Type": "AD",
            "Username": [
                f"{user['samaccountname']}"
            ],
            "ID": f"{user['dn']}"
        }
    }

    return user_template


""" Command functions """


def get_events_command(args):
    """
    returns the events, in this case the mock data
    """
    args.get("eventTypes")
    total = randrange(10, 20)
    events = mock_data(total)
    readable = tableToMarkdown("Training Events", events)
    results = CommandResults(readable_output=readable, ignore_auto_extract=True)
    return results


def simple_response_command(command):
    """
    returns a text response for the Active Directory and send mail Commands
    """
    command_map = {
        'xet-ad-expire-password': 'Expired password successfully',  # guardrails-disable-line
        'xet-ad-set-new-password': 'User password successfully set',    # guardrails-disable-line
        'xet-send-mail': 'XSOAR Engineer Training: fake email notification not sent'
    }
    return CommandResults(readable_output=command_map[command], ignore_auto_extract=True)


def ad_get_user_command(args):
    """
    Returns the user details from our simulated AD if the user is found
    """
    user: dict | None = {}
    demisto.debug(f"Initializing {user=}")

    # error handing if one of username, email or dn is not passed to the command
    if not args.get('username') and not args.get('email') and not args.get('dn'):
        return_error("Need either a username, email, or dn")

    # lookup the user
    if args.get('email'):
        username = args.get('email')
        user = lookup_ad_user(username, 'email')
    if args.get('username'):
        username = args.get('username')
        user = lookup_ad_user(username, 'samaccountname')
    if args.get('dn'):
        username = args.get('dn')
        user = lookup_ad_user(username, 'dn')

    # create the user response
    if user:
        user_output = create_ad_user_output(user)

        # return results like AD query would.
        demisto_entry = {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': user_output,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Active Directory - Get Users", user_output.get('attributes')),
            'EntryContext': {
                'ActiveDirectory.Users(obj.dn == val.dn)': user_output.get('attributes'),
                'Account(obj.ID == val.ID)': user_output.get('account')
            }
        }

        return demisto_entry
    else:
        return "No user found"


def siem_search_command(args):
    """
    Returns the results from the siem-search command
    """
    query = args.get('query')
    result_type = args.get('result_type')
    number = randint(1, 10)

    # return results for demo of siem search in example playbook.
    if result_type == "email" or query.startswith("email"):
        result = [
            {
                "Username": "XSOAR007",
                "Email": "james.bond@xsoar.local"
            },
            {
                "Username": "XSOAR001",
                "Email": "m@xsoar.local"
            }
        ]
    # return some data if the number is right.
    elif number >= 7 or result_type == "hosts" or query.startswith("username"):
        result = [
            {
                "Host": "crossiscoming01",
                "Online": "Yes"
            },
            {
                "Host": "crossiscoming02",
                "Online": "No"
            }
        ]
    # return some data if the number is right.
    elif query.startswith("ip"):
        result = [
            {
                "Host": "crossiscoming01",
                "Online": "Yes"
            }
        ]
    else:
        result = []

    results = CommandResults(
        readable_output=tableToMarkdown(f"SIEM Search results for query: {query}", result),
        outputs_prefix="SIEM.Result",
        outputs=result)

    return results


def fetch_incidents(limit):
    """
    fetch Incidents
    """
    incidents = []

    count = randrange(10, limit)
    events = mock_data(count)

    for event in events:
        if event.get("type") == "url allowed":
            event_type = "URL Allowed"
        else:
            event_type = "URL Blocked"
        event_user = event.get("sourceUser", "")
        incident = {
            "name": f"Alert - {event_type}- {event_user}",
            "rawJSON": json.dumps(event),
            "occurred": event["occurred"]
        }
        incidents.append(incident)

    # return our list of Incidents
    return incidents[:limit]


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    main function to run things
    """
    fetch_limit = 20

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        commands = {
            'xet-get-events': get_events_command,
            'xet-ad-expire-password': simple_response_command,
            'xet-ad-set-new-password': simple_response_command,
            'xet-send-mail': simple_response_command
        }
        if command == 'test-module':
            demisto.results('ok')
        elif demisto.command() == 'fetch-incidents':
            demisto.incidents(fetch_incidents(limit=fetch_limit))
        elif demisto.command() == 'xet-get-events':
            return_results(get_events_command(demisto.args()))
        elif demisto.command() == 'xet-ad-get-user':
            demisto.results(ad_get_user_command(demisto.args()))
        elif demisto.command() == 'xet-siem-search':
            return_results(siem_search_command(demisto.args()))
        elif command in commands:
            return_results(commands[command](command))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

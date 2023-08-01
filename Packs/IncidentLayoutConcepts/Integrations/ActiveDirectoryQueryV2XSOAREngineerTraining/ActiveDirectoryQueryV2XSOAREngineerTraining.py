import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Lab version of AD. Simulate the ad-get-user, ad-expire-password, and ad-set-new-password responses.

# Fun fact about data.  68% of all data is made up, but only 8% of people know that.

# Map samaccountname to email, in case you want to demo looking up with something else...
USERNAME_MAP = {
    "DEMISTO007": "james.bond@demisto.local",
    "DEMISTO003": "eve.moneypenny@demisto.local",
    "DEMISTO001": "m@demisto.local"
}

USERS = {
    "james.bond@demisto.local": {
        "attributes": {
            "displayName": [
                "James Bond"
            ],
            "mail": [
                "James.Bond@demisto.local"
            ],
            "manager": [
                "M@demisto.local"
            ],
            "memberOf": [
                "CN=Admins,CN=Users,DC=demisto,DC=local"
            ],
            "name": [
                "James Bond"
            ],
            "sAMAccountName": [
                "DEMISTO007"
            ],
            "userAccountControl": [
                512
            ],
            "dn": "CN=James Bond,CN=Users,DC=demisto,DC=local"
        },
        "account": {
            "DisplayName": [
                "James Bond"
            ],
            "Email": [
                "James.Bond@demisto.local"
            ],
            "Manager": [
                "M@demisto.local"
            ],
            "Groups": [
                "CN=Agent,CN=Users,DC=demisto,DC=local"
            ],
            "Type": "AD",
            "Username": [
                "DEMISTO007"
            ],
            "ID": "CN=James Bond,CN=Users,DC=demisto,DC=local"
        }
    },
    "eve.moneypenny@demisto.local": {
        "attributes": {
            "displayName": [
                "Eve Moneypenny"
            ],
            "mail": [
                "Eve.Moneypenny@demisto.local"
            ],
            "manager": [
                "M@demisto.local"
            ],
            "memberOf": [
                "CN=Employees,CN=Users,DC=demisto,DC=local"
            ],
            "name": [
                "Eve Moneypenny"
            ],
            "sAMAccountName": [
                "DEMISTO003"
            ],
            "userAccountControl": [
                512
            ],
            "dn": "CN=Eve Moneypenny,CN=Users,DC=demisto,DC=local"
        },
        "account": {
            "DisplayName": [
                "Eve Moneypenny"
            ],
            "Email": [
                "Eve.MoneyPenny@demisto.local"
            ],
            "Manager": [
                "M@demisto.local"
            ],
            "Groups": [
                "CN=Employees,CN=Users,DC=demisto,DC=local"
            ],
            "Type": "AD",
            "Username": [
                "DEMISTO003"
            ],
            "ID": "CN=Eve Moneypenny,CN=Users,DC=demisto,DC=local"
        }
    },
    "m@demisto.local": {
        "attributes": {
            "displayName": [
                "M"
            ],
            "mail": [
                "m@demisto.local"
            ],
            "manager": [],
            "memberOf": [
                "CN=Executives,CN=Users,DC=demisto,DC=local"
            ],
            "name": [
                "M"
            ],
            "sAMAccountName": [
                "DEMISTO001"
            ],
            "userAccountControl": [
                512
            ],
            "dn": "CN=M,CN=Users,DC=demisto,DC=local"
        },
        "account": {
            "DisplayName": [
                "M"
            ],
            "Email": [
                "M@demisto.local"
            ],
            "Manager": [],
            "Groups": [
                "CN=Executives,CN=Users,DC=demisto,DC=local"
            ],
            "Type": "AD",
            "Username": [
                "DEMISTO001"
            ],
            "ID": "CN=M,CN=Users,DC=demisto,DC=local"
        }
    }
}


def main():
    ''' COMMAND EXECUTION '''

    if demisto.command() == 'test-module':
        demisto.results('ok')

    args = demisto.args()

    if demisto.command() == 'ad-expire-password':
        demisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': "Expired password successfully"
        }
        demisto.results(demisto_entry)

    if demisto.command() == 'ad-set-new-password':
        demisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': "User password successfully set"
        }
        demisto.results(demisto_entry)

    if demisto.command() == 'ad-unlock-account':
        demisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': "Account unlocked"
        }
        demisto.results(demisto_entry)

    if demisto.command() == 'ad-disable-account':
        demisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': "Account disabled"
        }
        demisto.results(demisto_entry)

    if demisto.command() == 'ad-enable-account':
        ddemisto_entry = {
            'ContentsFormat': formats['text'],
            'Type': entryTypes['note'],
            'Contents': "Account enabled"
        }
        demisto.results(demisto_entry)

    if demisto.command() == 'ad-get-user':

        # error handing for Ori
        if not demisto.args().get('username') and not demisto.args().get('email'):
            return_error("Need either a username or email")

        # mock the demisto lookup with username
        username = demisto.args().get('username')
        username = USERNAME_MAP.get(username, 'NotExisted')

        # mock the demisto lookup via email
        email = demisto.args().get('email', username)
        user = USERS.get(email.lower(), {})

        if user:
            rawjson = user
            # rawjson.pop('account')
        else:
            rawjson = []

        # return results like AD query would.
        demisto_entry = {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': rawjson,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Active Directory - Get Users", user.get('attributes')),
            'EntryContext': {
                'ActiveDirectory.Users(obj.dn == val.dn)': user.get('attributes'),
                'Account(obj.ID == val.ID)': user.get('account')
            }
        }
        demisto.results(demisto_entry)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()

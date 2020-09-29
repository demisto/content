from pprint import pformat

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

context = demisto.context()

excluded_users = argToList(demisto.args().get('excluded_users', []))

# demisto.log(pformat(context))

try:
    users = [user for user in context['PaloAltoNetworksXDR']['Incident']['users'] if user not in excluded_users]
    usersObj = [{'ID': user, 'Username': user, 'Type': 'Unknown'} for user in users]

    demisto.results({
        'Type': entryTypes['note'],  # type of war room entry
        'Contents': usersObj,  # raw content data (can be json, binary file data, etc)
        'ContentsFormat': formats['json'],  # the type of raw data contained in the 'Contents' field
        'EntryContext': {'Account': usersObj},  # json data to be added to the incident context.  Is always JSON
        'ReadableContentsFormat': formats['markdown'],  # either formats['markdown'] or formats['json']
        # the data to display to the user in the war room.  If not specified, the value of the Contents field is displayed
        'HumanReadable': 'Extracted users: ' + ', '.join(users)
    })

    # demisto.log(pformat(users))

except KeyError as error:
    demisto.results('No users found')

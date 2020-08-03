import sys
from pprint import pformat

import demistomock as demisto
from CommonServerPython import *

try:
    users_to_parse = argToList(demisto.args()['value'])
except keyError:
    return_error('One or more users is required')

to_lower_case = argToBoolean(demisto.args().get('to_lower_case', False))

excluded_users = argToList(demisto.args().get('excluded_users', []))
# demisto.log('excluded_users: ' + pformat(excluded_users))

if to_lower_case:
    excluded_users = [user.lower() for user in excluded_users]

excluded_users_with_domains = {
    'none': {}  # 'none' is for if there is no domain found
}

for user in excluded_users:
    delim = None
    if '@' in user:
        delim = '@'
        [user, domain] = user.split(delim)
    elif '\\' in user:
        delim = '\\'
        [domain, user] = user.split(delim)
    if not delim:
        excluded_users_with_domains['none'][user] = {'Username': user, 'Type': 'Unknown'}
    elif delim:
        if not domain in excluded_users_with_domains:
            excluded_users_with_domains[domain] = {}
        excluded_users_with_domains[domain][user] = {'Domain': domain, 'Username': user, 'Type': 'AD'}

# demisto.log('excluded_users: ' + pformat(excluded_users))
# demisto.log('excluded_users_with_domains: ' + pformat(excluded_users_with_domains))


users_res = []


def proc_domain_user(raw_user, splitBy):
    [domain, user] = raw_user.split('\\')
    if to_lower_case:
        user = user.lower()
        domain = domain.lower()
    if domain in excluded_users_with_domains and user in excluded_users_with_domains[domain]:
        return
    # if user not in excluded_users:
    users_res.append({'Domain': domain, 'Username': user, 'Type': 'AD'})


for raw_user in users_to_parse:
    if '\\' in raw_user:
        proc_domain_user(raw_user, '\\')

    elif '@' in raw_user:
        proc_domain_user(raw_user, '@')

    else:
        if to_lower_case:
            user = user.lower()
        if user not in excluded_users_with_domains['none']:
            users_res.append({'Username': user, 'Type': 'Unknown'})

try:
    key = demisto.args()['key']
    demisto.results({
        'Type': entryTypes['note'],  # type of war room entry
        'Contents': users_res,  # raw content data (can be json, binary file data, etc)
        'ContentsFormat': formats['json'],  # the type of raw data contained in the 'Contents' field
        'EntryContext': {key: users_res}  # json data to be added to the incident context.  Is always JSON
    })

except KeyError:
    # demisto.log(pformat(users_res))
    demisto.results(users_res)

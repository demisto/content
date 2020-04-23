import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import List


def main():
    get_users_response: List = demisto.executeCommand('getUsers', {'onCall': True})
    if is_error(get_users_response):
        demisto.error(f'Failed to get users on call: {str(get_error(get_users_response))}')
    else:
        contents = get_users_response[0]['HumanReadable']
        if contents == 'No data returned':
            contents = '### On-Call Users\nNo analysts were found on-call.'
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': contents
        })


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

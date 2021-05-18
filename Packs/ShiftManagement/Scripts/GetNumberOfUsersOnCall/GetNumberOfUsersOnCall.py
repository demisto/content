import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import List


def main():
    get_users_response: List = demisto.executeCommand('getUsers', {'onCall': True})
    if is_error(get_users_response):
        demisto.error(f'Failed to get users on call: {str(get_error(get_users_response))}')
    else:
        number_widget = NumberWidget(len(get_users_response[0]['Contents']))
        return_results(number_widget)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

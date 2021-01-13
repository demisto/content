import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import ast

from typing import List


def filter_OOO_users(get_users_response, ooo_list_name):
    """
    Given the response with all OnCall users, remove the users that are Out Of Office, using the list `OOO List`.
    """
    all_users = get_users_response.get('Contents')
    if not all_users:
        return 'No data returned'

    # get OOO users
    ooo_list = demisto.executeCommand("GetUsersOOO", {"listname": ooo_list_name})
    if isError(ooo_list[0]):
        return_error(f'Error occurred while trying to get OOO users: {ooo_list[0].get("Contents")}')

    list_info = ooo_list[0].get('EntryContext').get('ShiftManagment.OOOUsers')
    OOO_usernames = [i['username'] for i in list_info]

    try:
        in_office_users = []
        for user in all_users:
            if user.get('username') in OOO_usernames:
                continue
            else:
                in_office_users.append(user)
        return tableToMarkdown('On-Call Users', in_office_users, ['username', 'email', 'name', 'phone', 'roles'])
    except Exception as e:
        demisto.error(f'Encountered the following exception: {e.args[0]}\n Returning all users without filtering.')
        return get_users_response.get('HumanReadable')


def main():
    include_out_of_office_users = demisto.args().get('include_OOO_users', 'false') == 'true'
    get_users_response: List = demisto.executeCommand('getUsers', {'onCall': True})
    list_name = demisto.getArg("listname")
    if is_error(get_users_response):
        demisto.error(f'Failed to get users on call: {str(get_error(get_users_response))}')
    else:
        if include_out_of_office_users:
            contents = get_users_response[0]['HumanReadable']
        else:
            contents = filter_OOO_users(get_users_response[0], list_name)

        if contents == 'No data returned':
            contents = '### On-Call Users\nNo analysts were found on-call.'
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': contents
        })


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

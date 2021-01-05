import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import ast

from typing import List


def filter_OOO_users(get_users_response):
    """
    Given the response with all OnCall users, remove the users that are Out Of Office, using the list `OOO List`.
    """
    all_users = get_users_response.get('Contents')
    if not all_users:
        return 'No data returned'

    OOO_users_list = demisto.executeCommand('getList', {'listName': 'OOO List'})
    if is_error(OOO_users_list):
        # check if the list `OOO List` exists:
        try:
            if 'Item not found' in OOO_users_list[0].get('Contents'):
                demisto.debug('The list `OOO List` does not exist. Returning all results without filtering.')
        except Exception:
            demisto.error('Error occurred while trying to load the `OOO List`, returning all users without filtering.')
        return get_users_response.get('HumanReadable')
    try:
        OOO_users = ast.literal_eval(OOO_users_list[0].get('Contents'))
        OOO_usernames = [user.get('user') for user in OOO_users]
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
    if is_error(get_users_response):
        demisto.error(f'Failed to get users on call: {str(get_error(get_users_response))}')
    else:
        if include_out_of_office_users:
            contents = get_users_response[0]['HumanReadable']
        else:
            contents = filter_OOO_users(get_users_response[0])

        if contents == 'No data returned':
            contents = '### On-Call Users\nNo analysts were found on-call.'
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': contents
        })


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

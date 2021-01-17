import csv
import io

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()


def main():
    csv_string = get_list(args.get('list_name'))
    reader = csv.DictReader(io.StringIO(csv_string))
    json_data = list(reader)

    for ad_user in json_data:
        ad_create_user_arguments = {
            'sAMAccountName': ad_user['samaccountname'],
            'user-dn': ad_user['dn'],
            'custom-attributes': {'mail': ad_user['email'], 'mailNickname': ad_user['samaccountname'], 'userPrincipalName': ad_user['email']}
        }
        ad_create_user_response = demisto.executeCommand("ad-create-user-temp", ad_create_user_arguments)
        if isError(ad_create_user_response[0]):
            demisto.log("Failed to Create AD User: " + ad_user['samaccountname']
                        + ". Error: " + demisto.get(ad_create_user_response[0], "Contents"))

    return_outputs(readable_output=None, raw_response=None)


def get_list(list_name):
    get_list_response = demisto.executeCommand("getList", {"listName": list_name})

    if isError(get_list_response[0]):
        demisto.error(f'Could not read the list: {get_list_response[0]}')
        raise Exception(f'Error: Could not read the list: {list_name}')
        list_data = None
    else:
        list_data = demisto.get(get_list_response[0], "Contents")

    return list_data


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

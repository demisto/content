from CommonServerPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
BASE_URL = 'https://api.telegram.org/bot{}/'.format(TOKEN)

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    result = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=False,
        params=params,
        data=data
    )
    if result.status_code not in {200}:
        return_error('Error in API call to Telegram Integration [%d] - %s' % (result.status_code, result.reason))

    return result.json()


def get_updates():
    return http_request('GET', 'getUpdates')


def get_bot():
    return http_request('GET', 'getMe')


def item_to_incident(item):
    incident = {
        'name': 'Example Incident: ' + item.get('name'),
        'occurred': item.get('createdDate'),
        'rawJSON': json.dumps(item)
    }

    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    contents = get_bot()
    if contents['ok']:
        demisto.results("ok")
    else:
        error_code = contents['error_code']
        description = contents['description']
        demisto.results(f'{error_code} {description}')


def telegram_send_message():
    """
    Gets details about a items using IDs or some other filters
    """
    user_id = demisto.args().get('userID')
    if user_id is None:
        username = demisto.args().get('username')
        if username is not None:
            user_id = str(get_user_id(username))

    if user_id is None:
        return_error(f'username {username} does not exists, please use list_user command')
    message = demisto.args().get('message')
    contents = http_request('GET', "sendMessage?chat_id=" + user_id + "&amp&text=" + message)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Message sent', contents, 'result', removeNull=True),
        'EntryContext': contents
    })


def get_users():
    users = {}

    contents = get_updates()
    for result in contents['result']:
        user_data = result['message']
        if 'username' in user_data['from']:
            users[user_data['from']['username']] = user_data['from']['id']
        # not all users have a username, so no choice but to save by their first_name (data can be overwritten)
        else:
            users[user_data['from']['first_name']] = user_data['from']['id']
    return users


def telegram_list_users():
    users = get_users()

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': users,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Users', users, removeNull=True),

        'EntryContext': users
    })


def get_user_id(username):
    users = get_users()
    if username in users:
        return users[username]
    else:
        return


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG(f'command is {demisto.command()}')

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'telegram-send-message' or demisto.command() == 'send-message':
            telegram_send_message()
        elif demisto.command() == 'telegram-list-users' or demisto.command() == 'list-users':
            telegram_list_users()

    except Exception as ex:
        return_error(str(ex))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()

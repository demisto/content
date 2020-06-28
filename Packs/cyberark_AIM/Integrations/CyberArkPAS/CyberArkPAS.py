from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


INTEGRATION_NAME = 'CyberArk PAS'


'''API Client'''


class Client(BaseClient):

    auth_token = ''

    def login(self, username, password, api_version='2', auth_type='cyberark'):
        body = {
            "username": username,
            "password": password,
            "concurrentSession": "false"
        }
        if auth_type == 'cyberark':
            LOG(f'Authenticating using {auth_type} authentication method')
            self.auth_token = self._http_request(
                "POST",
                url_suffix='/PasswordVault/API/Auth/CyberArk/Logon',
                data=body
            )

    def get_system_summary(self):
        LOG('Checking System Summary')
        headers = {
            'Authorization': self.auth_token
        }
        res = self._http_request(
            "GET",
            url_suffix='/PasswordVault/API/ComponentsMonitoringSummary',
            resp_type="json",
            headers=headers

        )
        return res

    def get_accounts(self, offset="25", limit="25"):
        LOG('Getting the List of Accounts')
        headers = {
            'Authorization': self.auth_token
        }
        res = self._http_request(
            "GET",
            url_suffix='/PasswordVault/api/Accounts',
            resp_type="json",
            headers=headers,
            params={
                'offset': offset,
                'limit': limit
            }
        )
        return res


'''' Commands '''


def test_module(client):
    client.get_system_summary()
    return 'ok'


def list_accounts(client, args):
    title = f'{INTEGRATION_NAME} - List of the Accounts'
    raws = []
    cyberark_ec = []
    raw_response = client.get_accounts(offset=args['offset'], limit=args['limit'])['value']

    if raw_response:
        for item in raw_response:
            raws.append(item)
            cyberark_ec.append({
                'AccountName': item['name'],
                'UserName': item['userName'],
                'PlatformID': item['platformId'],
                'SafeName': item['safeName'],
                'AccountID': item['id'],
                'CreatedTime': item['createdTime']
            })

    if not raws:
        return f'{INTEGRATION_NAME} - Could not any Accounts'

    context_entry = {
        "CyberArk": {"Accounts": cyberark_ec}
    }

    human_readable = tableToMarkdown(t=context_entry["CyberArk"]['Accounts'], name=title)
    return [human_readable, context_entry, raws]


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
    api_verion = params.get('apiVersion')
    auth_type = params.get('authType')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            ok_codes=(200, 201, 204),
            headers={'accept': "application/json"}
        )
        client.login(username=username, password=password, api_version=api_verion, auth_type=auth_type)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_outputs(result)

        elif demisto.command() == 'cyberark-list-accounts':
            result = list_accounts(client, args=demisto.args())
            return_outputs(*result)


    except Exception as e:
        return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

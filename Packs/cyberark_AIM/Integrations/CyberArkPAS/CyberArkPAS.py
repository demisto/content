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

    def login(self, username, password, auth_type='cyberark'):
        body = {
            "username": username,
            "password": password,
            "concurrentSession": "false"
        }
        if auth_type == 'cyberark':
            demisto.debug(f'Authenticating using {auth_type} authentication method')
            self.auth_token = self._http_request(
                "POST",
                url_suffix='/PasswordVault/API/Auth/CyberArk/Logon',
                data=body
            )

    def get_system_summary(self):
        demisto.debug('Checking System Summary')
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
        demisto.debug('Getting the List of Accounts')
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

    def add_account(self, address, user_name, platform_id, safe_name,
                    name='', secret='', secret_type='password', platform_account_properties='',
                    automatic_management_enabled='true', manual_management_reason='', remote_machines='',
                    access_restricted_to_remote_machines='false'):
        LOG('Adding a new Account')

        headers = {
            'Authorization': self.auth_token
        }

        body = {
            "userName": user_name,
            "address": address,
            "platformId": platform_id,
            "safeName": safe_name
        }

        if name:
            body['name'] = name

        if secret and secret_type:
            body['secret'] = secret
            body['secretType'] = secret_type

        if platform_account_properties:
            body['platformAccountProperties'] = platform_account_properties

        if automatic_management_enabled == "false":
            body['secretManagement'] = {
                "automaticManagementEnabled": automatic_management_enabled,
                "manualManagementReason": manual_management_reason
            }

        if remote_machines:
            body['remoteMachinesAccess'] = {
                "remoteMachines": remote_machines,
                "accessRestrictedToRemoteMachines": access_restricted_to_remote_machines
            }
        res = self._http_request(
            "POST",
            url_suffix='/PasswordVault/api/Accounts',
            resp_type="json",
            headers=headers,
            data=body
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
        return f'{INTEGRATION_NAME} - Could not find any Accounts'

    context_entry = {
        "CyberArk.Accounts": cyberark_ec
    }

    human_readable = tableToMarkdown(t=context_entry.get('CyberArk.Accounts'), name=title)
    return [human_readable, context_entry, raws]


def add_account(client, args):
    title = f'{INTEGRATION_NAME} - Add a New Account'
    raws = []
    cyberark_ec = []
    raw_response = client.add_account(user_name=args.get('user-name'), address=args.get('address'),
                                      platform_id=args.get('platform-Id'), safe_name=args.get('safe-name'),
                                      name=args.get('name'), secret=args.get('secret'),
                                      secret_type=args.get('secret-type'),
                                      platform_account_properties=args.get('platform-account-properties'),
                                      automatic_management_enabled=args.get('automatic-management-enabled'),
                                      manual_management_reason=args.get('manual-management-reason'),
                                      remote_machines=args.get('remote-machines'),
                                      access_restricted_to_remote_machines=args.get('access-restricted-'
                                                                                    'to-remote-machines'))
    if raw_response:
        raws.append(raw_response)
        cyberark_ec.append({
            'AccountName': raw_response['name'],
            'UserName': raw_response['userName'],
            'PlatformID': raw_response['platformId'],
            'SafeName': raw_response['safeName'],
            'AccountID': raw_response['id'],
            'CreatedTime': raw_response['createdTime']
        })

    if not raws:
        return f'{INTEGRATION_NAME} - Could not create the new Account'

    context_entry = {
        "CyberArk.Accounts": cyberark_ec
    }

    human_readable = tableToMarkdown(t=context_entry.get('CyberArk.Accounts'), name=title)
    return [human_readable, context_entry, raws]


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
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
        client.login(username=username, password=password, auth_type=auth_type)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_outputs(result)

        elif demisto.command() == 'cyberark-list-accounts':
            result = list_accounts(client, args=demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'cyberark-add-account':
            result = add_account(client, args=demisto.args())
            return_outputs(*result)

    except Exception as e:
        return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

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

    def login(self, username, password):
        body = {
            "username": username,
            "password": password,
            "concurrentSession": "false"
        }
        demisto.debug(f'Authenticating using CyberArk authentication method')
        auth_token = self._http_request(
            "POST",
            url_suffix='/PasswordVault/API/Auth/CyberArk/Logon',
            data=body
        )
        demisto.setIntegrationContext({
            "token": auth_token,
            "valid_until": int(time.time())+300
        })

    def get_system_summary(self):
        demisto.debug('Checking System Summary')
        headers = {
            'Authorization': demisto.getIntegrationContext()['token']
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
            'Authorization': demisto.getIntegrationContext()['token']
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
        demisto.debug('Adding a new Account')

        headers = {
            'Authorization': demisto.getIntegrationContext()['token']
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
    raw_response = client.get_accounts(offset=args.get('offset', '0'), limit=args.get('limit', '50')).get('value')

    if raw_response:
        for item in raw_response:
            raws.append(item)
            cyberark_ec.append({
                'AccountName': item.get('name'),
                'UserName': item.get('userName'),
                'PlatformID': item.get('platformId'),
                'SafeName': item.get('safeName'),
                'AccountID': item.get('id'),
                'CreatedTime': item.get('createdTime')
            })

    if not raws:
        return_outputs(f'{INTEGRATION_NAME} - Could not find any Accounts', {}, {})

    return CommandResults(
        outputs_prefix='CyberArk.Accounts',
        outputs_key_field='AccountID',
        outputs=cyberark_ec
    )


def add_account(client, args):
    title = f'{INTEGRATION_NAME} - Add a New Account'
    raws = []
    cyberark_ec = []
    raw_response = client.add_account(user_name=args.get('user_name'), address=args.get('address'),
                                      platform_id=args.get('platform_Id'), safe_name=args.get('safe_name'),
                                      name=args.get('name'), secret=args.get('secret'),
                                      secret_type=args.get('secret_type'),
                                      platform_account_properties=args.get('platform_account_properties'),
                                      automatic_management_enabled=args.get('automatic_management_enabled'),
                                      manual_management_reason=args.get('manual_management_reason'),
                                      remote_machines=args.get('remote_machines'),
                                      access_restricted_to_remote_machines=
                                      args.get('access_restricted_to_remote_machines'))
    if raw_response:
        raws.append(raw_response)
        cyberark_ec.append({
            'AccountName': raw_response.get('name'),
            'UserName': raw_response.get('userName'),
            'PlatformID': raw_response.get('platformId'),
            'SafeName': raw_response.get('safeName'),
            'AccountID': raw_response.get('id'),
            'CreatedTime': raw_response.get('createdTime')
        })

    if not raws:
        return_outputs(f'{INTEGRATION_NAME} - Could not create the new Account', {}, {})

    return CommandResults(
        outputs_prefix='CyberArk.Accounts',
        outputs_key_field='AccountID',
        outputs=cyberark_ec
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    base_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url']
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

        if not (demisto.getIntegrationContext().get('valid_until') or demisto.getIntegrationContext().get('valid_until')):
            client.login(username=username, password=password)

        if demisto.getIntegrationContext().get('valid_until'):
            if int(time.time()) > demisto.getIntegrationContext().get('valid_until'):
                client.login(username=username, password=password)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cyberark-list-accounts':
            result = list_accounts(client, args=demisto.args())
            return_results(result)

        elif demisto.command() == 'cyberark-add-account':
            result = add_account(client, args=demisto.args())
            return_results(result)

    except Exception as e:
        if "Not Found" in str(e):
            return_error(str(
                f'Failed to execute {demisto.command()} command. Error: API Endpoint not found, please check the URL parameter'))
        elif "ErrorMessage" in str(e):
            return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e).split("ErrorMessage")[1].split(":")[1].split(".")[0].split("}")[0]}'))
        elif "Connection Timeout" in str(e):
            return_error(str(f'Failed to execute {demisto.command()} command. Error: Connection Timeout, please check the URL address'))
        elif "SSL Certificate Verification Failed" in str(e):
            return_error(str(f'Failed to execute {demisto.command()} command. Error: SSL Certificate Verification Failed - try selecting "Trust any certificate" checkbox in the integration configuration.'))
        else:
            return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))




if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

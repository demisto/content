import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict
import urllib3

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
urllib3.disable_warnings()
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, username: str, password: str, use_ssl: bool, proxy: bool, max_fetch: int):
        super().__init__(base_url=base_url, verify=use_ssl, proxy=proxy)
        self._username = username
        self._password = password
        self._token = self._generate_token()
        self._headers = {'x-xsrf-token': self._token, 'Content-Type': 'application/json'}

    def _generate_token(self) -> str:
        body = {
            "username": self._username,
            "password": self._password
        }

        headers = {
            'Content-Type': 'application/json',
        }
        response = self._http_request("POST", "/aioc-rest-web/rest/login", json_data=body, headers=headers,
                                      resp_type='response')
        return response.headers.get("XSRF-TOKEN")

    def _logout(self):
        self._http_request("POST", "/aioc-rest-web/rest/logout")

    def list_all_sapm_accounts(self):
        body = {
            "secretName": ""
        }
        response = self._http_request("POST", "/aioc-rest-web/rest/sc/sapm/searchSapmAccounts", json_data=body)
        return response

    def search_sapm_with_secret_name(self, secret_name: str):
        body = {
            "secretName": secret_name
        }
        return self._http_request("POST", "/aioc-rest-web/rest/sc/sapm/searchSapmAccounts", json_data=body)

    def show_password(self, sapm_user_name: str, password_expiration_in_minute=int, sapm_db_id=int,
                      comment=str):
        body = {
            "sapmUserName": sapm_user_name,
            "passwordExpirationInMinute": password_expiration_in_minute,
            "sapmDbId": sapm_db_id,
            "comment": comment
        }
        return self._http_request("POST", "/aioc-rest-web/rest/sc/sapm/showPassword", json_data=body)

    def get_sapm_user_info(self, device_ip: str) -> Dict[str, str]:
        body = {
            "deviceIp4Search": device_ip
        }
        return self._http_request("POST", "/aioc-rest-web/rest/sc/sapm/getSapmUserInfo", json_data=body)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    """

    message: str = ''
    try:
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def list_all_sapm_accounts_command(client: Client) -> CommandResults:
    response = client.list_all_sapm_accounts()

    return CommandResults(
        outputs_prefix='SingleConnect.SapmAccount',
        outputs_key_field='dbId',
        outputs=response.get("searchResults")
    )


def search_sapm_with_secret_name_command(client: Client, secret_name: str) -> Dict[str, str]:
    response = client.search_sapm_with_secret_name(secret_name)
    return response


def show_password_command(client: Client, sapm_user_name: str, password_expiration_in_minute=int, sapm_db_id=int,
                          comment=str) -> Dict[str, str]:
    response = client.show_password(sapm_user_name, password_expiration_in_minute, sapm_db_id, comment)
    return response


def get_sapm_user_info_command(client: Client, device_ip: str) -> Dict[str, str]:
    response = client.get_sapm_user_info(device_ip)
    return response


''' MAIN FUNCTION '''


def main(params: dict, args: dict, command: str) -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    base_url = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = 50
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            username=username,
            password=password,
            proxy=proxy,
            max_fetch=max_fetch)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'single-connect-sapm-account-list-all':
            return_results(list_all_sapm_accounts_command(client))

        elif command == 'single-connect-sapm-account-show-password':
            return_results(show_password_command(client, **args))

        elif command == 'single-connect-device-list-sapm-accounts':
            return_results(get_sapm_user_info_command(client, **args))

        elif command == 'single-connect-sapm-account-search-with-secret-name':
            return_results(search_sapm_with_secret_name_command(client, **args))

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')
    finally:
        try:
            client._logout()
        except Exception as err:
            demisto.info(f"Single Connect error: {str(err)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params(), demisto.args(), demisto.command())

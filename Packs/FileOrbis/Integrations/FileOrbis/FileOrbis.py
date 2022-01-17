import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_LOGIN = '/account/login'
URL_LOGOUT = '/account/logout'
URL_CHANGE_USER_STATUS = '/account/status/change'

''' CLIENT CLASS '''


class FileOrbisClient(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, verify, proxy, api_client_id, api_client_secret):
        self.api_client_id = api_client_id
        self.api_client_secret = api_client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def login(self):
        """
        Login the current FileOrbis client.

        :return: Http response.
        """

        response = self._http_request(
            method='POST',
            url_suffix=URL_LOGIN,
            headers={
                'Accept-Language': 'en',
                'x-fo-client-key': self.api_client_id,
                'x-fo-client-secret': self.api_client_secret
            }
        )
        access_token = response.get('Data').get('Token')
        self._headers = {
            'Accept-Language': 'en',
            'Authorization': f'Bearer {access_token}'
        }

        return response

    def logout(self):
        """
        Logout the current FileOrbis client.

        :return: Http response.
        """

        return self._http_request(
            method='POST',
            url_suffix=URL_CHANGE_USER_STATUS
        )

    def change_user_status(self, user_id: str, status: int):
        """
        Changes user status

        :param user_id: str - User id
        :param status: int - New status of the user
        :return: Http response.
        """

        request_body = {
            'userId': user_id,
            'status': status
        }
        return self._http_request(
            method='POST',
            url_suffix=URL_CHANGE_USER_STATUS,
            json_data=request_body
        )


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: FileOrbisClient) -> str:
    """Tests API connectivity and authentication'

    :param client: Initiated Client object.

    :return: error message if any error occurred during connection
    """

    response = client._http_request(
        method='POST',
        url_suffix=URL_LOGIN,
        timeout=20,
        headers={
            'Accept-Language': 'en',
            'x-fo-client-key': client.api_client_id,
            'x-fo-client-secret': client.api_client_secret
        }
    )
    if response.get("Success"):
        return 'ok'
    else:
        return response.get("Message")


def change_user_status_command(client: FileOrbisClient, args: Dict[str, Any]) -> CommandResults:
    user_id: str = args.get('user_id')  # type:ignore
    status: int = int(args.get('status'))  # type:ignore

    client.login()
    result = client.change_user_status(user_id=user_id, status=status)
    client.logout()
    result['UserID'] = user_id

    return CommandResults(
        readable_output=result.get("Message"),
        outputs=result,
        outputs_prefix='FileOrbis.UserStatus',
        outputs_key_field='UserID',
        raw_response=result
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    verify_certificate = not demisto.params().get('insecure', True)
    proxy = demisto.params().get('proxy', False)
    base_url = urljoin(demisto.params()['url'], 'api/v2')
    api_client_id = demisto.params()['client_id']
    api_client_secret = demisto.params()['client_secret']

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = FileOrbisClient(base_url=base_url,
                                 verify=verify_certificate,
                                 proxy=proxy,
                                 api_client_id=api_client_id,
                                 api_client_secret=api_client_secret)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fileorbis-change-user-status':
            return_results(change_user_status_command(client, demisto.args()))

        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

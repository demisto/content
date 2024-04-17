import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MINUTES_BEFORE_TOKEN_EXPIRED = 2
CONTEXT_OUTPUT_BASE_PATH = "Venafi.Certificate"
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, username: str, password: str, client_id: str, proxy: bool = False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self._login(client_id, username, password)

    def _login(self, client_id: str, username: str, password: str) -> str:
        integration_context = get_integration_context()
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self._is_token_expired(expires_date):
                return token
            else:
                refresh_token = integration_context.get('refresh_token')
                url_suffix = "/vedauth/authorize/token"
                json_data = {
                    "client_id": client_id,
                    "refresh_token": refresh_token
                }

                return self._create_new_token(url_suffix, json_data)

        url_suffix = "/vedauth/authorize/oauth"
        json_data = {
            "username": username,
            "password": password,
            "client_id": client_id,
            "scope": "certificate"
        }

        return self._create_new_token(url_suffix, json_data)

    def _is_token_expired(self, expires_date: str) -> bool:
        """
        This method checks if the token is expired.

        Args:
            expires_date (str): The expiration date of the token.

        Returns:
            bool: True if the token is expired, False otherwise.
        """
        utc_now = get_current_time()
        expires_datetime = arg_to_datetime(expires_date)
        return utc_now < expires_datetime

    def _create_new_token(self, url_suffix: str, json_data: dict) -> str:
        try:
            access_token_obj = self._http_request(
                method="POST",
                url_suffix=url_suffix,
                json_data=json_data,
            )

        except DemistoException as e:
            if "Unauthorized" in str(e):
                raise DemistoException("Failed to generate a token. Credentials are incorrect.")
            raise e

        new_token = access_token_obj.get("access_token", "")
        expire_in = arg_to_number(access_token_obj.get("expires_in")) or 1
        refresh_token = access_token_obj.get("refresh_token", "")
        self._store_token_in_context(new_token, refresh_token, expire_in)
        return new_token

    def _store_token_in_context(self, token: str, refresh_token: str, expire_in: int) -> None:
        """
        This method stores the generated token and its expiration date in the integration context.

        Args:
            token (str): The generated authentication token.
            expire_in (int): The number of seconds until the token expires.

        Returns:
            None
        """
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context({"token": token, "refresh_token": refresh_token, "expire_date": str(expire_date)})

    def _get_certificates(self, args: Dict[str, Any]) -> List:
        headers = {
            "Authorization": f"Bearer {self.token}"
        }

        response = self._http_request(
            method="GET",
            url_suffix="/vedsdk/certificates/",
            headers=headers,
            data=args
        )

        certificates = response.get("Certificates", [])
        return certificates


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        args = {
            "CreatedOn": "2018-07-16"
        }
        results = client._get_certificates(args)
        if results:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# # TODO: REMOVE the following dummy command function
# def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
#     dummy = args.get('dummy', None)
#     if not dummy:
#         raise ValueError('dummy not specified')
#
#     # Call the Client function and get the raw response
#     result = client.baseintegration_dummy(dummy)
#
#     return CommandResults(
#         outputs_prefix='BaseIntegration',
#         outputs_key_field='',
#         outputs=result,
#     )


def get_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    message: List = []
    response = client._get_certificates(args)
    if response:
        message = response

    human_readable = ""

    return CommandResults(
        outputs_prefix=CONTEXT_OUTPUT_BASE_PATH,
        outputs=message,
        raw_response=response,
        readable_output=human_readable
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    demisto_params = demisto.params()
    base_url = demisto_params.get('url', "https://ao-tlspd.dev.ven-eco.com")
    username = demisto_params.get('credentials')['identifier']
    password = demisto_params.get('credentials')['password']
    client_id = demisto_params.get('client_id')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            username=username,
            password=password,
            client_id=client_id,
            proxy=proxy)

        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'get-certificates':
            result = get_certificates_command(client, args)
            return_results(result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

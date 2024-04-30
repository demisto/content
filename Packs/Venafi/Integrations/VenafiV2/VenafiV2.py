import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MINUTES_BEFORE_TOKEN_EXPIRED = 2
CONTEXT_OUTPUT_BASE_PATH = "Venafi.Certificate"

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, username: str, password: str, client_id: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self._login(client_id, username, password)

    def _login(self, client_id: str, username: str, password: str) -> str:
        """
        Log into the Venafi API using the provided credentials.
        If it's the first time logging in, it will create a new token, save it to the integration context, and log in.
        Otherwise, if the token is expired, it will use the refresh token, save it to the integration context, and log in.
        And if the token is valid, it will log in.

        Args:
            client_id (str): The client ID of the user.
            username (str): The username of the user.
            password (str): The password of the user.

       Returns:
            str: The token of the user.
        """

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
        return utc_now > expires_datetime

    def _create_new_token(self, url_suffix: str, json_data: dict) -> str:
        """
        This method creates a new token.

        Args:
            url_suffix (str): The url to use in the http request.
            json_data (dict): The data that contain user credentials.

        Returns:
            str: The new token
        """

        payload = json.dumps(json_data)
        try:
            access_token_obj = self._http_request(
                method="POST",
                url_suffix=url_suffix,
                headers={'Content-Type': 'application/json'},
                data=payload,
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

    def _get_certificates(self, args: dict[str, Any]) -> dict:
        """
        This method creates the HTTP request to retrieve the certificates the user has.

        Args:
            args (dict): The arguments for the command passed to the request.

        Returns:
            dict: The certificates.
        """

        headers = {
            "Authorization": f"Bearer {self.token}"
        }

        certificates = self._http_request(
            method="GET",
            url_suffix="/vedsdk/certificates/",
            headers=headers,
            params=args
        )

        return certificates

    def _get_certificate_details(self, guid: str) -> dict:
        """
        This method creates the HTTP request to retrieve certificate details.

        Args:
            guid (str): The GUID of the certificate.

        Returns:
            dict: The certificate details.
        """

        headers = {
            "Authorization": f"Bearer {self.token}"
        }

        url_suffix = f"/vedsdk/certificates/{guid}"
        certificate_details = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            headers=headers
        )

        return certificate_details


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
        test_empty_args: Dict = {}
        results = client._get_certificates(test_empty_args)
        if results:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_certificates_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get all the certificates belong to a user.

    Args:
        client (Client): A Venafi client.
        args (dict): The arguments for the command passed to the request.
    Returns:
        A CommandResult object with an outputs, raw_response and readable table, in case of a successful action.
    """
    outputs: dict[str, Any] = {}
    response = client._get_certificates(args)
    if response:
        outputs = delete_links_from_response(response)

    human_readable = []
    certificates = outputs.get('Certificates', [])
    for certificate in certificates:
        certificate_guid = certificate.get("Guid")
        certificate_id = certificate_guid[1:-1]  # Guid represent as {guid}
        certificate_details = {
            "CreatedOn": certificate.get('CreatedOn'),
            "DN": certificate.get('DN'),
            "Name": certificate.get('Name'),
            "ParentDN": certificate.get('ParentDn'),
            "SchemaClass": certificate.get('SchemaClass'),
            "ID": certificate_id
        }
        human_readable.append(certificate_details)

    markdown_table = tableToMarkdown('Venafi certificates', human_readable)

    return CommandResults(
        outputs_prefix=CONTEXT_OUTPUT_BASE_PATH,
        outputs=outputs,
        raw_response=response,
        readable_output=markdown_table
    )


def delete_links_from_response(response: dict[str, Any]) -> dict[str, Any]:
    """
    Delete links list from the response

    Args:
        response (dict): raw response
    Returns:
        response (dict): response without the links list
    """
    certificates = response.get('Certificates', [])
    for certificate in certificates:
        if certificate.get("_links"):
            del certificate["_links"]

    return response


def get_certificate_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get certificate details.

    Args:
        client (Client): A Venafi client.
        args (dict): The arguments for the command passed to the request.
    Returns:
        A CommandResult object with an outputs, raw_response and readable table, in case of a successful action.
    """
    outputs: dict[str, Any] = {}
    guid = args.get('guid', "")
    response = client._get_certificate_details(guid)
    if response:
        outputs = response

    human_readable = []
    certificate_guid = outputs.get("Guid", "")
    certificate_id = certificate_guid[1:-1]  # Guid represent as {guid}
    certificate_details = {
        "CreatedOn": outputs.get('CreatedOn'),
        "DN": outputs.get('DN'),
        "Name": outputs.get('Name'),
        "ParentDN": outputs.get('ParentDn'),
        "SchemaClass": outputs.get('SchemaClass'),
        "ID": certificate_id
    }
    human_readable.append(certificate_details)

    markdown_table = tableToMarkdown('Venafi certificate details', human_readable)

    return CommandResults(
        outputs_prefix=CONTEXT_OUTPUT_BASE_PATH,
        outputs=outputs,
        raw_response=response,
        readable_output=markdown_table
    )


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions

    :return:
    :rtype:
    """
    demisto_params = demisto.params()
    base_url = demisto_params.get('server', "https://ao-tlspd.dev.ven-eco.com")
    username = demisto_params.get('credentials')['identifier']
    password = demisto_params.get('credentials')['password']
    client_id = demisto_params.get("client_id")
    verify_certificate = demisto_params.get('insecure', False)
    proxy = demisto_params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            username=username,
            password=password,
            client_id=client_id,
            proxy=proxy)

        args = demisto.args()
        if command == 'test-module':
            test_module_result = test_module(client)
            return_results(test_module_result)
        elif command == 'venafi-get-certificates':
            command_result = get_certificates_command(client, args)
            return_results(command_result)
        elif command == 'venafi-get-certificate-details':
            command_result = get_certificate_details_command(client, args)
            return_results(command_result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

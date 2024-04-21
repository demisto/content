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
        demisto.debug(f"in init: {self.token=}")

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
            "client_id": client_id,
            "username": username,
            "password": password,
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

    def _get_certificates(self, args: Dict[str, Any]) -> Dict:
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

    def _get_certificate_details(self, guid: str) -> Dict:
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
        test_empty_args = {}
        results = client._get_certificates(test_empty_args)
        if results:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    outputs: Dict[str, Any] = dict()
    response = client._get_certificates(args)

    if response:
        outputs = edit_response(response)

    human_readable = []
    certificates = outputs.get('Certificates')
    for certificate in certificates:
        certificate_guid = certificate.get("Guid")
        certificate_id = certificate_guid[1:-1]
        certificate_details = {
            "CreatedOn": certificate.get('CreatedOn'),
            "DN": certificate.get('DN'),
            "Name": certificate.get('Name'),
            "ParentDN": certificate.get('ParentDn'),
            "SchemaClass": certificate.get('SchemaClass'),
            "ID": certificate_id,
            "X509": certificate.get('X509'),
        }
        human_readable.append(certificate_details)

    markdown_table = tableToMarkdown('Venafi certificates query response', human_readable)

    return CommandResults(
        outputs_prefix=CONTEXT_OUTPUT_BASE_PATH,
        outputs=outputs,
        raw_response=response,
        readable_output=markdown_table
    )


def get_certificate_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    pass
    # message: List = []
    # guid = args.get('guid')
    # # if not guid?
    # response = client._get_certificate_details(guid)
    # if response:
    #
    #     message = edit_response(response)
    #
    # human_readable = ""
    #
    # return CommandResults(
    #     outputs_prefix=CONTEXT_OUTPUT_BASE_PATH,
    #     outputs=message,
    #     raw_response=response,
    #     readable_output=human_readable
    # )


def edit_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """remove links list from the response
    """
    certificates = response.get('Certificates')
    for certificate in certificates:
        if certificate.get("_links"):
            del certificate["_links"]

    return response

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

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
        elif command == 'venafi-get-certificates':
            result = get_certificates_command(client, args)
            return_results(result)
        elif command == 'venafi-get-certificate-details':
            result = get_certificate_details_command(client, args)
            return_results(result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

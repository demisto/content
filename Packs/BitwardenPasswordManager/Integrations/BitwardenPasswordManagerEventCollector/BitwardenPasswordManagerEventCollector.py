import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self.login(client_id, client_secret)

    def login(self, client_id: str, client_secret: str) -> str:
        integration_context = get_integration_context()
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self.is_token_expired(expires_date):
                return token
            else:
                refresh_token = integration_context.get('refresh_token')
                json_data = {
                    'client_id': client_id,
                    'refresh_token': refresh_token
                }
                return self.create_new_token(json_data, is_token_exist=True)

        json_data = {
            'username': username,
            'password': password,
            'client_id': client_id,
            'scope': 'certificate'
        }
        return self.create_new_token(json_data, is_token_exist=False)

    def is_token_expired(self, expires_date: str) -> bool:
        utc_now = get_current_time()
        expires_datetime = arg_to_datetime(expires_date)
        return utc_now > expires_datetime

    def create_new_token(self, json_data: dict, is_token_exist: bool) -> str:
        if is_token_exist:
            url_suffix = '/vedauth/authorize/token'
        else:
            url_suffix = '/vedauth/authorize/oauth'

        access_token_obj = self._http_request(
            method='POST',
            url_suffix=url_suffix,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(json_data),
        )

        new_token = access_token_obj.get('access_token', '')
        expire_in = arg_to_number(access_token_obj.get('expires_in')) or 1
        refresh_token = access_token_obj.get('refresh_token', '')
        self.store_token_in_context(new_token, refresh_token, expire_in)

        return new_token

    def store_token_in_context(self, token: str, refresh_token: str, expire_in: int) -> None:

        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context({
            'token': token,
            'refresh_token': refresh_token,
            'expire_date': str(expire_date)
        })

    # def get_certificates(self, args: dict[str, Any]) -> dict:
    #     """
    #     This method creates the HTTP request to retrieve the certificates the user has.
    #
    #     Args:
    #         args (dict): The arguments for the command passed to the request.
    #
    #     Returns:
    #         dict: The response object.
    #     """
    #
    #     headers = {
    #         'Authorization': f'Bearer {self.token}'
    #     }
    #
    #     return self._http_request(
    #         method='GET',
    #         url_suffix='/vedsdk/certificates/',
    #         headers=headers,
    #         params=args
    #     )


def test_module(client: Client) -> str:
    try:
        test_empty_args: Dict = {}
        # client.get_certificates(test_empty_args)
    except DemistoException as e:
        raise e

    return 'ok'


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions

    :return:
    :rtype:
    """

    demisto_params = demisto.params()
    base_url = demisto_params.get('server', 'api.bitwarden.com')
    username = demisto_params.get('credentials', {}).get('identifier')
    password = demisto_params.get('credentials', {}).get('password')
    client_id = demisto_params.get('client_id')
    verify_certificate = not demisto_params.get('insecure', False)
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
            return_results(test_module(client))
        # elif command == 'venafi-get-certificates':
        #     return_results(get_certificates_command(client, args))
        # elif command == 'venafi-get-certificate-details':
        #     return_results(get_certificate_details_command(client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return_error('Authorization Error: make sure API Key is correctly set')
        else:
            return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import datetime
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

PAGE_SIZE = 1000
DEFAULT_MAX_FETCH = 10000
MINUTES_BEFORE_TOKEN_EXPIRED = 2
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str = "", client_password: str = "", proxy: bool = False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        """ due to deprecating the basic auth option from the classical API versions 10.35 and up
            the client will try to generate an auth token first, if it failed to do generate the token,
            the client will use basic auth instead.
        """
        self.token = self._login(client_id, client_password)

    def _login(self, client_id: str, client_password: str) -> str:
        """
        This method is used to log in to the client. It first checks if a valid token exists in the integration context.
        If a valid token is found, it returns the token. If not, it creates a new token.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            str: The authentication token.
        """
        integration_context = get_integration_context()
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self._is_token_expired(expires_date):
                return token
        return self._create_new_token(client_id, client_password)

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

    def _generate_token(self, client_id: str, client_password: str) -> dict:
        """
        This method generates a reusable access token to authenticate requests to the Jamf Protect API.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            dict: The response from the API, which includes the access token.
        """
        payload = {
            "client_id": client_id,
            "password": client_password,
        }
        return self._http_request(
            method="POST",
            url_suffix="/token",
            json_data=payload,
        )

    def _create_new_token(self, client_id: str, client_password: str) -> str:
        """
        This method generates a new authentication token and stores it in the integration context.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            str: The newly generated authentication token.
        """
        res = self._generate_token(client_id, client_password)
        new_token = res.get("access_token")
        expire_in = res.get("expires_in")
        self._store_token_in_context(new_token, expire_in)
        return new_token

    def _store_token_in_context(self, token: str, expire_in: int) -> None:
        """
        This method stores the generated token and its expiration date in the integration context.

        Args:
            token (str): The generated authentication token.
            expire_in (int): The number of seconds until the token expires.

        Returns:
            None
        """
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context({"token": token, "expire_date": str(expire_date)})


''' HELPER FUNCTIONS '''

''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    try:
        client_id = params.get('client_id', {}).get('password', '')
        client_password = params.get('client_password', {}).get('password', '')
        max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_FETCH

        demisto.debug(f'Command being called is {demisto.command()}')

        client = Client(
            base_url=params.get('base_url'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            client_id=client_id,
            client_password=client_password
        )

        if demisto.command() == 'test-module':
            last_run = demisto.getLastRun()
            return_results(test_module(client, first_fetch_time_timestamp, last_run))
        elif demisto.command() == 'darktrace-get-events':
            events, results = get_events_command(client=client,
                                                 args=args,
                                                 first_fetch_time_timestamp=first_fetch_time_timestamp)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
        elif demisto.command() == 'fetch-events':
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_fetch,
                                                start_time=first_fetch_time_timestamp,
                                                end_time=int(datetime.now().timestamp()),
                                                last_run=last_run)
            if events:
                add_time_field(events)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

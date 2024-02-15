import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_MAX_FETCH = 5000
VENDOR = "cybelangel"
PRODUCT = "platform"

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, method: str, url_suffix: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        response = super()._http_request(
            method, url_suffix=url_suffix, headers=headers, params=params, resp_type="response", ok_codes=(401, 200)
        )
        if response.status_code == 200:
            return response.json()

        token = self.get_token_request()
        headers["Authorization"] = f'Bearer {token}'

        return super()._http_request(method, url_suffix=url_suffix, headers=headers, params=params)

    def get_reports(self, start_date: str, end_date: str) -> Dict[str, Any]:
        params = {
            "start-date": start_date,
            "end-date": end_date
        }
        return self.http_request(method='GET', url_suffix="/api/v2/reports", params=params)

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token
        return self.get_access_token()

    def get_token_request(self) -> str:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """

        token_response = self._http_request(
            'POST',
            full_url='https://auth.cybelangel.com/oauth/token',
            json_data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://platform.cybelangel.com/",
                "grant_type": "client_credentials"
            }
        )
        access_token, token_expiration_seconds = token_response.get('access_token'), token_response.get('expires_in')
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.debug(f'updating access token')
        set_integration_context(context=integration_context)

        return access_token


''' HELPER FUNCTIONS '''


def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
    """
    Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
    seconds minus a minute.

    for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

    300.0001 - 240 < 120 - 60

    Args:
        token_initiate_time (float): the time in which the token was initiated in seconds.
        token_expiration_seconds (float): the time in which the token should be expired in seconds.

    Returns:
        bool: True if token has expired, False if not.
    """
    return time.time() - token_initiate_time >= token_expiration_seconds - 60


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT)
    )
    return "ok"


def fetch_events(client: Client, last_run: Dict, max_fetch: int):
    pass


def get_events(client: Client, args: Dict[str, Any]) -> CommandResults:
    pass


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            events, last_fetch = fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_fetch)
        elif command == "cyble-angel-get-events":
            return_results(get_events(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

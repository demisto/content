import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, credentials: dict, verify: bool, proxy: bool):
        super().__init__(base_url=url, verify=verify, proxy=proxy)
        self.user_name = credentials["identifier"]
        self.password = credentials["password"]
        self.login()

    def login(self):
        """
        In this method, the validity of the Access Token is checked, since the Access Token has a 30 minutes validity period.
        Refreshes the token as needed.
        """
        now = datetime.utcnow()

        if (cache := get_integration_context()) and (token := cache.get("Token")):
            expiration_time = datetime.strptime(
                cache["expiration_time"], DATE_FORMAT_FOR_TOKEN
            )

            # check if token is still valid, and use the old one. otherwise regenerate a new one
            if (seconds_left := (expiration_time - now).total_seconds()) > 0:
                demisto.debug(f"No need to regenerate the token, it is still valid for {seconds_left} more seconds")
                self._set_headers(token)
                return

        demisto.debug("IntegrationContext token cache is empty or token has expired, regenerating a new token")
        raw_token, expires_in_seconds = self._refresh_access_token()
        self._set_headers(raw_token)

        set_integration_context(
            {
                "Token": raw_token,
                "expiration_time": (
                    now + timedelta(seconds=(expires_in_seconds - 60))  # decreasing 60s from token expiry for safety
                ).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        )


    def _refresh_access_token(self) -> tuple[str, int]:
        """
        Since the validity of the Access Token is 120 minutes, this method refreshes it and returns the new token json.
        returns:
            - the token
            - the expiration in seconds
        """
        credentials = base64.b64encode(self.credentials.encode()).decode("utf-8")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        }
        data = {"grant_type": "client_credentials", "scope": "read"}

        try:
            response_json = self._http_request(
                method="POST", url_suffix="/token", headers=headers, data=data
            )
        except Exception as e:
            # 400 - "invalid_grant" - reason: invalid Server URL, Client ID or Secret Key.
            if "invalid_grant" in str(e):
                raise DemistoException(
                    "Error in test-module: Make sure Server URL, Client ID and Secret Key are correctly entered."
                ) from e
            raise
        return response_json["access_token"], response_json["expires_in"]


    def _set_headers(self, token: str):
        """
        This method is called during the client's building or when a new token is generated since the old one has expired.
        """
        self._headers = {"X-Auth-Token": token}


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


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
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    demisto.debug(f"Command being called is {command}")

    try:

        client = Client(
            base_url=params["url"],
            client_id=params["credentials"]["identifier"],
            secret_key=params["credentials"]["password"],
            max_fetch=max_fetch,
            verify=verify_certificate,
            proxy=proxy,
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

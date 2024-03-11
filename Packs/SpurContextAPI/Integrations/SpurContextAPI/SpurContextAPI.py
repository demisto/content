import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *   # noqa: F401 # pylint: disable=unused-wildcard-import

import ipaddress
import urllib3
import urllib.parse
import traceback
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def ip(self, ip: str) -> CommandResults:
        # Validate that the input is a valid IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f'Invalid IP address: {ip}')
        encoded_ip = urllib.parse.quote(ip)
        full_url = urljoin(self._base_url, "/v2/context")
        full_url = urljoin(full_url, encoded_ip)
        demisto.debug(f'SpurContextAPI full_url: {full_url}')

        # Make the request
        response = self._http_request(
            method='GET',
            full_url=full_url,
            headers=self._headers,
        )

        return response


''' HELPER FUNCTIONS '''


def fix_nested_client(data):
    new_dict = data.copy()
    if "client" in data:
        del new_dict["client"]
        client = data["client"]
        new_dict["client_behaviors"] = client.get("behaviors", [])
        new_dict["client_countries"] = client.get("countries", 0)
        new_dict["client_spread"] = client.get("spread", 0)
        new_dict["client_proxies"] = client.get("proxies", [])
        new_dict["client_count"] = client.get("count", 0)
        new_dict["client_types"] = client.get("types", [])
        new_dict["client_concentration"] = client.get("concentration", None)

    return new_dict


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
        full_url = urljoin(client._base_url, 'status')
        demisto.debug(f'SpurContextAPI full_url: {full_url}')
        client._http_request(
            method='GET',
            full_url=full_url,
            headers=client._headers,
            raise_on_status=True,
        )
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def enrich_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get('ip', None)
    if not ip:
        raise ValueError('IP not specified')

    response = client.ip(ip)

    # Make sure the response is a dictionary
    if isinstance(response, dict):
        response = fix_nested_client(response)
        return CommandResults(
            outputs_prefix='SpurContextAPI.Context',
            outputs_key_field='',
            outputs=response,
            raw_response=response,
        )
    else:
        raise ValueError(f'Invalid response from API: {response}')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('credentials', {}).get('password')
    base_url = "https://api.spur.us/"
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: dict = {
            "TOKEN": api_key
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'spur-context-api-enrich':
            return_results(enrich_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception:
        return_error(f'Error: {traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

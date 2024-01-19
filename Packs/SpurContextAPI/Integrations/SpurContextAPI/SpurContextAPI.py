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

import ipaddress
import urllib3
import urllib.parse
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def ip(self, ip: str) -> dict[str, str]:
        """Returns a Spur Context API response as a flattened dictionary for the given input ip.

        :type ip: ``str``
        :param ip: ip address to enrich

        :return: dict
        :rtype: ``str``
        """

        # Validate that the input is a valid IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f'Invalid IP address: {ip}')
        encoded_ip = urllib.parse.quote(ip)
        full_url = urljoin(self._base_url, "/v2/context")
        full_url = urljoin(full_url, encoded_ip)
        demisto.debug(f'SpurContextAPI full_url: {full_url}')

        response = self._http_request(
            method='GET',
            full_url=full_url,
            headers=self._headers,
        )

        # If we get a dict back from the API, we need to flatten it
        if isinstance(response, dict):
            response = flatten(response)
        else:
            raise ValueError(f'Invalid response from API: {response}')
        return response


''' HELPER FUNCTIONS '''


def flatten(data):
    """
    Flatten the data from the API to a format that can be used as outputs
    """
    new_dict = {
        "ip": data.get("ip", ""),
    }
    new_dict["organization"] = data.get("organization", "")
    new_dict["infrastructure"] = data.get("infrastructure", "")
    new_dict["services"] = data.get("services", "")
    new_dict["risks"] = data.get("risks", "")

    if "as" in data:
        if "number" in data["as"]:
            new_dict["as_number"] = data["as"]["number"]
        if "organization" in data["as"]:
            new_dict["as_organization"] = data["as"]["organization"]
    else:
        new_dict["as_number"] = ""
        new_dict["as_organization"] = ""
    if "client" in data:
        client = data["client"]
        new_dict["client_behaviors"] = client.get("behaviors", [])
        new_dict["client_countries"] = client.get("countries", 0)
        new_dict["client_spread"] = client.get("spread", 0)
        new_dict["client_proxies"] = client.get("proxies", [])
        new_dict["client_count"] = client.get("count", 0)
        new_dict["client_types"] = client.get("types", [])
        if "concentration" in data["client"]:
            concentration = data["client"]["concentration"]
            new_dict["client_concentration_country"] = concentration.get("country", "")
            new_dict["client_concentration_city"] = concentration.get("city", "")
            new_dict["client_concentration_geohash"] = concentration.get("geohash", "")
            new_dict["client_concentration_density"] = concentration.get("density", 0.0)
            new_dict["client_concentration_skew"] = concentration.get("skew", 0)
    else:
        new_dict["client_behaviors"] = []
        new_dict["client_countries"] = 0
        new_dict["client_spread"] = 0
        new_dict["client_proxies"] = []
        new_dict["client_count"] = 0
        new_dict["client_types"] = []
        new_dict["client_concentration_country"] = ""
        new_dict["client_concentration_city"] = ""
        new_dict["client_concentration_geohash"] = ""
        new_dict["client_concentration_density"] = 0.0
        new_dict["client_concentration_skew"] = 0
    if "location" in data:
        location = data["location"]
        new_dict["location_country"] = location.get("country", "")
        new_dict["location_state"] = location.get("state", "")
        new_dict["location_city"] = location.get("city", "")
    else:
        new_dict["location_country"] = ""
        new_dict["location_state"] = ""
        new_dict["location_city"] = ""
    if "tunnels" in data:
        tunnel_types = []
        tunnels_anonymous = []
        tunnels_operator = []
        for tunnel in data["tunnels"]:
            if "type" in tunnel:
                tunnel_types.append(tunnel["type"])
            if "anonymous" in tunnel:
                tunnels_anonymous.append(str(tunnel["anonymous"]))
            if "operator" in tunnel:
                tunnels_operator.append(tunnel["operator"])
        new_dict["tunnels_type"] = tunnel_types
        new_dict["tunnels_anonymous"] = tunnels_anonymous
        new_dict["tunnels_operator"] = tunnels_operator
    else:
        new_dict["tunnels_type"] = ""
        new_dict["tunnels_anonymous"] = ""
        new_dict["tunnels_operator"] = ""

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


def ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ip = args.get('ip', None)
    if not ip:
        raise ValueError('IP not specified')

    # Call the Client function and get the raw response
    result = client.ip(ip)

    return CommandResults(
        outputs_prefix='SpurContextAPI.IP',
        outputs_key_field='',
        outputs=result,
    )


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

        elif demisto.command() == 'enrich':
            return_results(ip_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

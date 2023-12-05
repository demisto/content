import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
from typing import Any, Dict, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    def get_ip_geolocation(self, ip: str, api_key: str) -> Dict[str, Any]:
        """Gets the IP geolocation using the '/' API endpoint

        Args:
            ip (str): IP address to get the geolocation for.

            api_key (str): IP2Location.io API key.

        Returns:
            dict: dict containing the IP geolocation as returned from the API
        """

        return self._http_request(
            method='GET',
            url_suffix='/',
            params={
                'ip': ip,
                'key': api_key
            }
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): IP2LocationIO client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        return client._http_request(
            method='GET',
            url_suffix='/',
            params={
                'ip': '8.8.8.8'
            }
        )
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def ip_geolocation_command(client: Client, args: Dict[str, Any], reliability: DBotScoreReliability,
                           api_key: str) -> List[CommandResults]:
    """
    ip command: Returns IP geolocation for a list of IPs

    Args:
        client (Client): IP2LocationIO client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip']`` is a list of IPs or a single IP.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains IPs.
    """

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    command_results: List[CommandResults] = []

    for ip in ips:
        if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{ip}" is not valid')
        ip_data = client.get_ip_geolocation(ip, api_key)
        ip_data['ip'] = ip

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='IP2LocationIO',
            score=Common.DBotScore.NONE,
            reliability=reliability
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip,
            geo_country=ip_data.get('country_name'),
            geo_latitude=ip_data.get('latitude'),
            geo_longitude=ip_data.get('longitude'),
            geo_description=f"{ip_data.get('city_name')}, {ip_data.get('region_name')}, {ip_data.get('country_name')}",
            region=ip_data.get('region'),
            asn=f"AS{ip_data.get('asn')}",
            dbot_score=dbot_score
        )

        # Define which fields we want to exclude from the context output as
        # they are too verbose.
        ip_context_excluded_fields = ['objects', 'nir']
        ip_data = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
        #  automatically
        readable_output = tableToMarkdown('IP', ip_data)

        # INTEGRATION DEVELOPER TIP
        # The output key will be ``IP2LocationIO.IP``, using ``ip`` as the key field.
        # ``indicator`` is used to provide the context standard (IP)
        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='IP2LocationIO.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            indicator=ip_standard_context
        ))
    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(params.get('url'), '')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    reliability = params.get('integrationReliability', DBotScoreReliability.C)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'ip':
            return_results(ip_geolocation_command(client, args, reliability, api_key))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

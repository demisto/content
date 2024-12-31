import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


VERSION = 'latest'
LIMIT = 1000
CONTEXT_KEY = 'EDL'
INTEGRATION_ENTRY_CONTEXT = 'ThreatVault'
LOG_LINE = INTEGRATION_ENTRY_CONTEXT + "_" + CONTEXT_KEY + " -"


class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(
        self, base_url: str, api_key: str, verify: bool, proxy: bool, reliability: str
    ):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Content-Type": "application/json", "X-API-KEY": api_key},
        )

        self.name = "ThreatVault"
        self.reliability = reliability

    def get_indicators_request(self, args: dict) -> dict:   # pragma: no cover
        """Get indicators with proper URL API prefix

        Returns the http response.

        :type client: ``Client``
        :param Client: client to use

        :return: HTTP response dict.
        :rtype: ``dict``
        """
        suffix = 'edl'

        demisto.debug(f"{LOG_LINE} Sending GET request with params: {args}")

        return self._http_request(method="GET", url_suffix=suffix, params=args)

    def test_module(self) -> str:   # pragma: no cover
        """Tests API connectivity and authentication'

        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param Client: client to use

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        """

        command_results_list = []

        query = assign_params(
            name='panw-known-ip-list',
            version=VERSION,
            listformat='array',
        )
        try:
            self.get_indicators_request(args=query)

        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                readable_output = "There is no information for your search."
                command_results_list.append(CommandResults(readable_output=readable_output))
            else:
                raise

        return 'ok'


"""
HELP FUNCTIONS
"""


def parse_indicator_for_fetch(indicator: dict, tags: str, tlp_color: str, feed_tag_name: str) -> dict[str, Any]:
    """Parses the indicator given from the api to an indicator that can be sent to TIM XSOAR.

    Args:
        indicator (dict): The raw data of the indicator.
        tags (str): tags to be applied to the indicator.
        tlp_color (str): The tlp color of the indicator.
        feed_tag_name (str): the name of the feed broken down to a tag.

    Returns:
        dict[str, Any]: An indicator that can be sent to TIM.
    """
    # print(tags)
    all_tags = argToList(tags)
    all_tags.append(feed_tag_name)

    fields = assign_params(
        indicatoridentification=indicator,
        tags=all_tags,
        trafficlightprotocol=tlp_color
    )

    return assign_params(
        value=indicator,
        type=FeedIndicatorType.IP,
        fields=fields
    )


"""
COMMANDS
"""


def threatvault_get_indicators_command(client: Client, list_format: str, args: Dict) -> CommandResults:
    """Threatvault get indicators query main command.

    Args:
        client (Client): client.
        args (dict): arguments.

    Returns:
        CommandResults: Command results response.
    """
    name = args.get("name")
    version = args.get("version")
    offset = LIMIT
    ipaddr_list = []

    query = assign_params(
        name=name,
        version=version,
        listformat=list_format,
        limit=LIMIT,
    )

    try:
        response = client.get_indicators_request(args=query)

    except DemistoException as err:
        if err.res is not None and err.res.status_code == 404:
            response = {}
            readable_output = "There is no information for your search."
            CommandResults(readable_output=readable_output)
        else:
            raise

    if response.get('success'):
        count = response.get("count", 0)
        content_version_number = response.get("data", {}).get("version")
        ipaddr_list.extend(response.get("data", {}).get("ipaddr", []))

        # get next page of data until there is none left
        while count > offset:

            query = assign_params(
                name=name,
                version=version,
                listformat=list_format,
                offset=offset,
            )

            response = client.get_indicators_request(args=query)
            ipaddr_list.extend(response.get("data", {}).get("ipaddr", []))
            offset += LIMIT

        # create the table based on the response
        table = {
            'Name': args.get("name"),
            'Count': int(count),
            'Content_Version': int(content_version_number),
        }

        markdown = tableToMarkdown(f'ThreatVault EDL Results for: {name}\n', table, removeNull=True)

        table_full = table
        table_full['Addresses'] = ipaddr_list

        return CommandResults(
            outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.{CONTEXT_KEY}',
            outputs_key_field='',
            outputs=table_full,
            readable_output=markdown,
            raw_response=response
        )

    else:
        raise DemistoException(f"couldn't fetch - {response.get('message')}")


def fetch_indicators_command(client: Client,
                             predefined_edl_name: str,
                             list_format: str,
                             tlp_color: str,
                             feed_tags: str):
    """Threatvault fetch indicators query main command.

    Args:
        client (Client): client.
        interval (int): interval to request new feed content.
        predefined_edl_name (str):  predefined EDL name to fetch.
        list_format (str): format of the list to be returned (e.g., "array").
        tlp_color (str): TLP color provided in the integration instance.
        feed_tags (str): tags to apply to the feed contents.
        last_run (dict): last time the feed fetch executed.

    Returns:
        CommandResults: Command results response.
    """

    now = datetime.now(timezone.utc)
    name = predefined_edl_name
    version = VERSION
    offset = LIMIT
    ipaddr_list = []
    # automatically add a tag for the feed name by stripping leading panw-* and trailing *-list
    # split on the first - and keep right match
    feed_tag_name = name.split('-', 1)[1]
    # split on the last - and keep the left match
    feed_tag_name = feed_tag_name.rsplit('-', 1)[0]

    query = assign_params(
        name=name,
        version=version,
        listformat=list_format,
        limit=LIMIT,
    )

    try:
        response = client.get_indicators_request(args=query)

    except DemistoException as err:
        if err.res is not None and err.res.status_code == 404:
            response = {}
            readable_output = "There is no information for your search."
            CommandResults(readable_output=readable_output)
        else:
            raise

    if response.get('success'):
        count = response.get("count", 0)
        ipaddr_list.extend(response.get("data", {}).get("ipaddr"))

        # get next page of data until there is none left
        while count > offset:

            query = assign_params(
                name=name,
                version=version,
                listformat=list_format,
                offset=offset,
            )

            response = client.get_indicators_request(args=query)
            ipaddr_list.extend(response.get("data", {}).get("ipaddr"))
            offset += LIMIT

    else:
        raise DemistoException(f"couldn't fetch - {response.get('message')}")

    indicators = ipaddr_list
    demisto.debug(f'{LOG_LINE} got {len(indicators)}')

    results = []

    for indicator in indicators:

        results.append(parse_indicator_for_fetch(indicator, feed_tags, tlp_color, feed_tag_name))

    return now.strftime('%Y-%m-%dT%H:%M:%SZ'), results


"""
MAIN
"""


def main():

    params = demisto.params()
    """PARAMS"""
    base_url = urljoin(params["url"], "service/v1/")
    api_key = params.get("credentials", {}).get("password")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", "")
    reliability = params.get("integrationReliability", "B - Usually reliable")
    # TLP 2.0 - CLEAR == WHITE, ++ TLP:AMBER+STRICT
    tlp_color = params.get('tlp_color') or 'WHITE'
    feed_tags = params.get('feedTags', '')
    predefined_edl_name = params['name']
    list_format = params['list_format'].lower()

    if not DBotScoreReliability.is_valid_type(reliability):
        raise Exception(
            "Please provide a valid value for the Source Reliability parameter."
        )

    try:
        command = demisto.command()
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
            reliability=reliability,
        )

        commands = {
            "threatvault-get-indicators": threatvault_get_indicators_command
        }
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = client.test_module()
            return_results(result)

        elif command == 'fetch-indicators':
            run_datetime, res = fetch_indicators_command(
                client=client,
                predefined_edl_name=predefined_edl_name,
                list_format=list_format,
                feed_tags=feed_tags,
                tlp_color=tlp_color,
            )

            for iter_ in batch(res, batch_size=2000):
                demisto.debug(f"{LOG_LINE} {iter_=}")
                demisto.createIndicators(iter_)

            demisto.setLastRun({"last_successful_run": run_datetime})

        elif command in commands:
            return_results(commands[command](client, list_format, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except NotImplementedError:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command. The command not implemented")

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error runnning integration - {err}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import re
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
SOURCE_NAME = "AutoFocusFeed"


class Client(BaseClient):
    """Client for AutoFocus Feed - gets indicator lists from the Custom and Daily threat feeds

    Attributes:
        api_key(str): The API key for AutoFocus.
        insecure(bool): Use SSH on http request.
        proxy(str): Use system proxy.
        indicator_feeds(List): A list of indicator feed types to bring from AutoFocus.
        output_feed_id(str): The ID given to the custom feed.
        output_feed_name(str): The name given to the custom feed.
    """
    def __init__(self, api_key, insecure, proxy, indicator_feeds, output_feed_id="", output_feed_name=""):
        self.url_feed_base_url = "https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/"
        self.daily_feed_base_url = "https://autofocus.paloaltonetworks.com/api/v1.0/output/threatFeedResult"
        self.headers = {
            "apiKey": api_key,
            'Content-Type': "application/json"
        }
        self.indicator_feeds = indicator_feeds
        self.url_feed_suffix = output_feed_id + "/" + output_feed_name
        self.verify = not insecure
        if proxy:
            handle_proxy()

    def http_request(self, feed_type) -> list:
        """The HTTP request for the feed.

        Args:
            feed_type(str): The feed type (Daily or Custom feed).

        Returns:
            list. A list of indicators fetched from the feed.
        """
        if feed_type == "Daily Threat Feed":
            url = self.daily_feed_base_url

        else:
            url = self.url_feed_base_url + self.url_feed_suffix

        res = requests.request(
            method="GET",
            url=url,
            verify=self.verify,
            headers=self.headers
        )
        res.raise_for_status()
        return res.text.split('\n')

    def find_indicator_type(self, indicator):
        """Infer the type of the indicator.

        Args:
            indicator(str): The indicator whose type we want to check.

        Returns:
            str. The type of the indicator.
        """
        if re.match(ipv4cidrRegex, indicator):
            return FeedIndicatorType.CIDR

        if re.match(ipv6cidrRegex, indicator):
            return FeedIndicatorType.IPv6CIDR

        if re.match(ipv4Regex, indicator):
            return FeedIndicatorType.IP

        if re.match(ipv6Regex, indicator):
            return FeedIndicatorType.IPv6

        elif re.match(sha256Regex, indicator):
            return FeedIndicatorType.File

        # in AutoFocus, URLs include '/' character while domains do not.
        elif '/' in indicator:
            return FeedIndicatorType.URL

        else:
            return FeedIndicatorType.Domain

    def build_iterator(self):
        """Builds a list of indicators.

        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        indicators = []

        if "Daily Threat Feed" in self.indicator_feeds:
            indicators.extend(self.http_request("Daily Threat Feed"))

        if "URL Feed" in self.indicator_feeds:
            indicators.extend(self.http_request("URL Feed"))

        parsed_indicators = []

        for indicator in indicators:
            if indicator:
                indicator_type = self.find_indicator_type(indicator)

                parsed_indicators.append({
                    "type": indicator_type,
                    "value": indicator,
                    "rawJSON": {
                        'value': indicator,
                        'type': indicator_type
                    }
                })

        return parsed_indicators


def module_test_command(client: Client, args: dict):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Autofocus Feed client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.build_iterator()
    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict):
    """Initiate a single fetch-indicators

    Args:
        client(Client): The AutoFocus Client.
        args(dict): Command arguments.

    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    indicators = client.build_iterator()

    if args.get('limit'):
        indicators = indicators[:int(str(args.get('limit')))]

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append({
            "Value": indicator.get('value'),
            "Type": indicator.get('type')
        })

    human_readable = tableToMarkdown("Indicators from AutoFocus:", hr_indicators,
                                     headers=['Value', 'Type'], removeNull=True)

    return human_readable, {
        f"{SOURCE_NAME}.Indicator(val.Value == obj.Value && val.Type == obj.Type)": hr_indicators}, indicators


def fetch_indicators_command(client: Client):
    """Fetch-indicators command from AutoFocus Feeds

    Args:
        client(Client): AutoFocus Feed client.

    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator()

    return indicators


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    client = Client(params.get('api_key'), params.get('insecure'), params.get('proxy'), params.get('indicator_feeds'),
                    params.get('output_feed_id'), params.get('output_feed_name'))
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': module_test_command,
        'get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=500):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

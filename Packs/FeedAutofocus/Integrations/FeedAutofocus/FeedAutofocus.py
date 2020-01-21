import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import re
import requests
import socket

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
        if 'URL Feed' in indicator_feeds and (output_feed_name is None or output_feed_id is None):
            return_error("Output Feed ID and Name are required for URL Feed")

        elif 'URL Feed' in indicator_feeds:
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

    def is_ip_type(self, indicator):
        if re.match(ipv4cidrRegex, indicator):
            return FeedIndicatorType.CIDR

        elif re.match(ipv6cidrRegex, indicator):
            return FeedIndicatorType.IPv6CIDR

        elif re.match(ipv4Regex, indicator):
            return FeedIndicatorType.IP

        elif re.match(ipv6Regex, indicator):
            return FeedIndicatorType.IPv6

        else:
            return None

    def find_indicator_type(self, indicator):
        """Infer the type of the indicator.

        Args:
            indicator(str): The indicator whose type we want to check.

        Returns:
            str. The type of the indicator.
        """

        # trying to catch X.X.X.X:portNum
        if ':' in indicator and '/' not in indicator:
            sub_indicator = indicator.split(':', 1)[0]
            ip_type = self.is_ip_type(sub_indicator)
            if ip_type:
                return ip_type

        ip_type = self.is_ip_type(indicator)
        if ip_type:
            # catch URLs of type X.X.X.X/path/url or X.X.X.X:portNum/path/url
            if '/' in indicator and (ip_type not in [FeedIndicatorType.IPv6CIDR, FeedIndicatorType.CIDR]):
                return FeedIndicatorType.URL

            else:
                return ip_type

        elif re.match(sha256Regex, indicator):
            return FeedIndicatorType.File

        # in AutoFocus, URLs include a path while domains do not - so '/' is a good sign for us to catch URLs.
        elif '/' in indicator:
            return FeedIndicatorType.URL

        else:
            return FeedIndicatorType.Domain

    def resolve_ip_address(self, ip):
        if self.is_ip_type(ip):
            return socket.gethostbyaddr(ip)[0]

        return None

    def build_iterator(self):
        """Builds a list of indicators.

        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        indicators = []

        if "Daily Threat Feed" in self.indicator_feeds:
            indicators.extend(self.http_request(feed_type="Daily Threat Feed"))

        if "URL Feed" in self.indicator_feeds:
            indicators.extend(self.http_request(feed_type="URL Feed"))

        parsed_indicators = []

        for indicator in indicators:
            if indicator:
                indicator_type = self.find_indicator_type(indicator)

                # catch ip of the form X.X.X.X:portNum and extract the IP without the port.
                if indicator_type in [FeedIndicatorType.IP, FeedIndicatorType.CIDR,
                                      FeedIndicatorType.IPv6CIDR, FeedIndicatorType.IPv6] and ":" in indicator:
                    indicator = indicator.split(":", 1)[0]

                elif indicator_type == FeedIndicatorType.URL:
                    if ":" in indicator:
                        resolved_address = self.resolve_ip_address(indicator.split(":", 1)[0])
                        semicolon_suffix = indicator.split(":", 1)[1]
                        slash_suffix = None

                    else:
                        resolved_address = self.resolve_ip_address(indicator.split("/", 1)[0])
                        slash_suffix = indicator.split("/", 1)[1]
                        semicolon_suffix = None

                    if resolved_address:
                        if semicolon_suffix:
                            indicator = resolved_address + ":" + semicolon_suffix

                        else:
                            indicator = resolved_address + "/" + slash_suffix

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
    indicator_feeds = client.indicator_feeds
    if 'Daily Threat Feed' in indicator_feeds:
        client.indicator_feeds = ['Daily Threat Feed']
        try:
            client.build_iterator()
        except Exception:
            raise Exception("Could not fetch Daily Threat Feed\n\nCheck your API key and your connection AutoFocus.")

    if 'URL Feed' in indicator_feeds:
        client.indicator_feeds = ['URL Feed']
        try:
            client.build_iterator()
        except Exception:
            raise Exception(f"Could not fetch URL Feed {client.url_feed_suffix}\n\n"
                            f"Check your API key the URL Feed ID and Name and Check if they are Enabled in AutoFocus.")
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
    if args.get('offset'):
        indicators = indicators[int(str(args.get('offset'))):]

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

    if args.get('limit'):
        human_readable = human_readable + f"\nTo bring the next batch of indicators run:\n!autofocus-get-indicators " \
            f"limit={args.get('limit')} offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"

    return human_readable, {}, indicators


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
    params = demisto.params()

    client = Client(params.get('api_key'),
                    params.get('insecure'),
                    params.get('proxy'),
                    params.get('indicator_feeds'),
                    params.get('output_feed_id'),
                    params.get('output_feed_name'))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'autofocus-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import re
import requests
from typing import List
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
        custom_feed_urls(str): The URLs of the custom feeds to fetch.
    """

    def __init__(self, api_key, insecure, proxy, indicator_feeds, custom_feed_urls=None):
        self.daily_feed_base_url = "https://autofocus.paloaltonetworks.com/api/v1.0/output/threatFeedResult"
        self.headers = {
            "apiKey": api_key,
            'Content-Type': "application/json"
        }
        self.indicator_feeds = indicator_feeds
        if 'Custom Feed' in indicator_feeds and (custom_feed_urls is None or custom_feed_urls == ''):
            return_error("Output Feed ID and Name are required for Custom Feed")

        elif 'Custom Feed' in indicator_feeds:
            url_list = []  # type:List
            for url in custom_feed_urls.split(','):
                url_list.append(self.url_format(url))

            self.custom_feed_url_list = url_list

        self.verify = not insecure
        if proxy:
            handle_proxy()

    def url_format(self, url):
        """Make sure the URL is in the format:
        https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/{ID}/{Name}

        Args:
            url(str): The URL to format.

        Returns:
            str. The reformatted URL.
        """
        if "https://autofocus.paloaltonetworks.com/IOCFeed/" in url:
            url = url.replace("https://autofocus.paloaltonetworks.com/IOCFeed/",
                              "https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/")

        elif "autofocus.paloaltonetworks.com/IOCFeed/" in url:
            url = url.replace("autofocus.paloaltonetworks.com/IOCFeed/",
                              "https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/")

        return url

    def http_request(self, feed_type) -> list:
        """The HTTP request for the feed.

        Args:
            feed_type(str): The feed type (Daily or Custom feed).

        Returns:
            list. A list of indicators fetched from the feed.
        """
        if feed_type == "Daily Threat Feed":
            urls = [self.daily_feed_base_url]

        else:
            urls = self.custom_feed_url_list

        indicator_list = []  # type:List
        for url in urls:
            res = requests.request(
                method="GET",
                url=url,
                verify=self.verify,
                headers=self.headers
            )
            res.raise_for_status()
            indicator_list.extend(res.text.split('\n'))

        return indicator_list

    def get_ip_type(self, indicator):
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
            ip_type = self.get_ip_type(sub_indicator)
            if ip_type:
                return ip_type

        ip_type = self.get_ip_type(indicator)
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

    def build_iterator(self, limit=None, offset=None):
        """Builds a list of indicators.

        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        indicators = []  # type:List

        if "Daily Threat Feed" in self.indicator_feeds:
            indicators.extend(self.http_request(feed_type="Daily Threat Feed"))

        if "Custom Feed" in self.indicator_feeds:
            indicators.extend(self.http_request(feed_type="Custom Feed"))

        if limit:
            indicators = indicators[int(offset): int(offset)+int(limit)]

        parsed_indicators = []  # type:List

        for indicator in indicators:
            if indicator:
                indicator_type = self.find_indicator_type(indicator)

                # catch ip of the form X.X.X.X:portNum and extract the IP without the port.
                if indicator_type in [FeedIndicatorType.IP, FeedIndicatorType.CIDR,
                                      FeedIndicatorType.IPv6CIDR, FeedIndicatorType.IPv6] and ":" in indicator:
                    indicator = indicator.split(":", 1)[0]

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
    exception_list = []  # type:List
    if 'Daily Threat Feed' in indicator_feeds:
        client.indicator_feeds = ['Daily Threat Feed']
        try:
            client.build_iterator(1, 0)
        except Exception:
            exception_list.append("Could not fetch Daily Threat Feed\n"
                                  "\nCheck your API key and your connection to AutoFocus.")

    if 'Custom Feed' in indicator_feeds:
        client.indicator_feeds = ['Custom Feed']
        url_list = client.custom_feed_url_list
        for url in url_list:
            client.custom_feed_url_list = [url]
            try:
                client.build_iterator(1, 0)
            except Exception:
                exception_list.append(f"Could not fetch Custom Feed {url}\n"
                                      f"\nCheck your API key the URL for the feed and Check "
                                      f"if they are Enabled in AutoFocus.")

    if len(exception_list) > 0:
        raise Exception("\n".join(exception_list))

    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict):
    """Initiate a single fetch-indicators

    Args:
        client(Client): The AutoFocus Client.
        args(dict): Command arguments.

    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 100))

    indicators = fetch_indicators_command(client, limit, offset)

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


def fetch_indicators_command(client: Client, limit=None, offset=None):
    """Fetch-indicators command from AutoFocus Feeds

    Args:
        client(Client): AutoFocus Feed client.
        limit: limit the amount of incidators fetched.
        offset: the index of the first index to fetch.

    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator(limit, offset)

    return indicators


def main():
    params = demisto.params()

    client = Client(params.get('api_key'),
                    params.get('insecure'),
                    params.get('proxy'),
                    params.get('indicator_feeds'),
                    params.get('custom_feed_urls'))

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

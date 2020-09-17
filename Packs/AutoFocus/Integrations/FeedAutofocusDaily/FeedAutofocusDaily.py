import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import requests
from typing import List, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """Client for AutoFocus Feed - gets indicator lists from Daily threat feeds

    Attributes:
        api_key(str): The API key for AutoFocus.
        insecure(bool): Use SSH on http request.
        proxy(str): Use system proxy.
    """

    def __init__(self, api_key, insecure):
        self.api_key = api_key
        self.verify = not insecure
        handle_proxy()

    def daily_http_request(self) -> list:
        """The HTTP request for daily feeds.
        Returns:
            list. A list of indicators fetched from the feed.
        """
        headers = {
            "apiKey": self.api_key,
            'Content-Type': "application/json"
        }

        res = requests.request(
            method="GET",
            url='https://autofocus.paloaltonetworks.com/api/v1.0/output/threatFeedResult',
            verify=self.verify,
            headers=headers
        )
        res.raise_for_status()
        indicator_list = res.text.split('\n')
        return indicator_list

    def get_ip_type(self, indicator):
        """
        Indicates the correct IP of the given indicator.
        Args:
            indicator: (str) Will be checked according to it the type will be returned.
        Returns:
            Indicator Type of the given value.
        """
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

    def create_indicators_from_response(self, response: list, feed_tags: list) -> list:
        """
        Creates a list of indicators from a given response
        Args:
            response: List of dict that represent the response from the api
            feed_tags: The indicator tags
        Returns:
            List of indicators with the correct indicator type.
        """
        parsed_indicators = []  # type:List

        for indicator in response:
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
                        'type': indicator_type,
                        'service': 'Daily Threat Feed'
                    },
                    'fields': {'service': 'Daily Threat Feed', 'tags': feed_tags}
                })

        return parsed_indicators

    def build_iterator(self, feed_tags: List, limit=None, offset=None):
        """Builds a list of indicators.
        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        response = self.daily_http_request()
        parsed_indicators = self.create_indicators_from_response(response, feed_tags)  # list of dict of indicators

        # for get_indicator_command only
        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]
        return parsed_indicators


def module_test_command(client: Client, args: dict, feed_tags: list):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client(Client): Autofocus Feed client
        args(Dict): The instance parameters
        feed_tags: The indicator tags

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.build_iterator(argToList(demisto.params().get('feedTags')), 1, 0)
    except Exception:
        raise Exception("Could not fetch Daily Threat Feed\n"
                        "\nCheck your API key and your connection to AutoFocus.")
    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict, feed_tags: list) -> Tuple[str, dict, list]:
    """Initiate a single fetch-indicators

    Args:
        client(Client): The AutoFocus Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags
    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 100))

    indicators = fetch_indicators_command(client, feed_tags, limit, offset)

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append({
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON'),
            'fields': indicator.get('fields'),
        })

    human_readable = tableToMarkdown("Indicators from AutoFocus:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'], removeNull=True)

    if args.get('limit'):
        human_readable = human_readable + f"\nTo bring the next batch of indicators " \
                                          f"run:\n!autofocus-daily-get-indicators " \
                                          f"limit={args.get('limit')} " \
                                          f"offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"

    return human_readable, {}, indicators


def fetch_indicators_command(client: Client, feed_tags: List, limit=None, offset=None) -> list:
    """Fetch-indicators command from AutoFocus Feeds

    Args:
        client(Client): AutoFocus Feed client.
        feed_tags: The indicator tags
        limit: limit the amount of incidators fetched.
        offset: the index of the first index to fetch.

    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator(feed_tags, limit, offset)

    return indicators


def main():
    params = demisto.params()
    feed_tags = argToList(params.get('feedTags'))
    client = Client(api_key=params.get('api_key'),
                    insecure=params.get('insecure'))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'autofocus-daily-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, feed_tags)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args(),
                                                                       feed_tags)  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in AutoFocusFeed Daily Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

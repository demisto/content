import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import requests
from typing import List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
SOURCE_NAME = "AutoFocusFeedDaily"
DAILY_FEED_BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0/output/threatFeedResult'


class Client(BaseClient):
    """Client for AutoFocus Feed - gets indicator lists from the Custom and Daily threat feeds

    Attributes:
        api_key(str): The API key for AutoFocus.
        insecure(bool): Use SSH on http request.
        proxy(str): Use system proxy.
    """

    def __init__(self, api_key, insecure, proxy):
        self.api_key = api_key
        self.verify = not insecure
        if proxy:
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
            url=DAILY_FEED_BASE_URL,
            verify=self.verify,
            headers=headers
        )
        res.raise_for_status()
        indicator_list = res.text.split('\n')
        return indicator_list

    def create_indicators_from_response(self, feed_type, response):
        parsed_indicators = []  # type:List

        for indicator in response:
            if indicator:
                indicator_type = auto_detect_indicator_type(indicator)
                parsed_indicators.append({
                    "type": indicator_type,
                    "value": indicator,
                    "rawJSON": {
                        'value': indicator,
                        'type': indicator_type,
                        'service': feed_type
                    },
                    'fields': {'service': feed_type}
                })

        return parsed_indicators

    def build_iterator(self, limit=None, offset=None):
        """Builds a list of indicators.
        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        response = self.daily_http_request()
        parsed_indicators = self.create_indicators_from_response('Daily Threat Feed',
                                                                 response)  # list of dict of indicators

        # for get_indicator_command only
        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]
        return parsed_indicators


def module_test_command(client: Client, args: dict):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client(Client): Autofocus Feed client
        args(Dict): The instance parameters

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.build_iterator(1, 0)
    except Exception:
        raise Exception("Could not fetch Daily Threat Feed\n"
                        "\nCheck your API key and your connection to AutoFocus.")
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
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON'),
            'fields': indicator.get('fields'),
        })

    human_readable = tableToMarkdown("Indicators from AutoFocus:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'], removeNull=True)

    if args.get('limit'):
        human_readable = human_readable + f"\nTo bring the next batch of indicators run:\n!autofocus-get-indicators " \
                                          f"limit={args.get('limit')} " \
                                          f"offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"

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

    client = Client(api_key=params.get('api_key'),
                    insecure=params.get('insecure'),
                    proxy=params.get('proxy'))

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
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

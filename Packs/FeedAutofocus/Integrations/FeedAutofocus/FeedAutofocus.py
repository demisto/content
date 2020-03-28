import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
import re
import requests
from typing import List
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
SOURCE_NAME = "AutoFocusFeed"
DAILY_FEED_BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0/output/threatFeedResult'
SAMPLE_FEED_BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0/samples/'
SAMPLE_FEED_REQUEST_BASE_URL = f'{SAMPLE_FEED_BASE_URL}search'
SAMPLE_FEED_RESPONSE_BASE_URL = f'{SAMPLE_FEED_BASE_URL}results/'

EPOCH_BASE = datetime.utcfromtimestamp(0)

af_indicator_type_to_demisto = {
    'Domain': FeedIndicatorType.Domain,
    'Url': FeedIndicatorType.URL,
    'IPv4': FeedIndicatorType.IP
}


def datetime_to_epoch(dt_to_convert):
    delta_from_epoch_base = dt_to_convert - EPOCH_BASE
    return int(delta_from_epoch_base.total_seconds() * 1000)


class Client(BaseClient):
    """Client for AutoFocus Feed - gets indicator lists from the Custom and Daily threat feeds

    Attributes:
        api_key(str): The API key for AutoFocus.
        insecure(bool): Use SSH on http request.
        proxy(str): Use system proxy.
        indicator_feeds(List): A list of indicator feed types to bring from AutoFocus.
        scope_type(str): The scope type of the AutoFocus sample feed.
        sample_query(str): The query to use to fetch indicators from AutoFocus sample feed.
        sample_size(str): The amount of indicators to fetch from AutoFocus sample feed.
        custom_feed_urls(str): The URLs of the custom feeds to fetch.
    """

    def __init__(self, api_key, insecure, proxy, indicator_feeds, custom_feed_urls=None,
                 scope_type=None, sample_query=None, sample_size=None):
        self.api_key = api_key
        self.indicator_feeds = indicator_feeds

        if 'Custom Feed' in indicator_feeds and (custom_feed_urls is None or custom_feed_urls == ''):
            return_error(f'{SOURCE_NAME} - Output Feed ID and Name are required for Custom Feed')

        elif 'Custom Feed' in indicator_feeds:
            url_list = []  # type:List
            for url in custom_feed_urls.split(','):
                url_list.append(self.url_format(url))

            self.custom_feed_url_list = url_list

        if 'Sample Feed' in indicator_feeds:
            self.scope_type = scope_type

            if not sample_query:
                return_error(f'{SOURCE_NAME} - Sample Query can not be empty for Sample Feed')
            try:
                self.sample_query = json.loads(sample_query)
            except Exception:
                return_error(f'{SOURCE_NAME} - Sample Query is not a well formed JSON object')

            if not str.isdigit(sample_size):
                return_error(f'{SOURCE_NAME} - Sample Size needs to be a valid integer')
            self.sample_size = int(sample_size)

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

    def daily_custom_http_request(self, feed_type) -> list:
        """The HTTP request for daily and custom feeds.

        Args:
            feed_type(str): The feed type (Daily / Custom feed / Sample feed).

        Returns:
            list. A list of indicators fetched from the feed.
        """
        headers = {
            "apiKey": self.api_key,
            'Content-Type': "application/json"
        }

        if feed_type == "Daily Threat Feed":
            urls = [DAILY_FEED_BASE_URL]

        else:
            urls = self.custom_feed_url_list

        indicator_list = []  # type:List
        for url in urls:
            res = requests.request(
                method="GET",
                url=url,
                verify=self.verify,
                headers=headers
            )
            res.raise_for_status()
            indicator_list.extend(res.text.split('\n'))

        return indicator_list

    def sample_http_request(self) -> list:
        """The HTTP request for the sample feed.

        Args:

        Returns:
            list. A list of indicators fetched from the feed.
        """
        request_body = {
            'apiKey': self.api_key,
            'artifactSource': 'af',
            'scope': self.scope_type,
            'query': self.sample_query,
            'type': 'scan',
            'size': self.sample_size
        }

        initiate_sample_res = requests.request(
            method="POST",
            headers={'Content-Type': "application/json"},
            url=SAMPLE_FEED_REQUEST_BASE_URL,
            verify=self.verify,
            json=request_body
        )
        initiate_sample_res.raise_for_status()

        af_cookie = initiate_sample_res.json()['af_cookie']
        time.sleep(20)

        get_results_res = requests.request(
            method="POST",
            url=SAMPLE_FEED_RESPONSE_BASE_URL + af_cookie,
            verify=self.verify,
            json={'apiKey': self.api_key}
        )
        get_results_res.raise_for_status()

        indicator_list = []  # type:List

        for single_sample in get_results_res.json()['hits']:
            indicator_list.extend(self.create_indicators_from_single_sample_response(single_sample))

        return indicator_list

    @staticmethod
    def create_indicators_from_single_sample_response(single_sample):
        indicators = []

        single_sample_data = single_sample.get('_source', {})
        if not single_sample_data:
            return []

        raw_json_data = {
            'autofocus_id': single_sample.get('_id'),
            'autofocus_region': single_sample_data.get('region', []),
            'autofocus_malware': single_sample_data.get('malware', 0),
            'autofocus_tags': single_sample_data.get('tag', []),
            'autofocus_tags_groups': single_sample_data.get('tag_groups', []),
        }

        update_date = single_sample_data.get('update_date', None)
        if update_date is not None:
            update_date = datetime.strptime(update_date, '%Y-%m-%dT%H:%M:%S')
            raw_json_data['autofocus_update_date'] = datetime_to_epoch(update_date)

        create_date = datetime.strptime(single_sample_data['create_date'], '%Y-%m-%dT%H:%M:%S')
        raw_json_data['autofocus_create_date'] = datetime_to_epoch(create_date)

        # raw_json_data['autofocus_malware'] = item['malware']

        # sha256_ = item['sha256']
        # sha1_ = item.get('sha1', None)
        # md5_ = item['md5']
        #
        # if '...' in sha256_:
        #     return []
        #
        # tvalue = copy.copy(rawJSON_data)
        # tvalue['type'] = 'sha256'
        # indicators.append([
        #     sha256_,
        #     tvalue
        # ])
        #
        # tvalue = copy.copy(rawJSON_data)
        # tvalue['type'] = 'md5'
        # tvalue['autofocus_sha256'] = sha256_
        # indicators.append([
        #     md5_,
        #     tvalue
        # ])
        #
        # if sha1_ is not None:
        #     tvalue = copy.copy(rawJSON_data)
        #     tvalue['type'] = 'sha1'
        #     tvalue['autofocus_sha256'] = sha256_
        #     indicators.append([
        #         sha1_,
        #         tvalue
        #     ])

        artifacts = single_sample_data.get('artifact', [])
        artifacts_count = len(artifacts)

        for artifact in artifacts:
            indicator_value = artifact.get('indicator', None)
            if indicator_value is None:
                continue

            autofocus_indicator_type = artifact.get('indicator_type', None)
            indicator_type = af_indicator_type_to_demisto.get(autofocus_indicator_type)
            if not indicator_type:
                continue

            autofocus_benign = artifact.get('b', 0)
            autofocus_grayware = artifact.get('g', 0)
            autofocus_malware = artifact.get('m', 0)
            autofocus_confidence = artifact.get('confidence', '')

            indicator_raw_json = raw_json_data
            indicator_raw_json.update(
                {
                    'value': indicator_value,
                    'type': indicator_type,
                    'confidence': autofocus_confidence,
                    'autofocus_num_matching_artifacts': artifacts_count,
                    'autofocus_malware': autofocus_malware,
                    'autofocus_benign': autofocus_benign,
                    'autofocus_grayware': autofocus_grayware
                }
            )

            if indicator_type == FeedIndicatorType.IP and ':' in indicator_value:
                indicator_value, port = indicator_value.split(':', 1)
                indicator_raw_json['autofocus_port'] = port

            single_indicator = {
                'value': indicator_raw_json['value'],
                'type': indicator_raw_json['type'],
                'rawJSON': indicator_raw_json
            }

            indicators.append(single_indicator)

        return indicators

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
            indicators.extend(self.daily_custom_http_request(feed_type="Daily Threat Feed"))

        if "Custom Feed" in self.indicator_feeds:
            indicators.extend(self.daily_custom_http_request(feed_type="Custom Feed"))

        if limit:
            indicators = indicators[int(offset): int(offset) + int(limit)]

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

        if "Sample Feed" in self.indicator_feeds:
            parsed_indicators.extend(self.sample_http_request())

        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]

        return parsed_indicators[:10]


def module_test_command(client: Client, args: dict):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client(Client): Autofocus Feed client
        args(Dict): The instance parameters

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

    if 'Sample Feed' in indicator_feeds:
        client.indicator_feeds = ['Sample Feed']
        try:
            client.build_iterator(1, 0)
        except Exception:
            exception_list.append("Could not fetch Sample Feed\n"
                                  "\nCheck your instance configuration and your connection to AutoFocus.")

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
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON')
        })

    human_readable = tableToMarkdown("Indicators from AutoFocus:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON'], removeNull=True)

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

    client = Client(api_key=params.get('api_key'),
                    insecure=params.get('insecure'),
                    proxy=params.get('proxy'),
                    indicator_feeds=params.get('indicator_feeds'),
                    custom_feed_urls=params.get('custom_feed_urls'),
                    scope_type=params.get('scope_type'),
                    sample_query=params.get('sample_query'),
                    sample_size=params.get('sample_size'))

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

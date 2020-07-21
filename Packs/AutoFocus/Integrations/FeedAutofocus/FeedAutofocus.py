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

VERDICTS_TO_DBOTSCORE = {
    '0': 1,
    '1': 3,
    '2': 2,
    '4': 3,
}

VERDICTS_TO_TEXT = {
    '0': 'benign',
    '1': 'malware',
    '2': 'grayware',
    '4': 'phishing',
}

CONFIDENCE_TO_DBOTSCORE = {
    'interesting': 2,
    'suspect': 3,
    'highly_suspect': 3
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
        scope_type(str): The scope type of the AutoFocus samples feed.
        sample_query(str): The query to use to fetch indicators from AutoFocus samples feed.
        custom_feed_urls(str): The URLs of the custom feeds to fetch.
    """

    def __init__(self, api_key, insecure, proxy, indicator_feeds, custom_feed_urls=None,
                 scope_type=None, sample_query=None):
        self.api_key = api_key
        self.indicator_feeds = indicator_feeds

        if 'Custom Feed' in indicator_feeds and (custom_feed_urls is None or custom_feed_urls == ''):
            return_error(f'{SOURCE_NAME} - Output Feed ID and Name are required for Custom Feed')

        elif 'Custom Feed' in indicator_feeds:
            url_list = []  # type:List
            for url in custom_feed_urls.split(','):
                url_list.append(self.url_format(url))

            self.custom_feed_url_list = url_list

        if 'Samples Feed' in indicator_feeds:
            self.scope_type = scope_type

            if not sample_query:
                return_error(f'{SOURCE_NAME} - Samples Query can not be empty for Samples Feed')
            try:
                self.sample_query = json.loads(sample_query)
            except Exception:
                return_error(f'{SOURCE_NAME} - Samples Query is not a well formed JSON object')

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
            feed_type(str): The feed type (Daily / Custom feed / Samples feed).

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
        """The HTTP request for the samples feed.

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

        for single_sample in get_results_res.json().get('hits'):
            indicator_list.extend(self.create_indicators_from_single_sample_response(single_sample))

        return indicator_list

    @staticmethod
    def get_basic_raw_json(single_sample: dict):
        single_sample_data = single_sample.get('_source', {})
        artifacts = single_sample_data.get('artifact', [])

        raw_json_data = {
            'autofocus_id': single_sample.get('_id'),
            'autofocus_region': [single_region.upper() for single_region in single_sample_data.get('region', [])],
            'autofocus_tags': single_sample_data.get('tag', []),
            'autofocus_tags_groups': single_sample_data.get('tag_groups', []),
            'autofocus_num_matching_artifacts': len(artifacts),
            'service': 'AutoFocus Samples Feed'
        }

        create_date = single_sample_data.get('create_date', None)
        if create_date is not None:
            create_date = datetime.strptime(create_date, '%Y-%m-%dT%H:%M:%S')
            raw_json_data['autofocus_create_date'] = datetime_to_epoch(create_date)

        update_date = single_sample_data.get('update_date', None)
        if update_date is not None:
            update_date = datetime.strptime(update_date, '%Y-%m-%dT%H:%M:%S')
            raw_json_data['autofocus_update_date'] = datetime_to_epoch(update_date)

        return raw_json_data

    @staticmethod
    def create_indicators_for_file(raw_json_data: dict, full_sample_json: dict):
        raw_json_data['type'] = FeedIndicatorType.File
        raw_json_data['md5'] = full_sample_json.get('md5')
        raw_json_data['size'] = full_sample_json.get('size')
        raw_json_data['sha1'] = full_sample_json.get('sha1')
        raw_json_data['value'] = full_sample_json.get('sha256')
        raw_json_data['sha256'] = full_sample_json.get('sha256')
        raw_json_data['ssdeep'] = full_sample_json.get('ssdeep')
        raw_json_data['region'] = [single_region.upper() for single_region in full_sample_json.get('region', [])]
        raw_json_data['imphash'] = full_sample_json.get('imphash')
        raw_json_data['autofocus_filetype'] = full_sample_json.get('filetype')
        raw_json_data['autofocus_malware'] = VERDICTS_TO_TEXT.get(full_sample_json.get('malware'))  # type: ignore

        fields_mapping = {
            'md5': full_sample_json.get('md5'),
            'tags': full_sample_json.get('tag'),
            'size': full_sample_json.get('size'),
            'sha1': full_sample_json.get('sha1'),
            'region': raw_json_data.get('region'),
            'sha256': full_sample_json.get('sha256'),
            'ssdeep': full_sample_json.get('ssdeep'),
            'imphash': full_sample_json.get('imphash'),
            'filetype': full_sample_json.get('filetype'),
            'threattypes': [{'threatcategory': threat} for threat in full_sample_json.get('tag_groups', [])],
            'creationdate': raw_json_data.get('autofocus_create_date'),
        }

        return [
            {
                'value': raw_json_data['value'],
                'type': raw_json_data['type'],
                'rawJSON': raw_json_data,
                'fields': fields_mapping,
                'score': VERDICTS_TO_DBOTSCORE.get(full_sample_json.get('malware'), 0)  # type: ignore
            }
        ]

    @staticmethod
    def create_indicator_from_artifact(raw_json_data: dict, artifact: dict):
        indicator_value = artifact.get('indicator', None)
        if indicator_value is None:
            return None

        autofocus_indicator_type = artifact.get('indicator_type', None)
        indicator_type = af_indicator_type_to_demisto.get(autofocus_indicator_type)
        if not indicator_type:
            return None

        raw_json_data.update(
            {
                'value': indicator_value,
                'type': indicator_type,
                'autofocus_confidence': artifact.get('confidence', ''),
                'autofocus_malware': artifact.get('m', 0),
                'autofocus_benign': artifact.get('b', 0),
                'autofocus_grayware': artifact.get('g', 0)
            }
        )

        if indicator_type == FeedIndicatorType.IP and ':' in indicator_value:
            indicator_value, port = indicator_value.split(':', 1)
            raw_json_data['autofocus_port'] = port

        fields_mapping = {
            'firstseenbysource': raw_json_data.get('autofocus_create_date'),
            'region': raw_json_data.get('autofocus_region'),
            'tags': raw_json_data.get('autofocus_tags'),
            'threattypes': [{'threatcategory': threat} for threat in raw_json_data.get('autofocus_tags_groups', [])],
            'service': 'AutoFocus Samples Feed'
        }

        return {
            'value': raw_json_data['value'],
            'type': raw_json_data['type'],
            'rawJSON': raw_json_data,
            'fields': fields_mapping,
            'score': CONFIDENCE_TO_DBOTSCORE.get(artifact.get('confidence'), 0),  # type: ignore
        }

    @staticmethod
    def create_indicators_from_single_sample_response(single_sample):
        single_sample_data = single_sample.get('_source', {})
        if not single_sample_data:
            return []

        # When the user do not have access to sample's details a truncated sha256 is used.
        if '...' in single_sample_data.get('sha256', '...'):
            return []

        indicators = Client.create_indicators_for_file(Client.get_basic_raw_json(single_sample), single_sample_data)

        artifacts = single_sample_data.get('artifact', [])

        for artifact in artifacts:
            indicator_from_artifact = Client.create_indicator_from_artifact(Client.get_basic_raw_json(single_sample),
                                                                            artifact)
            if indicator_from_artifact:
                indicators.append(indicator_from_artifact)

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

    def create_indicators_from_response(self, feed_type, response, feed_tags):
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
                        'service': feed_type
                    },
                    'fields': {'service': feed_type, 'tags': feed_tags}
                })

        return parsed_indicators

    def build_iterator(self, feed_tags: List, limit=None, offset=None):
        """Builds a list of indicators.

        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        parsed_indicators = []  # type:List

        for service in ["Daily Threat Feed", "Custom Feed"]:
            if service in self.indicator_feeds:
                response = self.daily_custom_http_request(feed_type=service)
                parsed_indicators.extend(self.create_indicators_from_response(service, response, feed_tags))

        # for get_indicator_command only
        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]

        if "Samples Feed" in self.indicator_feeds:
            parsed_indicators.extend(self.sample_http_request())

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
    indicator_feeds = client.indicator_feeds
    exception_list = []  # type:List
    if 'Daily Threat Feed' in indicator_feeds:
        raise Exception("Daily Feed is no longer supported by this feed,"
                        " please configure the AutoFocus Daily Feed for this action")
    if 'Custom Feed' in indicator_feeds:
        client.indicator_feeds = ['Custom Feed']
        url_list = client.custom_feed_url_list
        for url in url_list:
            client.custom_feed_url_list = [url]
            try:
                client.build_iterator(feed_tags, 1, 0)
            except Exception:
                exception_list.append(f"Could not fetch Custom Feed {url}\n"
                                      f"\nCheck your API key the URL for the feed and Check "
                                      f"if they are Enabled in AutoFocus.")

    if 'Samples Feed' in indicator_feeds:
        client.indicator_feeds = ['Samples Feed']
        try:
            client.build_iterator(feed_tags, 1, 0)
        except Exception:
            exception_list.append("Could not fetch Samples Feed\n"
                                  "\nCheck your instance configuration and your connection to AutoFocus.")

    if len(exception_list) > 0:
        raise Exception("\n".join(exception_list))

    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict, feed_tags):
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
        human_readable = human_readable + f"\nTo bring the next batch of indicators run:\n!autofocus-get-indicators " \
                                          f"limit={args.get('limit')} " \
                                          f"offset={int(str(args.get('limit'))) + int(str(args.get('offset')))}"

    return human_readable, {}, indicators


def fetch_indicators_command(client: Client, feed_tags: List, limit=None, offset=None):
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
                    insecure=params.get('insecure'),
                    proxy=params.get('proxy'),
                    indicator_feeds=params.get('indicator_feeds'),
                    custom_feed_urls=params.get('custom_feed_urls'),
                    scope_type=params.get('scope_type'),
                    sample_query=params.get('sample_query'))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'autofocus-get-indicators': get_indicators_command
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
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

from CommonServerPython import *
''' IMPORTS '''
from typing import List, Dict, Union, Optional
import jmespath
import urllib3

# disable insecure warnings
urllib3.disable_warnings()


class Client:
    def __init__(self, url: str = '', credentials: Dict[str, str] = None,
                 feed_name_to_config: Dict[str, dict] = None, source_name: str = 'JSON',
                 extractor: str = '', indicator: str = 'indicator', fields: Union[List, str] = None,
                 insecure: bool = False, cert_file: str = None, key_file: str = None, headers: dict = None, **_):
        """
        Implements class for miners of JSON feeds over http/https.
        :param url: URL of the feed.
        :param credentials:
            username: username for BasicAuth authentication
            password: password for BasicAuth authentication
        :param extractor: JMESPath expression for extracting the indicators from
        :param indicator: the JSON attribute to use as indicator. Default: indicator
        :param source_name: feed source name
        :param fields: list of JSON attributes to include in the indicator value.
        If None no additional attributes will be extracted.
        :param insecure: if *False* feed HTTPS server certificate will be verified
        Hidden parameters:
        :param: cert_file: client certificate
        :param: key_file: private key of the client certificate
        :param: headers: Header parameters are optional to specify a user-agent or an api-token
        Example: headers = {'user-agent': 'my-app/0.0.1'} or Authorization: Bearer
        (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")
         Example:
            Example feed config:
            'AMAZON': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "prefixes[?service=='AMAZON']",
                'indicator': 'ip_prefix',
                'fields': ['region', 'service']
            }
        """

        self.source_name = source_name or 'JSON'
        if feed_name_to_config:
            self.feed_name_to_config = feed_name_to_config
        else:
            self.feed_name_to_config = {
                self.source_name: {
                    'url': url,
                    'indicator': indicator or 'indicator',
                    'extractor': extractor or '@',
                    'fields': argToList(fields)
                }}

        # Request related attributes
        self.url = url
        self.verify = not insecure
        self.auth: Optional[tuple] = None
        if credentials:
            self.auth = (credentials.get('username'), credentials.get('password'))

        # Hidden params
        self.headers = headers
        self.cert = (cert_file, key_file) if cert_file and key_file else None

    def build_iterator(self, **kwargs) -> List:
        results = []
        for feed_name, feed in self.feed_name_to_config.items():
            r = requests.get(
                url=feed.get('url', self.url),
                verify=self.verify,
                auth=self.auth,
                cert=self.cert,
                headers=self.headers,
                **kwargs
            )

            try:
                r.raise_for_status()
                data = r.json()
                result = jmespath.search(expression=feed.get('extractor'), data=data)
                results.append({feed_name: result})

            except ValueError as VE:
                raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')

        return results


def test_module(client, params) -> str:
    indicator_type = params.get('indicator_type')
    if 'feed_name_to_config' not in params and not FeedIndicatorType.is_valid_type(indicator_type):
        supported_values = ', '.join((
            FeedIndicatorType.Account,
            FeedIndicatorType.CVE,
            FeedIndicatorType.Domain,
            FeedIndicatorType.Email,
            FeedIndicatorType.File,
            FeedIndicatorType.MD5,
            FeedIndicatorType.SHA1,
            FeedIndicatorType.SHA256,
            FeedIndicatorType.Host,
            FeedIndicatorType.IP,
            FeedIndicatorType.CIDR,
            FeedIndicatorType.IPv6,
            FeedIndicatorType.IPv6CIDR,
            FeedIndicatorType.Registry,
            FeedIndicatorType.SSDeep,
            FeedIndicatorType.URL
        ))
        raise ValueError(f'Indicator type of {indicator_type} is not supported. Supported values are:'
                         f' {supported_values}')
    client.build_iterator()
    return 'ok'


def fetch_indicators_command(client: Client, indicator_type: str, **kwargs) -> Union[Dict, List[Dict]]:
    """
    Fetches the indicators from client.
    :param client: Client of a JSON Feed
    :param indicator_type: the default indicator type
    """
    indicators = []
    for result in client.build_iterator(**kwargs):
        for sub_feed_name, items in result.items():
            feed_config = client.feed_name_to_config.get(sub_feed_name, {})
            indicator_field = feed_config.get('indicator', 'indicator')
            indicator_type = feed_config.get('indicator_type', indicator_type)
            fields = feed_config.get('fields', [])
            for item in items:
                mapping = feed_config.get('mapping')
                attributes = {'source_name': sub_feed_name}
                indicator_value = item.get(indicator_field)
                indicator = {'value': indicator_value, 'type': indicator_type}
                for f in fields:
                    attributes[f] = item.get(f)
                    if mapping and f in mapping:
                        indicator[mapping[f]] = item.get(f)

                attributes.update(indicator)
                indicator['rawJSON'] = attributes

                indicators.append(indicator)

    return indicators


def feed_main(params, feed_name, prefix):
    # handle proxy settings
    handle_proxy()

    client = Client(**params)
    indicator_type = params.get('indicator_type')
    command = demisto.command()
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    if command != 'fetch-indicators':
        demisto.info(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            return_outputs(test_module(client, params))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, indicator_type)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == f'{prefix}get-indicators':
            # dummy command for testing
            limit = int(demisto.args().get('limit', 10))
            indicators = fetch_indicators_command(client, indicator_type)[:limit]
            hr = tableToMarkdown('Indicators', indicators, headers=['value', 'type', 'rawJSON'])
            return_outputs(hr, {}, indicators)

    except Exception as err:
        err_msg = f'Error in {feed_name} integration [{err}]'
        return_error(err_msg)

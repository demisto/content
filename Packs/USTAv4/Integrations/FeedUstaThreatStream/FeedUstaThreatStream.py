import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from datetime import datetime, timedelta


# Disable insecure warnings
urllib3.disable_warnings()

USTA_API_PREFIX = 'api/threat-stream/v4/'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

USTA_IOC_FEED_TYPES = [
    "malicious-urls",
    "malware-hashes",
    "phishing-sites"
]

SERVICE_NAME = 'FeedUstaThreatStream'

MAX_HISTORICAL_DAYS = 7


class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def check_auth(self):
        self._http_request('GET', 'company/me', error_handler=self._http_error_handler)

    def build_iterator(self, ioc_feed_type: str, start_time: str, limit: int = 0) -> list:
        params = assign_params(start=start_time, size=limit)
        res = self._http_request(
            'GET',
            f'security-intelligence/ioc/{ioc_feed_type}',
            params=params,
            headers=self._headers
        )
        next_url = res.get('next', None)
        results = res.get('results', [])

        # Make sure limit is not exceeded on returned results
        if len(results) > limit:
            demisto.debug(f"Limit of {limit} exceeded. Truncating results.")
            return results[:limit]

        while next_url:
            res = self._http_request('GET', full_url=next_url, headers=self._headers)
            results += res.get('results', [])
            next_url = res.get('next', None)

        return results

    def search_iterator_without_pagination(self, ioc_feed_type: str, **kwargs) -> dict:
        params = assign_params(**kwargs)
        return self._http_request(
            'GET',
            f'security-intelligence/ioc/{ioc_feed_type}',
            params=params,
            headers=self._headers
        )

    @staticmethod
    def _http_error_handler(response):
        # Handle error responses here to proper error messages to the user
        if response.status_code == 401:
            raise DemistoException('Authorization Error: make sure API Key is correctly set')
        if response.status_code == 429:
            raise DemistoException('Rate limit exceeded. Please try again later..!')


def check_module(client: Client):
    try:
        client.check_auth()
    except DemistoException as e:
        if 'Connection Timeout Error' in str(e):
            return ValueError('Unable to connect to the USTA API! Make sure that your IP is whitelisted in the USTA.')
        raise e
    return 'ok'


def parse_malware_hashes(indicator: dict) -> dict:
    _value = indicator.get("hashes", {}).get("sha256")
    _type = FeedIndicatorType.File

    parsed_indicator = {
        'value': _value,
        "type": _type,
        "rawJSON": indicator,
        'fields': {
            'md5': indicator.get("hashes", '{}').get("md5"),
            'sha1': indicator.get("hashes", {}).get("sha1"),
            'sha256': indicator.get("hashes", {}).get("sha256"),
            'tags': indicator.get("tags", [])
        }
    }
    parsed_indicator['fields']['tags'].append('usta-malware-hashes')

    return parsed_indicator


def parse_malicious_urls(indicator: dict):
    _value = indicator.get("url")
    _type = FeedIndicatorType.URL

    # _value may contain only domain. Thus following function may return different indicator type.
    if new_type := auto_detect_indicator_type(_value):
        _type = new_type

    parsed_indicator = {
        'value': _value,
        'type': _type,
        'rawJSON': indicator,
        'fields': {
            'ip_addresses': indicator.get("ip_addresses", []),
            'host': indicator.get("host", ''),
            'tags': indicator.get("tags", [])
        }
    }
    parsed_indicator['fields']['tags'].append('usta-malicious-urls')  # type: ignore
    return parsed_indicator


def parse_phishing_sites(indicator: dict):
    _value = indicator.get("url")
    _type = FeedIndicatorType.URL

    # _value may contain only domain. Thus following function may return different indicator type.
    if new_type := auto_detect_indicator_type(_value):
        _type = new_type

    parsed_indicator = {
        'value': _value,
        'type': _type,
        'rawJSON': indicator,
        'fields': {
            'country': indicator.get("country", ''),
            'ip_addresses': indicator.get("ip_addresses", []),
            'host': indicator.get("host", ''),
            'tags': indicator.get("tags", [])
        }
    }
    parsed_indicator['fields']['tags'].append('usta-phishing-sites')  # type: ignore
    return parsed_indicator


def search_command(client: Client, args: dict, ioc_feed_type: str) -> CommandResults:
    limit = int(args.get('limit', 10))
    search_value = args.get('hash') if ioc_feed_type == 'malware-hashes' else args.get('url')
    if results := client.search_iterator_without_pagination(ioc_feed_type=ioc_feed_type, search=search_value, size=limit):
        indicators = results.get('results', [])
        human_readable = tableToMarkdown(f'Indicators from USTA Feed ({ioc_feed_type}):', indicators)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='',
            outputs_key_field='',
            raw_response=indicators,
            outputs={},
        )
    return CommandResults(readable_output='No results found.')


def fetch_indicators_command(client: Client, last_run: dict, params: Dict[str, Any]):  # -> tuple[dict, list[dict]]:
    """Fetches indicators from the chosen feed. The indicators are fetched based on the last fetch time we received
    from the last fetch. The indicators are then iterated over, and for each indicator, we create a dictionary with
    the indicator's value, type, and raw data. We then append this dictionary to a list of indicators.

    Args:
        client (Client): The HTTP client object.
        last_run (dict): A dictionary containing the last_fetch key with the last fetch time.
        params (Dict[str, Any]): The integration parameters.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    ioc_feed_type = argToList(params.get('ioc_feed_type'))
    if 'ALL' in ioc_feed_type:
        ioc_feed_type = USTA_IOC_FEED_TYPES

    all_indicators = {}

    parsed_indicators = []

    # Fetch indicators for each feed type
    for ioc_type in ioc_feed_type:
        start_time = (datetime.now() - timedelta(days=MAX_HISTORICAL_DAYS)).strftime("%Y-%m-%dT00:00:00")
        if last_fetch := last_run.get(ioc_type):
            start_time = last_fetch.get('created')

        indicators = client.build_iterator(
            ioc_feed_type=ioc_type,
            start_time=start_time,
            limit=100
        )

        if indicators:
            all_indicators[ioc_type] = indicators

        demisto.debug(f"Found {len(indicators)} indicators for feed type {ioc_type}")

    # process indicators and skip if indicator id in last_run
    for feed in all_indicators:
        indicators = all_indicators[feed]
        last_run_for_feed = last_run.get(feed, {})
        for indicator in indicators:
            # Skip if indicator is already saved ! deduplication
            if indicator.get('created') == last_run_for_feed.get('created'):
                demisto.debug(f"Skipping indicator {indicator.get('id')} as it was already fetched.")
                indicators.remove(indicator)
                continue
            # Initialize indicator_obj to avoid using it before assignment
            indicator_obj = {}

            # If type is malware-hashes, then we need to convert the hashes to hash type indicator of Cortex XSOAR
            if feed == 'malware-hashes':
                indicator_obj = parse_malware_hashes(indicator)

            elif feed == 'malicious-urls':
                indicator_obj = parse_malicious_urls(indicator)

            elif feed == 'phishing-sites':
                indicator_obj = parse_phishing_sites(indicator)

            if feed_tags:
                indicator_obj['fields']['tags'].extend(feed_tags)

            if tlp_color:
                indicator_obj['fields']['trafficlightprotocol'] = tlp_color

            # Adding name of the service supplying this feed.
            indicator_obj['service'] = SERVICE_NAME

            # make sure tags are unique
            indicator_obj['fields']['tags'] = list(set(indicator_obj['fields']['tags']))

            parsed_indicators.append(indicator_obj)

    # Update last_run with the latest indicator for each feed type
    for feed in all_indicators:
        if not all_indicators[feed]:
            continue

        latest_item = all_indicators[feed][0]
        last_run[feed] = {
            'created': latest_item.get('created'),
            'id': latest_item.get('id')
        }
    return last_run, parsed_indicators


def search_malware_hashes_command(client: Client, args: dict) -> CommandResults:
    return search_command(client, args, 'malware-hashes')


def search_malicious_urls_command(client: Client, args: dict) -> CommandResults:
    return search_command(client, args, 'malicious-urls')


def search_phishing_site_command(client: Client, args: dict) -> CommandResults:
    return search_command(client, args, 'phishing-sites')


def main():
    # demisto params and args
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    # Instance parameters
    verify_certificate: bool = not params.get('insecure', False)
    base_url = urljoin(params['url'], USTA_API_PREFIX)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key')

    cmd = demisto.command()
    demisto.debug(f"Command being called is {cmd}")

    try:
        headers: dict = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        commands = {
            'usta-tsa-search-malware-hash': search_malware_hashes_command,
            'usta-tsa-search-malicious-url': search_malicious_urls_command,
            'usta-tsa-search-phishing-site': search_phishing_site_command,
        }

        if cmd == "test-module":
            return_results(check_module(client))

        elif cmd == "fetch-indicators":
            next_run, indicators = fetch_indicators_command(
                client=client,
                last_run=demisto.getLastRun(),
                params=params
            )
            demisto.debug(f"All fetching is done. Total found {len(indicators)} indicators.")
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
            demisto.setLastRun(next_run)
        elif cmd in commands:
            return_results(commands[cmd](client, args))
        else:
            raise NotImplementedError(f"Command {cmd} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {cmd} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()

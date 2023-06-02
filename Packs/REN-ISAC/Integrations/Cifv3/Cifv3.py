import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import requests
import traceback
from typing import Dict, Any
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

# CONSTANTS
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # Date Format for times in CIFv3 timestamps
USER_AGENT = 'PALO-ALTO-XSOAR/REN-ISAC/CIFv3'

indicatorMap = {"ipv4": FeedIndicatorType.IP,
                "ipv6": FeedIndicatorType.IPv6,
                "fqdn": FeedIndicatorType.Domain,
                "url": FeedIndicatorType.URL,
                "email": FeedIndicatorType.Email,
                "md5": FeedIndicatorType.File,
                "sha1": FeedIndicatorType.File,
                "sha256": FeedIndicatorType.File
                }


# CLIENT CLASS: No business logic, just 3rd party API commands
class Client(BaseClient):
    "Abstract Client Class to interact with REN-ISAC's CIFv3 framework"

    def test(self):
        "Test Function"
        return self._http_request(
            method='GET',
            url_suffix='/help',
            resp_type='text')

    def search_indicators(self, filters: dict) -> json:
        """
        Search Function to query REN-ISAC for indicators with a custom filter string.
        This is really not a FEED function, but more of an enrichment function.
        """
        r = self._http_request(
            method='GET',
            url_suffix='/search',
            resp_type='json',
            params=filters)
        return json.loads(r["data"])

    def fetch_indicators(self, filters: dict) -> list:
        "Fetch function that is periodically called to fetch indicators"
        r = self._http_request(
            method='GET',
            url_suffix='/feed',
            resp_type='json',
            params=filters)
        return r["data"]


''' HELPER FUNCTIONS '''


def buildIndicatorObs(itype: str, rawList: list, start_time):
    latest_timestamp = start_time
    indicators = []

    for item in rawList:
        indicators.append(
            {'type': indicatorMap.get(itype),
             'value': item.get('indicator'),
             'rawJSON': item
             })
        stamp = datetime.strptime(item.get('reporttime'), DATE_FORMAT)
        if stamp > latest_timestamp:
            latest_timestamp = stamp

    return indicators, latest_timestamp.strftime(DATE_FORMAT)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    message: str = ''
    try:
        client.test()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_indicators(client: Client, params: dict) -> str:
    """
    Wrapper funtion that calls fetch indicators with the default integration settings;
    however, limits the number of returned items and will only fetch the last 3 days of
    indicators.
    """
    last_run = datetime.today() - timedelta(3)
    reporttime = last_run.strftime(DATE_FORMAT)
    itype = str(params.get('itype'))
    confidence = params.get('confidence')
    tags = argToList(params.get('tags'))
    limit = params.get('max_fetch')

    filter = {"itype": itype, "confidence": confidence,
              "tags": tags, "limit": limit, "reporttime": reporttime}

    try:
        result = client.fetch_indicators(filter)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    if result:
        indicators, _ = buildIndicatorObs(itype, result, last_run)
        result = indicators
        return CommandResults(
            outputs_prefix='CIFv3',
            outputs=result
        )


def fetch_indicators(client: Client, params: dict) -> str:
    "Fetch indicators Function"
    first = params.get('first_fetch', '4 days')
    start_time = dateparser.parse(first, settings={'TIMEZONE': 'UTC'})

    last_run = str(demisto.getLastRun())
    if last_run and 'start_time' in last_run:
        stime = str(demisto.getLastRun().get('start_time'))
        start_time = datetime.strptime(stime, DATE_FORMAT)

    # Build Filter for fetch
    itype = str(params.get('itype'))
    confidence = params.get('confidence')
    tags = argToList(params.get('tags'))
    limit = params.get('max_fetch')
    reporttime = start_time.strftime(DATE_FORMAT)

    filter = {"itype": itype, "confidence": confidence,
              "tags": tags, "limit": limit, "reporttime": reporttime}

    try:
        result = client.fetch_indicators(filter)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    if result:
        indicators, latest_timestamp = buildIndicatorObs(itype, result, start_time)
        for b in batch(indicators, batch_size=2000):
            demisto.createIndicators(b)
        demisto.setLastRun(
            {'start_time': latest_timestamp}
        )


def search_indicators(client: Client, args: dict) -> str:
    filter = args.get('filter')
    limit = args.get('limit')
    confidence = args.get('confidence')
    filter.update({"confidence": f"{confidence}"})
    filter.update({"limit": f"{limit}"})

    try:
        result = client.search_indicators(filter)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    if result:
        hits = result.get('hits')
    return CommandResults(
        outputs_prefix='CIFv3',
        outputs_key_field='provider',
        outputs=hits,
    )


def main() -> None:
    params = demisto.params()
    ''' Parameters extracted for now '''
    base_url = params.get('url')
    api_key = params.get('apikey')
    proxy = params.get('proxy', False)
    verify_certificate = not demisto.params().get('insecure', False)

    args = demisto.args()
    demisto.debug(f'Command being called is {demisto.command()}')
    headers = {
        'Authorization': f'Token token={api_key}',
        'User-Agent': USER_AGENT,
        'Content-Type': 'application/json',
        'Accept-Encoding': 'deflate',
        'Accept': 'application/vnd.cif.v3+json'
    }
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'cifv3-get-indicators':
            return_results(get_indicators(client, params))

        elif demisto.command() == 'fetch-indicators':
            return_results(fetch_indicators(client, params))

        elif demisto.command() == 'cifv3-search-indicators':
            return_results(search_indicators(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

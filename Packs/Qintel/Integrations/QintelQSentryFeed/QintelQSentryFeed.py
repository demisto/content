import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

''' IMPORTS '''

import urllib3
from typing import Dict, Any, Generator
from datetime import datetime
from dateutil.parser import parse as parse_dt
from pytz import utc as pyutc
import traceback
from gzip import GzipFile
from json import loads

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %I:%M:%S'
VERSION = 'v1.0.0'
USER_AGENT = f'Qintel-CortexXSOAR/{VERSION}'
VENDOR = 'Qintel'

QSENTRY_REMOTE = 'https://qsentry.qintel.com'


class Client(BaseClient):
    """Client class to interact with Qintel APIs"""

    def __init__(self, base_url, verify=True, proxy=False, **kwargs):
        super(Client, self).__init__(base_url, verify=verify, proxy=proxy)

        self._headers = {
            'User-Agent': USER_AGENT,
            'x-api-key': kwargs.get('token')
        }

    def _process_feed_reponse(self, response) -> Generator[Dict, None, None]:
        with GzipFile(fileobj=response) as file:
            for line in file.readlines():
                yield loads(line)

    def fetch(self, path) -> Generator[Dict, None, None]:

        response = self._http_request(
            method='GET',
            url_suffix=path,
            resp_type='response',
            stream=True
        )

        for i in self._process_feed_reponse(response.raw):
            yield i

    def ping(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='files'
        )


def test_module(client) -> str:

    try:
        client.ping()
    except Exception as e:
        return 'Test failed: {}'.format(e)

    return 'ok'


def _make_timestamp(ts):
    if not ts:
        return

    if isinstance(ts, int):
        return datetime.utcfromtimestamp(ts)

    if isinstance(ts, str):
        return parse_dt(ts).replace(tzinfo=pyutc)


def _make_remote_path(feed):

    feed_type = feed.lower().replace(' ', '_')
    feed_date = (datetime.today() - timedelta(days=1)).strftime('%Y%m%d')

    return f'/files/{feed_type}/{feed_date}'


def _format_hr_columns(s):
    s = s.replace('_', ' ')
    return s.title()


def _make_dbot_score(tags, params):
    base_score = params.get('feedReputation')
    if base_score:
        base_score = 'NONE' if base_score == 'Unknown' else base_score
        return getattr(Common.DBotScore, base_score.upper())

    if 'Cdn' in tags:
        return 0

    if 'Criminal' in tags or 'Malicious Hosting' in tags:
        return 3

    return 2


def fetch_command(client, args, params):

    limit = int(args.get('limit', 10))
    feeds = params.get('feeds', [])
    indicators = []

    for feed in feeds:
        path = _make_remote_path(feed)
        count = 0

        for i in client.fetch(path):
            if i.get('ip_address'):
                i['indicator'] = i.pop('ip_address')
            if i.get('cidr'):
                i['indicator'] = i.pop('cidr')

            indicators.append(i)
            count += 1

            if count >= limit:
                break

    columns = ['indicator', 'service_name', 'service_type', 'criminal',
               'cdn', 'comment']

    hr = tableToMarkdown(
        "Indicators from QSentry Feed:",
        indicators,
        headers=columns,
        headerTransform=_format_hr_columns
    )

    return CommandResults(
        readable_output=hr
    )


def _make_indicator(i, params):

    value_field = 'ip_address'
    itype = FeedIndicatorType.IP
    service = 'Anonymization'
    tlp = params.get('tlp_color')

    tags = [i.get('service_type'), i.get('service_name')]
    [tags.append(k) for k in ['cdn', 'criminal'] if i.get(k)]  # type: ignore
    tags = [t for t in tags if t]
    tags = [t.capitalize() for t in tags]

    if i.get('cidr'):
        value_field = 'cidr'
        service = 'Malicious Hosting'
        itype = FeedIndicatorType.CIDR
        tags = ['Malicious Hosting']
        if ':' in i['cidr']:
            itype = FeedIndicatorType.IPv6CIDR

    return {
        'value': i[value_field],
        'type': itype,
        'rawJSON': i,
        'fields': {
            'service': f'QSentry {service}',
            'tags': tags,
            'trafficlightprotocol': tlp,
            'description': i.get('comment')
        },
        'score': _make_dbot_score(tags, params)
    }


def fetch_indicators_command(client, params):

    feeds = params.get('feeds', [])
    indicators = []
    for feed in feeds:
        path = _make_remote_path(feed)

        for i in client.fetch(path):
            indicators.append(_make_indicator(i, params))

    return indicators


def main() -> None:

    params = demisto.params()

    client_args = {
        'token': params.get('token')
    }

    remote = params.get('remote', QSENTRY_REMOTE)

    proxy = params.get('proxy', False)
    verify_ssl = not params.get('insecure', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:

        client = Client(remote, verify_ssl, proxy, **client_args)

        args = demisto.args()

        if command == 'test-module':
            demisto.results(test_module(client))

        elif command == 'qintel-qsentry-get-indicators':
            return_results(fetch_command(client, args, params))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

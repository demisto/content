import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

''' IMPORTS '''

import urllib3
from typing import Dict, Any
from datetime import datetime
from dateutil.parser import parse as parse_dt
from pytz import utc as pyutc
from dateparser import parse as parse_date
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %I:%M:%S'
ISO8601_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VERSION = 'v1.0.0'
USER_AGENT = f'Qintel-CortexXSOAR/{VERSION}'
VENDOR = 'Qintel'

QWATCH_REMOTE = 'https://api.qwatch.qintel.com'

MAX_START_TIME = '90 days'
INCIDENT_NAME = 'Qintel QWatch Alert'
INCIDENT_TYPE = 'Qintel - QWatch Alert'

EXPOSURE_FIELDS = {
    'email': 'attributes.login_name',
    'password': 'attributes.password',
    'source': 'attributes.source_name',
}

EXPOSURE_HR_MAP = {
    'Email': 'email',
    'Password': 'password',
    'Source': 'source',
    'Loaded': 'loaded',
    'First Seen': 'firstseen',
    'Last Seen': 'lastseen'
}


class Client(BaseClient):
    """Client class to interact with Qintel APIs"""

    def __init__(self, base_url, verify=True, proxy=False, **kwargs):
        super(Client, self).__init__(base_url, verify=verify, proxy=proxy)

        self._headers = {
            'User-Agent': USER_AGENT,
            'Cf-Access-Client-Id': kwargs.get('client_id'),
            'Cf-Access-Client-Secret': kwargs.get('client_secret')
        }

    def search(self, endpoint: str, params: dict) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=endpoint,
            params=params,
            backoff_factor=0.5,
            retries=5
        )

    def ping(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/users/me',
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


def _set_fetch_params(params, now):

    fetch_params: Dict[str, Any] = {'meta[total]': True, 'stats': True}

    limit = arg_to_number(
        arg=demisto.params().get('max_fetch'),
        arg_name='max_fetch',
        required=False
    )

    if limit is not None:
        if limit > 10000:
            demisto.info('Adjusting artifact limit to maximum of 10000')
            limit = 10000

        fetch_params['limit'] = limit

    last_run = demisto.getLastRun()

    max_time = parse_date(MAX_START_TIME).timestamp()
    start_time = parse_date(params.get('first_fetch')).timestamp()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')

    if max_time > start_time:
        raise DemistoException('First fetch time can be a maximum of 90 days')

    fetch_params['date[start]'] = int(start_time)
    fetch_params['date[end]'] = int(now.timestamp())
    return fetch_params


def _process_exposure_data(data, fetch_passwords):

    return_data = []

    for r in data:
        entry: Dict = {}
        for k, v in EXPOSURE_FIELDS.items():
            if k == 'password' and not fetch_passwords:
                entry[k] = None
                continue

            entry[k] = demisto.get(r, v)

        timestamps = demisto.get(r, 'attributes.timestamps') or []
        for ts in timestamps:
            if ts['context'] == 'loaded':
                entry['loaded'] = \
                    _make_timestamp(ts['value']).strftime(DATE_FORMAT)

        timestamps = demisto.get(r, 'meta.stats.credential.timestamps') or []
        for ts in timestamps:
            if ts['context'] == 'first_seen':
                entry['firstseen'] = \
                    _make_timestamp(ts['value']).strftime(DATE_FORMAT)

            if ts['context'] == 'last_seen':
                entry['lastseen'] = \
                    _make_timestamp(ts['value']).strftime(DATE_FORMAT)

        return_data.append(entry)

    return {'QWatch': {'Exposures': return_data}}


def fetch_incidents(client, params):

    now = datetime.utcnow()
    incidents = []

    fetch_params = _set_fetch_params(params, now)

    fetch_passwords = params.get('fetch_passwords')
    severity = getattr(IncidentSeverity, params['fetch_severity'].upper())
    incident_type = params.get('incidentType')
    if not incident_type or incident_type == '':
        incident_type = INCIDENT_TYPE

    response = client.search('exposures', fetch_params)

    if response and response.get('data'):
        data = _process_exposure_data(response['data'], fetch_passwords)

        i = {
            'name': INCIDENT_NAME,
            'occurred': now.strftime(ISO8601_FORMAT),
            'rawJSON': json.dumps(data),
            'type': incident_type,
            'severity': severity
        }
        incidents.append(i)

    demisto.setLastRun({'start_time': now.timestamp()})
    return incidents


def search_exposures(client, args, params):
    searches = []
    command_results = []
    fetch_passwords = params.get('fetch_passwords')

    email = args.get('email')
    if email:
        searches.append({'search_term': email, 'search_type': 'email'})

    domain = args.get('domain')
    if domain:
        searches.append({'search_term': domain, 'search_type': 'domain'})

    for search in searches:
        search.update({'meta[total]': True, 'stats': True})

        response = client.search('exposures', search)

        if response and response.get('data'):
            data = _process_exposure_data(response['data'], fetch_passwords)

            hr_data = []
            for r in data['QWatch']['Exposures']:
                entry = {}
                for k, v in EXPOSURE_HR_MAP.items():
                    entry[k] = r.get(v)
                hr_data.append(entry)
                demisto.debug(entry)

            header = f"Qintel QWatch exposures for: {search['search_term']}\n"
            hr = tableToMarkdown(header, hr_data,
                                 headers=list(EXPOSURE_HR_MAP.keys()))

            command_results.append(CommandResults(
                outputs_prefix='Qintel',
                outputs=data,
                outputs_key_field='',
                readable_output=hr
            ))

        else:
            header = f"Qintel QWatch exposures for: {search['search_term']}\n"
            hr = tableToMarkdown(header, {})

            command_results.append(CommandResults(
                readable_output=hr
            ))

    return command_results


def main() -> None:

    params = demisto.params()

    client_args = {
        'client_id': params.get('credentials').get('identifier'),
        'client_secret': params.get('credentials').get('password')
    }

    remote = params.get('remote', QWATCH_REMOTE)

    proxy = params.get('proxy', False)
    verify_ssl = not params.get('insecure', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:

        client = Client(remote, verify_ssl, proxy, **client_args)

        args = demisto.args()

        if command == 'test-module':
            demisto.results(test_module(client))

        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client, params))

        elif command == 'qintel-qwatch-exposures':
            return_results(search_exposures(client, args, params))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

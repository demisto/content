import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

''' IMPORTS '''

import urllib3
from typing import Dict, Any
from datetime import datetime
from dateutil.parser import parse as parse_dt
import traceback
from functools import reduce

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %I:%M:%S'
VERSION = 'v1.0.0'
USER_AGENT = f'Qintel-CortexXSOAR/{VERSION}'
VENDOR = 'Qintel'

PMI_REMOTE = 'https://pmi.api.qintel.com'


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
        return datetime.fromtimestamp(ts)

    if isinstance(ts, str):
        return parse_dt(ts)


def _map_fields(d, path, default='Unknown'):
    try:
        value = reduce(dict.get, path, d)
    except KeyError:
        return default

    if not value:
        return default

    return value


def _process_cve_attributes(data, rv):

    rv['AffectedSystem'] = \
        _map_fields(data, ('attributes', 'affected_system', 'name'))

    rv['AffectedVersions'] = \
        _map_fields(data, ('attributes', 'affected_system', 'versions'))

    if isinstance(rv['AffectedVersions'], list):
        rv['AffectedVersions'] = ', '.join(rv['AffectedVersions'])

    rv['LastObserved'] = \
        _make_timestamp(
            _map_fields(data, ('attributes', 'last_observed'))
        ).strftime(DATE_FORMAT)  # noqa


def _process_cve_observations(observ, rv):

    observations_data = []

    for obs in observ:
        actor_label = _map_fields(obs, ('relationships', 'tags', 'data'), None)
        if actor_label:
            actor_label = _map_fields(actor_label[0], ('attributes', 'label'))

        actor_type = _map_fields(obs, ('relationships', 'tags', 'data'), None)
        if actor_type:
            actor_type = _map_fields(actor_type[0], ('attributes', 'tag_type'))

        exploit_type = _map_fields(obs, ('attributes', 'exploit_type'))
        exploit_notes = _map_fields(obs, ('attributes', 'notes'), None)

        ts_observ = None
        timestamps = _map_fields(obs, ('attributes', 'timestamps'), None)
        if timestamps:
            for t in timestamps:
                if t['context'] == 'observed':
                    ts_observ = \
                        _make_timestamp(t['value']).strftime(DATE_FORMAT)

        observations_data.append(
            {'actor': actor_label, 'actor_type': actor_type,
             'exploit_type': exploit_type,
             'exploit_notes': exploit_notes, 'date_observed': ts_observ})

    rv['Observations'] = observations_data


def _process_cve_data(data, cve):

    rv = {'id': cve}

    _process_cve_attributes(data, rv)

    observ = _map_fields(data, ('relationships', 'observations', 'data'), [])
    _process_cve_observations(observ, rv)

    return rv


def cve_command(client, **args):

    cves = args.get('cve', '')
    cves = argToList(cves)
    command_results = []

    for cve in cves:

        search_params = {
            'identifier': cve
        }

        response = client.search('cves', search_params)

        if response and response.get('data'):
            data = _process_cve_data(response['data'][0], cve)

            # human readable output
            columns = ['actor', 'actor_type', 'exploit_type', 'exploit_notes',
                       'date_observed']

            header = f'Qintel vulnerability results for: {cve}'
            metadata = f"**Vulnerability in {data['AffectedSystem']} " \
                       f"affecting versions: {data['AffectedVersions']}**\n"
            metadata += f"**Last observed: {data['LastObserved']}**"

            hr = tableToMarkdown(header, data['Observations'], columns,
                                 metadata=metadata)

            cve_return = Common.CVE(
                id=cve,
                cvss='None',
                description='None',
                published='None',
                modified='None'
            )

            command_results.append(CommandResults(
                outputs_prefix='Qintel.CVE',
                outputs_key_field='id',
                outputs=data,
                indicator=cve_return,
                readable_output=hr
            ))

        else:
            # human readable output
            header = f'Qintel vulnerability results for: {cve}'
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

    remote = params.get('remote', PMI_REMOTE)

    proxy = params.get('proxy', False)
    verify_ssl = not params.get('insecure', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:

        client = Client(remote, verify_ssl, proxy, **client_args)

        args = demisto.args()

        if command == 'test-module':
            demisto.results(test_module(client))

        elif command == 'cve':
            return_results(cve_command(client, **args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

''' IMPORTS '''

import urllib3
from typing import Any
from datetime import datetime
from dateutil.parser import parse as parse_dt
from pytz import utc as pyutc
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %I:%M:%S'
VERSION = 'v1.0.0'
USER_AGENT = f'Qintel-CortexXSOAR/{VERSION}'
VENDOR = 'Qintel'

QSENTRY_REMOTE = 'https://api.qsentry.qintel.com'


IP_HR_FIELDS = {
    'ASN': 'IP.asn',
    'AS Owner': 'IP.as_owner',
    'Tags': 'Qintel.Tags',
    'Description': 'Qintel.Description',
    'Last Observed': 'Qintel.LastObserved'
}


DBOT_TYPE_MAP = {
    'ip': DBotScoreType.IP,
    'email': DBotScoreType.EMAIL
}


class Client(BaseClient):
    """Client class to interact with Qintel APIs"""

    def __init__(self, base_url, verify=True, proxy=False, **kwargs):
        super().__init__(base_url, verify=verify, proxy=proxy)

        self._headers = {
            'User-Agent': USER_AGENT,
            'x-api-key': kwargs.get('token')
        }

    def search(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            params=params,
            backoff_factor=0.5,
            retries=5
        )

    def ping(self) -> dict[str, Any]:
        return self._http_request(
            method='GET',
        )


def test_module(client) -> str:

    search_params = {
        'q': '1.1.1.1'
    }

    try:
        client.search(search_params)
    except Exception as e:
        return f'Test failed: {e}'

    return 'ok'


def _make_timestamp(ts):
    if not ts:
        return None

    if isinstance(ts, int):
        return datetime.utcfromtimestamp(ts)

    if isinstance(ts, str):
        return parse_dt(ts).replace(tzinfo=pyutc)
    return None


def _make_dbot_score(itype, i, data):

    dbot_itype = DBOT_TYPE_MAP[itype]
    mal_desc = None

    score = Common.DBotScore.NONE
    tags = demisto.get(data, 'Qintel.Tags')
    if tags:
        score = Common.DBotScore.SUSPICIOUS

    if tags and 'Criminal' in tags:
        mal_desc = 'Indicator is associated with a criminal proxy/vpn'
        score = Common.DBotScore.BAD

    return Common.DBotScore(
        indicator=i,
        indicator_type=dbot_itype,
        integration_name=VENDOR,
        score=score,
        malicious_description=mal_desc,
        reliability=demisto.params().get('integrationReliability')
    )


def _process_ip_record(ip, data, return_data):

    return_data['IP']['ip'] = ip
    return_data['Qintel']['Address'] = ip

    return_data['IP']['asn'] = data.get('asn')

    as_owner = data.get('asn_name')
    if as_owner:
        asn_owner = as_owner.title()
        return_data['IP']['as_owner'] = asn_owner

    tags = data.get('tags')
    if tags:
        tags = [t.capitalize() for t in tags]

    return_data['IP']['tags'] = tags
    return_data['Qintel']['Tags'] = tags

    desc = data.get('descriptions')
    if desc:
        desc = [d.capitalize() for d in desc]

    return_data['Qintel']['Description'] = desc

    last = data.get('last_seen')
    if last:
        last = _make_timestamp(last).strftime(DATE_FORMAT)

    return_data['Qintel']['LastObserved'] = last


def _process_ip_data(data, ip):

    return_data: dict = {'IP': {}, 'Qintel': {}}

    _process_ip_record(ip, data, return_data)

    return_data['IP']['dbot_score'] = _make_dbot_score('ip', ip, return_data)

    return return_data


def ip_command(client, args):

    ips = args.get('ip', '')
    ips = argToList(ips)
    command_results = []

    for ip in ips:

        response = client.search({'q': ip})

        if response:
            data = _process_ip_data(response, ip)

            ip_return = Common.IP(**data['IP'])

            hr_data = {}
            for k, v in IP_HR_FIELDS.items():
                hr_data[k] = demisto.get(data, v)

            header = f'Qintel results for IP: {ip}'
            hr = tableToMarkdown(header, hr_data, headers=list(hr_data.keys()))

            command_results.append(CommandResults(
                outputs_prefix='Qintel.IP',
                outputs_key_field='Address',
                outputs=data['Qintel'],
                indicator=ip_return,
                readable_output=hr
            ))

        else:
            # human readable output
            header = f'Qintel vulnerability results for: {ip}'
            hr = tableToMarkdown(header, {})

            command_results.append(CommandResults(
                readable_output=hr
            ))

    return command_results


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

        elif command == 'ip':
            return_results(ip_command(client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

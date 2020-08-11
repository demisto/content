# Copyright (c) 2020 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import inspect
import locale
from typing import Iterator, Dict, List, Union
import urllib
import urllib.parse

from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import datetime  # type: ignore[no-redef]
import json
import re

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

INTEGRATION_NAME = 'Farsight DNSDB'
INTEGRATION_COMMAND_NAME = 'dnsdb'
INTEGRATION_CONTEXT_NAME = 'DNSDB'
RECORD_SUBCONTEXT_NAME = 'Record'
SUMMARY_SUBCONTEXT_NAME = 'Summary'
RATE_SUBCONTEXT_NAME = 'Rate'

# CONSTANTS
DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'
SWCLIENT = "demisto-integration"
VERSION = "v2.0"
IDN_REGEX = re.compile(r'(?:^|(?<=[\s=.:@]))xn--[a-z0-9\-]+\.')
FALSE_REGEX = re.compile(r'^(?i:f(alse)?)$')

locale.setlocale(locale.LC_ALL, '')

''' HELPER FUNCTIONS '''


class QueryError(Exception):
    pass


class Client(BaseClient):
    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            headers={
                'Accept': 'application/json',
                'X-Api-Key': apikey,
            },
            proxy=proxy,
            ok_codes=(200, 404),
        )

    @staticmethod
    def base_params() -> dict:
        return {
            'swclient': SWCLIENT,
            'version': VERSION,
        }

    def rate_limit(self) -> Dict:
        url_suffix = 'lookup/rate_limit?{0}'.format(urllib.parse.urlencode(self.base_params()))

        return self._http_request('GET', url_suffix)

    def lookup_rrset(self, owner_name: str, rrtype: str = None, bailiwick: str = None, limit: int = None,
                     time_first_before: int = None, time_first_after: int = None,
                     time_last_before: int = None, time_last_after: int = None,
                     aggr: bool = None, offset: int = None) -> Iterator[Dict]:
        return self._query_rrset("lookup",
                                 owner_name=owner_name,
                                 rrtype=rrtype,
                                 bailiwick=bailiwick,
                                 limit=limit,
                                 time_first_before=time_first_before,
                                 time_first_after=time_first_after,
                                 time_last_before=time_last_before,
                                 time_last_after=time_last_after,
                                 aggr=aggr,
                                 offset=offset)

    def summarize_rrset(self, owner_name: str, rrtype: str = None, bailiwick: str = None, limit: int = None,
                        time_first_before: int = None, time_first_after: int = None,
                        time_last_before: int = None, time_last_after: int = None,
                        aggr: bool = None, max_count: int = None) -> dict:
        try:
            return next(self._query_rrset("summarize",
                                          owner_name=owner_name,
                                          rrtype=rrtype,
                                          bailiwick=bailiwick,
                                          limit=limit,
                                          time_first_before=time_first_before,
                                          time_first_after=time_first_after,
                                          time_last_before=time_last_before,
                                          time_last_after=time_last_after,
                                          aggr=aggr,
                                          max_count=max_count))
        except StopIteration:
            raise QueryError("no data")

    def _query_rrset(self, mode: str, owner_name: str, rrtype: str = None, bailiwick: str = None, limit: int = None,
                     time_first_before: int = None, time_first_after: int = None,
                     time_last_before: int = None, time_last_after: int = None,
                     aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        owner_name = quote(to_ascii(owner_name))
        if bailiwick:
            if not rrtype:
                rrtype = 'ANY'
            bailiwick = quote(to_ascii(bailiwick))
            path = f'{mode}/rrset/name/{owner_name}/{rrtype}/{bailiwick}'
        elif rrtype:
            path = f'{mode}/rrset/name/{owner_name}/{rrtype}'
        else:
            path = f'{mode}/rrset/name/{owner_name}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def lookup_rdata_name(self, value: str, rrtype: str = None,
                          limit: int = None, time_first_before: int = None, time_first_after: int = None,
                          time_last_before: int = None, time_last_after: int = None,
                          aggr: bool = None, offset: int = None) -> Iterator[Dict]:
        return self._query_rdata_name("lookup",
                                      name=value,
                                      rrtype=rrtype,
                                      limit=limit,
                                      time_first_before=time_first_before,
                                      time_first_after=time_first_after,
                                      time_last_before=time_last_before,
                                      time_last_after=time_last_after,
                                      aggr=aggr,
                                      offset=offset)

    def summarize_rdata_name(self, value: str, rrtype: str = None,
                             limit: int = None, time_first_before: int = None, time_first_after: int = None,
                             time_last_before: int = None, time_last_after: int = None,
                             aggr: bool = None, max_count: int = None) -> dict:
        try:
            return next(self._query_rdata_name("summarize",
                                               name=value,
                                               rrtype=rrtype,
                                               limit=limit,
                                               time_first_before=time_first_before,
                                               time_first_after=time_first_after,
                                               time_last_before=time_last_before,
                                               time_last_after=time_last_after,
                                               aggr=aggr,
                                               max_count=max_count))
        except StopIteration:
            raise QueryError("no data")

    def _query_rdata_name(self, mode: str, name: str, rrtype: str = None,
                          limit: int = None, time_first_before: int = None, time_first_after: int = None,
                          time_last_before: int = None, time_last_after: int = None,
                          aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        rdata_name = quote(to_ascii(name))
        if rrtype:
            path = f'{mode}/rdata/name/{rdata_name}/{rrtype}'
        else:
            path = f'{mode}/rdata/name/{rdata_name}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def lookup_rdata_ip(self, value: str, limit: int = None,
                        time_first_before: int = None, time_first_after: int = None,
                        time_last_before: int = None, time_last_after: int = None,
                        aggr: bool = None, offset: int = None) -> Iterator[Dict]:
        return self._query_rdata_ip("lookup",
                                    ip=value,
                                    limit=limit,
                                    time_first_before=time_first_before,
                                    time_first_after=time_first_after,
                                    time_last_before=time_last_before,
                                    time_last_after=time_last_after,
                                    aggr=aggr,
                                    offset=offset)

    def summarize_rdata_ip(self, value: str, limit: int = None,
                           time_first_before: int = None, time_first_after: int = None,
                           time_last_before: int = None, time_last_after: int = None,
                           aggr: bool = None, max_count: int = None) -> dict:
        try:
            return next(self._query_rdata_ip("summarize",
                                             ip=value,
                                             limit=limit,
                                             time_first_before=time_first_before,
                                             time_first_after=time_first_after,
                                             time_last_before=time_last_before,
                                             time_last_after=time_last_after,
                                             aggr=aggr,
                                             max_count=max_count))
        except StopIteration:
            raise QueryError("no data")

    def _query_rdata_ip(self, mode: str, ip: str,
                        limit: int = None, time_first_before: int = None, time_first_after: int = None,
                        time_last_before: int = None, time_last_after: int = None,
                        aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        ip = ip.replace('/', ',')
        path = f'{mode}/rdata/ip/{ip}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def _query(self, path: str, limit: int = None, time_first_before: int = None, time_first_after: int = None,
               time_last_before: int = None, time_last_after: int = None,
               aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        params = self.base_params()
        if limit is not None:
            params['limit'] = limit
        if time_first_before is not None:
            params['time_first_before'] = time_first_before
        if time_first_after is not None:
            params['time_first_after'] = time_first_after
        if time_last_before is not None:
            params['time_last_before'] = time_last_before
        if time_last_after is not None:
            params['time_last_after'] = time_last_after
        if aggr is not None:
            params['aggr'] = aggr
        if offset is not None:
            params['offset'] = offset
        if max_count is not None:
            params['max_count'] = max_count

        if params:
            path = '{0}?{1}'.format(path, urllib.parse.urlencode(params))

        res = self._http_request('GET', path, stream=True, resp_type='response')

        if res.status_code == 404:
            return

        try:
            res.raise_for_status()
        except requests.RequestException as e:
            raise QueryError from e

        for line in res.iter_lines():
            yield json.loads(line)


def quote(path: str) -> str:
    return urllib.parse.quote(path, safe='')


@logger
def _run_query(f, args):
    sig = inspect.signature(f)
    kwargs = {}

    for name, p in sig.parameters.items():
        if name in args:
            if p.annotation != p.empty:
                if p.annotation == bool:
                    if FALSE_REGEX.match(args[name]):
                        kwargs[name] = False
                    else:
                        kwargs[name] = True
                else:
                    kwargs[name] = p.annotation(args[name])
            else:
                kwargs[name] = args[name]
        elif p.kind == p.POSITIONAL_ONLY:
            raise Exception(f'Missing argument: {name}')

    return f(**kwargs)


def to_unicode(domain: str) -> str:
    try:
        return domain.encode('utf8').decode('idna')
    except UnicodeError:
        return domain


def to_ascii(domain: str) -> str:
    try:
        return domain.encode('idna').decode('utf8')
    except UnicodeError:
        return domain


def format_name_for_context(domain: str) -> str:
    return domain.rstrip('.')


def format_name_for_markdown(domain: str) -> str:
    return to_unicode(domain.rstrip('.'))


def parse_rdata(rdata: Union[str, List[str]]):
    if isinstance(rdata, list):
        return [parse_rdata(entry) for entry in rdata]  # pragma: no cover

    def f(m):
        return to_unicode(m.group(0))

    return str(IDN_REGEX.sub(f, rdata))


def format_rdata_for_markdown(rdata: Union[str, List[str]]):
    rdata = parse_rdata(rdata)

    if isinstance(rdata, str):
        return rdata

    return '<br>'.join(rdata)


def parse_rate_limit_int(i):
    try:
        return int(i)
    except ValueError:
        return i


def parse_unix_time(ts) -> str:
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore[attr-defined]
    except TypeError:
        return ts


def nop(x):
    return x


@logger
def build_result_context(results: Dict) -> Dict:
    ctx = {}
    for ckey, rkey, f in (
            ('RRName', 'rrname', format_name_for_context),
            ('RRType', 'rrtype', str),
            ('Bailiwick', 'bailiwick', format_name_for_context),
            ('RData', 'rdata', nop),
            ('Count', 'count', int),
            ('NumResults', 'num_results', int),
            ('TimeFirst', 'time_first', parse_unix_time),
            ('TimeLast', 'time_last', parse_unix_time),
            ('TimeFirst', 'zone_time_first', parse_unix_time),
            ('TimeLast', 'zone_time_last', parse_unix_time),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    ctx['FromZoneFile'] = 'zone_time_first' in results

    return ctx


@logger
def build_rate_limits_context(results: Dict) -> Dict:
    """Formatting results from Rate Limit API to Demisto Context"""
    rate = results.get('rate')
    if rate is None:
        raise ValueError("Missing rate key")
    ctx = {}

    if rate['limit'] == 'unlimited':
        return {
            'Unlimited': True
        }

    for ckey, rkey, f in (
            ('Limit', 'limit', parse_rate_limit_int),
            ('Remaining', 'remaining', parse_rate_limit_int),
            ('Expires', 'expires', parse_unix_time),
            ('ResultsMax', 'results_max', parse_rate_limit_int),
            ('BurstSize', 'burst_size', parse_rate_limit_int),
            ('BurstWindow', 'burst_window', parse_rate_limit_int),
    ):
        if rkey in rate:
            ctx[ckey] = f(rate[rkey])

    if 'reset' in rate:
        if rate['reset'] == "n/a":
            ctx['NeverResets'] = True
        else:
            ctx['Reset'] = parse_unix_time(rate['reset'])

    if 'offset_max' in rate:
        if rate['offset_max'] == "n/a":
            ctx['OffsetNotAllowed'] = True
        else:
            ctx['OffsetMax'] = parse_rate_limit_int(rate['offset_max'])

    return ctx


@logger
def lookup_to_markdown(results: List[Dict], want_bailiwick=True) -> str:
    # TODO this should be more specific, include arguments?
    out = ['### Farsight DNSDB Lookup']

    keys = [
        ('RRName', 'rrname', format_name_for_context),
        ('RRType', 'rrtype', str),
        ('Bailiwick', 'bailiwick', format_name_for_context),
        ('RData', 'rdata', format_rdata_for_markdown),
        ('Count', 'count', str),
        ('TimeFirst', 'time_first'),
        ('TimeLast', 'time_last'),
        ('TimeFirst', 'zone_time_first'),
        ('TimeLast', 'zone_time_last'),
    ]

    if not want_bailiwick:
        keys = list(filter(lambda r: r[1] != 'bailiwick', keys))

    out += ['|' + '|'.join(str(k[0]) for k in keys[:-2]) + '|', '|-' * len(keys) + '|']

    for result in results:
        row = []
        for ckey, rkey, f in keys[:-4]:
            if rkey in result:
                row += [f(result[rkey])]  # type: ignore[operator]
            else:
                row += [' ']

        if 'time_first' in result:
            row += [parse_unix_time(result['time_first'])]
        elif 'zone_time_first' in result:
            row += [parse_unix_time(result['zone_time_first'])]
        else:
            row += [' ']

        if 'time_last' in result:
            row += [parse_unix_time(result['time_last'])]
        elif 'zone_time_last' in result:
            row += [parse_unix_time(result['zone_time_last'])]
        else:
            row += [' ']

        row += [str("zone_time_first" in result)]
        out += ['|' + '|'.join(row) + '|']

    return '\n'.join(out) + '\n'


@logger
def summarize_to_markdown(summary: Dict) -> str:
    # TODO this should be more specific, include arguments?
    out = ['### Farsight DNSDB Summarize']

    for ckey, rkey, f in (
            ('Count', 'count', int),
            ('NumResults', 'num_results', int),
            ('TimeFirst', 'time_first', parse_unix_time),
            ('TimeLast', 'time_last', parse_unix_time),
            ('TimeFirst', 'zone_time_first', parse_unix_time),
            ('TimeLast', 'zone_time_last', parse_unix_time),
    ):
        if rkey in summary:
            out += [f'{ckey}', f' : {f(summary[rkey])}']  # type: ignore[operator]

    out += ['FromZoneFile', f' : {"zone_time_first" in summary}']

    return '\n'.join(out) + '\n'


@logger
def rate_limit_to_markdown(results: Dict) -> str:
    rate = results.get('rate')
    if rate is None:
        return '### Error'

    out = ['### Farsight DNSDB Service Limits']

    if rate['limit'] != "unlimited":
        for ckey, rkey, f in (
                ('Limit', 'limit', parse_rate_limit_int),
                ('Remaining', 'remaining', parse_rate_limit_int),
                ('Reset', 'reset', parse_unix_time),
                ('Expires', 'expires', parse_unix_time),
                ('ResultsMax', 'results_max', parse_rate_limit_int),
                ('OffsetMax', 'offset_max', parse_rate_limit_int),
                ('BurstSize', 'burst_size', parse_rate_limit_int),
                ('BurstWindow', 'burst_window', parse_rate_limit_int),
        ):
            if rkey in rate:
                if rkey == 'reset':
                    if rate[rkey] == "n/a":
                        out += ['NeverResets', ' : True']
                    else:
                        out += [f'{ckey}', f' : {f(rate[rkey])}']
                elif rkey == 'offset_max':
                    if rate[rkey] == "n/a":
                        out += ['OffsetNotAllowed', ' : True']
                    else:
                        out += [f'{ckey}', f' : {f(rate[rkey])}']
                else:
                    out += [f'{ckey}', f' : {f(rate[rkey])}']
    else:
        out += ['Unlimited', ' : True']

    return '\n'.join(out) + '\n'


''' COMMANDS '''


@logger
def test_module(client, _):
    try:
        client.rate_limit()
        return 'ok'
    except Exception as e:
        raise DemistoException from e


@logger
def dnsdb_rdata(client, args):
    type = args.get('type')
    if type == 'name':
        res = list(_run_query(client.lookup_rdata_name, args))
    elif type == 'ip':
        res = list(_run_query(client.lookup_rdata_ip, args))
    else:
        raise Exception(f'Invalid rdata query type: {type}')

    ctx = {
        INTEGRATION_CONTEXT_NAME: {
            RECORD_SUBCONTEXT_NAME: [build_result_context(r) for r in res]
        }
    }
    md = lookup_to_markdown(res, want_bailiwick=False)
    return md, ctx, res


@logger
def dnsdb_summarize_rdata(client, args):
    type = args.get('type')
    if type == 'name':
        res = _run_query(client.summarize_rdata_name, args)
    elif type == 'ip':
        res = _run_query(client.summarize_rdata_ip, args)
    else:
        raise Exception(f'Invalid rdata query type: {type}')

    ctx = {
        INTEGRATION_CONTEXT_NAME: {
            SUMMARY_SUBCONTEXT_NAME: build_result_context(res)
        }
    }
    md = summarize_to_markdown(res)
    return md, ctx, res


@logger
def dnsdb_rrset(client, args):
    q = _run_query(client.lookup_rrset, args)
    res = list(q)

    ctx = {
        INTEGRATION_CONTEXT_NAME: {
            RECORD_SUBCONTEXT_NAME: [build_result_context(r) for r in res],
        }
    }
    md = lookup_to_markdown(res)
    return md, ctx, res


@logger
def dnsdb_summarize_rrset(client, args):
    res = _run_query(client.summarize_rrset, args)
    ctx = {
        INTEGRATION_CONTEXT_NAME: {
            SUMMARY_SUBCONTEXT_NAME: build_result_context(res)
        }
    }
    md = summarize_to_markdown(res)
    return md, ctx, res


@logger
def dnsdb_rate_limit(client, _):
    res = client.rate_limit()
    ctx = {
        INTEGRATION_CONTEXT_NAME: {
            RATE_SUBCONTEXT_NAME: build_rate_limits_context(res)
        }
    }
    md = rate_limit_to_markdown(res)
    return md, ctx, res


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    apikey = demisto.params().get('apikey')
    if not apikey:
        raise DemistoException('apikey is required')
    base_url = demisto.params().get('url', DEFAULT_DNSDB_SERVER)
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(
        base_url,
        apikey,
        verify=verify_certificate,
        proxy=proxy)

    command = demisto.command()
    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        f'{INTEGRATION_COMMAND_NAME}-rdata': dnsdb_rdata,
        f'{INTEGRATION_COMMAND_NAME}-summarize-rdata': dnsdb_summarize_rdata,
        f'{INTEGRATION_COMMAND_NAME}-rrset': dnsdb_rrset,
        f'{INTEGRATION_COMMAND_NAME}-summarize-rrset': dnsdb_summarize_rrset,
        f'{INTEGRATION_COMMAND_NAME}-rate-limit': dnsdb_rate_limit,
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

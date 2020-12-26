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
from typing import Iterator, Dict, List, Tuple, Union, Any, Callable, Iterable
import urllib
import urllib.parse

from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

import datetime  # type: ignore[no-redef]
import json
import re

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

INTEGRATION_NAME = 'Farsight DNSDB'
INTEGRATION_CONTEXT_NAME = 'DNSDB'
RECORD_SUBCONTEXT_NAME = 'Record'
SUMMARY_SUBCONTEXT_NAME = 'Summary'
RATE_SUBCONTEXT_NAME = 'Rate'

# CONSTANTS
DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'
TIMEOUT = 60
SWCLIENT = "demisto-integration"
VERSION = "v2.0"
PATH_PREFIX = 'dnsdb/v2'
IDN_REGEX = re.compile(r'(?:^|(?<=[\s=.:@]))xn--[a-z0-9\-]+\.')
FALSE_REGEX = re.compile(r'^(?i:f(alse)?)$')
COND_BEGIN = 'begin'
COND_ONGOING = 'ongoing'
COND_SUCCEEDED = 'succeeded'
COND_LIMITED = 'limited'
COND_FAILED = 'failed'


locale.setlocale(locale.LC_ALL, '')

''' HELPER FUNCTIONS '''


class QueryError(Exception):
    pass


class timeval(int):
    pass


class Client(BaseClient):
    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            headers={
                'Accept': 'application/x-ndjson',
                'X-Api-Key': apikey,
            },
            proxy=proxy,
            ok_codes=(200, ),
        )
        self.apikey = apikey

    @staticmethod
    def base_params() -> dict:
        return {
            'swclient': SWCLIENT,
            'version': VERSION,
        }

    def rate_limit(self) -> Dict:
        params = self.base_params()
        url_suffix = 'dnsdb/v2/rate_limit'
        return self._http_request('GET', url_suffix=url_suffix, params=params)

    def lookup_rrset(self, owner_name: str, rrtype: str = None, bailiwick: str = None, limit: int = None,
                     time_first_before: timeval = None, time_first_after: timeval = None,
                     time_last_before: timeval = None, time_last_after: timeval = None,
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
                        time_first_before: timeval = None, time_first_after: timeval = None,
                        time_last_before: timeval = None, time_last_after: timeval = None,
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
                     time_first_before: timeval = None, time_first_after: timeval = None,
                     time_last_before: timeval = None, time_last_after: timeval = None,
                     aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        owner_name = quote(to_ascii(owner_name))
        if bailiwick:
            if not rrtype:
                rrtype = 'ANY'
            bailiwick = quote(to_ascii(bailiwick))
            path = f'{PATH_PREFIX}/{mode}/rrset/name/{owner_name}/{rrtype}/{bailiwick}'
        elif rrtype:
            path = f'{PATH_PREFIX}/{mode}/rrset/name/{owner_name}/{rrtype}'
        else:
            path = f'{PATH_PREFIX}/{mode}/rrset/name/{owner_name}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def lookup_rdata_name(self, value: str, rrtype: str = None,
                          limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                          time_last_before: timeval = None, time_last_after: timeval = None,
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
                             limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                             time_last_before: timeval = None, time_last_after: timeval = None,
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
                          limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                          time_last_before: timeval = None, time_last_after: timeval = None,
                          aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        rdata_name = quote(to_ascii(name))
        if rrtype:
            path = f'{PATH_PREFIX}/{mode}/rdata/name/{rdata_name}/{rrtype}'
        else:
            path = f'{PATH_PREFIX}/{mode}/rdata/name/{rdata_name}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def lookup_rdata_ip(self, value: str, limit: int = None,
                        time_first_before: timeval = None, time_first_after: timeval = None,
                        time_last_before: timeval = None, time_last_after: timeval = None,
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
                           time_first_before: timeval = None, time_first_after: timeval = None,
                           time_last_before: timeval = None, time_last_after: timeval = None,
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
                        limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                        time_last_before: timeval = None, time_last_after: timeval = None,
                        aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        ip = ip.replace('/', ',')
        path = f'{PATH_PREFIX}/{mode}/rdata/ip/{ip}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def lookup_rdata_raw(self, value: str, rrtype: str = None,
                         limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                         time_last_before: timeval = None, time_last_after: timeval = None,
                         aggr: bool = None, offset: int = None) -> Iterator[Dict]:
        return self._query_rdata_raw("lookup",
                                     raw=value,
                                     rrtype=rrtype,
                                     limit=limit,
                                     time_first_before=time_first_before,
                                     time_first_after=time_first_after,
                                     time_last_before=time_last_before,
                                     time_last_after=time_last_after,
                                     aggr=aggr,
                                     offset=offset)

    def summarize_rdata_raw(self, value: str, rrtype: str = None,
                            limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                            time_last_before: timeval = None, time_last_after: timeval = None,
                            aggr: bool = None, max_count: int = None) -> dict:
        try:
            return next(self._query_rdata_raw("summarize",
                                              raw=value,
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

    def _query_rdata_raw(self, mode: str, raw: str, rrtype: str = None,
                         limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
                         time_last_before: timeval = None, time_last_after: timeval = None,
                         aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        if rrtype:
            path = f'{PATH_PREFIX}/{mode}/rdata/raw/{quote(raw)}/{rrtype}'
        else:
            path = f'{PATH_PREFIX}/{mode}/rdata/raw/{quote(raw)}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after,
                           aggr=aggr, offset=offset, max_count=max_count)

    def flex(self, method: str, key: str, value: str, rrtype: str = None,
             limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
             time_last_before: timeval = None, time_last_after: timeval = None):
        path = f'{PATH_PREFIX}/{method}/{key}/{quote(value)}'
        if rrtype:
            path += f'/{rrtype}'
        return self._query(path, limit=limit, time_first_before=time_first_before, time_first_after=time_first_after,
                           time_last_before=time_last_before, time_last_after=time_last_after)

    def _query(self, path: str, limit: int = None, time_first_before: timeval = None, time_first_after: timeval = None,
               time_last_before: timeval = None, time_last_after: timeval = None,
               aggr: bool = None, offset: int = None, max_count: int = None) -> Iterator[Dict]:
        params = self.base_params()
        params.update(
            assign_params(
                limit=limit,
                time_first_before=time_first_before,
                time_first_after=time_first_after,
                time_last_before=time_last_before,
                time_last_after=time_last_after,
                aggr=aggr,
                offset=offset,
                max_count=max_count,
            )
        )

        res = self._http_request('GET', path,
                                 params=params,
                                 stream=True,
                                 resp_type='response',
                                 timeout=TIMEOUT)

        return _handle_saf(res.iter_lines(decode_unicode=True))


def _handle_saf(i: Iterable[str]):
    for line in i:
        if not line:
            continue

        try:
            saf_msg = json.loads(line)
        except json.JSONDecodeError as e:
            raise DemistoException(f'saf protocol error: could not decode json: {line}') from e

        cond = saf_msg.get('cond')
        obj = saf_msg.get('obj')
        msg = saf_msg.get('msg')

        if cond == COND_BEGIN:
            continue
        elif cond == COND_SUCCEEDED:
            return

        if obj:
            yield obj

        if cond == COND_ONGOING or not cond:
            continue
        elif cond == COND_LIMITED:
            return
        elif cond == COND_FAILED:
            raise QueryError(f'saf query failed: {msg}')
        else:
            raise QueryError(f'saf protocol error: invalid cond: {cond}')

    raise QueryError('saf query truncated')


def quote(path: str) -> str:
    return urllib.parse.quote(path, safe='')


@logger
def _run_query(f, args):
    sig = inspect.signature(f)
    kwargs = {}  # type: Dict[str, Any]

    for name, p in sig.parameters.items():
        if name in args:
            if p.annotation != p.empty:
                if p.annotation == bool:
                    if FALSE_REGEX.match(args[name]):
                        kwargs[name] = False
                    else:
                        kwargs[name] = True
                elif p.annotation == timeval:
                    try:
                        kwargs[name] = int(args[name])
                    except ValueError:
                        kwargs[name] = date_to_timestamp(args[name])
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
            ('RawRData', 'raw_rdata', nop),
            ('Count', 'count', int),
            ('NumResults', 'num_results', int),
            ('TimeFirst', 'time_first', parse_unix_time),
            ('TimeLast', 'time_last', parse_unix_time),
            ('TimeFirst', 'zone_time_first', parse_unix_time),
            ('TimeLast', 'zone_time_last', parse_unix_time),
    ):
        if rkey in results:
            ctx[ckey] = f(results[rkey])  # type: ignore[operator]

    if 'zone_time_first' in results or 'time_first' in results:
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
def lookup_to_markdown(results: List[Dict], title: str = 'Farsight DNSDB Lookup', want_bailiwick=True, header_filter=None) -> str:
    # TODO this should be more specific, include arguments?
    out = []

    keys = [
        ('RRName', 'rrname', format_name_for_context),
        ('RRType', 'rrtype', str),
        ('Bailiwick', 'bailiwick', format_name_for_context),
        ('RData', 'rdata', format_rdata_for_markdown),
        ('Count', 'count', str),
    ]  # type: List[Tuple[str, str, Callable]]

    if not want_bailiwick:
        keys = list(filter(lambda r: r[1] != 'bailiwick', keys))

    headers = [k[0] for k in keys] + ['TimeFirst', 'TimeLast', 'FromZoneFile']
    if header_filter:
        headers = list(filter(header_filter, headers))

    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])

        if 'time_first' in result:
            row['TimeFirst'] = parse_unix_time(result['time_first'])
        elif 'zone_time_first' in result:
            row['TimeFirst'] = parse_unix_time(result['zone_time_first'])

        if 'time_last' in result:
            row['TimeLast'] = parse_unix_time(result['time_last'])
        elif 'zone_time_last' in result:
            row['TimeLast'] = parse_unix_time(result['zone_time_last'])

        row['FromZoneFile'] = str("zone_time_first" in result)
        out.append(row)

    return tableToMarkdown(title, out, headers=headers)


@logger
def summarize_to_markdown(summary: Dict) -> str:
    headers = []
    out = dict()  # type: Dict[str, Any]
    for ckey, rkey, f in (
            ('Count', 'count', int),
            ('NumResults', 'num_results', int),
            ('TimeFirst', 'time_first', parse_unix_time),
            ('TimeLast', 'time_last', parse_unix_time),
            ('ZoneTimeFirst', 'zone_time_first', parse_unix_time),
            ('ZoneTimeLast', 'zone_time_last', parse_unix_time),
    ):
        if rkey in summary:
            headers.append(ckey)
            out[ckey] = f(summary[rkey])  # type: ignore[operator]

    return tableToMarkdown('Farsight DNSDB Summarize', out, headers=headers)


@logger
def rate_limit_to_markdown(results: Dict) -> str:
    rate = results.get('rate')
    if rate is None:
        return '### Error'

    out = dict()  # type: Dict[str, Any]

    headers = []

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
                headers.append(ckey)
                if rkey == 'reset':
                    if rate[rkey] == "n/a":
                        NEVER_RESETS = 'NeverResets'
                        out[NEVER_RESETS] = True
                        headers.append(NEVER_RESETS)
                    else:
                        out[f'{ckey}'] = f(rate[rkey])
                elif rkey == 'offset_max':
                    if rate[rkey] == "n/a":
                        OFFSET_NOT_ALLOWED = 'OffsetNotAllowed'
                        out[OFFSET_NOT_ALLOWED] = True
                        headers.append(OFFSET_NOT_ALLOWED)
                    else:
                        out[f'{ckey}'] = f(rate[rkey])
                else:
                    out[f'{ckey}'] = f(rate[rkey])
    else:
        UNLIMITED = 'Unlimited'
        out[UNLIMITED] = True
        headers.append(UNLIMITED)

    return tableToMarkdown('Farsight DNSDB Service Limits', out, headers=headers)


''' COMMANDS '''


@logger
def test_module(client, _):
    try:
        client.rate_limit()
    except DemistoException as e:
        if 'forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


@logger
def dnsdb_flex(client, args):
    res = list(_run_query(client.flex, args))

    def skip_rrname(header) -> bool:
        return header.lower() not in ('rrname', 'fromzonefile')

    def skip_rdata(header) -> bool:
        return header.lower() not in ('rdata', 'fromzonefile')
    if args.get('key') == 'rdata':
        skip = skip_rrname
    else:
        skip = skip_rdata

    return CommandResults(
        readable_output=lookup_to_markdown(res, title='Farsight DNSDB Flex Search', want_bailiwick=False,
                                           header_filter=skip),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{RECORD_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=[build_result_context(r) for r in res],
    )


@logger
def dnsdb_rdata(client, args):
    type = args.get('type')
    if type == 'name':
        res = list(_run_query(client.lookup_rdata_name, args))
    elif type == 'ip':
        res = list(_run_query(client.lookup_rdata_ip, args))
    elif type == 'raw':
        res = list(_run_query(client.lookup_rdata_raw, args))
    else:
        raise Exception(f'Invalid rdata query type: {type}')

    return CommandResults(
        readable_output=lookup_to_markdown(res, want_bailiwick=False),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{RECORD_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=[build_result_context(r) for r in res],
    )


@logger
def dnsdb_summarize_rdata(client, args):
    type = args.get('type')
    if type == 'name':
        res = _run_query(client.summarize_rdata_name, args)
    elif type == 'ip':
        res = _run_query(client.summarize_rdata_ip, args)
    elif type == 'raw':
        res = _run_query(client.summarize_rdata_raw, args)
    else:
        raise Exception(f'Invalid rdata query type: {type}')

    return CommandResults(
        readable_output=summarize_to_markdown(res),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{SUMMARY_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=build_result_context(res),
    )


@logger
def dnsdb_rrset(client, args):
    q = _run_query(client.lookup_rrset, args)
    res = list(q)

    return CommandResults(
        readable_output=lookup_to_markdown(res),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{RECORD_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=[build_result_context(r) for r in res],
    )


@logger
def dnsdb_summarize_rrset(client, args):
    res = _run_query(client.summarize_rrset, args)
    return CommandResults(
        readable_output=summarize_to_markdown(res),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{SUMMARY_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=build_result_context(res),
    )


@logger
def dnsdb_rate_limit(client, _):
    res = client.rate_limit()
    return CommandResults(
        readable_output=rate_limit_to_markdown(res),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{RATE_SUBCONTEXT_NAME}',
        outputs_key_field='',
        outputs=build_rate_limits_context(res),
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    apikey = demisto.params().get('apikey')
    base_url = demisto.params().get('url')
    if not base_url:
        base_url = DEFAULT_DNSDB_SERVER
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(
        base_url,
        apikey,
        verify=verify_certificate,
        proxy=proxy)

    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if command == 'test-module':
            return_results(test_module(client, demisto.args()))

        elif command == 'dnsdb-flex':
            return_results(dnsdb_flex(client, demisto.args()))

        elif command == 'dnsdb-rdata':
            return_results(dnsdb_rdata(client, demisto.args()))

        elif command == 'dnsdb-summarize-rdata':
            return_results(dnsdb_summarize_rdata(client, demisto.args()))

        elif command == 'dnsdb-rrset':
            return_results(dnsdb_rrset(client, demisto.args()))

        elif command == 'dnsdb-summarize-rrset':
            return_results(dnsdb_summarize_rrset(client, demisto.args()))

        elif command == 'dnsdb-rate-limit':
            return_results(dnsdb_rate_limit(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

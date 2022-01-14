import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re

from base64 import b64decode
from flask import Flask, Response, request
from netaddr import IPSet
from typing import Any, Dict, cast, Iterable
from math import ceil
import urllib3
import dateparser
import hashlib
import ipaddress

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'EDL'
PAGE_SIZE: int = 2000
PAN_OS_MAX_URL_LEN = 255
APP: Flask = Flask('demisto-edl')
EDL_LIMIT_ERR_MSG: str = 'Please provide a valid integer for EDL Size'
EDL_OFFSET_ERR_MSG: str = 'Please provide a valid integer for Starting Index'
EDL_COLLAPSE_ERR_MSG: str = 'The Collapse parameter can only get the following: 0 - Dont Collapse, ' \
                            '1 - Collapse to Ranges, 2 - Collapse to CIDRS'
EDL_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'
# based on func ToIoC https://github.com/demisto/server/blob/master/domain/insight.go
EDL_FILTER_FIELDS: Optional[str] = "name,type"
EDL_ON_DEMAND_KEY: str = 'UpdateEDL'
EDL_ON_DEMAND_CACHE_PATH: str = ''
EDL_SEARCH_LOOP_LIMIT: int = 10

''' REFORMATTING REGEXES '''
_PROTOCOL_REMOVAL = re.compile('^(?:[a-z]+:)*//')
_PORT_REMOVAL = re.compile(r'^((?:[a-z]+:)*//([a-z0-9\-\.]+)|([a-z0-9\-\.]+))(?:\:[0-9]+)*')
_URL_WITHOUT_PORT = r'\g<1>'
_INVALID_TOKEN_REMOVAL = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')

DONT_COLLAPSE = "Don't Collapse"
COLLAPSE_TO_CIDR = "To CIDRS"
COLLAPSE_TO_RANGES = "To Ranges"

'''Request Arguments Class'''


class RequestArguments:
    CTX_QUERY_KEY = 'last_query'
    CTX_LIMIT_KEY = 'last_limit'
    CTX_OFFSET_KEY = 'last_offset'
    CTX_INVALIDS_KEY = 'drop_invalids'
    CTX_PORT_STRIP_KEY = 'url_port_stripping'
    CTX_COLLAPSE_IPS_KEY = 'collapse_ips'
    CTX_EMPTY_EDL_COMMENT_KEY = 'add_comment_if_empty'

    def __init__(self,
                 query: str,
                 limit: int = 10000,
                 offset: int = 0,
                 url_port_stripping: bool = False,
                 drop_invalids: bool = False,
                 collapse_ips: str = DONT_COLLAPSE,
                 add_comment_if_empty: bool = True):

        self.query = query
        self.limit = try_parse_integer(limit, EDL_LIMIT_ERR_MSG)
        self.offset = try_parse_integer(offset, EDL_OFFSET_ERR_MSG)
        self.url_port_stripping = url_port_stripping
        self.drop_invalids = drop_invalids
        self.collapse_ips = collapse_ips
        self.add_comment_if_empty = add_comment_if_empty

    def to_context_json(self):
        return {
            self.CTX_QUERY_KEY: self.query,
            self.CTX_LIMIT_KEY: self.limit,
            self.CTX_OFFSET_KEY: self.offset,
            self.CTX_INVALIDS_KEY: self.drop_invalids,
            self.CTX_PORT_STRIP_KEY: self.url_port_stripping,
            self.CTX_COLLAPSE_IPS_KEY: self.collapse_ips,
            self.CTX_EMPTY_EDL_COMMENT_KEY: self.add_comment_if_empty,
        }

    @classmethod
    def from_context_json(cls, ctx_dict):
        """Returns an initiated instance of the class from a json"""
        return cls(
            **assign_params(
                query=ctx_dict.get(cls.CTX_QUERY_KEY),
                limit=ctx_dict.get(cls.CTX_LIMIT_KEY),
                offset=ctx_dict.get(cls.CTX_OFFSET_KEY),
                drop_invalids=ctx_dict.get(cls.CTX_INVALIDS_KEY),
                url_port_stripping=ctx_dict.get(cls.CTX_PORT_STRIP_KEY),
                collapse_ips=ctx_dict.get(cls.CTX_COLLAPSE_IPS_KEY),
                add_comment_if_empty=ctx_dict.get(cls.CTX_EMPTY_EDL_COMMENT_KEY),
            )
        )


''' HELPER FUNCTIONS '''


def iterable_to_str(iterable: Iterable, delimiter: str = '\n') -> str:
    """
    Transforms an iterable object to an str, with a custom delimiter between each item
    """
    str_res = ""
    if iterable:
        try:
            iter(iterable)
        except TypeError:
            raise DemistoException(f'non iterable object provided to iterable_to_str: {iterable}')
        str_res = delimiter.join(map(str, iterable))
    return str_res


def create_new_edl(request_args: RequestArguments) -> str:
    """
    Gets indicators from XSOAR server using IndicatorsSearcher and formats them

    Parameters:
        request_args: Request arguments

    Returns: Formatted indicators to display in EDL
    """
    limit = request_args.offset + request_args.limit
    indicator_searcher = IndicatorsSearcher(
        filter_fields=EDL_FILTER_FIELDS,
        query=request_args.query,
        size=PAGE_SIZE,
        limit=limit
    )
    iocs: List[dict] = []
    formatted_iocs: set = set()
    loop_counter = 0
    while not indicator_searcher.is_search_done() and loop_counter < EDL_SEARCH_LOOP_LIMIT:
        new_iocs = find_indicators_to_limit(indicator_searcher)
        iocs.extend(new_iocs)
        formatted_iocs = format_indicators(iocs, request_args)
        indicator_searcher.limit += limit - len(formatted_iocs)
        loop_counter += 1
    return iterable_to_str(list(formatted_iocs)[request_args.offset:limit])


def find_indicators_to_limit(indicator_searcher: IndicatorsSearcher) -> List[dict]:
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page

    Parameters:
        indicator_searcher (IndicatorsSearcher): The indicator searcher used to look for indicators

    Returns:
        (list): List of Indicators dict with value,indicator_type keys
    """
    iocs: List[dict] = []
    for ioc_res in indicator_searcher:
        fetched_iocs = ioc_res.get('iocs') or []
        # save only the value and type of each indicator
        iocs.extend({'value': ioc.get('value'), 'indicator_type': ioc.get('indicator_type')}
                    for ioc in fetched_iocs)
    return iocs


def ip_groups_to_cidrs(ip_range_groups: Iterable):
    """Collapse ip groups list to CIDRs

    Args:
        ip_range_groups (Iterable): an Iterable of lists containing connected IPs

    Returns:
        Set. a set of CIDRs.
    """
    ip_ranges = set()
    for cidr in ip_range_groups:
        # handle single ips
        if len(cidr) == 1:
            # CIDR with a single IP appears with "/32" suffix so handle them differently
            ip_ranges.add(str(cidr[0]))
            continue

        ip_ranges.add(str(cidr))

    return ip_ranges


def ip_groups_to_ranges(ip_range_groups: Iterable):
    """Collapse ip groups to ranges.

    Args:
        ip_range_groups (Iterable): a list of lists containing connected IPs

    Returns:
        Set. a set of Ranges.
    """
    ip_ranges = set()
    for group in ip_range_groups:
        # handle single ips
        if len(group) == 1:
            ip_ranges.add(str(group[0]))
            continue

        ip_ranges.add(str(group))

    return ip_ranges


def ips_to_ranges(ips: Iterable, collapse_ips: str):
    """Collapse IPs to Ranges or CIDRs.

    Args:
        ips (Iterable): a group of IP strings.
        collapse_ips (str): Whether to collapse to Ranges or CIDRs.

    Returns:
        Set. a list to Ranges or CIDRs.
    """
    invalid_ips = []
    valid_ips = []

    for ip_or_cidr in ips:
        if is_valid_cidr(ip_or_cidr) or is_valid_ip(ip_or_cidr):
            valid_ips.append(ip_or_cidr)
        else:
            invalid_ips.append(ip_or_cidr)

    if collapse_ips == COLLAPSE_TO_RANGES:
        ips_range_groups = IPSet(valid_ips).iter_ipranges()
        collapsed_list = ip_groups_to_ranges(ips_range_groups)
    else:
        cidrs = IPSet(valid_ips).iter_cidrs()
        collapsed_list = ip_groups_to_cidrs(cidrs)

    collapsed_list.update(invalid_ips)
    return collapsed_list


def is_valid_ip(ip: str) -> bool:
    """
    Args:
        ip: IP address
    Returns: True if the string represents an IPv4 or an IPv6 address, false otherwise.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False


def is_valid_cidr(cidr: str) -> bool:
    """
    Args:
        cidr: CIDR string
    Returns: True if the string represents an IPv4 network or an IPv6 network, false otherwise.
    """
    if '/' not in cidr:
        return False
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.IPv6Network(cidr, strict=False)
            return True
        except ValueError:
            return False


def format_indicators(iocs: list, request_args: RequestArguments) -> set:
    """
    Create a list result of formatted_indicators
     * Empty list:
         1) if add_comment_if_empty, return {'# Empty EDL'}
     * IP / CIDR:
         1) if collapse_ips, collapse IPs/CIDRs
     * URL:
         1) if drop_invalids, drop invalids (length > 254 or has invalid chars)
    * Other indicator types:
        1) if drop_invalids, drop invalids (has invalid chars)
        2) if port_stripping, strip ports
    """
    formatted_indicators = set()
    ipv4_formatted_indicators = set()
    ipv6_formatted_indicators = set()
    for ioc in iocs:
        indicator = ioc.get('value')
        if not indicator:
            continue
        ioc_type = ioc.get('indicator_type')
        # protocol stripping
        indicator = _PROTOCOL_REMOVAL.sub('', indicator)

        if ioc_type not in [FeedIndicatorType.IP, FeedIndicatorType.IPv6,
                            FeedIndicatorType.CIDR, FeedIndicatorType.IPv6CIDR]:
            # Port stripping
            indicator_with_port = indicator
            # remove port from indicator - from demisto.com:369/rest/of/path -> demisto.com/rest/of/path
            indicator = _PORT_REMOVAL.sub(_URL_WITHOUT_PORT, indicator)
            # check if removing the port changed something about the indicator
            if indicator != indicator_with_port and not request_args.url_port_stripping:
                # if port was in the indicator and url_port_stripping param not set - ignore the indicator
                continue
            # Reformatting to PAN-OS URL format
            with_invalid_tokens_indicator = indicator
            # mix of text and wildcard in domain field handling
            indicator = _INVALID_TOKEN_REMOVAL.sub('*', indicator)
            # check if the indicator held invalid tokens
            if request_args.drop_invalids:
                if with_invalid_tokens_indicator != indicator:
                    # invalid tokens in indicator - ignore the indicator
                    continue
                if ioc_type == FeedIndicatorType.URL and len(indicator) >= PAN_OS_MAX_URL_LEN:
                    # URL indicator exceeds allowed length - ignore the indicator
                    continue

            # for PAN-OS *.domain.com does not match domain.com
            # we should provide both
            # this could generate more than num entries according to PAGE_SIZE
            if indicator.startswith('*.'):
                formatted_indicators.add(indicator.lstrip('*.'))

        if request_args.collapse_ips != DONT_COLLAPSE and ioc_type in (FeedIndicatorType.IP, FeedIndicatorType.CIDR):
            ipv4_formatted_indicators.add(indicator)

        elif request_args.collapse_ips != DONT_COLLAPSE and ioc_type == FeedIndicatorType.IPv6:
            ipv6_formatted_indicators.add(indicator)

        else:
            formatted_indicators.add(indicator)

    if len(ipv4_formatted_indicators) > 0:
        ipv4_formatted_indicators = ips_to_ranges(ipv4_formatted_indicators, request_args.collapse_ips)
        formatted_indicators.update(ipv4_formatted_indicators)

    if len(ipv6_formatted_indicators) > 0:
        ipv6_formatted_indicators = ips_to_ranges(ipv6_formatted_indicators, request_args.collapse_ips)
        formatted_indicators.update(ipv6_formatted_indicators)
    return formatted_indicators


def get_edl_on_demand():
    """
    Use the local file system to store the on-demand result, using a lock to
    limit access to the file from multiple threads.
    """
    ctx = get_integration_context()
    if EDL_ON_DEMAND_KEY in ctx:
        ctx.pop(EDL_ON_DEMAND_KEY, None)
        request_args = RequestArguments.from_context_json(ctx)
        edl = create_new_edl(request_args)
        with open(EDL_ON_DEMAND_CACHE_PATH, 'w') as file:
            file.write(edl)
        set_integration_context(ctx)
    else:
        with open(EDL_ON_DEMAND_CACHE_PATH, 'r') as file:
            edl = file.read()
    return edl


def validate_basic_authentication(headers: dict, username: str, password: str) -> bool:
    """
    Checks whether the authentication is valid.
    :param headers: The headers of the http request
    :param username: The integration's username
    :param password: The integration's password
    :return: Boolean which indicates whether the authentication is valid or not
    """
    credentials: str = headers.get('Authorization', '')
    if not credentials or 'Basic ' not in credentials:
        return False
    encoded_credentials: str = credentials.split('Basic ')[1]
    credentials: str = b64decode(encoded_credentials).decode('utf-8')
    if ':' not in credentials:
        return False
    credentials_list = credentials.split(':')
    if len(credentials_list) != 2:
        return False
    user, pwd = credentials_list
    return user == username and pwd == password


def get_bool_arg_or_param(args: dict, params: dict, key: str):
    val = args.get(key)
    return val.lower() == 'true' if isinstance(val, str) else params.get(key, False)


''' ROUTE FUNCTIONS '''


@APP.route('/', methods=['GET'])
def route_edl() -> Response:
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()

    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    cache_refresh_rate: str = params.get('cache_refresh_rate')
    if username and password:
        headers: dict = cast(Dict[Any, Any], request.headers)
        if not validate_basic_authentication(headers, username, password):
            err_msg: str = 'Basic authentication failed. Make sure you are using the right credentials.'
            demisto.debug(err_msg)
            return Response(err_msg, status=401, mimetype='text/plain', headers=[
                ('WWW-Authenticate', 'Basic realm="Login Required"'),
            ])

    request_args = get_request_args(request.args, params)
    on_demand = params.get('on_demand')
    created = datetime.now(timezone.utc)
    edl = get_edl_on_demand() if on_demand else create_new_edl(request_args)
    etag = f'"{hashlib.sha1(edl.encode()).hexdigest()}"'  # guardrails-disable-line
    query_time = (datetime.now(timezone.utc) - created).total_seconds()
    edl_size = 0
    if edl.strip():
        edl_size = edl.count('\n') + 1  # add 1 as last line doesn't have a \n
    if len(edl) == 0 and request_args.add_comment_if_empty:
        edl = '# Empty EDL'
    max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]
    demisto.debug(f'Returning edl of size: [{edl_size}], created: [{created}], query time seconds: [{query_time}],'
                  f' max age: [{max_age}], etag: [{etag}]')
    resp = Response(edl, status=200, mimetype='text/plain', headers=[
        ('X-EDL-Created', created.isoformat()),
        ('X-EDL-Query-Time-Secs', "{:.3f}".format(query_time)),
        ('X-EDL-Size', str(edl_size)),
        ('ETag', etag),
    ])
    resp.cache_control.max_age = max_age
    resp.cache_control[
        'stale-if-error'] = '600'  # number of seconds we are willing to serve stale content when there is an error
    return resp


def get_request_args(request_args: dict, params: dict) -> RequestArguments:
    """
    Processing a flask request arguments and generates a RequestArguments instance from it.
    Args:
        request_args: Flask request arguments
        params: Integration configuration parameters

    Returns:
        RequestArguments instance with processed arguments
    """
    limit = try_parse_integer(request_args.get('n', params.get('edl_size') or 10000), EDL_LIMIT_ERR_MSG)
    offset = try_parse_integer(request_args.get('s', 0), EDL_OFFSET_ERR_MSG)
    query = request_args.get('q', params.get('indicators_query') or '')
    strip_port = request_args.get('sp', params.get('url_port_stripping') or False)
    drop_invalids = request_args.get('di', params.get('drop_invalids') or False)
    collapse_ips = request_args.get('tr', params.get('collapse_ips', DONT_COLLAPSE))
    add_comment_if_empty = request_args.get('ce', params.get('add_comment_if_empty', True))

    # handle flags
    if drop_invalids == '':
        drop_invalids = True

    if strip_port == '':
        strip_port = True

    if collapse_ips not in [DONT_COLLAPSE, COLLAPSE_TO_CIDR, COLLAPSE_TO_RANGES]:
        collapse_ips = try_parse_integer(collapse_ips, EDL_COLLAPSE_ERR_MSG)

        if collapse_ips not in [0, 1, 2]:
            raise DemistoException(EDL_COLLAPSE_ERR_MSG)

        collapse_options = {
            0: DONT_COLLAPSE,
            1: COLLAPSE_TO_RANGES,
            2: COLLAPSE_TO_CIDR
        }
        collapse_ips = collapse_options[collapse_ips]
    return RequestArguments(query,
                            limit,
                            offset,
                            strip_port,
                            drop_invalids,
                            collapse_ips,
                            add_comment_if_empty)


''' COMMAND FUNCTIONS '''


def test_module(_: Dict, params: Dict):
    """
    Validates:
        1. Valid port.
        2. Valid cache_refresh_rate
    """
    get_params_port(params)
    on_demand = params.get('on_demand', None)
    if not on_demand:
        try_parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG)  # validate EDL Size was set
        cache_refresh_rate = params.get('cache_refresh_rate', '')
        if not cache_refresh_rate:
            raise ValueError(EDL_MISSING_REFRESH_ERR_MSG)
        # validate cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError(EDL_MISSING_REFRESH_ERR_MSG)
        try_parse_integer(range_split[0], 'Invalid time value for the Refresh Rate. Must be a valid integer.')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError(
                'Invalid time unit for the Refresh Rate. Must be minutes, hours, days, months, or years.')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    run_long_running(params, is_test=True)
    return 'ok', {}, {}


def update_edl_command(args: Dict, params: Dict):
    """
    Updates the context to update the EDL values on demand the next time it runs
    """
    on_demand = params.get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update EDL On Demand" is off. If you want to update the EDL manually please toggle it on.')
    limit = try_parse_integer(args.get('edl_size', params.get('edl_size')), EDL_LIMIT_ERR_MSG)
    query = args.get('query', '')
    collapse_ips = args.get('collapse_ips', DONT_COLLAPSE)
    url_port_stripping = get_bool_arg_or_param(args, params, 'url_port_stripping')
    drop_invalids = get_bool_arg_or_param(args, params, 'drop_invalids')
    add_comment_if_empty = get_bool_arg_or_param(args, params, 'add_comment_if_empty')
    offset = try_parse_integer(args.get('offset', 0), EDL_OFFSET_ERR_MSG)
    request_args = RequestArguments(query,
                                    limit,
                                    offset,
                                    url_port_stripping,
                                    drop_invalids,
                                    collapse_ips,
                                    add_comment_if_empty)
    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)
    hr = 'EDL will be updated the next time you access it'
    return hr, {}, {}


def initialize_edl_context(params: dict):
    global EDL_ON_DEMAND_CACHE_PATH
    limit = try_parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG)
    query = params.get('indicators_query', '')
    collapse_ips = params.get('collapse_ips', DONT_COLLAPSE)
    url_port_stripping = params.get('url_port_stripping', False)
    drop_invalids = params.get('drop_invalids', False)
    add_comment_if_empty = params.get('add_comment_if_empty', True)
    offset = 0
    request_args = RequestArguments(query,
                                    limit,
                                    offset,
                                    url_port_stripping,
                                    drop_invalids,
                                    collapse_ips,
                                    add_comment_if_empty)
    EDL_ON_DEMAND_CACHE_PATH = demisto.uniqueFile()
    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)


def main():
    """
    Main
    """
    global PAGE_SIZE, EDL_FILTER_FIELDS
    params = demisto.params()
    try:
        PAGE_SIZE = max(1, int(params.get('page_size') or PAGE_SIZE))
    except ValueError:
        demisto.debug(f'Non integer "page_size" provided: {params.get("page_size")}. defaulting to {PAGE_SIZE}')
    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        EDL_FILTER_FIELDS = None
    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if (username and not password) or (password and not username):
        err_msg: str = 'If using credentials, both username and password should be provided.'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'edl-update': update_edl_command,
    }

    try:
        initialize_edl_context(params)
        if command == 'long-running-execution':
            run_long_running(params)
        elif command in commands:
            readable_output, outputs, raw_response = commands[command](demisto.args(), params)
            return_outputs(readable_output, outputs, raw_response)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from NGINXApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

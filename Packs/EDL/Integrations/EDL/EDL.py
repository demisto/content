import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re

from base64 import b64decode
from flask import Flask, Response, request
from netaddr import IPAddress, IPSet
from typing import Callable, Any, Dict, cast
from math import ceil
from threading import Lock
import urllib3
import dateparser

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
EDL_ON_DEMAND_CACHE_PATH: Optional[str] = None
EDL_LOCK = Lock()

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
    CTX_INVALIDATE_EDL_KEY = 'invalidate_empty_edl'
    CTX_DOMAIN_GLOB_KEY = 'dont_duplicate_glob'

    def __init__(self,
                 query: str,
                 limit: int = 10000,
                 offset: int = 0,
                 url_port_stripping: bool = False,
                 drop_invalids: bool = False,
                 collapse_ips: str = DONT_COLLAPSE,
                 invalidate_empty_edl: bool = False,
                 dont_duplicate_glob=False):

        self.query = query
        self.limit = try_parse_integer(limit, EDL_LIMIT_ERR_MSG)
        self.offset = try_parse_integer(offset, EDL_OFFSET_ERR_MSG)
        self.url_port_stripping = url_port_stripping
        self.drop_invalids = drop_invalids
        self.collapse_ips = collapse_ips
        self.invalidate_empty_edl = invalidate_empty_edl
        self.dont_duplicate_glob = dont_duplicate_glob

    def to_context_json(self):
        return {
            self.CTX_QUERY_KEY: self.query,
            self.CTX_LIMIT_KEY: self.limit,
            self.CTX_OFFSET_KEY: self.offset,
            self.CTX_INVALIDS_KEY: self.drop_invalids,
            self.CTX_PORT_STRIP_KEY: self.url_port_stripping,
            self.CTX_COLLAPSE_IPS_KEY: self.collapse_ips,
            self.CTX_INVALIDATE_EDL_KEY: self.invalidate_empty_edl,
            self.CTX_DOMAIN_GLOB_KEY: self.dont_duplicate_glob
        }

    @classmethod
    def from_context_json(cls, ctx_dict):
        return cls(
            **assign_params(
                query=ctx_dict.get(cls.CTX_QUERY_KEY),
                limit=ctx_dict.get(cls.CTX_LIMIT_KEY),
                offset=ctx_dict.get(cls.CTX_OFFSET_KEY),
                drop_invalids=ctx_dict.get(cls.CTX_INVALIDS_KEY),
                url_port_stripping=ctx_dict.get(cls.CTX_PORT_STRIP_KEY),
                collapse_ips=ctx_dict.get(cls.CTX_COLLAPSE_IPS_KEY),
                invalidate_empty_edl=ctx_dict.get(cls.CTX_INVALIDATE_EDL_KEY),
                dont_duplicate_glob=ctx_dict.get(cls.CTX_DOMAIN_GLOB_KEY),
            )
        )


''' HELPER FUNCTIONS '''


def list_to_str(inp_list: list, delimiter: str = ',', map_func: Callable = str) -> str:
    """
    Transforms a list to an str, with a custom delimiter between each list item
    """
    str_res = ""
    if inp_list:
        if isinstance(inp_list, list):
            str_res = delimiter.join(map(map_func, inp_list))
        else:
            raise AttributeError('Invalid inp_list provided to list_to_str')
    return str_res


def create_new_edl(request_args: RequestArguments) -> str:
    """
    Gets indicators from XSOAR server using IndicatorsSearcher and formats them

    Parameters:
        request_args: Request arguments

    Returns: Formatted indicators to display in EDL
    """
    limit = request_args.offset + request_args.limit
    indicator_searcher = IndicatorsSearcher(page=0, filter_fields=EDL_FILTER_FIELDS)
    iocs = find_indicators_to_limit(indicator_searcher, request_args.query, limit)
    formatted_iocs = format_indicators(iocs, request_args)
    if len(formatted_iocs) < len(iocs):
        # indicator list was truncated - try to fetch more indicators
        while len(formatted_iocs) < limit:
            current_search_limit = limit - len(formatted_iocs)
            new_iocs = find_indicators_to_limit(indicator_searcher, request_args.query, current_search_limit)

            # in case no additional indicators exist - exit
            if len(new_iocs) == 0:
                break

            # add the new results to the existing results
            iocs += new_iocs

            # reformat the output
            formatted_iocs = format_indicators(iocs, request_args)

    return list_to_str(formatted_iocs[request_args.offset:limit], '\n')


def find_indicators_to_limit(indicator_searcher: IndicatorsSearcher,
                             indicator_query: str,
                             limit: int
                             ) -> List[dict]:
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page

    Parameters:
        indicator_searcher (IndicatorsSearcher): The indicator searcher used to look for indicators
        indicator_query (str): Cortex XSOAR indicator query
        limit (int): The maximum number of indicators to include in the EDL

    Returns:
        (list): List of Indicators dict with value,indicator_type keys
    """
    iocs: List[dict] = []
    last_found_len = PAGE_SIZE
    total_fetched = 0
    # last_found_len should be PAGE_SIZE (or PAGE_SIZE - 1, as observed for some users) for full pages
    while last_found_len in (PAGE_SIZE, PAGE_SIZE - 1) and (limit and total_fetched < limit):
        res = indicator_searcher.search_indicators_by_version(query=indicator_query, size=PAGE_SIZE)
        fetched_iocs = res.get('iocs') or []
        # save only the value and type of each indicator
        iocs.extend({'value': ioc.get('value'), 'indicator_type': ioc.get('indicator_type')}
                    for ioc in fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
    return iocs


def ip_groups_to_cidrs(ip_range_groups: list):
    """Collapse ip groups list to CIDRs

    Args:
        ip_range_groups (list): a list of lists containing connected IPs

    Returns:
        list. a list of CIDRs.
    """
    ip_ranges = []  # type:List
    for cidr in ip_range_groups:
        # handle single ips
        if len(cidr) == 1:
            # CIDR with a single IP appears with "/32" suffix so handle them differently
            ip_ranges.append(str(cidr[0]))
            continue

        ip_ranges.append(str(cidr))

    return ip_ranges


def ip_groups_to_ranges(ip_range_groups: list):
    """Collapse ip groups list to ranges.

    Args:
        ip_range_groups (list): a list of lists containing connected IPs

    Returns:
        list. a list of Ranges.
    """
    ip_ranges = []  # type:List
    for group in ip_range_groups:
        # handle single ips
        if len(group) == 1:
            ip_ranges.append(str(group[0]))
            continue

        ip_ranges.append(str(group))

    return ip_ranges


def ips_to_ranges(ips: list, collapse_ips: str):
    """Collapse IPs to Ranges or CIDRs.

    Args:
        ips (list): a list of IP strings.
        collapse_ips (str): Whether to collapse to Ranges or CIDRs.

    Returns:
        list. a list to Ranges or CIDRs.
    """

    if collapse_ips == COLLAPSE_TO_RANGES:
        ips_range_groups = IPSet(ips).iter_ipranges()
        return ip_groups_to_ranges(ips_range_groups)

    else:
        cidrs = IPSet(ips).iter_cidrs()
        return ip_groups_to_cidrs(cidrs)


def format_indicators(iocs: list, request_args: RequestArguments) -> list:
    """
    Create a list result of formatted_indicators
     * Empty list:
         1) if invalidate_empty_edl, return ['#']
     * IP / CIDR:
         1) if collapse_ips, collapse IPs/CIDRs
     * URL:
         1) if drop_invalids, drop invalids (length > 254 or has invalid chars)
    * Other:
        1) if drop_invalids, drop invalids (has invalid chars)
        2) if port_stripping, strip ports
        3) if not dont_duplicate_glob, add a duplicate domain without the glob - negative condition for BC
    """
    formatted_indicators = []
    ipv4_formatted_indicators = []
    ipv6_formatted_indicators = []
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
            if not request_args.dont_duplicate_glob and indicator.startswith('*.'):
                formatted_indicators.append(indicator.lstrip('*.'))

        if request_args.collapse_ips != DONT_COLLAPSE and ioc_type == FeedIndicatorType.IP:
            ipv4_formatted_indicators.append(IPAddress(indicator))

        elif request_args.collapse_ips != DONT_COLLAPSE and ioc_type == FeedIndicatorType.IPv6:
            ipv6_formatted_indicators.append(IPAddress(indicator))

        else:
            formatted_indicators.append(indicator)

    if len(ipv4_formatted_indicators) > 0:
        ipv4_formatted_indicators = ips_to_ranges(ipv4_formatted_indicators, request_args.collapse_ips)
        formatted_indicators.extend(ipv4_formatted_indicators)

    if len(ipv6_formatted_indicators) > 0:
        ipv6_formatted_indicators = ips_to_ranges(ipv6_formatted_indicators, request_args.collapse_ips)
        formatted_indicators.extend(ipv6_formatted_indicators)
    if len(formatted_indicators) == 0 and request_args.invalidate_empty_edl:
        formatted_indicators.append('#')
    return formatted_indicators


def get_edl_on_demand():
    """
    Use the local file system to store the on-demand result, using a lock to
    limit access to the file from multiple threads.
    """
    global EDL_ON_DEMAND_CACHE_PATH
    try:
        EDL_LOCK.acquire()
        ctx = get_integration_context()
        if EDL_ON_DEMAND_KEY in ctx:
            ctx.pop(EDL_ON_DEMAND_KEY, None)
            set_integration_context(ctx)
            request_args = RequestArguments.from_context_json(ctx)
            values_str = create_new_edl(request_args)
            if EDL_ON_DEMAND_CACHE_PATH is None:
                EDL_ON_DEMAND_CACHE_PATH = demisto.uniqueFile()
            with open(EDL_ON_DEMAND_CACHE_PATH, 'w') as file:
                file.write(values_str)
        else:
            if EDL_ON_DEMAND_CACHE_PATH is None:  # EDL cache was never written
                return ""
            else:
                with open(EDL_ON_DEMAND_CACHE_PATH, 'r') as file:
                    values_str = file.read()
    finally:
        EDL_LOCK.release()
    return values_str


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


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
    return val.lower() == 'true' if isinstance(val, str) else params.get(key) or False


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
    query_time = (datetime.now(timezone.utc) - created).total_seconds()
    edl_size = 0
    if edl.strip():
        edl_size = edl.count('\n') + 1  # add 1 as last line doesn't have a \n
    max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]
    demisto.debug(f'Returning edl of size: [{edl_size}], created: [{created}], query time seconds: [{query_time}],'
                  f' max age: [{max_age}]')
    resp = Response(edl, status=200, mimetype='text/plain', headers=[
        ('X-EDL-Created', created.isoformat()),
        ('X-EDL-Query-Time-Secs', "{:.3f}".format(query_time)),
        ('X-EDL-Size', str(edl_size))
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
    invalidate_empty_edl = request_args.get('iee', params.get('invalidate_empty_edl') or False)
    dont_duplicate_glob = request_args.get('ddg', params.get('dont_duplicate_glob') or False)

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
                            invalidate_empty_edl,
                            dont_duplicate_glob)


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
        query = params.get('indicators_query')  # validate indicators_query isn't empty
        if not query:
            raise ValueError('"Indicator Query" is required. Provide a valid query.')
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
    invalidate_empty_edl = get_bool_arg_or_param(args, params, 'invalidate_empty_edl')
    dont_duplicate_glob = get_bool_arg_or_param(args, params, 'dont_duplicate_glob')
    offset = try_parse_integer(args.get('offset', 0), EDL_OFFSET_ERR_MSG)
    request_args = RequestArguments(query,
                                    limit,
                                    offset,
                                    url_port_stripping,
                                    drop_invalids,
                                    collapse_ips,
                                    invalidate_empty_edl,
                                    dont_duplicate_glob)
    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)
    hr = 'EDL will be updated the next time you access it'
    return hr, {}, {}


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


import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re
from base64 import b64decode
from flask import Flask, Response, request
from netaddr import IPAddress, IPSet
from typing import Callable, Any, cast, Dict, Tuple
from math import ceil
import dateparser

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'Export Indicators Service'
PAGE_SIZE: int = 200
APP: Flask = Flask('demisto-export_iocs')
CTX_VALUES_KEY: str = 'dmst_export_iocs_values'
CTX_MIMETYPE_KEY: str = 'dmst_export_iocs_mimetype'
SEARCH_LOOP_LIMIT: int = 10

FORMAT_CSV: str = 'csv'
FORMAT_TEXT: str = 'text'
FORMAT_JSON_SEQ: str = 'json-seq'
FORMAT_JSON: str = 'json'
FORMAT_ARG_MWG = 'mwg'
FORMAT_ARG_PANOSURL = 'panosurl'
FORMAT_ARG_BLUECOAT = 'bluecoat'
FORMAT_ARG_PROXYSG = 'proxysg'
FORMAT_MWG: str = 'McAfee Web Gateway'
FORMAT_PROXYSG: str = "Symantec ProxySG"
FORMAT_PANOSURL: str = "PAN-OS URL"
FORMAT_XSOAR_JSON: str = 'XSOAR json'
FORMAT_ARG_XSOAR_JSON: str = 'xsoar-json'
FORMAT_XSOAR_JSON_SEQ: str = 'XSOAR json-seq'
FORAMT_ARG_XSOAR_JSON_SEQ: str = 'xsoar-seq'
FORMAT_XSOAR_CSV: str = 'XSOAR csv'
FORMAT_ARG_XSOAR_CSV: str = 'xsoar-csv'

MWG_TYPE_OPTIONS = ["string", "applcontrol", "dimension", "category", "ip", "mediatype", "number", "regex"]

CTX_FORMAT_ERR_MSG: str = 'Please provide a valid format from: text, json, json-seq, csv, mgw, panosurl and proxysg'
CTX_LIMIT_ERR_MSG: str = 'Please provide a valid integer for List Size'
CTX_OFFSET_ERR_MSG: str = 'Please provide a valid integer for Starting Index'
CTX_MWG_TYPE_ERR_MSG: str = 'The McAFee Web Gateway type can only be one of the following: string,' \
                            ' applcontrol, dimension, category, ip, mediatype, number, regex'
CTX_COLLAPSE_ERR_MSG: str = 'The Collapse parameter can only get the following: 0 - Dont Collapse, ' \
                            '1 - Collapse to Ranges, 2 - Collapse to CIDRS'
CTX_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'
CTX_NO_URLS_IN_PROXYSG_FORMAT = 'ProxySG format only outputs URLs - no URLs found in the current query'

MIMETYPE_JSON_SEQ: str = 'application/json-seq'
MIMETYPE_JSON: str = 'application/json'
MIMETYPE_CSV: str = 'text/csv'
MIMETYPE_TEXT: str = 'text/plain'

DONT_COLLAPSE = "Don't Collapse"
COLLAPSE_TO_CIDR = "To CIDRs"
COLLAPSE_TO_RANGES = "To Ranges"

SORT_ASCENDING = 'asc'
SORT_DESCENDING = 'desc'

_PROTOCOL_REMOVAL = re.compile(r'^(?:[a-z]+:)*//')
_PORT_REMOVAL = re.compile(r'^([a-z0-9\-\.]+)(?:\:[0-9]+)*')
_INVALID_TOKEN_REMOVAL = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')
_BROAD_PATTERN = re.compile(r'^(?:\*\.)+[a-zA-Z]+(?::[0-9]+)?$')


'''Request Arguments Class'''


class RequestArguments:
    def __init__(self, query: str, out_format: str = FORMAT_TEXT, limit: int = 10000, offset: int = 0,
                 mwg_type: str = 'string', strip_port: bool = False, drop_invalids: bool = False,
                 category_default: str = 'bc_category', category_attribute: str = '',
                 collapse_ips: str = DONT_COLLAPSE, csv_text: bool = False, sort_field: str = '',
                 sort_order: str = ''):

        self.query = query
        self.out_format = out_format
        self.limit = limit
        self.offset = offset
        self.mwg_type = mwg_type
        self.strip_port = strip_port
        self.drop_invalids = drop_invalids
        self.category_default = category_default
        self.category_attribute = []  # type:List
        self.collapse_ips = collapse_ips
        self.csv_text = csv_text
        self.sort_field = sort_field
        self.sort_order = sort_order

        if category_attribute is not None:
            category_attribute_list = category_attribute.split(',')

            if len(category_attribute_list) != 1 or '' not in category_attribute_list:
                self.category_attribute = category_attribute_list

    def is_request_change(self, last_update_data: Dict):
        if self.limit != last_update_data.get('last_limit'):
            return True

        elif self.offset != last_update_data.get('last_offset'):
            return True

        elif self.out_format != last_update_data.get('last_format'):
            return True

        elif self.mwg_type != last_update_data.get('mwg_type'):
            return True

        elif self.drop_invalids != last_update_data.get('drop_invalids'):
            return True

        elif self.strip_port != last_update_data.get('strip_port'):
            return True

        elif self.category_default != last_update_data.get('category_default'):
            return True

        elif self.category_attribute != last_update_data.get('category_attribute'):
            return True

        elif self.collapse_ips != last_update_data.get('collapse_ips'):
            return True

        elif self.csv_text != last_update_data.get('csv_text'):
            return True

        elif self.sort_field != last_update_data.get('sort_field'):
            return True

        elif self.sort_order != last_update_data.get('sort_order'):
            return True

        return False


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


def sort_iocs(request_args: RequestArguments, iocs: list) -> list:
    """
    Sorts the IoCs according to the sort field and order.
    Returns: Sorted List of IoCs, if sorting arguments are defined.
    """
    try:
        if request_args.sort_field:
            if request_args.sort_order == SORT_ASCENDING:
                return sorted(iocs, key=lambda ioc: ioc[request_args.sort_field], reverse=False)
            elif request_args.sort_order == SORT_DESCENDING:
                return sorted(iocs, key=lambda ioc: ioc[request_args.sort_field], reverse=True)
    except KeyError:
        demisto.debug('ExportIndicators - Could not sort IoCs, please verify that you entered the correct field name.\n'
                      f'Field used: {request_args.sort_field}')
    except Exception as e:
        demisto.debug(f'ExportIndicators - Could not sort IoCs due to an unknown error.\n{e}')

    return iocs


def refresh_outbound_context(request_args: RequestArguments, on_demand: bool = False) -> str:
    """
    Refresh the values and format using an indicator_query to call demisto.searchIndicators
    Update integration cache only in case of running on demand
    Returns: List(IoCs in output format)
    """
    now = datetime.now()
    # poll indicators into list from demisto
    iocs = []
    out_dict: dict = {}
    limit = request_args.offset + request_args.limit
    indicator_searcher = IndicatorsSearcher(
        query=request_args.query,
        size=PAGE_SIZE,
        limit=limit
    )
    loop_counter = 0
    while not indicator_searcher.is_search_done() and loop_counter < SEARCH_LOOP_LIMIT:
        new_iocs = find_indicators_with_limit(indicator_searcher)
        if not new_iocs:
            break
        iocs += new_iocs
        iocs = sort_iocs(request_args, iocs)
        # reformat the output
        out_dict, actual_indicator_amount = create_values_for_returned_dict(iocs[request_args.offset:], request_args)
        if request_args.out_format in [FORMAT_CSV, FORMAT_XSOAR_CSV]:
            actual_indicator_amount = actual_indicator_amount - 1
        # advance search window with gap size
        indicator_searcher.limit += request_args.limit - actual_indicator_amount
        loop_counter += 1

    if request_args.out_format == FORMAT_JSON:
        out_dict[CTX_MIMETYPE_KEY] = MIMETYPE_JSON

    elif request_args.out_format in [FORMAT_CSV, FORMAT_XSOAR_CSV]:
        if request_args.csv_text:
            out_dict[CTX_MIMETYPE_KEY] = MIMETYPE_TEXT

        else:
            out_dict[CTX_MIMETYPE_KEY] = MIMETYPE_CSV

    elif request_args.out_format in [FORMAT_JSON_SEQ, FORMAT_XSOAR_JSON_SEQ]:
        out_dict[CTX_MIMETYPE_KEY] = MIMETYPE_JSON_SEQ

    else:
        out_dict[CTX_MIMETYPE_KEY] = MIMETYPE_TEXT

    if on_demand:
        set_integration_context({
            "last_output": out_dict,
            'last_run': date_to_timestamp(now),
            'last_limit': request_args.limit,
            'last_offset': request_args.offset,
            'last_format': request_args.out_format,
            'last_query': request_args.query,
            'current_iocs': iocs,
            'mwg_type': request_args.mwg_type,
            'drop_invalids': request_args.drop_invalids,
            'strip_port': request_args.strip_port,
            'category_default': request_args.category_default,
            'category_attribute': request_args.category_attribute,
            'collapse_ips': request_args.collapse_ips,
            'csv_text': request_args.csv_text,
            'sort_field': request_args.sort_field,
            'sort_order': request_args.sort_order,
        })
    return out_dict[CTX_VALUES_KEY] if CTX_VALUES_KEY in out_dict else []


def find_indicators_with_limit(indicator_searcher: IndicatorsSearcher) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """
    iocs: List[dict] = []
    for ioc_res in indicator_searcher:
        fetched_iocs = ioc_res.get('iocs') or []
        iocs.extend(fetched_iocs)
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


def panos_url_formatting(iocs: list, drop_invalids: bool, strip_port: bool):
    formatted_indicators = []  # type:List
    for indicator_data in iocs:
        # only format URLs and Domains
        indicator = indicator_data.get('value')
        if not indicator:
            continue
        if indicator_data.get('indicator_type') in ['URL', 'Domain', 'DomainGlob']:
            indicator = indicator.lower()

            # remove initial protocol - http/https/ftp/ftps etc
            indicator = _PROTOCOL_REMOVAL.sub('', indicator)

            indicator_with_port = indicator
            # remove port from indicator - from demisto.com:369/rest/of/path -> demisto.com/rest/of/path
            indicator = _PORT_REMOVAL.sub(r'\g<1>', indicator)
            # check if removing the port changed something about the indicator
            if indicator != indicator_with_port and not strip_port:
                # if port was in the indicator and strip_port param not set - ignore the indicator
                continue

            with_invalid_tokens_indicator = indicator
            # remove invalid tokens from indicator
            indicator = _INVALID_TOKEN_REMOVAL.sub('*', indicator)

            # check if the indicator held invalid tokens
            if with_invalid_tokens_indicator != indicator:
                # invalid tokens in indicator- if drop_invalids is set - ignore the indicator
                if drop_invalids:
                    continue

                # check if after removing the tokens the indicator is too broad if so - ignore
                # example of too broad terms: "*.paloalto", "*.*.paloalto", "*.paloalto:60"
                hostname = indicator
                if '/' in hostname:
                    hostname, _ = hostname.split('/', 1)

                if _BROAD_PATTERN.match(hostname) is not None:
                    continue

            # for PAN-OS "*.domain.com" does not match "domain.com" - we should provide both
            if indicator.startswith('*.'):
                formatted_indicators.append(indicator[2:])

        formatted_indicators.append(indicator)
    return {CTX_VALUES_KEY: list_to_str(formatted_indicators, '\n')}, len(formatted_indicators)


def create_json_out_format(iocs: list):
    formatted_indicators = []  # type:List
    for indicator_data in iocs:
        if indicator_data.get("value"):
            json_format_indicator = json_format_single_indicator(indicator_data)
            formatted_indicators.append(json_format_indicator)

    return {CTX_VALUES_KEY: json.dumps(formatted_indicators)}


def json_format_single_indicator(indicator: dict):
    json_format_indicator = {
        "indicator": indicator.get("value")
    }
    indicator.pop("value", None)

    json_format_indicator["value"] = indicator
    return json_format_indicator


def add_indicator_to_category(indicator, category, category_dict):
    if category in category_dict.keys():
        category_dict[category].append(indicator)

    else:
        category_dict[category] = [indicator]

    return category_dict


def create_proxysg_out_format(iocs: list, category_attribute: list, category_default: str = 'bc_category'):
    formatted_indicators = ''
    category_dict = {}  # type:Dict
    num_of_returned_indicators = 0

    for indicator in iocs:
        if indicator.get('indicator_type') in ['URL', 'Domain', 'DomainGlob'] and indicator.get('value'):
            stripped_indicator = _PROTOCOL_REMOVAL.sub('', indicator.get('value'))
            indicator_proxysg_category = indicator.get('proxysgcategory')
            # if a ProxySG Category is set and it is in the category_attribute list or that the attribute list is empty
            # than list add the indicator to it's category list
            if indicator_proxysg_category is not None and \
                    (indicator_proxysg_category in category_attribute or len(category_attribute) == 0):
                category_dict = add_indicator_to_category(stripped_indicator, indicator_proxysg_category,
                                                          category_dict)

            else:
                # if ProxySG Category is not set or does not exist in the category_attribute list
                category_dict = add_indicator_to_category(stripped_indicator, category_default, category_dict)

    for category, indicator_list in category_dict.items():
        sub_output_string = f"define category {category}\n"
        sub_output_string += list_to_str(indicator_list, '\n')
        sub_output_string += "\nend\n"
        formatted_indicators += sub_output_string
        num_of_returned_indicators = num_of_returned_indicators + len(indicator_list)

    if len(formatted_indicators) == 0:
        raise Exception(CTX_NO_URLS_IN_PROXYSG_FORMAT)

    return {CTX_VALUES_KEY: formatted_indicators}, num_of_returned_indicators


def create_mwg_out_format(iocs: list, mwg_type: str) -> dict:
    formatted_indicators = []  # type:List
    for indicator in iocs:
        if not indicator.get('value'):
            continue
        value = "\"" + indicator.get('value') + "\""
        sources = indicator.get('sourceBrands')
        if sources:
            sources_string = "\"" + ','.join(sources) + "\""

        else:
            sources_string = "\"from CORTEX XSOAR\""

        formatted_indicators.append(value + " " + sources_string)

    string_formatted_indicators = list_to_str(formatted_indicators, '\n')

    if isinstance(mwg_type, list):
        mwg_type = mwg_type[0]

    string_formatted_indicators = "type=" + mwg_type + "\n" + string_formatted_indicators

    return {CTX_VALUES_KEY: string_formatted_indicators}


def create_values_for_returned_dict(iocs: list, request_args: RequestArguments) -> Tuple[dict, int]:
    """
    Create a dictionary for output values using the selected format (json, json-seq, text, csv, McAfee Web Gateway,
    Symantec ProxySG, panosurl)
    """
    if request_args.out_format == FORMAT_PANOSURL:
        return panos_url_formatting(iocs, request_args.drop_invalids, request_args.strip_port)

    if request_args.out_format == FORMAT_PROXYSG:
        return create_proxysg_out_format(iocs, request_args.category_attribute, request_args.category_default)

    if request_args.out_format == FORMAT_MWG:
        return create_mwg_out_format(iocs, request_args.mwg_type), len(iocs)

    if request_args.out_format == FORMAT_JSON:
        return create_json_out_format(iocs), len(iocs)

    if request_args.out_format == FORMAT_XSOAR_JSON:
        iocs_list = [ioc for ioc in iocs]
        return {CTX_VALUES_KEY: json.dumps(iocs_list)}, len(iocs)

    else:
        ipv4_formatted_indicators = []
        ipv6_formatted_indicators = []
        formatted_indicators = []
        if request_args.out_format == FORMAT_XSOAR_CSV and len(iocs) > 0:  # add csv keys as first item
            headers = list(iocs[0].keys())
            formatted_indicators.append(list_to_str(headers))

        elif request_args.out_format == FORMAT_CSV and len(iocs) > 0:
            formatted_indicators.append('indicator')

        for ioc in iocs:
            value = ioc.get('value')
            type = ioc.get('indicator_type')
            if value:
                if request_args.out_format in [FORMAT_TEXT, FORMAT_CSV]:
                    if type == 'IP' and request_args.collapse_ips != DONT_COLLAPSE:
                        ipv4_formatted_indicators.append(IPAddress(value))

                    elif type == 'IPv6' and request_args.collapse_ips != DONT_COLLAPSE:
                        ipv6_formatted_indicators.append(IPAddress(value))

                    else:
                        formatted_indicators.append(value)

                elif request_args.out_format == FORMAT_XSOAR_JSON_SEQ:
                    formatted_indicators.append(json.dumps(ioc))

                elif request_args.out_format == FORMAT_JSON_SEQ:
                    json_format_indicator = json_format_single_indicator(ioc)
                    formatted_indicators.append(json.dumps(json_format_indicator))

                elif request_args.out_format == FORMAT_XSOAR_CSV:
                    # wrap csv values with " to escape them
                    values = list(ioc.values())
                    formatted_indicators.append(list_to_str(values, map_func=lambda val: f'"{val}"'))

        if len(ipv4_formatted_indicators) > 0:
            ipv4_formatted_indicators = ips_to_ranges(ipv4_formatted_indicators, request_args.collapse_ips)
            formatted_indicators.extend(ipv4_formatted_indicators)

        if len(ipv6_formatted_indicators) > 0:
            ipv6_formatted_indicators = ips_to_ranges(ipv6_formatted_indicators, request_args.collapse_ips)
            formatted_indicators.extend(ipv6_formatted_indicators)

    return {CTX_VALUES_KEY: list_to_str(formatted_indicators, '\n')}, len(formatted_indicators)


def get_outbound_mimetype() -> str:
    """Returns the mimetype of the export_iocs"""
    ctx = get_integration_context().get('last_output', {})
    return ctx.get(CTX_MIMETYPE_KEY, 'text/plain')


def get_outbound_ioc_values(on_demand, request_args: RequestArguments,
                            last_update_data=None, cache_refresh_rate=None) -> str:
    """
    Get the ioc list to return in the list
    """
    if last_update_data is None:
        last_update_data = {}

    last_update = last_update_data.get('last_run')
    last_query = last_update_data.get('last_query')
    current_iocs = last_update_data.get('current_iocs')

    # on_demand ignores cache
    if on_demand:
        if request_args.is_request_change(last_update_data):
            values_str = get_ioc_values_str_from_context(request_args=request_args, iocs=current_iocs)

        else:
            values_str = get_ioc_values_str_from_context(request_args=request_args)

    else:
        if last_update:
            # takes the cache_refresh_rate amount of time back since run time.
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            if last_update <= cache_time or request_args.is_request_change(last_update_data) or \
                    request_args.query != last_query:
                values_str = refresh_outbound_context(request_args=request_args)
            else:
                values_str = get_ioc_values_str_from_context(request_args=request_args)
        else:
            values_str = refresh_outbound_context(request_args)

    return values_str


def get_ioc_values_str_from_context(request_args: RequestArguments, iocs=None) -> str:
    """
    Extracts output values from cache
    """
    if iocs:
        if request_args.offset > len(iocs):
            return ''

        iocs = iocs[request_args.offset: request_args.limit + request_args.offset]
        returned_dict, _ = create_values_for_returned_dict(iocs, request_args=request_args)
        current_cache = get_integration_context()
        current_cache['last_output'] = returned_dict
        set_integration_context(current_cache)

    else:
        returned_dict = get_integration_context().get('last_output', {})

    return returned_dict.get(CTX_VALUES_KEY, '')


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


''' ROUTE FUNCTIONS '''


def get_request_args(params):
    limit = try_parse_integer(request.args.get('n', params.get('list_size', 10000)), CTX_LIMIT_ERR_MSG)
    offset = try_parse_integer(request.args.get('s', 0), CTX_OFFSET_ERR_MSG)
    out_format = request.args.get('v', params.get('format', 'text'))
    query = request.args.get('q', params.get('indicators_query'))
    mwg_type = request.args.get('t', params.get('mwg_type', "string"))
    strip_port = request.args.get('sp', params.get('strip_port', False))
    drop_invalids = request.args.get('di', params.get('drop_invalids', False))
    category_default = request.args.get('cd', params.get('category_default', 'bc_category'))
    category_attribute = request.args.get('ca', params.get('category_attribute', ''))
    collapse_ips = request.args.get('tr', params.get('collapse_ips', DONT_COLLAPSE))
    csv_text = request.args.get('tx', params.get('csv_text', False))
    sort_field = request.args.get('sf', params.get('sort_field'))
    sort_order = request.args.get('so', params.get('sort_order'))

    # handle flags
    if strip_port is not None and strip_port == '':
        strip_port = True

    if drop_invalids is not None and drop_invalids == '':
        drop_invalids = True

    if csv_text is not None and csv_text == '':
        csv_text = True

    if collapse_ips is not None and collapse_ips not in [DONT_COLLAPSE, COLLAPSE_TO_CIDR, COLLAPSE_TO_RANGES]:
        collapse_ips = try_parse_integer(collapse_ips, CTX_COLLAPSE_ERR_MSG)
        if collapse_ips == 0:
            collapse_ips = DONT_COLLAPSE

        elif collapse_ips == 1:
            collapse_ips = COLLAPSE_TO_RANGES

        elif collapse_ips == 2:
            collapse_ips = COLLAPSE_TO_CIDR

    # prevent given empty params
    if len(query) == 0:
        query = params.get('indicators_query')

    if len(out_format) == 0:
        out_format = params.get('format', 'text')

    if out_format not in [FORMAT_PROXYSG, FORMAT_PANOSURL, FORMAT_TEXT, FORMAT_JSON, FORMAT_CSV,
                          FORMAT_JSON_SEQ, FORMAT_MWG, FORMAT_ARG_BLUECOAT, FORMAT_ARG_MWG, FORMAT_ARG_PANOSURL,
                          FORMAT_ARG_PROXYSG, FORMAT_ARG_PANOSURL, FORMAT_XSOAR_JSON, FORMAT_ARG_XSOAR_JSON,
                          FORMAT_XSOAR_JSON_SEQ, FORAMT_ARG_XSOAR_JSON_SEQ, FORMAT_XSOAR_CSV, FORMAT_ARG_XSOAR_CSV]:
        raise DemistoException(CTX_FORMAT_ERR_MSG)

    elif out_format in [FORMAT_ARG_PROXYSG, FORMAT_ARG_BLUECOAT]:
        out_format = FORMAT_PROXYSG

    elif out_format == FORMAT_ARG_MWG:
        out_format = FORMAT_MWG

    elif out_format == FORMAT_ARG_PANOSURL:
        out_format = FORMAT_PANOSURL

    elif out_format == FORMAT_ARG_XSOAR_JSON:
        out_format = FORMAT_XSOAR_JSON

    elif out_format == FORAMT_ARG_XSOAR_JSON_SEQ:
        out_format = FORMAT_XSOAR_JSON_SEQ

    elif out_format == FORMAT_ARG_XSOAR_CSV:
        out_format = FORMAT_XSOAR_CSV

    if out_format == FORMAT_MWG:
        if mwg_type not in MWG_TYPE_OPTIONS:
            raise DemistoException(CTX_MWG_TYPE_ERR_MSG)

    return RequestArguments(query, out_format, limit, offset, mwg_type, strip_port, drop_invalids, category_default,
                            category_attribute, collapse_ips, csv_text, sort_field, sort_order)


@APP.route('/', methods=['GET'])
def route_list_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    try:
        params = demisto.params()

        credentials = params.get('credentials') if params.get('credentials') else {}
        username: str = credentials.get('identifier', '')
        password: str = credentials.get('password', '')
        if username and password:
            headers: dict = cast(Dict[Any, Any], request.headers)
            if not validate_basic_authentication(headers, username, password):
                err_msg: str = 'Basic authentication failed. Make sure you are using the right credentials.'
                demisto.debug(err_msg)
                return Response(err_msg, status=401, mimetype='text/plain', headers=[
                    ('WWW-Authenticate', 'Basic realm="Login Required"'),
                ])

        request_args = get_request_args(params)
        created = datetime.now(timezone.utc)
        cache_refresh_rate = params.get('cache_refresh_rate')

        values = get_outbound_ioc_values(
            on_demand=params.get('on_demand'),
            last_update_data=get_integration_context(),
            cache_refresh_rate=cache_refresh_rate,
            request_args=request_args
        )
        query_time = (datetime.now(timezone.utc) - created).total_seconds()

        if not get_integration_context() and params.get('on_demand'):
            values = 'You are running in On-Demand mode - please run !eis-update command to initialize the ' \
                     'export process'

        elif not values:
            values = "No Results Found For the Query"

        # if the case there are strings to add to the EDL, add them if the output type is text
        if request_args.out_format == FORMAT_TEXT:
            append_str = params.get("append_string")
            prepend_str = params.get("prepend_string")
            if append_str:
                append_str = append_str.replace("\\n", "\n")
                values = f"{values}{append_str}"
            if prepend_str:
                prepend_str = prepend_str.replace("\\n", "\n")
                values = f"{prepend_str}\n{values}"

        mimetype = get_outbound_mimetype()

        list_size = 0
        if values.strip():
            list_size = values.count('\n') + 1  # add 1 as last line doesn't have a \n
        max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]
        demisto.debug(f'Returning exported indicators list of size: [{list_size}], created: [{created}], '
                      f'query time seconds: [{query_time}], max age: [{max_age}]')
        resp = Response(values, status=200, mimetype=mimetype, headers=[
            ('X-ExportIndicators-Created', created.isoformat()),
            ('X-ExportIndicators-Query-Time-Secs', "{:.3f}".format(query_time)),
            ('X-ExportIndicators-Size', str(list_size))
        ])
        resp.cache_control.max_age = max_age
        resp.cache_control[
            'stale-if-error'] = '600'  # number of seconds we are willing to serve stale content when there is an error
        return resp

    except Exception:
        return Response(traceback.format_exc(), status=400, mimetype='text/plain')


''' COMMAND FUNCTIONS '''


def test_module(args, params):
    """
    Validates:
        1. Valid port.
        2. Valid cache_refresh_rate
    """
    get_params_port(params)
    on_demand = params.get('on_demand', None)
    if not on_demand:
        try_parse_integer(params.get('list_size'), CTX_LIMIT_ERR_MSG)  # validate export_iocs Size was set
        cache_refresh_rate = params.get('cache_refresh_rate', '')
        if not cache_refresh_rate:
            raise ValueError(CTX_MISSING_REFRESH_ERR_MSG)
        # validate cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError(CTX_MISSING_REFRESH_ERR_MSG)
        try_parse_integer(range_split[0], 'Invalid time value for the Refresh Rate. Must be a valid integer.')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError(
                'Invalid time unit for the Refresh Rate. Must be minutes, hours, days, months, or years.')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    run_long_running(params, is_test=True)
    return 'ok'


def update_outbound_command(args, params):
    """
    Updates the export_iocs values and format on demand
    """
    on_demand = params.get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update exported IOCs On Demand" is off. If you want to update manually please toggle it on.')
    limit = try_parse_integer(args.get('list_size', params.get('list_size')), CTX_LIMIT_ERR_MSG)
    print_indicators = args.get('print_indicators')

    query = args.get('query')
    # in case no query is entered take the query in the integration params
    if not query:
        query = params.get('indicators_query')

    out_format = args.get('format')
    offset = try_parse_integer(args.get('offset', 0), CTX_OFFSET_ERR_MSG)
    mwg_type = args.get('mwg_type')
    strip_port = args.get('strip_port') == 'True'
    drop_invalids = args.get('drop_invalids') == 'True'
    category_attribute = args.get('category_attribute')
    category_default = args.get('category_default')
    collapse_ips = args.get('collapse_ips')
    csv_text = args.get('csv_text') == 'True'
    sort_field = args.get('sort_field')
    sort_order = args.get('sort_order')

    request_args = RequestArguments(query, out_format, limit, offset, mwg_type, strip_port, drop_invalids,
                                    category_default, category_attribute, collapse_ips, csv_text, sort_field, sort_order)

    indicators = refresh_outbound_context(request_args, on_demand=on_demand)
    if indicators:
        hr = tableToMarkdown('List was updated successfully with the following values', indicators,
                             ['Indicators']) if print_indicators == 'true' else 'List was updated successfully'

    else:
        hr = "No Results Found For the Query"

    return CommandResults(readable_output=hr, raw_response=indicators)


def main():
    """
    Main
    """
    params = demisto.params()

    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if (username and not password) or (password and not username):
        err_msg: str = 'If using credentials, both username and password should be provided.'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)

    command = demisto.command()
    demisto.debug('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'eis-update': update_outbound_command
    }

    try:
        if command == 'long-running-execution':
            run_long_running(params)
        elif command in commands:
            return_results(commands[command](demisto.args(), params))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from NGINXApiModule import *  # noqa: E402


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

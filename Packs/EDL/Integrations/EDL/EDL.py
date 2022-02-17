import tempfile

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import re

from base64 import b64decode
from flask import Flask, Response, request
from netaddr import IPSet
from typing import Any, Dict, cast, Iterable, Callable, IO
from math import ceil
import urllib3
import dateparser
import hashlib
import json
import ipaddress

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'Generic Export Indicators service'
PAGE_SIZE: int = 2000
PAN_OS_MAX_URL_LEN = 255
APP: Flask = Flask('demisto-edl')
EDL_LIMIT_ERR_MSG: str = 'Please provide a valid integer for List Size'
EDL_OFFSET_ERR_MSG: str = 'Please provide a valid integer for Starting Index'
EDL_COLLAPSE_ERR_MSG: str = 'The Collapse parameter can only get the following: 0 - none, ' \
                            '1 - range, 2 - CIDR'
EDL_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'
EDL_FORMAT_ERR_MSG: str = 'Please provide a valid format from: text, json, csv, mgw and proxysg'
EDL_MWG_TYPE_ERR_MSG: str = 'The McAFee Web Gateway type can only be one of the following: string,' \
                            ' applcontrol, dimension, category, ip, mediatype, number, regex'
EDL_NO_URLS_IN_PROXYSG_FORMAT = 'ProxySG format only outputs URLs - no URLs found in the current query'

EDL_ON_DEMAND_KEY: str = 'UpdateEDL'
EDL_ON_DEMAND_CACHE_PATH: str = ''
EDL_SEARCH_LOOP_LIMIT: int = 10

''' REFORMATTING REGEXES '''
_PROTOCOL_REMOVAL = re.compile('^(?:[a-z]+:)*//')
_PORT_REMOVAL = re.compile(r'^((?:[a-z]+:)*//([a-z0-9\-\.]+)|([a-z0-9\-\.]+))(?:\:[0-9]+)*')
_URL_WITHOUT_PORT = r'\g<1>'
_INVALID_TOKEN_REMOVAL = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')
_BROAD_PATTERN = re.compile(r'^(?:\*\.)+[a-zA-Z]+(?::[0-9]+)?$')

DONT_COLLAPSE = "Don't Collapse"
COLLAPSE_TO_CIDR = "To CIDRS"
COLLAPSE_TO_RANGES = "To Ranges"

MIMETYPE_JSON_SEQ: str = 'application/json-seq'
MIMETYPE_JSON: str = 'application/json'
MIMETYPE_CSV: str = 'text/csv'
MIMETYPE_TEXT: str = 'text/plain'

FORMAT_CSV: str = 'CSV'
FORMAT_TEXT: str = 'PAN-OS (text)'
FORMAT_JSON: str = 'JSON'
FORMAT_ARG_MWG = 'mwg'
FORMAT_ARG_BLUECOAT = 'bluecoat'
FORMAT_ARG_PROXYSG = 'proxysg'
FORMAT_MWG: str = 'McAfee Web Gateway'
FORMAT_PROXYSG: str = "Symantec ProxySG"

MWG_TYPE_OPTIONS = ["string", "applcontrol", "dimension", "category", "ip", "mediatype", "number", "regex"]

INCREASE_LIMIT = 1.1
'''Request Arguments Class'''


class RequestArguments:
    CTX_QUERY_KEY = 'last_query'
    CTX_OUT_FORMAT = 'out_format'
    CTX_LIMIT_KEY = 'last_limit'
    CTX_OFFSET_KEY = 'last_offset'
    CTX_INVALIDS_KEY = 'drop_invalids'
    CTX_PORT_STRIP_KEY = 'url_port_stripping'
    CTX_COLLAPSE_IPS_KEY = 'collapse_ips'
    CTX_EMPTY_EDL_COMMENT_KEY = 'add_comment_if_empty'
    CTX_MWG_TYPE = 'mwg_type'
    CTX_CATEGORY_DEFAULT = 'bc_category'
    CTX_CATEGORY_ATTRIBUTE = 'category_attribute'
    CTX_FIELDS_TO_PRESENT = 'fields_to_present'
    CTX_CSV_TEXT = 'csv_text'
    CTX_PROTOCOL_STRIP_KEY = 'url_protocol_stripping'
    CTX_URL_TRUNCATE_KEY = 'url_truncate'

    FILTER_FIELDS_ON_FORMAT_TEXT = "name,type"
    FILTER_FIELDS_ON_FORMAT_MWG = "name,type,sourceBrands"
    FILTER_FIELDS_ON_FORMAT_PROXYSG = "name,type,proxysgcategory"
    FILTER_FIELDS_ON_FORMAT_CSV = "name,type"
    FILTER_FIELDS_ON_FORMAT_JSON = "name,type"

    def __init__(self,
                 query: str,
                 out_format: str = FORMAT_TEXT,
                 limit: int = 10000,
                 offset: int = 0,
                 url_port_stripping: bool = False,
                 drop_invalids: bool = False,
                 collapse_ips: str = DONT_COLLAPSE,
                 add_comment_if_empty: bool = True,
                 mwg_type: str = 'string',
                 category_default: str = 'bc_category',
                 category_attribute: Optional[str] = None,
                 fields_to_present: str = '',
                 csv_text: bool = False,
                 url_protocol_stripping: bool = False,
                 url_truncate: bool = False
                 ):

        self.query = query
        self.out_format = out_format
        self.limit = try_parse_integer(limit, EDL_LIMIT_ERR_MSG)
        self.offset = try_parse_integer(offset, EDL_OFFSET_ERR_MSG)
        self.url_port_stripping = url_port_stripping
        self.url_protocol_stripping = url_protocol_stripping
        self.drop_invalids = drop_invalids
        self.collapse_ips = collapse_ips
        self.add_comment_if_empty = add_comment_if_empty
        self.mwg_type = mwg_type
        self.category_default = category_default
        self.category_attribute = []  # type:List
        self.fields_to_present = self.get_fields_to_present(fields_to_present)
        self.csv_text = csv_text
        self.url_truncate = url_truncate

        if category_attribute is not None:
            category_attribute_list = argToList(category_attribute)

            if len(category_attribute_list) != 1 or '' not in category_attribute_list:
                self.category_attribute = category_attribute_list

    def to_context_json(self):
        return {
            self.CTX_QUERY_KEY: self.query,
            self.CTX_OUT_FORMAT: self.out_format,
            self.CTX_LIMIT_KEY: self.limit,
            self.CTX_OFFSET_KEY: self.offset,
            self.CTX_INVALIDS_KEY: self.drop_invalids,
            self.CTX_PORT_STRIP_KEY: self.url_port_stripping,
            self.CTX_COLLAPSE_IPS_KEY: self.collapse_ips,
            self.CTX_EMPTY_EDL_COMMENT_KEY: self.add_comment_if_empty,
            self.CTX_MWG_TYPE: self.mwg_type,
            self.CTX_CATEGORY_DEFAULT: self.category_default,
            self.CTX_CATEGORY_ATTRIBUTE: self.category_attribute,
            self.CTX_FIELDS_TO_PRESENT: self.fields_to_present,
            self.CTX_CSV_TEXT: self.csv_text,
            self.CTX_PROTOCOL_STRIP_KEY: self.url_protocol_stripping,
            self.CTX_URL_TRUNCATE_KEY: self.url_truncate

        }

    @classmethod
    def from_context_json(cls, ctx_dict):
        """Returns an initiated instance of the class from a json"""
        return cls(
            **assign_params(
                query=ctx_dict.get(cls.CTX_QUERY_KEY),
                out_format=ctx_dict.get(cls.CTX_OUT_FORMAT),
                limit=ctx_dict.get(cls.CTX_LIMIT_KEY),
                offset=ctx_dict.get(cls.CTX_OFFSET_KEY),
                drop_invalids=ctx_dict.get(cls.CTX_INVALIDS_KEY),
                url_port_stripping=ctx_dict.get(cls.CTX_PORT_STRIP_KEY),
                collapse_ips=ctx_dict.get(cls.CTX_COLLAPSE_IPS_KEY),
                add_comment_if_empty=ctx_dict.get(cls.CTX_EMPTY_EDL_COMMENT_KEY),
                mwg_type=ctx_dict.get(cls.CTX_MWG_TYPE),
                category_default=ctx_dict.get(cls.CTX_CATEGORY_DEFAULT),
                category_attributeself=ctx_dict.get(cls.CTX_CATEGORY_ATTRIBUTE),
                fields_to_present=ctx_dict.get(cls.CTX_FIELDS_TO_PRESENT),
                csv_text=ctx_dict.get(cls.CTX_CSV_TEXT),
                url_protocol_stripping=ctx_dict.get(cls.CTX_PROTOCOL_STRIP_KEY),
                url_truncate=ctx_dict.get(cls.CTX_URL_TRUNCATE_KEY)
            )
        )

    def get_fields_to_present(self, fields_to_present: str) -> str:
        # based on func ToIoC https://github.com/demisto/server/blob/master/domain/insight.go

        if fields_to_present == 'use_legacy_query':
            return ''

        fields_for_format = {
            FORMAT_TEXT: self.FILTER_FIELDS_ON_FORMAT_TEXT,
            FORMAT_CSV: self.FILTER_FIELDS_ON_FORMAT_CSV,
            FORMAT_JSON: self.FILTER_FIELDS_ON_FORMAT_JSON,
            FORMAT_MWG: self.FILTER_FIELDS_ON_FORMAT_MWG,
            FORMAT_PROXYSG: self.FILTER_FIELDS_ON_FORMAT_PROXYSG
        }
        if self.out_format in [FORMAT_CSV, FORMAT_JSON] and\
                fields_to_present:
            if 'all' in argToList(fields_to_present):
                return ''
            else:
                # replace "value" to "name"
                list_fields = argToList(fields_to_present)
                if 'value' in list_fields:
                    list_fields[list_fields.index('value')] = 'name'
                    fields_to_present = ",".join(list_fields)
                return fields_to_present

        return fields_for_format.get(self.out_format, self.FILTER_FIELDS_ON_FORMAT_TEXT)


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
        filter_fields=request_args.fields_to_present,
        query=request_args.query,
        size=PAGE_SIZE,
        limit=limit
    )
    formatted_indicators = ''
    if request_args.out_format == FORMAT_TEXT:
        if request_args.drop_invalids or request_args.collapse_ips != "Don't Collapse":
            # Because there may be illegal indicators or they may turn into cider, the limit is increased
            indicator_searcher.limit = int(limit * INCREASE_LIMIT)
        new_iocs_file = get_indicators_to_format(indicator_searcher, request_args)
        # we collect first all indicators because we ned all ips to collapse_ips
        new_iocs_file = create_text_out_format(new_iocs_file, request_args)
        new_iocs_file.seek(0)
        for count, line in enumerate(new_iocs_file):
            # continue searching iocs if 1) iocs was truncated or 2) got all available iocs
            if count + 1 > limit:
                break
            else:
                formatted_indicators += line
    else:
        new_iocs_file = get_indicators_to_format(indicator_searcher, request_args)
        new_iocs_file.seek(0)
        formatted_indicators = new_iocs_file.read()
    new_iocs_file.close()
    return formatted_indicators


def replace_field_name_to_output_format(fields: str):
    """
     convert from the request name field to the name in the response from the server
    """
    fields_list = argToList(fields)
    new_list = []
    for field in fields_list:
        if field == 'name':
            field = 'value'
        elif field == 'type':
            field = 'indicator_type'
        new_list.append(field)
    return new_list


def get_indicators_to_format(indicator_searcher: IndicatorsSearcher, request_args: RequestArguments) ->\
        Union[IO, IO[str]]:
    """
    Finds indicators using demisto.searchIndicators, and returns the indicators in file written in the requested format
    Parameters:
        indicator_searcher (IndicatorsSearcher): The indicator searcher used to look for indicators
        request_args (RequestArguments):  all the request arguments.
    Returns:
        (IO): indicators in file writen in requested format
    """
    f = tempfile.TemporaryFile(mode='w+t')
    list_fields = replace_field_name_to_output_format(request_args.fields_to_present)
    headers_was_writen = False
    files_by_category = {}  # type:Dict
    ioc_counter = 0
    try:
        for ioc_res in indicator_searcher:
            fetched_iocs = ioc_res.get('iocs') or []
            for ioc in fetched_iocs:
                ioc_counter += 1
                if request_args.out_format == FORMAT_PROXYSG:
                    files_by_category = create_proxysg_out_format(ioc, files_by_category, request_args)

                elif request_args.out_format == FORMAT_MWG:
                    f.write(create_mwg_out_format(ioc, request_args, headers_was_writen))
                    headers_was_writen = True

                elif request_args.out_format == FORMAT_JSON:
                    f.write(create_json_out_format(list_fields, ioc, request_args, headers_was_writen))
                    headers_was_writen = True

                elif request_args.out_format == FORMAT_TEXT:
                    # save only the value and type of each indicator
                    f.write(str(json.dumps({"value": ioc.get("value"),
                                            "indicator_type": ioc.get("indicator_type")})) + "\n")

                elif request_args.out_format == FORMAT_CSV:
                    f.write(create_csv_out_format(headers_was_writen, list_fields, ioc, request_args))
                    headers_was_writen = True
                if ioc_counter >= indicator_searcher.limit:
                    break

    except Exception as e:
        demisto.error(f'Error parsing the following indicator: {ioc.get("value")}\n{e}')

    if request_args.out_format == FORMAT_JSON:
        f.write(']')
    elif request_args.out_format == FORMAT_PROXYSG:
        f = create_proxysg_all_category_out_format(f, files_by_category)
    return f


def create_json_out_format(list_fields: List, indicator: Dict, request_args: RequestArguments, not_first_call=True) -> str:
    """format the indicator to json format.

    Args:
        list_fields (list): the fields to return.
        indicator (dict): the indicator info
        request_args (RequestArguments): all the request arguments.
        not_first_call (bool): Indicates if this is the first call to the function.

    Returns:
        An indicator to add to the file in json format.
    """
    if (indicator_value := indicator.get('value')) and indicator.get('indicator_type') == 'URL':
        indicator['value'] = url_handler(indicator_value, request_args.url_protocol_stripping,
                                         request_args.url_port_stripping, request_args.url_truncate)
    filtered_json = {}
    if list_fields:
        for field in list_fields:
            value = indicator.get(field) or indicator.get('CustomFields', {}).get(field)
            filtered_json[field] = value
        indicator = filtered_json
    if not_first_call:
        return ', ' + json.dumps(indicator)
    return '[' + json.dumps(indicator)


def create_mwg_out_format(indicator: dict, request_args: RequestArguments, headers_was_writen: bool) -> str:
    """format the indicator to mwg format.

    Args:
        indicator (dict): the indicator info
        request_args (RequestArguments): Request Arguments
        headers_was_writen (bool): Whether if the headers was writen to the file.

    Returns:
        An indicator to add to the file in mwg format.
    """
    if (indicator_value := indicator.get('value')) and indicator.get('indicator_type') == 'URL':
        indicator['value'] = url_handler(indicator_value, request_args.url_protocol_stripping,
                                         request_args.url_port_stripping, request_args.url_truncate)

    value = "\"" + indicator.get('value', '') + "\""
    sources = indicator.get('sourceBrands')
    if sources:
        sources_string = "\"" + ','.join(sources) + "\""
    else:
        sources_string = "\"from CORTEX XSOAR\""

    if not headers_was_writen:
        mwg_type = request_args.mwg_type
        if isinstance(mwg_type, list):
            mwg_type = mwg_type[0]
        return "type=" + mwg_type + "\n" + value + " " + sources_string
    return '\n' + value + " " + sources_string


def create_proxysg_all_category_out_format(indicators_file: IO, files_by_category: dict):
    """write all indicators to file in proxysg format.

    Args:
        indicators_file (IO): the fields to return.
        files_by_category (dict): all indicators by category

    Returns:
        a file in proxysg format.
    """
    # the first time "define category" will be writen without a new line
    new_line = ''
    for category, category_file in files_by_category.items():
        indicators_file.write(f"{new_line}define category {category}\n")
        new_line = '\n'
        category_file.seek(0)
        indicators_file.write(category_file.read())
        category_file.close()
        indicators_file.write("end")

    return indicators_file


def create_proxysg_out_format(indicator: dict, files_by_category: dict, request_args: RequestArguments) -> dict:
    """format the indicator to proxysg.

    Args:
        indicator (dict): the indicator info
        files_by_category (list): a dict of the formatted indicators by category.
        request_args (RequestArguments): Request Arguments

    Returns:
        a dict of the formatted indicators by category.
    """
    if (indicator_value := indicator.get('value')) and indicator.get('indicator_type') in ['URL', 'Domain', 'DomainGlob']:
        stripped_indicator = url_handler(indicator_value, True, request_args.url_port_stripping,
                                         request_args.url_truncate)
        indicator_proxysg_category = indicator.get('CustomFields', {}).get('proxysgcategory')
        # if a ProxySG Category is set and it is in the category_attribute list or that the attribute list is empty
        # than list add the indicator to it's category list
        if indicator_proxysg_category is not None and \
                (indicator_proxysg_category in request_args.category_attribute or len(request_args.category_attribute) == 0):
            proxysg_category = indicator_proxysg_category
        else:
            # if ProxySG Category is not set or does not exist in the category_attribute list
            proxysg_category = request_args.category_default

        files_by_category = add_indicator_to_category(stripped_indicator, proxysg_category, files_by_category)
    return files_by_category


def add_indicator_to_category(indicator: str, category: str, files_by_category: Dict):
    if category in files_by_category.keys():
        files_by_category[category].write(indicator + '\n')

    else:
        files_by_category[category] = tempfile.TemporaryFile(mode='w+t')
        files_by_category[category].write(indicator + '\n')

    return files_by_category


def create_csv_out_format(headers_was_writen: bool, list_fields: List, ioc, request_args: RequestArguments):
    """format the ioc to csv format.

    Args:
        headers_was_writen (bool): Whether if the headers was writen to the file.
        list_fields (list): the fields to return.
        ioc (dict): the indicator info
        request_args (RequestArguments): all the request arguments.

    Returns:
        a one indicator to add to the file in csv format.
    """

    if (indicator_value := ioc.get('value')) and ioc.get('indicator_type') == 'URL':
        ioc['value'] = url_handler(indicator_value, request_args.url_protocol_stripping,
                                   request_args.url_port_stripping, request_args.url_truncate)
    if not list_fields:
        values = list(ioc.values())
        if not headers_was_writen:
            headers = list(ioc.keys())
            headers_str = list_to_str(headers) + "\n"
            return headers_str + list_to_str(values, map_func=lambda val: f'"{val}"')
        return "\n" + list_to_str(values, map_func=lambda val: f'"{val}"')
    else:
        fields_value_list = []
        for field in list_fields:
            value = ioc.get(field) or ioc.get('CustomFields', {}).get(field)
            fields_value_list.append(value)
        if not headers_was_writen:
            headers_str = request_args.fields_to_present + '\n'
            return headers_str + list_to_str(fields_value_list, map_func=lambda val: f'"{val}"')
        return "\n" + list_to_str(fields_value_list, map_func=lambda val: f'"{val}"')


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


def list_to_str(inp_list: list, delimiter: str = ',', map_func: Callable = str) -> str:
    """
    Transforms a list to an str, with a custom delimiter between each list item
    """
    str_res = ""
    if inp_list:
        if isinstance(inp_list, list):
            str_res = delimiter.join(map(map_func, inp_list))
        else:
            raise AttributeError(f'Invalid inp_list provided to list_to_str: \n{inp_list}')
    return str_res


def create_text_out_format(iocs: IO, request_args: RequestArguments) -> Union[IO, IO[str]]:
    """
    Create a list in new file of formatted_indicators
     * IP / CIDR:
         1) if collapse_ips, collapse IPs/CIDRs
     * URL:
        1) if drop_invalids, drop invalids (length > 254 or has invalid chars)
        2) if port_stripping, strip ports
        3) if protocol_stripping, strip protocols
        4) if url_truncate, truncate urls
    * Other indicator types:
        1) if drop_invalids, drop invalids (has invalid chars)
        2) if port_stripping, strip ports
    """
    ipv4_formatted_indicators = set()
    ipv6_formatted_indicators = set()
    iocs.seek(0)
    formatted_indicators = tempfile.TemporaryFile(mode='w+t')
    new_line = ''  # For the first time he will not add a new line
    for str_ioc in iocs:
        ioc = json.loads(str_ioc.rstrip())
        indicator = ioc.get('value')
        if not indicator:
            continue
        ioc_type = ioc.get('indicator_type')

        if ioc_type not in [FeedIndicatorType.IP, FeedIndicatorType.IPv6,
                            FeedIndicatorType.CIDR, FeedIndicatorType.IPv6CIDR]:

            indicator = url_handler(indicator, request_args.url_protocol_stripping,
                                    request_args.url_port_stripping, request_args.url_truncate)

            if request_args.drop_invalids:
                if indicator != _PORT_REMOVAL.sub(_URL_WITHOUT_PORT, indicator) or\
                        indicator != _INVALID_TOKEN_REMOVAL.sub('*', indicator):
                    # check if the indicator held invalid tokens or port
                    continue

                if ioc_type == FeedIndicatorType.URL and len(indicator) >= PAN_OS_MAX_URL_LEN:
                    # URL indicator exceeds allowed length - ignore the indicator
                    continue

            # for PAN-OS *.domain.com does not match domain.com
            # we should provide both
            # this could generate more than num entries according to PAGE_SIZE
            if indicator.startswith('*.'):
                formatted_indicators.write(new_line + str(indicator.lstrip('*.')))
                new_line = '\n'

        if request_args.collapse_ips != DONT_COLLAPSE and ioc_type in (FeedIndicatorType.IP, FeedIndicatorType.CIDR):
            ipv4_formatted_indicators.add(indicator)

        elif request_args.collapse_ips != DONT_COLLAPSE and ioc_type == FeedIndicatorType.IPv6:
            ipv6_formatted_indicators.add(indicator)

        else:
            formatted_indicators.write(new_line + str(indicator))
            new_line = '\n'
    iocs.close()

    if len(ipv4_formatted_indicators) > 0:
        ipv4_formatted_indicators = ips_to_ranges(ipv4_formatted_indicators, request_args.collapse_ips)
        for ip in ipv4_formatted_indicators:
            formatted_indicators.write(new_line + str(ip))
            new_line = '\n'

    if len(ipv6_formatted_indicators) > 0:
        ipv6_formatted_indicators = ips_to_ranges(ipv6_formatted_indicators, request_args.collapse_ips)
        for ip in ipv6_formatted_indicators:
            formatted_indicators.write(new_line + str(ip))
            new_line = '\n'

    return formatted_indicators


def url_handler(indicator: str, url_protocol_stripping: bool, url_port_stripping: bool, url_truncate: bool) -> str:
    """
     * URL:
        1) if port_stripping, strip ports
        2) if protocol_stripping, strip protocols
        3) if url_truncate, truncate urls
    """

    # protocol stripping
    if url_protocol_stripping:
        indicator = _PROTOCOL_REMOVAL.sub('', indicator)

    if url_port_stripping:
        # remove port from indicator - from demisto.com:369/rest/of/path -> demisto.com/rest/of/path
        indicator = _PORT_REMOVAL.sub(_URL_WITHOUT_PORT, indicator)

    if url_truncate and len(indicator) >= PAN_OS_MAX_URL_LEN:
        indicator = indicator[0:PAN_OS_MAX_URL_LEN - 1]

    return indicator


def get_outbound_mimetype(request_args: RequestArguments) -> str:
    """Returns the mimetype of the export_iocs"""
    if request_args.out_format == FORMAT_JSON:
        return MIMETYPE_JSON

    elif request_args.out_format == FORMAT_CSV and not request_args.csv_text:
        return MIMETYPE_CSV

    else:
        return MIMETYPE_TEXT


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
    if len(edl) == 0 and request_args.add_comment_if_empty or edl == ']' and request_args.add_comment_if_empty:
        edl = '# Empty List'
    # if the case there are strings to add to the EDL, add them if the output type is text
    elif request_args.out_format == FORMAT_TEXT:
        append_str = params.get("append_string")
        prepend_str = params.get("prepend_string")
        if append_str:
            append_str = append_str.replace("\\n", "\n")
            edl = f"{edl}{append_str}"
        if prepend_str:
            prepend_str = prepend_str.replace("\\n", "\n")
            edl = f"{prepend_str}\n{edl}"
    mimetype = get_outbound_mimetype(request_args)
    max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]
    demisto.debug(f'Returning edl of size: [{edl_size}], created: [{created}], query time seconds: [{query_time}],'
                  f' max age: [{max_age}], etag: [{etag}]')
    resp = Response(edl, status=200, mimetype=mimetype, headers=[
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
    out_format = request_args.get('v', params.get('format', FORMAT_TEXT))
    query = request_args.get('q', params.get('indicators_query') or '')
    mwg_type = request_args.get('t', params.get('mwg_type', "string"))
    strip_port = request_args.get('sp', params.get('url_port_stripping') or False)
    strip_protocol = request_args.get('pr', params.get('url_protocol_stripping') or False)
    drop_invalids = request_args.get('di', params.get('drop_invalids') or False)
    category_default = request_args.get('cd', params.get('category_default', 'bc_category'))
    category_attribute = request_args.get('ca', params.get('category_attribute', ''))
    collapse_ips = request_args.get('tr', params.get('collapse_ips', DONT_COLLAPSE))
    csv_text = request_args.get('tx', params.get('csv_text', False))
    add_comment_if_empty = request_args.get('ce', params.get('add_comment_if_empty', True))
    fields_to_present = request_args.get('fi', params.get('fields_filter', ''))
    url_truncate = request_args.get('ut', params.get('url_truncate', ''))

    # handle flags
    if drop_invalids == '':
        drop_invalids = True

    if strip_port == '':
        strip_port = True

    if strip_protocol == '':
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
    if out_format not in [FORMAT_PROXYSG, FORMAT_TEXT, FORMAT_JSON, FORMAT_CSV, FORMAT_MWG, FORMAT_ARG_BLUECOAT,
                          FORMAT_ARG_MWG, FORMAT_ARG_PROXYSG]:
        raise DemistoException(EDL_FORMAT_ERR_MSG)

    elif out_format in [FORMAT_ARG_PROXYSG, FORMAT_ARG_BLUECOAT]:
        out_format = FORMAT_PROXYSG

    elif out_format == FORMAT_ARG_MWG:
        out_format = FORMAT_MWG

    if out_format == FORMAT_MWG:
        if mwg_type not in MWG_TYPE_OPTIONS:
            raise DemistoException(EDL_MWG_TYPE_ERR_MSG)

    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        fields_to_present = 'use_legacy_query'

    return RequestArguments(query,
                            out_format,
                            limit,
                            offset,
                            strip_port,
                            drop_invalids,
                            collapse_ips,
                            add_comment_if_empty,
                            mwg_type,
                            category_default,
                            category_attribute,
                            fields_to_present,
                            csv_text,
                            strip_protocol,
                            url_truncate
                            )


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
    strip_protocol = get_bool_arg_or_param(args, params, 'url_protocol_stripping')
    drop_invalids = get_bool_arg_or_param(args, params, 'drop_invalids')
    add_comment_if_empty = get_bool_arg_or_param(args, params, 'add_comment_if_empty')
    offset = try_parse_integer(args.get('offset', 0), EDL_OFFSET_ERR_MSG)
    mwg_type = args.get('mwg_type', "string")
    category_default = args.get('category_default', 'bc_category')
    category_attribute = args.get('category_attribute', '')
    fields_to_present = args.get('fields_filter', '')
    out_format = args.get('format', FORMAT_TEXT)
    csv_text = get_bool_arg_or_param(args, params, 'csv_text') == 'True'
    url_truncate = get_bool_arg_or_param(args, params, 'url_truncate')

    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        fields_to_present = 'use_legacy_query'

    request_args = RequestArguments(query,
                                    out_format,
                                    limit,
                                    offset,
                                    url_port_stripping,
                                    drop_invalids,
                                    collapse_ips,
                                    add_comment_if_empty,
                                    mwg_type,
                                    category_default,
                                    category_attribute,
                                    fields_to_present,
                                    csv_text,
                                    strip_protocol,
                                    url_truncate)

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
    url_protocol_stripping = params.get('url_protocol_stripping', False)
    drop_invalids = params.get('drop_invalids', False)
    add_comment_if_empty = params.get('add_comment_if_empty', True)
    mwg_type = params.get('mwg_type', "string")
    category_default = params.get('category_default', 'bc_category')
    category_attribute = params.get('category_attribute', '')
    fields_to_present = params.get('fields_filter', '')
    out_format = params.get('format', FORMAT_TEXT)
    csv_text = argToBoolean(params.get('csv_text', False))
    url_truncate = params.get('url_truncate', False)

    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        fields_to_present = 'use_legacy_query'
    offset = 0
    request_args = RequestArguments(query,
                                    out_format,
                                    limit,
                                    offset,
                                    url_port_stripping,
                                    drop_invalids,
                                    collapse_ips,
                                    add_comment_if_empty,
                                    mwg_type,
                                    category_default,
                                    category_attribute,
                                    fields_to_present,
                                    csv_text,
                                    url_protocol_stripping,
                                    url_truncate)

    EDL_ON_DEMAND_CACHE_PATH = demisto.uniqueFile()
    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)


def main():
    """
    Main
    """
    global PAGE_SIZE
    params = demisto.params()
    try:
        PAGE_SIZE = max(1, int(params.get('page_size') or PAGE_SIZE))
    except ValueError:
        demisto.debug(f'Non integer "page_size" provided: {params.get("page_size")}. defaulting to {PAGE_SIZE}')
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
        'export-indicators-list-update': update_edl_command,
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

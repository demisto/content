import os
from datetime import datetime
from pathlib import Path


import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import tempfile
import re
from base64 import b64decode
from flask import Flask, Response, request, send_file
from netaddr import IPSet, IPNetwork
from typing import IO
from collections.abc import Iterable, Callable
from math import ceil
from enum import Enum
import tldextract
import urllib3
import hashlib
import ipaddress
import zipfile
import glob

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'Generic Export Indicators service'
PAGE_SIZE: int = 2000
PAN_OS_MAX_URL_LEN = 255
APP: Flask = Flask('demisto-edl')
EDL_LIMIT_ERR_MSG: str = 'Please provide a valid integer for List Size'
EDL_CIDR_SIZR_MSG: str = 'Please provide a valid integer for CIDR size'
EDL_OFFSET_ERR_MSG: str = 'Please provide a valid integer for Starting Index'
EDL_COLLAPSE_ERR_MSG: str = 'The Collapse parameter can only get the following: 0 - none, ' \
                            '1 - range, 2 - CIDR'
EDL_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'
EDL_FORMAT_ERR_MSG: str = 'Please provide a valid format from: text, json, csv, mgw and proxysg'
EDL_MWG_TYPE_ERR_MSG: str = 'The McAFee Web Gateway type can only be one of the following: string,' \
                            ' applcontrol, dimension, category, ip, mediatype, number, regex'
EDL_NO_URLS_IN_PROXYSG_FORMAT = 'ProxySG format only outputs URLs - no URLs found in the current query'
MAX_LIST_SIZE_WITH_URL_QUERY = 100000

EDL_ON_DEMAND_KEY: str = 'UpdateEDL'
EDL_ON_DEMAND_CACHE_PATH: str = ''
EDL_FULL_LOG_PATH: str = f'full_log_{demisto.uniqueFile()}'
EDL_FULL_LOG_PATH_WIP: str = f'wip_log_{demisto.uniqueFile()}'
LOGS_ZIP_FILE_PREFIX: str = 'log_download'
EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE: int = 0
EDL_SEARCH_LOOP_LIMIT: int = 10
MAX_DISPLAY_LOG_FILE_SIZE = 100000
LARGE_LOG_DISPLAY_MSG = '# Log exceeds max size. Refresh to download as file.'

''' REFORMATTING REGEXES '''
_PROTOCOL_REMOVAL = re.compile('^(?:[a-z]+:)*//')
_PORT_REMOVAL = re.compile(r'^((?:[a-z]+:)*//([a-z0-9\-\.]+)|([a-z0-9\-\.]+))(?:\:[0-9]+)*')
_URL_WITHOUT_PORT = r'\g<1>'
_INVALID_TOKEN_REMOVAL = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')
_BROAD_PATTERN = re.compile(r'^(?:\*\.)+[a-zA-Z]+(?::[0-9]+)?$')

DONT_COLLAPSE = "Don't Collapse"
COLLAPSE_TO_CIDR = "To CIDRS"
COLLAPSE_TO_RANGES = "To Ranges"

MAXIMUM_CIDR_SIZE_DEFAULT = 8

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


class IndicatorAction(Enum):
    ADDED = 'Added'
    MODIFIED = 'Modified'
    DROPPED = 'Dropped'


'''Request Arguments Class'''


def debug_function(func):
    def wrapper(*args, **kwargs):
        demisto.debug(f"edl: Entering function {func.__name__}")
        results = func(*args, **kwargs)
        demisto.debug(f"edl: Exiting function {func.__name__}")
        return results

    return wrapper


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
    CTX_MAXIMUM_CIDR = 'maximum_cidr_size'
    CTX_NO_TLD = 'no_wildcard_tld'

    FILTER_FIELDS_ON_FORMAT_TEXT = "name,type"
    FILTER_FIELDS_ON_FORMAT_MWG = "name,type,sourceBrands"
    FILTER_FIELDS_ON_FORMAT_PROXYSG = "name,type,proxysgcategory"
    FILTER_FIELDS_ON_FORMAT_CSV = "name,type"
    FILTER_FIELDS_ON_FORMAT_JSON = "name,type"

    def __init__(self,
                 query: str = '',
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
                 url_truncate: bool = False,
                 maximum_cidr_size: int = MAXIMUM_CIDR_SIZE_DEFAULT,
                 no_wildcard_tld: bool = False,
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
        self.maximum_cidr_size = maximum_cidr_size
        self.no_wildcard_tld = no_wildcard_tld

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
            self.CTX_URL_TRUNCATE_KEY: self.url_truncate,
            self.CTX_MAXIMUM_CIDR: self.maximum_cidr_size,
            self.CTX_NO_TLD: self.no_wildcard_tld,

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
                url_truncate=ctx_dict.get(cls.CTX_URL_TRUNCATE_KEY),
                maximum_cidr_size=ctx_dict.get(cls.CTX_MAXIMUM_CIDR),
                no_wildcard_tld=ctx_dict.get(cls.CTX_NO_TLD),
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


@debug_function
def log_iocs_file_data(formatted_indicators: str, max_length: int = 100) -> None:
    """Prints a debug log of the first `max_length` characters in the formatted indicators data.

    Args:
        formatted_indicators (str): The IOCs formatted data.
        max_length (int, optional): max # of chars to print. Defaults to 100.
    """
    if formatted_indicators:
        truncated_data = formatted_indicators[:max_length]
        demisto.debug(f"Formatted IOC data (first {max_length} characters):\n{truncated_data}")
    else:
        demisto.debug("No data from IOC search.")


@debug_function
def create_new_edl(request_args: RequestArguments) -> tuple[str, int, dict]:
    """
    Get indicators from the server using IndicatorsSearcher and format them.

    Parameters:
        request_args: Request arguments

    Returns:
        tuple[str, int]: A tuple of formatted indicators to display in EDL's response (str),
            and the number of original indicators received from the server before formatting (int).
    """
    limit = request_args.offset + request_args.limit
    offset = request_args.offset
    indicator_searcher = IndicatorsSearcher(
        filter_fields=request_args.fields_to_present,
        query=request_args.query,
        size=PAGE_SIZE,
        limit=limit
    )
    demisto.debug(f"Creating a new EDL file in {request_args.out_format} format")
    formatted_indicators = ''
    new_log_stats = {}
    if request_args.out_format == FORMAT_TEXT:
        if request_args.drop_invalids or request_args.collapse_ips != "Don't Collapse":
            # Because there may be illegal indicators or they may turn into cider, the limit is increased
            indicator_searcher.limit = int(limit * INCREASE_LIMIT)
        new_iocs_file, original_indicators_count = get_indicators_to_format(indicator_searcher, request_args)
        # we collect first all indicators because we need all ips to collapse_ips
        new_iocs_file, new_log_stats = create_text_out_format(new_iocs_file, request_args)
        new_iocs_file.seek(0)
        iocs_set = set()
        for count, line in enumerate(new_iocs_file):
            # continue searching iocs if 1) iocs was truncated or 2) got all available iocs
            if count + 1 > limit:
                break
            if count < offset:
                continue
            elif line not in iocs_set:
                iocs_set.add(line)
                formatted_indicators += line

    else:
        new_iocs_file, original_indicators_count = get_indicators_to_format(indicator_searcher, request_args)
        new_iocs_file.seek(0)
        formatted_indicators = new_iocs_file.read()
    new_iocs_file.close()
    log_iocs_file_data(formatted_indicators)
    return formatted_indicators, original_indicators_count, new_log_stats


@debug_function
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


@debug_function
def get_indicators_to_format(indicator_searcher: IndicatorsSearcher,
                             request_args: RequestArguments) -> tuple[IO | IO[str], int]:
    """
    Finds indicators using demisto.searchIndicators, and returns the indicators in file written in the requested format
    Parameters:
        indicator_searcher (IndicatorsSearcher): The indicator searcher used to look for indicators
        request_args (RequestArguments):  all the request arguments.
    Returns:
        tuple[IO | IO[str], int]: A tuple of indicators in the requested format (IO | IO[str]),
            and the total number of indicators found by indicator_searcher (int).
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
                demisto.debug(f"Parsing the following indicator: {ioc.get('value')}")

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
        demisto.error(f'Error in parsing the indicators, error: {str(e)}')
        # 429 error can only be raised when the Elasticsearch instance encountered an error
        if '[429] Failed with error' in str(e):
            version = demisto.demistoVersion()
            # NG + XSIAM can recover from a shutdown
            if version.get('platform') == 'x2' or is_demisto_version_ge('8'):
                raise SystemExit('Encountered issue in Elastic Search query. Restarting container and trying again.')

    demisto.debug(f"Completed IOC search & format, found {ioc_counter} IOCs.")
    if request_args.out_format == FORMAT_JSON:
        f.write(']')
    elif request_args.out_format == FORMAT_PROXYSG:
        f = create_proxysg_all_category_out_format(f, files_by_category)
    return f, ioc_counter


@debug_function
def create_json_out_format(list_fields: List, indicator: dict, request_args: RequestArguments, not_first_call=True) -> str:
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


@debug_function
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


@debug_function
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


@debug_function
def create_proxysg_out_format(indicator: dict, files_by_category: dict, request_args: RequestArguments) -> dict:
    """format the indicator to proxysg.

    Args:
        indicator (dict): the indicator info
        files_by_category (list): a dict of the formatted indicators by category.
        request_args (RequestArguments): Request Arguments

    Returns:
        a dict of the formatted indicators by category.
    """
    if (indicator_value := indicator.get('value')) and indicator.get('indicator_type') in ['IP', 'URL', 'Domain', 'DomainGlob']:
        stripped_indicator = url_handler(indicator_value, request_args.url_protocol_stripping,
                                         request_args.url_port_stripping, request_args.url_truncate)
        indicator_proxysg_category = indicator.get('CustomFields', {}).get('proxysgcategory')
        # if a ProxySG Category is set and it is in the category_attribute list or that the attribute list is empty
        # than list add the indicator to it's category list
        if indicator_proxysg_category is not None and \
                (indicator_proxysg_category in request_args.category_attribute or len(request_args.category_attribute) == 0):
            # handle indicators in multiple categories
            if isinstance(indicator_proxysg_category, list):
                for category in indicator_proxysg_category:
                    files_by_category = add_indicator_to_category(stripped_indicator, category, files_by_category)
            else:
                files_by_category = add_indicator_to_category(stripped_indicator, indicator_proxysg_category, files_by_category)
        else:
            # if ProxySG Category is not set or does not exist in the category_attribute list
            files_by_category = add_indicator_to_category(stripped_indicator, request_args.category_default, files_by_category)

    return files_by_category


@debug_function
def add_indicator_to_category(indicator: str, category: str, files_by_category: dict):
    if category in files_by_category:
        files_by_category[category].write(indicator + '\n')

    else:
        files_by_category[category] = tempfile.TemporaryFile(mode='w+t')
        files_by_category[category].write(indicator + '\n')

    return files_by_category


@debug_function
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


@debug_function
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


@debug_function
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


@debug_function
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


def is_large_cidr(cidr: str, prefix_threshold: int):
    try:
        return IPNetwork(cidr).prefixlen <= prefix_threshold
    except Exception as e:
        demisto.debug(str(e))
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


@debug_function
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


def log_indicator_line(raw_indicator: str, indicator: str, action: str, reason: str, log_stats: dict) -> dict:
    """Create and store a log line for the indicator.

    Args:
        raw_indicator (str): The raw indicator before modification.
        indicator (str): The indicator after modification.
        action (str): The action preformed, Added / Dropped / Modified.
        reason (str): The reason for the action.
        log_stats (dict): Stats of previous log entries.

    Returns:
        (dict) Updated log stats
    """
    log_line = f"\n{action} | {indicator} | {raw_indicator} | {reason}"
    append_log_edl_data(log_line)
    log_stats[action] = log_stats.get(action, 0) + 1

    return log_stats


def store_log_data(request_args: RequestArguments, created: datetime, log_stats: dict) -> None:
    """Add the header to the log string.

    Args:
        request_args (RequestArguments): The request args, they will be added to the header.
        created (datetime): The time the log was created. This will be added to the header.
        log_stats (dict): A statistics dict for the indicator modifications (e.g. {'Added': 5, 'Dropped': 3, 'Modified': 2}
    """
    log_file_wip = Path(EDL_FULL_LOG_PATH_WIP)
    if log_file_wip.exists():
        added_count = log_stats.get(IndicatorAction.ADDED.value, 0)
        dropped_count = log_stats.get(IndicatorAction.DROPPED.value, 0)
        modified_count = log_stats.get(IndicatorAction.MODIFIED.value, 0)

        total_count = added_count + dropped_count + modified_count

        header = f"# Created new EDL at {created.isoformat()}\n\n" \
            f"## Configuration Arguments: {request_args.to_context_json()}\n\n" \
            f"## EDL stats: {total_count} indicators in total, {modified_count} modified, {dropped_count} dropped, " \
            f"{added_count} added.\n" \
            f"\nAction | Indicator | Raw Indicator | Reason"

        with open(EDL_FULL_LOG_PATH, 'w+') as new_full_log_file, log_file_wip.open('r') as log_file_data:
            # Finalize the current log: write the headers and the WIP log to full_log_path
            new_full_log_file.write(header)
            for log_line in log_file_data:
                new_full_log_file.write(log_line)

        with open(EDL_FULL_LOG_PATH_WIP, 'w+') as log_file_data:
            # Empty WIP log file after finalization.
            log_file_data.seek(0)


@debug_function
def create_text_out_format(iocs: IO, request_args: RequestArguments) -> tuple[Union[IO, IO[str]], dict]:
    """
    Create a list in new file of formatted_indicators, and log the modifications.
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
    enforce_ascii = argToBoolean(demisto.params().get('enforce_ascii', False))
    ipv4_formatted_indicators = set()
    ipv6_formatted_indicators = set()
    iocs.seek(0)
    formatted_indicators = tempfile.TemporaryFile(mode='w+t')
    log_stats: dict = {}
    new_line = ''  # For the first time he will not add a new line
    for str_ioc in iocs:
        ioc = json.loads(str_ioc.rstrip())
        indicator_raw = ioc.get('value')
        if not indicator_raw:
            continue
        if enforce_ascii:
            try:
                indicator_raw.encode('ascii')
            except UnicodeEncodeError:
                continue
        ioc_type = ioc.get('indicator_type')

        indicator = indicator_raw

        if ioc_type not in [FeedIndicatorType.IP, FeedIndicatorType.IPv6,
                            FeedIndicatorType.CIDR, FeedIndicatorType.IPv6CIDR]:

            indicator = url_handler(indicator_raw, request_args.url_protocol_stripping,
                                    request_args.url_port_stripping, request_args.url_truncate)

            if request_args.drop_invalids:
                if indicator != _PORT_REMOVAL.sub(_URL_WITHOUT_PORT, indicator) or \
                        indicator != _INVALID_TOKEN_REMOVAL.sub('*', indicator):
                    # check if the indicator held invalid tokens or port
                    log_stats = log_indicator_line(raw_indicator=indicator_raw,
                                                   indicator=indicator,
                                                   action=IndicatorAction.DROPPED.value,
                                                   reason='Invalid tokens or port.',
                                                   log_stats=log_stats)
                    continue

                if ioc_type == FeedIndicatorType.URL and len(indicator) >= PAN_OS_MAX_URL_LEN:
                    # URL indicator exceeds allowed length - ignore the indicator
                    log_stats = log_indicator_line(raw_indicator=indicator_raw,
                                                   indicator=indicator,
                                                   action=IndicatorAction.DROPPED.value,
                                                   reason=f'URL exceeds max length {PAN_OS_MAX_URL_LEN}.',
                                                   log_stats=log_stats)

                    continue

            # for PAN-OS *.domain.com does not match domain.com
            # we should provide both
            # this could generate more than num entries according to PAGE_SIZE
            if indicator.startswith('*.'):
                domain = str(indicator.lstrip('*.'))
                # if we should ignore TLDs and the domain is a TLD
                if request_args.no_wildcard_tld and tldextract.extract(domain).suffix == domain:
                    log_stats = log_indicator_line(raw_indicator=indicator_raw,
                                                   indicator=domain,
                                                   action=IndicatorAction.DROPPED.value,
                                                   reason='Domain is a TLD.',
                                                   log_stats=log_stats)
                    continue
                formatted_indicators.write(new_line + domain)
                new_line = '\n'

        if ioc_type in [FeedIndicatorType.CIDR, FeedIndicatorType.IPv6CIDR] and is_large_cidr(indicator, request_args.maximum_cidr_size):
            log_stats = log_indicator_line(raw_indicator=indicator_raw,
                                           indicator=indicator,
                                           action=IndicatorAction.DROPPED.value,
                                           reason=f'CIDR exceeds max length {request_args.maximum_cidr_size}.',
                                           log_stats=log_stats)
            continue

        if request_args.collapse_ips != DONT_COLLAPSE and ioc_type in (FeedIndicatorType.IP, FeedIndicatorType.CIDR):
            ipv4_formatted_indicators.add(indicator)

        elif request_args.collapse_ips != DONT_COLLAPSE and ioc_type == FeedIndicatorType.IPv6:
            ipv6_formatted_indicators.add(indicator)

        else:
            formatted_indicators.write(new_line + str(indicator))
            new_line = '\n'
            log_stats = log_indicator_line(raw_indicator=indicator_raw,
                                           indicator=indicator,
                                           action=IndicatorAction.ADDED.value,
                                           reason=f'Found new {ioc_type}.',
                                           log_stats=log_stats)

    iocs.close()
    if len(ipv4_formatted_indicators) > 0:
        ipv4_formatted_indicators_collapsed = ips_to_ranges(ipv4_formatted_indicators, request_args.collapse_ips)
        for ip in ipv4_formatted_indicators_collapsed:
            formatted_indicators.write(new_line + str(ip))
            new_line = '\n'

        for ip in ipv4_formatted_indicators:
            if ip not in ipv4_formatted_indicators_collapsed:
                log_stats = log_indicator_line(raw_indicator=ip,
                                               indicator=ip,
                                               action=IndicatorAction.MODIFIED.value,
                                               reason=f'Collapsed IPv4 {request_args.collapse_ips}.',
                                               log_stats=log_stats)

            else:
                log_stats = log_indicator_line(raw_indicator=ip,
                                               indicator=ip,
                                               action=IndicatorAction.ADDED.value,
                                               reason='Found new IPv4.',
                                               log_stats=log_stats)

    if len(ipv6_formatted_indicators) > 0:
        ipv6_formatted_indicators_collapsed = ips_to_ranges(ipv6_formatted_indicators, request_args.collapse_ips)
        for ip in ipv6_formatted_indicators_collapsed:
            formatted_indicators.write(new_line + str(ip))
            new_line = '\n'

        for ip in ipv6_formatted_indicators:
            if ip not in ipv6_formatted_indicators_collapsed:
                log_stats = log_indicator_line(raw_indicator=ip,
                                               indicator=ip,
                                               action=IndicatorAction.MODIFIED.value,
                                               reason=f'Collapsed IPv6 {request_args.collapse_ips}.',
                                               log_stats=log_stats)

            else:
                log_stats = log_indicator_line(raw_indicator=ip,
                                               indicator=ip,
                                               action=IndicatorAction.ADDED.value,
                                               reason='Found new IPv6.',
                                               log_stats=log_stats)

    return formatted_indicators, log_stats


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


def append_log_edl_data(log_edl_data: str) -> None:
    """Store the generated log string in the log file.

    Args:
        log_edl_data (str): The generated log data string.
    """
    try:
        with open(EDL_FULL_LOG_PATH_WIP, 'a') as last_full_log_file:
            last_full_log_file.write(log_edl_data)

    except Exception as e:
        demisto.debug(f"edl: Error in writing to log file: {str(e)}")
        raise e


@debug_function
def get_edl_on_demand() -> tuple[str, int]:
    """
    Use the local file system to store the on-demand result, using a lock to
    limit access to the file from multiple threads.

    Returns:
        tuple[str, int]: A tuple of formatted indicators to display in EDL's response (str),
            and the number of original indicators received from the server before formatting (int).
    """
    global EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE
    ctx = get_integration_context()

    if EDL_ON_DEMAND_KEY in ctx:
        ctx.pop(EDL_ON_DEMAND_KEY, None)
        request_args = RequestArguments.from_context_json(ctx)
        edl_data, EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE, edl_data_stats = create_new_edl(request_args)
        created_time = datetime.now(timezone.utc)
        store_log_data(request_args, created_time, edl_data_stats)

        try:
            demisto.debug("edl: Writing EDL data to cache")

            with open(EDL_ON_DEMAND_CACHE_PATH, 'w') as file:
                file.write(edl_data)

        except Exception as e:
            demisto.debug(f"edl: Error in writing to file: {str(e)}")
            raise e

        demisto.debug("edl: Finished writing EDL data to cache")
        set_integration_context(ctx)

    else:
        demisto.debug("edl: Reading EDL data from cache")

        try:
            with open(EDL_ON_DEMAND_CACHE_PATH) as file:
                edl_data = file.read()

        except Exception as e:
            demisto.debug(f"edl: Error reading cache file: {str(e)}")
            raise e

    demisto.debug("edl: Finished reading EDL data from cache")

    return edl_data, EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE


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


def authenticate_app(params: dict, request_headers: Any) -> Optional[Response]:
    """Make sure the user is authenticated on API request.

    Args:
        params (dict): The demisto params, where the credentials are stored.
        request_headers: The request headers.

    Returns:
        (Response) '401 Login Required' on failure to authenticate.
        None on success.
    """
    credentials = params.get('credentials', {})
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')

    if username and password:
        headers: dict = cast(dict[Any, Any], request_headers)
        if not validate_basic_authentication(headers, username, password):
            err_msg: str = 'Basic authentication failed. Make sure you are using the right credentials.'
            demisto.debug(err_msg)
            return Response(err_msg, status=401, mimetype='text/plain', headers=[
                ('WWW-Authenticate', 'Basic realm="Login Required"'),
            ])

    return None


def get_edl_log_file() -> str:
    """Check if edl log file exists, if it does return its contents (str)."""
    edl_data_log = ''
    if os.path.exists(EDL_FULL_LOG_PATH):
        demisto.debug("found log file")
        if os.path.getsize(EDL_FULL_LOG_PATH) > MAX_DISPLAY_LOG_FILE_SIZE:
            return LARGE_LOG_DISPLAY_MSG

        with open(EDL_FULL_LOG_PATH) as log_file:
            log_file.seek(0)
            edl_data_log = log_file.read()
            log_file.seek(0)

    return edl_data_log


def prepare_response_data(data: str, prepend_str: str, append_str: str) -> str:
    """Prepare data for app response.

    Args:
        data (str): The raw data.
        prepend_str (str): The string to prepend to the data.
        append_str (str): The string to append to the data.

    Returns:
        (str) The prepared data.
    """
    if append_str:
        append_str = append_str.replace("\\n", "\n")
        data = f"{data}{append_str}"
    if prepend_str:
        prepend_str = prepend_str.replace("\\n", "\n")
        data = f"{prepend_str}\n{data}"

    return data


@APP.route('/', methods=['GET'])
def route_edl() -> Response:
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()
    cache_refresh_rate: str = params.get('cache_refresh_rate')
    auth_resp = authenticate_app(params, request.headers)
    if auth_resp:
        return auth_resp

    request_args = get_request_args(request.args, params)
    on_demand = params.get('on_demand')
    created = datetime.now(timezone.utc)
    if on_demand:
        edl_data, original_indicators_count = get_edl_on_demand()
    else:
        edl_data, original_indicators_count, edl_data_stats = create_new_edl(request_args)
        store_log_data(request_args, created, edl_data_stats)

    query_time = (datetime.now(timezone.utc) - created).total_seconds()
    etag = f'"{hashlib.sha1(edl_data.encode()).hexdigest()}"'  # nosec
    edl_size = 0

    if edl_data.strip():
        edl_size = edl_data.count('\n') + 1  # add 1 as last line doesn't have a \n

    if len(edl_data) == 0 and request_args.add_comment_if_empty or \
            edl_data == ']' and request_args.add_comment_if_empty:
        edl_data = '# Empty List'

    # if the case there are strings to add to the EDL, add them if the output type is text
    elif request_args.out_format == FORMAT_TEXT:
        edl_data = prepare_response_data(data=edl_data,
                                         append_str=params.get("append_string"),
                                         prepend_str=params.get("prepend_string"))

    mimetype = get_outbound_mimetype(request_args)
    max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]

    headers = [
        ('X-EDL-Created', created.isoformat()),
        ('X-EDL-Query-Time-Secs', f"{query_time:.3f}"),
        ('X-EDL-Size', str(edl_size)),
        ('X-EDL-Origin-Size', original_indicators_count),
        ('ETag', etag),
    ]  # type: ignore[assignment]

    demisto.debug(f'edl: Returning response with the following headers:\n'
                  f'{[f"{header[0]}: {header[1]}" for header in headers]}')

    resp = Response(edl_data, status=200, mimetype=mimetype, headers=headers)
    resp.cache_control.max_age = max_age
    # number of seconds we are willing to serve stale content when there is an error
    resp.cache_control['stale-if-error'] = '600'

    return resp


@APP.route('/log_download', methods=['GET'])
def log_download() -> Response:
    params = demisto.params()

    auth_resp = authenticate_app(params, request.headers)
    if auth_resp:
        return auth_resp

    demisto.debug("Getting log file to show")

    created = datetime.now(timezone.utc)

    for previous_zip in glob.glob(f'{LOGS_ZIP_FILE_PREFIX}_*.zip'):
        os.remove(previous_zip)
    log_zip_filename = f'{LOGS_ZIP_FILE_PREFIX}_{created.strftime("%Y%m%d-%H%M%S")}.zip'
    zipf = zipfile.ZipFile(log_zip_filename, 'w', zipfile.ZIP_DEFLATED)
    zipf.write(EDL_FULL_LOG_PATH)
    zipf.close()
    return send_file(log_zip_filename,
                     mimetype='zip',
                     download_name=log_zip_filename,
                     as_attachment=True)


@APP.route('/log', methods=['GET'])
def route_edl_log() -> Response:
    """Show the edl indicators log on '/log' API request. """
    params = demisto.params()

    cache_refresh_rate: str = params.get('cache_refresh_rate')
    auth_resp = authenticate_app(params, request.headers)
    if auth_resp:
        return auth_resp

    demisto.debug("Getting log file to show")

    edl_data_log = get_edl_log_file() or '# Empty'
    request_args = get_request_args(request.args, params)
    created = datetime.now(timezone.utc)
    ctx = demisto.getIntegrationContext()

    # If edl_data_log is too large, first return a corresponding message as text.
    # Second, return the log as a file.
    # Alternate between the two via log_as_file context data key.
    if edl_data_log == LARGE_LOG_DISPLAY_MSG:
        # If we should return the log as a file this time
        if ctx.get('log_as_file', False):
            # Reset the log_as_file context key. Next time a message will be returned.
            ctx['log_as_file'] = False
            set_integration_context(ctx)
            # Remove previous zip versions of the log file if they exist.
            for previous_zip in glob.glob(f'{LOGS_ZIP_FILE_PREFIX}_*.zip'):
                os.remove(previous_zip)
            # zip the current log file and return it.
            log_zip_filename = f'{LOGS_ZIP_FILE_PREFIX}_{created.strftime("%Y%m%d-%H%M%S")}.zip'
            zipf = zipfile.ZipFile(log_zip_filename, 'w', zipfile.ZIP_DEFLATED)
            zipf.write(EDL_FULL_LOG_PATH)
            zipf.close()
            return send_file(log_zip_filename,
                             mimetype='zip',
                             download_name=log_zip_filename,
                             as_attachment=True)
        else:
            # Reset the log_as_file context key. Next time a file will be returned.
            ctx['log_as_file'] = True
            set_integration_context(ctx)

    if request_args.out_format == FORMAT_TEXT and edl_data_log not in ['# Empty', LARGE_LOG_DISPLAY_MSG]:
        ctx['log_as_file'] = False
        set_integration_context(ctx)
        edl_data_log = prepare_response_data(data=edl_data_log,
                                             append_str=params.get("append_string"),
                                             prepend_str=params.get("prepend_string"))

    etag = f'"{hashlib.sha3_256(edl_data_log.encode()).hexdigest()}"'
    headers = [
        ('X-EDL-LOG-Request-Created', created.isoformat()),
        ('ETag', etag)
    ]  # type: ignore[assignment]
    headers_str = f'{[f"{header[0]}: {header[1]}" for header in headers]}'
    demisto.debug(f'edl: Returning log response with the following headers:\n{headers_str}')
    max_age = ceil((datetime.now() - dateparser.parse(cache_refresh_rate)).total_seconds())  # type: ignore[operator]
    if edl_data_log == '# Empty':
        # If log file content was not created yet, refresh after 15 seconds.
        # If EDL indicator list refresh rate is less than 30s, refresh the log after half of the time.
        # This way, the corresponding log will be shown after at most 15 seconds.
        max_age = min(ceil(max_age / 2), 15)
    if edl_data_log == LARGE_LOG_DISPLAY_MSG:
        max_age = 0

    mimetype = get_outbound_mimetype(request_args)
    resp = Response(edl_data_log, status=200, mimetype=mimetype, headers=headers)
    resp.cache_control.max_age = max_age
    # number of seconds we are willing to serve stale content when there is an error
    resp.cache_control['stale-if-error'] = '600'

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
    maximum_cidr_size = try_parse_integer(request_args.get('mc', params.get(
        'maximum_cidr_size', MAXIMUM_CIDR_SIZE_DEFAULT)), EDL_CIDR_SIZR_MSG)
    no_wildcard_tld = argToBoolean(request_args.get('nt', params.get('no_wildcard_tld')))

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

    if out_format == FORMAT_MWG and mwg_type not in MWG_TYPE_OPTIONS:
        raise DemistoException(EDL_MWG_TYPE_ERR_MSG)

    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        demisto.info("Note: You are using a legacy query, it may have an impact on the performance of the integration."
                     "This parameter is deprecated, make sure to adjust your queries accordingly.")
        fields_to_present = 'use_legacy_query'

    if query and request_args.get("q"):
        demisto.debug("Adjusting the number of exported indicators if above 100,000, due to using the q URL inline parameter."
                      "For more information, review the documentation.")
        limit = min(limit, MAX_LIST_SIZE_WITH_URL_QUERY)

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
                            url_truncate,
                            maximum_cidr_size,
                            no_wildcard_tld
                            )


''' COMMAND FUNCTIONS '''


def test_module(_: dict, params: dict):
    """
    Validates:
        1. Valid port.
        2. Valid cache_refresh_rate
    """
    if not params.get('longRunningPort'):
        params['longRunningPort'] = '1111'
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
        if range_split[1] not in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year', 'years']:
            raise ValueError(
                'Invalid time unit for the Refresh Rate. Must be minutes, hours, days, months, or years.')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    run_long_running(params, is_test=True)
    return 'ok', {}, {}


@debug_function
def update_edl_command(args: dict, params: dict):
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
    maximum_cidr_size = try_parse_integer(params.get('maximum_cidr_size', MAXIMUM_CIDR_SIZE_DEFAULT), EDL_CIDR_SIZR_MSG)
    no_wildcard_tld = argToBoolean(params.get('no_wildcard_tld', False))

    if params.get('use_legacy_query'):
        demisto.info("Note: You are using a legacy query, it may have an impact on the performance of the integration."
                     "This parameter is deprecated, make sure to adjust your queries accordingly.")
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
                                    url_truncate,
                                    maximum_cidr_size,
                                    no_wildcard_tld)

    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)
    hr = 'EDL will be updated the next time you access it.'

    if not query:
        warning = "\n**Warning**: Updating EDL, while not specifying a query, may load unwanted indicators."

        if (param_query := params.get("query")):
            warning += f" Hint: use {param_query} to update indicators using the configured integration instance parameter."

        hr += warning
        demisto.info(warning)

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
    maximum_cidr_size = try_parse_integer(params.get('maximum_cidr_size', MAXIMUM_CIDR_SIZE_DEFAULT), EDL_CIDR_SIZR_MSG)
    no_wildcard_tld = argToBoolean(params.get('no_wildcard_tld', False))

    if params.get('use_legacy_query'):
        # workaround for "msgpack: invalid code" error
        demisto.info("Note: You are using a legacy query, it may have an impact on the performance of the integration."
                     "This parameter is getting deprecated, make sure to adjust your queries accordingly.")
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
                                    url_truncate,
                                    maximum_cidr_size,
                                    no_wildcard_tld)

    EDL_ON_DEMAND_CACHE_PATH = demisto.uniqueFile()
    demisto.debug(f"The full log path: {EDL_FULL_LOG_PATH}")
    ctx = request_args.to_context_json()
    ctx[EDL_ON_DEMAND_KEY] = True
    set_integration_context(ctx)
    demisto.debug("Setting context data on demand to true.")


def check_platform_and_version(params: dict) -> bool:
    """
    Args:
        - params: The demisto params from the integration configuration.
    Returns:
        (bool): True if the platform is xsoar or xsoar hosted and no port specified, false otherwise
    """
    platform = demisto.demistoVersion().get("platform", 'xsoar')
    if platform in ['xsoar', 'xsoar_hosted'] and not is_demisto_version_ge('8.0.0') and not params.get('longRunningPort'):
        return True
    return False


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
        'export-indicators-list-update': update_edl_command
    }

    try:
        if check_platform_and_version(params):
            raise DemistoException('Please specify a Listen Port, in the integration configuration')

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
    register_signal_handler_profiling_dump(profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT)
    main()

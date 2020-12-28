from typing import Optional

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import re
import json
import requests
import socket
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
API_KEY = PARAMS.get('api_key')
# Remove trailing slash to prevent wrong URL path to service
SERVER = 'https://autofocus.paloaltonetworks.com'
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/api/v1.0'

VENDOR_NAME = 'AutoFocus V2'

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json'
}

API_PARAM_DICT = {
    'scope': {
        'Private': 'private',
        'Public': 'public',
        'Global': 'global'
    },
    'order': {
        'Ascending': 'asc',
        'Descending': 'desc'
    },
    'artifact': 'artifactSource',
    'sort': {
        'App Name': 'app_name',
        'App Packagename': 'app_packagename',
        'File type': 'filetype',
        'Size': 'size',
        'Finish Date': 'finish_date',
        'First Seen (Create Date)': 'create_date',
        'Last Updated (Update Date)': 'update_date',
        'MD5': 'md5',
        'SHA1': 'sha1',
        'SHA256': 'sha256',
        'Ssdeep Fuzzy Hash': 'ssdeep',
        'Application': 'app',
        'Device Country': 'device_country',
        'Device Country Code': 'device_countrycode',
        'Device Hostname': 'device_hostname',
        'Device Serial': 'device_serial',
        'Device vsys': 'vsys',
        'Destination Country': 'dst_country',
        'Destination Country Code': 'dst_countrycode',
        'Destination IP': 'dst_ip',
        'Destination Port': 'dst_port',
        'Email Charset': 'emailsbjcharset',
        'Industry': 'device_industry',
        'Source Country': 'src_country',
        'Source Country Code': 'src_countrycode',
        'Source IP': 'src_ip',
        'Source Port': 'src_port',
        'Time': 'tstamp',
        'Upload source': 'upload_srcPossible'
    },
    'tag_class': {
        'Actor': 'actor',
        'Campaign': 'campaign',
        'Exploit': 'exploit',
        'Malicious Behavior': 'malicious_behavior',
        'Malware Family': 'malware_family'

    },
    'search_arguments': {
        'file_hash': {
            'api_name': 'alias.hash',
            'operator': 'contains'
        },
        'domain': {
            'api_name': 'alias.domain',
            'operator': 'contains'
        },
        'ip': {
            'api_name': 'alias.ip_address',
            'operator': 'contains'
        },
        'url': {
            'api_name': 'alias.url',
            'operator': 'contains'
        },
        'wildfire_verdict': {
            'api_name': 'sample.malware',
            'operator': 'is',
            'translate': {
                'Malware': 1,
                'Grayware': 2,
                'Benign': 3,
                'Phishing': 4,
            }
        },
        'first_seen': {
            'api_name': 'sample.create_date',
            'operator': 'is in the range'
        },
        'last_updated': {
            'api_name': 'sample.update_date',
            'operator': 'is in the range'
        },
        'time_range': {
            'api_name': 'session.tstamp',
            'operator': 'is in the range'
        },
        'time_after': {
            'api_name': 'session.tstamp',
            'operator': 'is after'
        },
        'time_before': {
            'api_name': 'session.tstamp',
            'operator': 'is before'
        }
    },

    'file_indicators': {
        'Size': 'Size',
        'SHA1': 'SHA1',
        'SHA256': 'SHA256',
        'FileType': 'Type',
        'Tags': 'Tags',
        'FileName': 'Name'
    },
    'search_results': {
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'filetype': 'FileType',
        'malware': 'Verdict',
        'size': 'Size',
        'create_date': 'Created',
        'finish_date': 'Finished',
        'md5': 'MD5',
        'region': 'Region',
        'tag': 'Tags',
        '_id': 'ID',
        'tstamp': 'Seen',
        'filename': 'FileName',
        'device_industry': 'Industry',
        'upload_src': 'UploadSource',
        'fileurl': 'FileURL',
        'artifact': 'Artifact',
    }
}
SAMPLE_ANALYSIS_LINE_KEYS = {
    'behavior': {
        'display_name': 'behavior',
        'indexes': {
            'risk': 0,
            'behavior': -1
        }
    },
    'process': {
        'display_name': 'processes',
        'indexes': {
            'parent_process': 0,
            'action': 1
        }
    },
    'file': {
        'display_name': 'files',
        'indexes': {
            'parent_process': 0,
            'action': 1
        }
    },
    'registry': {
        'display_name': 'registry',
        'indexes': {
            'action': 1,
            'parameters': 2
        }
    },
    'dns': {
        'display_name': 'DNS',
        'indexes': {
            'query': 0,
            'response': 1
        }
    },
    'http': {
        'display_name': 'HTTP',
        'indexes': {
            'host': 0,
            'method': 1,
            'url': 2
        }
    },
    'connection': {
        'display_name': 'connections',
        'indexes': {
            'destination': 2
        }
    },
    'mutex': {
        'display_name': 'mutex',
        'indexes': {
            'process': 0,
            'action': 1,
            'parameters': 2
        }
    }
}
SAMPLE_ANALYSIS_COVERAGE_KEYS = {
    'wf_av_sig': {
        'display_name': 'wildfire_signatures',
        'fields': ['name', 'create_date']
    },
    'fileurl_sig': {
        'display_name': 'fileurl_signatures',
        'fields': ['name', 'create_date']
    },
    'dns_sig': {
        'display_name': 'dns_signatures',
        'fields': ['name', 'create_date']
    },
    'url_cat': {
        'display_name': 'url_categories',
        'fields': ['url', 'cat']
    }
}

VERDICTS_TO_DBOTSCORE = {
    'benign': 1,
    'malware': 3,
    'grayware': 2,
    'phishing': 3,
    'c2': 3
}

ERROR_DICT = {
    '404': 'Invalid URL.',
    '408': 'Invalid URL.',
    '409': 'Invalid message or missing parameters.',
    '500': 'Internal error.',
    '503': 'Rate limit exceeded.'
}

if PARAMS.get('mark_as_malicious'):
    verdicts = argToList(PARAMS.get('mark_as_malicious'))
    for verdict in verdicts:
        VERDICTS_TO_DBOTSCORE[verdict] = 3

''' HELPER FUNCTIONS '''


def parse_response(resp, err_operation):
    try:
        # Handle error responses gracefully
        res_json = resp.json()
        resp.raise_for_status()
        return res_json
    # Errors returned from AutoFocus
    except requests.exceptions.HTTPError:
        err_msg = f'{err_operation}: {res_json.get("message")}'
        if res_json.get("message").find('Requested sample not found') != -1:
            demisto.results(err_msg)
            sys.exit(0)
        elif res_json.get("message").find("AF Cookie Not Found") != -1:
            demisto.results(err_msg)
            sys.exit(0)
        elif err_operation == 'Tag details operation failed' and \
                res_json.get("message").find("Tag") != -1 and res_json.get("message").find("not found") != -1:
            demisto.results(err_msg)
            sys.exit(0)
        else:
            return return_error(err_msg)
    # Unexpected errors (where no json object was received)
    except Exception as err:
        err_msg = f'{err_operation}: {err}'
        return return_error(err_msg)


def http_request(url_suffix, method='POST', data={}, err_operation=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    data.update({'apiKey': API_KEY})
    try:
        res = requests.request(
            method=method,
            url=BASE_URL + url_suffix,
            verify=USE_SSL,
            data=json.dumps(data),
            headers=HEADERS
        )
    # Handle with connection error
    except requests.exceptions.ConnectionError as err:
        err_message = f'Error connecting to server. Check your URL/Proxy/Certificate settings: {err}'
        return_error(err_message)
    return parse_response(res, err_operation)


def validate_sort_and_order_and_artifact(sort: Optional[str] = None, order: Optional[str] = None,
                                         artifact_source: Optional[str] = None) -> bool:
    """
    Function that validates the arguments combination.
    sort and order arguments must be defined together.
    Sort and order can't appear with artifact.
    Args:
        sort: variable to sort by.
        order: the order which the results is ordered by.
        artifact_source: true if artifacts are needed and false otherwise.
    Returns:
        true if arguments are valid for the request, false otherwise.
    """
    if artifact_source == 'true' and sort:
        raise Exception('Please remove or disable one of sort or artifact,'
                        ' As they are not supported in the api together.')
    elif sort and not order:
        raise Exception('Please specify the order of sorting (Ascending or Descending).')
    elif order and not sort:
        raise Exception('Please specify a field to sort by.')
    elif sort and order:
        return True
    return False


def do_search(search_object: str, query: dict, scope: Optional[str], size: Optional[str] = None,
              sort: Optional[str] = None, order: Optional[str] = None, err_operation: Optional[str] = None,
              artifact_source: Optional[str] = None) -> dict:
    """
    This function created the data to be sent in http request and sends it.
    Args:
        search_object: Type of search sessions or samples.
        query: Query based on conditions specified within this object.
        scope:  Scope of the search. Only available and required for: samples. e.g. Public, Global, Private.
        size: Number of results to provide.
        sort: Sort based on the provided artifact.
        order: How to display sort results in ascending or descending order.
        err_operation: String error which specificed which command failed.
        artifact_source: Whether artifacts are wanted or not.
    Returns:
        raw response of the http request.
    """
    path = '/samples/search' if search_object == 'samples' else '/sessions/search'
    data = {
        'query': query,
        'size': size
    }
    if scope:
        data.update({'scope': API_PARAM_DICT['scope'][scope]})  # type: ignore
    if validate_sort_and_order_and_artifact(sort, order, artifact_source):
        data.update({'sort': {API_PARAM_DICT['sort'][sort]: {'order': API_PARAM_DICT['order'][order]}}})  # type: ignore
    if artifact_source == 'true':
        data.update({'artifactSource': 'af'})
        data.update({'type': 'scan'})
    # Remove nulls
    data = createContext(data, removeNull=True)
    result = http_request(path, data=data, err_operation=err_operation)
    return result


def run_search(search_object: str, query: str, scope: Optional[str] = None, size: str = None, sort: str = None,
               order: str = None, artifact_source: str = None) -> dict:
    """
    This function searches the relevent search and returns search info for result command.
    Args:
        search_object: Type of search sessions or samples.
        query: Query based on conditions specified within this object.
        scope:  Scope of the search. Only available and required for: samples. e.g. Public, Global, Private.
        size: Number of results to provide.
        sort: Sort based on the provided artifact.
        order: How to display sort results in ascending or descending order.
        artifact_source: Whether artifacts are wanted or not.
    Returns:
        dict of response for result commands.
    """
    result = do_search(search_object, query=json.loads(query), scope=scope, size=size, sort=sort, order=order,
                       artifact_source=artifact_source, err_operation='Search operation failed')
    in_progress = result.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    search_info = {
        'AFCookie': result.get('af_cookie'),
        'Status': status,
        'SessionStart': datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    }
    return search_info


def run_get_search_results(search_object, af_cookie):
    path = f'/samples/results/{af_cookie}' if search_object == 'samples' else f'/sessions/results/{af_cookie}'
    results = http_request(path, err_operation='Fetching search results failed')
    return results


def get_fields_from_hit_object(result_object, response_dict_name):
    new_object = {}
    af_params_dict = API_PARAM_DICT.get(response_dict_name)
    for key, value in result_object.items():
        if key in af_params_dict:  # type: ignore
            new_key = af_params_dict.get(key)  # type: ignore
            new_object[new_key] = value
        else:
            new_object[key] = value
    return new_object


def parse_hits_response(hits, response_dict_name):
    parsed_objects = []  # type: ignore
    if not hits:
        return parsed_objects
    else:
        for hit in hits:
            flattened_obj = {}  # type: ignore
            flattened_obj.update(hit.get('_source'))
            flattened_obj['_id'] = hit.get('_id')
            parsed_obj = get_fields_from_hit_object(flattened_obj, response_dict_name)
            parsed_objects.append(parsed_obj)
        return parsed_objects


def get_search_results(search_object, af_cookie):
    results = run_get_search_results(search_object, af_cookie)
    retry_count = 0
    # Checking if the query has no results because the server has not fetched them yet.
    # In this case, the complete percentage would be 0 (or lower than 100).
    # In a case where there really aren't results (hits), the af_complete_percentage would be 100.
    while (not results.get('hits') and (results.get('af_complete_percentage', 0) != 100)) and retry_count < 10:
        time.sleep(5)
        results = run_get_search_results(search_object, af_cookie)
        retry_count += 1
    parsed_results = parse_hits_response(results.get('hits'), 'search_results')
    in_progress = results.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    return parsed_results, status


def get_session_details(session_id):
    path = f'/session/{session_id}'
    result = http_request(path, err_operation='Get session failed')
    parsed_result = parse_hits_response(result.get('hits'), 'search_results')
    return parsed_result


def validate_if_line_needed(category, info_line):
    line = info_line.get('line')
    line_values = line.split(',')
    category_indexes = SAMPLE_ANALYSIS_LINE_KEYS.get(category).get('indexes')  # type: ignore
    if category == 'behavior':
        risk_index = category_indexes.get('risk')  # type: ignore
        risk = line_values[risk_index].strip()
        # only lines with risk higher the informational are considered
        return not risk == 'informational'
    elif category == 'registry':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        # Only lines with actions SetValueKey, CreateKey or RegSetValueEx are considered
        return action == 'SetValueKey' or action == 'CreateKey' or action == 'RegSetValueEx'
    elif category == 'file':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        benign_count = info_line.get('b') if info_line.get('b') else 0
        malicious_count = info_line.get('m') if info_line.get('m') else 0
        # Only lines with actions Create or CreateFileW where malicious count is grater than benign count are considered
        return (action == 'Create' or action == 'CreateFileW') and malicious_count > benign_count
    elif category == 'process':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        # Only lines with actions created, CreateKey or CreateProcessInternalW are considered
        return action == 'created' or action == 'CreateProcessInternalW'
    else:
        return True


def get_data_from_line(line, category_name):
    category_indexes = SAMPLE_ANALYSIS_LINE_KEYS.get(category_name).get('indexes')  # type: ignore
    values = line.split(',')
    sub_categories = {}  # type: ignore
    if not category_indexes:
        return sub_categories
    else:
        for sub_category in category_indexes:  # type: ignore
            sub_category_index = category_indexes.get(sub_category)  # type: ignore
            sub_categories.update({
                sub_category: values[sub_category_index]
            })
        return sub_categories


def get_data_from_coverage_sub_category(sub_category_name, sub_category_data):
    sub_categories_list = []
    for item in sub_category_data:
        new_sub_category = {}
        fields_to_extract = SAMPLE_ANALYSIS_COVERAGE_KEYS.get(sub_category_name).get('fields')  # type: ignore
        for field in fields_to_extract:  # type: ignore
            new_sub_category[field] = item.get(field)  # type: ignore
        sub_categories_list.append(new_sub_category)
    return sub_categories_list


def parse_coverage_sub_categories(coverage_data):
    new_coverage = {}
    for sub_category_name, sub_category_data in coverage_data.items():
        if sub_category_name in SAMPLE_ANALYSIS_COVERAGE_KEYS and isinstance(sub_category_data, dict):
            new_sub_category_data = get_data_from_coverage_sub_category(sub_category_name, sub_category_data)
            new_sub_category_name = SAMPLE_ANALYSIS_COVERAGE_KEYS.get(sub_category_name).get(  # type: ignore
                'display_name')  # type: ignore
            new_coverage[new_sub_category_name] = new_sub_category_data
    return {'coverage': new_coverage}


def parse_lines_from_os(category_name, data, filter_data_flag):
    new_lines = []
    for info_line in data:
        if not filter_data_flag or validate_if_line_needed(category_name, info_line):
            new_sub_categories = get_data_from_line(info_line.get('line'), category_name)
            new_lines.append(new_sub_categories)
    return new_lines


def parse_sample_analysis_response(resp, filter_data_flag):
    analysis = {}
    for category_name, category_data in resp.items():
        if category_name in SAMPLE_ANALYSIS_LINE_KEYS:
            new_category = {}
            for os_name, os_data in category_data.items():
                os_sanitized_data = parse_lines_from_os(category_name, os_data, filter_data_flag)
                new_category[os_name] = os_sanitized_data

            category_dict = SAMPLE_ANALYSIS_LINE_KEYS.get(category_name)
            analysis.update({category_dict['display_name']: new_category})  # type: ignore

        elif category_name == 'coverage':
            new_category = parse_coverage_sub_categories(category_data)
            analysis.update(new_category)

    return analysis


def sample_analysis(sample_id, os, filter_data_flag):
    path = f'/sample/{sample_id}/analysis'
    data = {
        'coverage': 'true'
    }
    if os:
        data['platforms'] = [os]  # type: ignore
    result = http_request(path, data=data, err_operation='Sample analysis failed')
    analysis_obj = parse_sample_analysis_response(result, filter_data_flag)
    return analysis_obj


def parse_tag_details_response(resp):
    tag_details = resp.get('tag')
    fields_to_extract_from_tag_details = [
        'public_tag_name',
        'tag_name',
        'customer_name',
        'source',
        'tag_definition_scope',
        'tag_definition_status',
        'tag_class',
        'count',
        'lasthit',
        'description'
    ]
    new_tag_info = {}
    for field in fields_to_extract_from_tag_details:
        new_tag_info[field] = tag_details.get(field)

    tag_group_details = resp.get('tag_groups')
    if tag_group_details:
        new_tag_info['tag_group'] = tag_group_details

    return new_tag_info


def autofocus_tag_details(tag_name):
    path = f'/tag/{tag_name}'
    resp = http_request(path, err_operation='Tag details operation failed')
    tag_info = parse_tag_details_response(resp)
    return tag_info


def validate_tag_scopes(private, public, commodity, unit42):
    if not private and not public and not commodity and not unit42:
        return_error('Add at least one Tag scope by setting `commodity`, `private`, `public` or `unit42` to True')


def autofocus_top_tags_search(scope, tag_class_display, private, public, commodity, unit42):
    validate_tag_scopes(private, public, commodity, unit42)
    tag_class = API_PARAM_DICT['tag_class'][tag_class_display]  # type: ignore
    query = {
        "operator": "all",
        "children": [
            {
                "field": "sample.tag_class",
                "operator": "is",
                "value": tag_class
            }
        ]
    }
    tag_scopes = list()
    if private:
        tag_scopes.append('private')
    if public:
        tag_scopes.append('public')
    if commodity:
        tag_scopes.append('commodity')
    if unit42:
        tag_scopes.append('unit42')
    data = {
        'query': query,
        'scope': scope,
        'tagScopes': tag_scopes
    }
    path = '/top-tags/search/'
    resp = http_request(path, data=data, err_operation='Top tags operation failed')
    in_progress = resp.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    search_info = {
        'AFCookie': resp.get('af_cookie'),
        'Status': status
    }
    return search_info


def parse_top_tags_response(response):
    top_tags_list = []  # type: ignore
    top_tags = response.get('top_tags')
    if not top_tags:
        return top_tags_list
    else:
        for tag in top_tags:
            fields_to_extract_from_top_tags = ['tag_name', 'public_tag_name', 'count', 'lasthit']
            new_tag = {}
            for field in fields_to_extract_from_top_tags:
                new_tag[field] = tag[field]
            top_tags_list.append(new_tag)
        return top_tags_list


def get_top_tags_results(af_cookie):
    path = f'/top-tags/results/{af_cookie}'
    results = http_request(path, err_operation='Fetching top tags results failed')
    top_tags = parse_top_tags_response(results)
    in_progress = results.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    return top_tags, status


def print_hr_by_category(category_name, category_data):
    hr = content = f'### {string_to_table_header(category_name)}:\nNo entries'
    if category_name == 'coverage':
        content = category_data
        if category_data:
            hr = tableToMarkdown(f'{string_to_table_header(category_name)}:', category_data,
                                 headerTransform=string_to_table_header)
        else:
            hr = f'### {string_to_table_header(category_name)}:\nNo entries'
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': content,
            'HumanReadable': hr
        })
    else:
        for os_name, os_data in category_data.items():
            content = os_data
            table_header = f'{category_name}_{os_name}'
            if os_data:
                hr = tableToMarkdown(f'{string_to_table_header(table_header)}:', os_data,
                                     headerTransform=string_to_table_header)
            else:
                hr = f'### {string_to_table_header(table_header)}:\nNo entries'
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': content,
                'HumanReadable': hr
            })


def get_files_data_from_results(results):
    """
    Gets a list of results and for each result returns a file object includes all relevant file indicators exists
    in that result
    :param results: a list of dictionaries
    :return: a list of file objects
    """
    files = []
    if results:
        for result in results:
            raw_file = get_fields_from_hit_object(result, 'file_indicators')
            file_data = filter_object_entries_by_dict_values(raw_file, 'file_indicators')
            files.append(file_data)
    return files


def filter_object_entries_by_dict_values(result_object, response_dict_name):
    """
    Gets a dictionary (result_object) and filters it's keys by the values of another
    dictionary (response_dict_name)
    input: response_dict_name = 'file_indicators' - see API_PARAM_DICT above
           result_object = {
                              "app": "web-browsing",
                              "vsys": 1,
                              "SHA256": "18c9acd34a3aea09121f027857e0004a3ea33a372b213a8361e8a978330f0dc8",
                              "UploadSource": "Firewall",
                              "src_port": 80,
                              "device_serial": "007051000050926",
                              "Seen": "2019-07-24T09:37:04",
                              "Name": "wildfire-test-pe-file.exe",
                              "user_id": "unknown",
                              "src_country": "United States",
                              "src_countrycode": "US",
                              "dst_port": 65168,
                              "device_countrycode": "US",
                              "Industry": "High Tech",
                              "Region": "us",
                              "device_country": "United States",
                              "ID": "179972200903"
                            }
    output: {
                "SHA256": "18c9acd34a3aea09121f027857e0004a3ea33a372b213a8361e8a978330f0dc8",
                "Name": "wildfire-test-pe-file.exe"
            }
    :param result_object: a dictionary representing an object
    :param response_dict_name: a dictionary which it's values are the relevant fields (filters)
    :return: the result_object filtered by the relevant fields
    """
    af_params_dict = API_PARAM_DICT.get(response_dict_name)
    result_object_filtered = {}
    if af_params_dict and isinstance(result_object, dict) and isinstance(af_params_dict, dict):
        for key in result_object.keys():
            if key in af_params_dict.values():  # type: ignore
                result_object_filtered[key] = result_object.get(key)
    return result_object_filtered


def search_samples(query=None, scope=None, size=None, sort=None, order=None, file_hash=None, domain=None, ip=None,
                   url=None, wildfire_verdict=None, first_seen=None, last_updated=None, artifact_source=None):
    validate_no_query_and_indicators(query, [file_hash, domain, ip, url, wildfire_verdict, first_seen, last_updated])
    if not query:
        validate_no_multiple_indicators_for_search([file_hash, domain, ip, url])
        query = build_sample_search_query(file_hash, domain, ip, url, wildfire_verdict, first_seen, last_updated)
    return run_search('samples', query=query, scope=scope, size=size, sort=sort, order=order,
                      artifact_source=artifact_source)


def build_sample_search_query(file_hash, domain, ip, url, wildfire_verdict, first_seen, last_updated):
    indicator_args_for_query = {
        'file_hash': file_hash,
        'domain': domain,
        'ip': ip,
        'url': url
    }
    indicator_list = build_indicator_children_query(indicator_args_for_query)
    indicator_query = build_logic_query('OR', indicator_list)
    filtering_args_for_search = {}  # type: ignore
    if wildfire_verdict:
        filtering_args_for_search['wildfire_verdict'] = \
            demisto.get(API_PARAM_DICT, f'search_arguments.wildfire_verdict.translate.{wildfire_verdict}')
    if first_seen:
        filtering_args_for_search['first_seen'] = first_seen
    if last_updated:
        filtering_args_for_search['last_updated'] = last_updated
    filters_list = build_children_query(filtering_args_for_search)
    filters_list.append(indicator_query)
    logic_query = build_logic_query('AND', filters_list)
    return json.dumps(logic_query)


def search_sessions(query=None, size=None, sort=None, order=None, file_hash=None, domain=None, ip=None, url=None,
                    from_time=None, to_time=None):
    validate_no_query_and_indicators(query, [file_hash, domain, ip, url, from_time, to_time])
    if not query:
        validate_no_multiple_indicators_for_search([file_hash, domain, ip, url])
        query = build_session_search_query(file_hash, domain, ip, url, from_time, to_time)
    return run_search('sessions', query=query, size=size, sort=sort, order=order)


def build_session_search_query(file_hash, domain, ip, url, from_time, to_time):
    indicator_args_for_query = {
        'file_hash': file_hash,
        'domain': domain,
        'ip': ip,
        'url': url
    }
    indicator_list = build_indicator_children_query(indicator_args_for_query)
    indicator_query = build_logic_query('OR', indicator_list)
    time_filters_for_search = {}  # type: ignore
    if from_time and to_time:
        time_filters_for_search = {'time_range': [from_time, to_time]}
    elif from_time:
        time_filters_for_search = {'time_after': [from_time]}
    elif to_time:
        time_filters_for_search = {'time_before': [to_time]}

    filters_list = build_children_query(time_filters_for_search)
    filters_list.append(indicator_query)
    logic_query = build_logic_query('AND', filters_list)
    return json.dumps(logic_query)


def build_logic_query(logic_operator, condition_list):
    operator = None
    if logic_operator == 'AND':
        operator = 'all'
    elif logic_operator == 'OR':
        operator = 'any'
    return {
        'operator': operator,
        'children': condition_list
    }


def build_children_query(args_for_query):
    children_list = []  # type: ignore
    for key, val in args_for_query.items():
        field_api_name = API_PARAM_DICT['search_arguments'][key]['api_name']  # type: ignore
        operator = API_PARAM_DICT['search_arguments'][key]['operator']  # type: ignore
        children_list += children_list_generator(field_api_name, operator, [val])
    return children_list


def build_indicator_children_query(args_for_query):
    for key, val in args_for_query.items():
        if val:
            field_api_name = API_PARAM_DICT['search_arguments'][key]['api_name']  # type: ignore
            operator = API_PARAM_DICT['search_arguments'][key]['operator']  # type: ignore
            children_list = children_list_generator(field_api_name, operator, val)
    return children_list


def children_list_generator(field_name, operator, val_list):
    query_list = []
    for value in val_list:
        query_list.append({
            'field': field_name,
            'operator': operator,
            'value': value
        })
    return query_list


def validate_no_query_and_indicators(query, arg_list):
    if query:
        for arg in arg_list:
            if arg:
                return_error('The search command can either run a search using a custom query '
                             'or use the builtin arguments, but not both')


def validate_no_multiple_indicators_for_search(arg_list):
    used_arg = None
    for arg in arg_list:
        if arg and used_arg:
            return_error(f'The search command can receive one indicator type at a time, two were given: {used_arg}, '
                         f'{arg}. For multiple indicator types use the custom query')
        elif arg:
            used_arg = arg
    if not used_arg:
        return_error('In order to perform a samples/sessions search, a query or an indicator must be given.')
    return


def search_indicator(indicator_type, indicator_value):
    headers = HEADERS
    headers['apiKey'] = API_KEY

    params = {
        'indicatorType': indicator_type,
        'indicatorValue': indicator_value,
        'includeTags': 'true',
    }

    try:
        result = requests.request(
            method='GET',
            url=f'{BASE_URL}/tic',
            verify=USE_SSL,
            headers=headers,
            params=params
        )

        # Handle error responses gracefully
        result.raise_for_status()
        result_json = result.json()

    # Handle with connection error
    except requests.exceptions.ConnectionError as err:
        err_message = f'Error connecting to server. Check your URL/Proxy/Certificate settings: {err}'
        return_error(err_message)

    # Unexpected errors (where no json object was received)
    except Exception as err:
        try:
            text_error = result.json()
        except ValueError:
            text_error = {}
        error_message = text_error.get('message')
        if error_message:
            return_error(f'Request Failed with status: {result.status_code}.\n'
                         f'Reason is: {str(error_message)}.')
        elif str(result.status_code) in ERROR_DICT:
            return_error(f'Request Failed with status: {result.status_code}.\n'
                         f'Reason is: {ERROR_DICT[str(result.status_code)]}.')
        else:
            err_msg = f'Request Failed with message: {err}.'
        return_error(err_msg)

    return result_json


def parse_indicator_response(res, raw_tags, indicator_type):
    indicator = {}
    indicator['IndicatorValue'] = res.get('indicatorValue', '')
    indicator['IndicatorType'] = res.get('indicatorType', '')
    indicator['LatestPanVerdicts'] = res.get('latestPanVerdicts', '')
    indicator['WildfireRelatedSampleVerdictCounts'] = res.get('wildfireRelatedSampleVerdictCounts', '')
    indicator['SeenBy'] = res.get('seenByDataSourceIds', '')

    first_seen = res.get('firstSeenTsGlobal', '')
    last_seen = res.get('lastSeenTsGlobal', '')

    if first_seen:
        indicator['FirstSeen'] = timestamp_to_datestring(first_seen)
    if last_seen:
        indicator['LastSeen'] = timestamp_to_datestring(last_seen)

    if raw_tags:
        tags = []
        for tag in raw_tags:
            tags.append({
                'PublicTagName': tag.get('public_tag_name', ''),
                'TagName': tag.get('tag_name', ''),
                'CustomerName': tag.get('customer_name', ''),
                'Source': tag.get('source', ''),
                'TagDefinitionScopeID': tag.get('tag_definition_scope_id', ''),
                'TagDefinitionStatusID': tag.get('tag_definition_status_id', ''),
                'TagClassID': tag.get('tag_class_id', ''),
                'Count': tag.get('count', ''),
                'Lasthit': tag.get('lasthit', ''),
                'Description': tag.get('description', '')})
        indicator['Tags'] = tags

    if indicator_type == 'Domain':
        indicator['WhoisAdminCountry'] = res.get('whoisAdminCountry', '')
        indicator['WhoisAdminEmail'] = res.get('whoisAdminEmail', '')
        indicator['WhoisAdminName'] = res.get('whoisAdminName', '')
        indicator['WhoisDomainCreationDate'] = res.get('whoisDomainCreationDate', '')
        indicator['WhoisDomainExpireDate'] = res.get('whoisDomainExpireDate', '')
        indicator['WhoisDomainUpdateDate'] = res.get('whoisDomainUpdateDate', '')
        indicator['WhoisRegistrar'] = res.get('whoisRegistrar', '')
        indicator['WhoisRegistrarUrl'] = res.get('whoisRegistrarUrl', '')
        indicator['WhoisRegistrant'] = res.get('whoisRegistrant', '')

    return indicator


def calculate_dbot_score(indicator_response, indicator_type):
    latest_pan_verdicts = indicator_response['latestPanVerdicts']
    if not latest_pan_verdicts:
        raise Exception('latestPanVerdicts value is empty in indicator response.')

    pan_db = latest_pan_verdicts.get('PAN_DB')
    wf_sample = latest_pan_verdicts.get('WF_SAMPLE')

    # use WF_SAMPLE value for file indicator and PAN_DB for domain,url and ip indicators
    if indicator_type == 'File' and wf_sample:
        return VERDICTS_TO_DBOTSCORE.get(wf_sample.lower(), 0)
    elif pan_db:
        return VERDICTS_TO_DBOTSCORE.get(pan_db.lower(), 0)
    else:
        score = next(iter(latest_pan_verdicts.values()))
        return VERDICTS_TO_DBOTSCORE.get(score.lower(), 0)


def check_for_ip(indicator):
    if '-' in indicator:
        # check for address range
        ip1, ip2 = indicator.split('-', 1)

        if re.match(ipv4Regex, ip1) and re.match(ipv4Regex, ip2):
            return FeedIndicatorType.IP

        elif re.match(ipv6Regex, ip1) and re.match(ipv6Regex, ip2):
            return FeedIndicatorType.IPv6

        elif re.match(ipv4cidrRegex, ip1) and re.match(ipv4cidrRegex, ip2):
            return FeedIndicatorType.CIDR

        elif re.match(ipv6cidrRegex, ip1) and re.match(ipv6cidrRegex, ip2):
            return FeedIndicatorType.IPv6CIDR

        return None

    if '/' in indicator:

        if re.match(ipv4cidrRegex, indicator):
            return FeedIndicatorType.CIDR

        elif re.match(ipv6cidrRegex, indicator):
            return FeedIndicatorType.IPv6CIDR

        return None

    else:
        if re.match(ipv4Regex, indicator):
            return FeedIndicatorType.IP

        elif re.match(ipv6Regex, indicator):
            return FeedIndicatorType.IPv6

    return None


def find_indicator_type(indicator):
    """Infer the type of the indicator.

    Args:
        indicator(str): The indicator whose type we want to check.

    Returns:
        str. The type of the indicator.
    """
    # trying to catch X.X.X.X:portNum
    if ':' in indicator and '/' not in indicator:
        sub_indicator = indicator.split(':', 1)[0]
        ip_type = check_for_ip(sub_indicator)
        if ip_type:
            return ip_type

    ip_type = check_for_ip(indicator)

    if ip_type:
        # catch URLs of type X.X.X.X/path/url or X.X.X.X:portNum/path/url
        if '/' in indicator and (ip_type not in [FeedIndicatorType.IPv6CIDR, FeedIndicatorType.CIDR]):
            return FeedIndicatorType.URL

        else:
            return ip_type

    elif re.match(sha256Regex, indicator):
        return FeedIndicatorType.File

    # in AutoFocus, URLs include a path while domains do not - so '/' is a good sign for us to catch URLs.
    elif '/' in indicator:
        return FeedIndicatorType.URL

    else:
        return FeedIndicatorType.Domain


def resolve_ip_address(ip):
    if check_for_ip(ip):
        return socket.gethostbyaddr(ip)[0]

    return None


''' COMMANDS'''


def test_module():
    """
    Performs basic get request to get item samples
    """
    query = {
        'operator': 'all',
        'children': [
            {
                'field': 'sample.malware',
                'operator': 'is',
                'value': 1
            }
        ]
    }

    do_search('samples', query=query, scope='Public', err_operation='Test module failed')
    return


def search_samples_command():
    args = demisto.args()
    file_hash = argToList(args.get('file_hash'))
    domain = argToList(args.get('domain'))
    ip = argToList(args.get('ip'))
    url = argToList(args.get('url'))
    wildfire_verdict = args.get('wildfire_verdict')
    first_seen = argToList(args.get('first_seen'))
    last_updated = argToList(args.get('last_updated'))
    query = args.get('query')
    scope = args.get('scope').capitalize()
    max_results = args.get('max_results')
    sort = args.get('sort')
    order = args.get('order')
    artifact_source = args.get('artifact')
    info = search_samples(query=query, scope=scope, size=max_results, sort=sort, order=order, file_hash=file_hash,
                          domain=domain, ip=ip, url=url, wildfire_verdict=wildfire_verdict, first_seen=first_seen,
                          last_updated=last_updated, artifact_source=artifact_source)
    md = tableToMarkdown('Search Samples Info:', info)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': info,
        'EntryContext': {'AutoFocus.SamplesSearch(val.AFCookie == obj.AFCookie)': info},
        'HumanReadable': md
    })


def search_sessions_command():
    args = demisto.args()
    file_hash = argToList(args.get('file_hash'))
    domain = argToList(args.get('domain'))
    ip = argToList(args.get('ip'))
    url = argToList(args.get('url'))
    from_time = args.get('from_time')
    to_time = args.get('to_time')
    query = args.get('query')
    max_results = args.get('max_results')
    sort = args.get('sort')
    order = args.get('order')
    info = search_sessions(query=query, size=max_results, sort=sort, order=order, file_hash=file_hash, domain=domain,
                           ip=ip, url=url, from_time=from_time, to_time=to_time)
    md = tableToMarkdown('Search Sessions Info:', info)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': info,
        'EntryContext': {'AutoFocus.SessionsSearch(val.AFCookie == obj.AFCookie)': info},
        'HumanReadable': md
    })


def samples_search_results_command():
    args = demisto.args()
    af_cookie = args.get('af_cookie')
    results, status = get_search_results('samples', af_cookie)
    files = get_files_data_from_results(results)
    hr = ''
    if not results or len(results) == 0:
        hr = 'No entries found that match the query'
        status = 'complete'
    context = {
        'AutoFocus.SamplesResults(val.ID === obj.ID)': results,
        'AutoFocus.SamplesSearch(val.AFCookie ==== obj.AFCookie)': {'Status': status, 'AFCookie': af_cookie},
        outputPaths['file']: files
    }
    if not results:
        return_outputs(readable_output=hr, outputs=context, raw_response={})
    else:
        # for each result a new entry will be set with two tables, one of the result and one of its artifacts
        for result in results:
            if 'Artifact' in result:
                hr = samples_search_result_hr(result, status)
                return_outputs(readable_output=hr, outputs=context, raw_response=results)
            else:
                hr = tableToMarkdown(f'Search Samples Result is {status}', result)
                hr += tableToMarkdown('Artifacts for Sample: ', [])
                return_outputs(readable_output=hr, outputs=context, raw_response=results)


def samples_search_result_hr(result: dict, status: str) -> str:
    """
    Creates human readable output for a specific entry which contains two tables, one for the result's
    and another for the artifacts that are related to it.
    Args:
        result: one result of the search sample command.
        status: status of result command.
    Returns:
        human readable of two tables for this result.
    """
    artifact = result.pop('Artifact')
    updated_artifact = []
    for indicator in artifact:
        # Filter on returned indicator types, as we do not support Mutex and User Agent.
        if 'Mutex' not in indicator.get('indicator_type') and 'User Agent' not in indicator.get('indicator_type'):
            updated_artifact.append(indicator)
    rest = result
    hr = tableToMarkdown(f'Search Samples Result is {status}', rest)
    hr += '\n\n'
    hr += tableToMarkdown(
        'Artifacts for Sample: ', updated_artifact,
        headers=["b", "g", "m", "indicator_type", "confidence", "indicator"])
    return hr


def sessions_search_results_command():
    args = demisto.args()
    af_cookie = args.get('af_cookie')
    results, status = get_search_results('sessions', af_cookie)
    files = get_files_data_from_results(results)
    if not results or len(results) == 0:
        md = results = 'No entries found that match the query'
        status = 'complete'
    else:
        md = tableToMarkdown(f'Search Sessions Results is {status}', results)
    context = {
        'AutoFocus.SessionsResults(val.ID === obj.ID)': results,
        'AutoFocus.SessionsSearch(val.AFCookie === obj.AFCookie)': {'Status': status, 'AFCookie': af_cookie},
        outputPaths['file']: files
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': context,
        'HumanReadable': md
    })


def get_session_details_command():
    args = demisto.args()
    session_id = args.get('session_id')
    result = get_session_details(session_id)
    files = get_files_data_from_results(result)
    md = tableToMarkdown(f'Session {session_id}:', result)
    context = {
        'AutoFocus.Sessions(val.ID === obj.ID)': result,
        outputPaths['file']: files
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': result,
        'EntryContext': context,
        'HumanReadable': md
    })


def sample_analysis_command():
    args = demisto.args()
    sample_id = args.get('sample_id')
    os = args.get('os')
    filter_data = False if args.get('filter_data') == 'False' else True
    analysis = sample_analysis(sample_id, os, filter_data)
    context = createContext(analysis, keyTransform=string_to_context_key)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': {'ID': sample_id, 'Analysis': analysis},
        'HumanReadable': f'### Sample Analysis results for {sample_id}:',
        'EntryContext': {'AutoFocus.SampleAnalysis(val.ID == obj.ID)': {'ID': sample_id, 'Analysis': context}},
    })
    for category_name, category_data in analysis.items():
        print_hr_by_category(category_name, category_data)


def tag_details_command():
    args = demisto.args()
    tag_name = args.get('tag_name')
    result = autofocus_tag_details(tag_name)
    md = tableToMarkdown(f'Tag {tag_name} details:', result, headerTransform=string_to_table_header)
    context = createContext(result, keyTransform=string_to_context_key)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': result,
        'EntryContext': {'AutoFocus.Tag(val.ID == obj.ID)': context},
        'HumanReadable': md
    })


def top_tags_search_command():
    args = demisto.args()
    scope = args.get('scope')
    tag_class = args.get('class')
    private = args.get('private') == 'True'
    public = args.get('public') == 'True'
    commodity = args.get('commodity') == 'True'
    unit42 = args.get('unit42') == 'True'
    info = autofocus_top_tags_search(scope, tag_class, private, public, commodity, unit42)
    md = tableToMarkdown('Top tags search Info:', info)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': info,
        'EntryContext': {'AutoFocus.TopTagsSearch(val.AFCookie == obj.AFCookie)': info},
        'HumanReadable': md
    })


def top_tags_results_command():
    args = demisto.args()
    af_cookie = args.get('af_cookie')
    results, status = get_top_tags_results(af_cookie)
    md = tableToMarkdown(f'Search Top Tags Results is {status}:', results, headerTransform=string_to_table_header)
    context = createContext(results, keyTransform=string_to_context_key)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': {'AutoFocus.TopTagsResults(val.PublicTagName == obj.PublicTagName)': context,
                         'AutoFocus.TopTagsSearch(val.AFCookie == obj.AFCookie)': {'Status': status,
                                                                                   'AFCookie': af_cookie}},
        'HumanReadable': md
    })


def search_ip_command(ip):
    indicator_type = 'IP'
    ip_list = argToList(ip)

    command_results = []

    for ip_address in ip_list:
        raw_res = search_indicator('ipv4_address', ip_address)
        if not raw_res.get('indicator'):
            raise ValueError('Invalid response for indicator')

        indicator = raw_res.get('indicator')
        raw_tags = raw_res.get('tags')

        score = calculate_dbot_score(indicator, indicator_type)
        dbot_score = Common.DBotScore(
            indicator=ip_address,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=score
        )

        ip = Common.IP(
            ip=ip_address,
            dbot_score=dbot_score
        )

        autofocus_ip_output = parse_indicator_response(indicator, raw_tags, indicator_type)

        # create human readable markdown for ip
        tags = autofocus_ip_output.get('Tags')
        table_name = f'{VENDOR_NAME} {indicator_type} reputation for: {ip_address}'
        if tags:
            indicators_data = autofocus_ip_output.copy()
            del indicators_data['Tags']
            md = tableToMarkdown(table_name, indicators_data)
            md += tableToMarkdown('Indicator Tags:', tags)
        else:
            md = tableToMarkdown(table_name, autofocus_ip_output)

        command_results.append(CommandResults(
            outputs_prefix='AutoFocus.IP',
            outputs_key_field='IndicatorValue',
            outputs=autofocus_ip_output,
            readable_output=md,
            raw_response=raw_res,
            indicator=ip
        ))

    return command_results


def search_url_command(url):
    indicator_type = 'URL'
    url_list = argToList(url)

    command_results = []

    for url_name in url_list:

        raw_res = search_indicator('url', url_name)
        if not raw_res.get('indicator'):
            raise ValueError('Invalid response for indicator')

        indicator = raw_res.get('indicator')
        raw_tags = raw_res.get('tags')

        score = calculate_dbot_score(indicator, indicator_type)

        dbot_score = Common.DBotScore(
            indicator=url_name,
            indicator_type=DBotScoreType.URL,
            integration_name=VENDOR_NAME,
            score=score
        )

        url = Common.URL(
            url=url_name,
            dbot_score=dbot_score
        )

        autofocus_url_output = parse_indicator_response(indicator, raw_tags, indicator_type)

        tags = autofocus_url_output.get('Tags')
        table_name = f'{VENDOR_NAME} {indicator_type} reputation for: {url_name}'
        if tags:
            indicators_data = autofocus_url_output.copy()
            del indicators_data['Tags']
            md = tableToMarkdown(table_name, indicators_data)
            md += tableToMarkdown('Indicator Tags:', tags)
        else:
            md = tableToMarkdown(table_name, autofocus_url_output)

        command_results.append(CommandResults(
            outputs_prefix='AutoFocus.URL',
            outputs_key_field='IndicatorValue',
            outputs=autofocus_url_output,

            readable_output=md,
            raw_response=raw_res,
            indicator=url
        ))

    return command_results


def search_file_command(file):
    indicator_type = 'File'
    file_list = argToList(file)

    command_results = []

    for sha256 in file_list:
        raw_res = search_indicator('filehash', sha256.lower())
        if not raw_res.get('indicator'):
            raise ValueError('Invalid response for indicator')

        indicator = raw_res.get('indicator')
        raw_tags = raw_res.get('tags')

        score = calculate_dbot_score(indicator, indicator_type)
        dbot_score = Common.DBotScore(
            indicator=sha256,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=score
        )

        file = Common.File(
            sha256=sha256,
            dbot_score=dbot_score
        )

        autofocus_file_output = parse_indicator_response(indicator, raw_tags, indicator_type)

        tags = autofocus_file_output.get('Tags')
        table_name = f'{VENDOR_NAME} {indicator_type} reputation for: {sha256}'
        if tags:
            indicators_data = autofocus_file_output.copy()
            del indicators_data['Tags']
            md = tableToMarkdown(table_name, indicators_data)
            md += tableToMarkdown('Indicator Tags:', tags)
        else:
            md = tableToMarkdown(table_name, autofocus_file_output)

        command_results.append(CommandResults(
            outputs_prefix='AutoFocus.File',
            outputs_key_field='IndicatorValue',
            outputs=autofocus_file_output,

            readable_output=md,
            raw_response=raw_res,
            indicator=file
        ))

    return command_results


def get_export_list_command(args):
    # the label is the name of the export list we want to fetch.
    # panosFormatted is a flag stating that only indicators should be returned in the list.
    data = {
        'label': args.get('label'),
        'panosFormatted': True,
        'apiKey': ''
    }

    results = http_request(url_suffix='/export', method='POST', data=data,
                           err_operation=f"Failed to fetch export list: {args.get('label')}")

    indicators = []
    context_ip = []
    context_url = []
    context_domain = []
    context_file = []
    for indicator_value in results.get('export_list'):
        indicator_type = find_indicator_type(indicator_value)
        if indicator_type in [FeedIndicatorType.IP,
                              FeedIndicatorType.IPv6, FeedIndicatorType.IPv6CIDR, FeedIndicatorType.CIDR]:
            if '-' in indicator_value:
                context_ip.append({
                    'Address': indicator_value.split('-')[0]
                })
                context_ip.append({
                    'Address': indicator_value.split('-')[1]
                })

            elif ":" in indicator_value:
                context_ip.append({
                    'Address': indicator_value.split(":", 1)[0]
                })

            else:
                context_ip.append({
                    'Address': indicator_value
                })

        elif indicator_type in [FeedIndicatorType.Domain]:
            context_domain.append({
                'Name': indicator_value
            })

        elif indicator_type in [FeedIndicatorType.File]:
            context_file.append({
                'SHA256': indicator_value
            })

        elif indicator_type in [FeedIndicatorType.URL]:
            if ":" in indicator_value:
                resolved_address = resolve_ip_address(indicator_value.split(":", 1)[0])
                semicolon_suffix = indicator_value.split(":", 1)[1]
                slash_suffix = None

            else:
                resolved_address = resolve_ip_address(indicator_value.split("/", 1)[0])
                slash_suffix = indicator_value.split("/", 1)[1]
                semicolon_suffix = None

            if resolved_address:
                if semicolon_suffix:
                    indicator_value = resolved_address + ":" + semicolon_suffix

                else:
                    indicator_value = resolved_address + "/" + slash_suffix

            context_url.append({
                'Data': indicator_value,
            })

        indicators.append({
            'Type': indicator_type,
            'Value': indicator_value,
        })

    hr = tableToMarkdown(f"Export list {args.get('label')}", indicators, headers=['Type', 'Value'])

    return_outputs(hr, {'AutoFocus.Indicator(val.Value == obj.Value && val.Type == obj.Type)': indicators,
                        'IP(obj.Address == val.Address)': context_ip,
                        'URL(obj.Data == val.Data)': context_url,
                        'File(obj.SHA256 == val.SHA256)': context_file,
                        'Domain(obj.Name == val.Name)': context_domain},
                   results)


def main():
    demisto.debug('Command being called is %s' % (demisto.command()))

    try:
        # Remove proxy if not set to true in params
        handle_proxy()
        active_command = demisto.command()

        args = {k: v for (k, v) in demisto.args().items() if v}
        if active_command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif active_command == 'autofocus-search-samples':
            search_samples_command()
        elif active_command == 'autofocus-search-sessions':
            search_sessions_command()
        elif active_command == 'autofocus-samples-search-results':
            samples_search_results_command()
        elif active_command == 'autofocus-sessions-search-results':
            sessions_search_results_command()
        elif active_command == 'autofocus-get-session-details':
            get_session_details_command()
        elif active_command == 'autofocus-sample-analysis':
            sample_analysis_command()
        elif active_command == 'autofocus-tag-details':
            tag_details_command()
        elif active_command == 'autofocus-top-tags-search':
            top_tags_search_command()
        elif active_command == 'autofocus-top-tags-results':
            top_tags_results_command()
        elif active_command == 'autofocus-get-export-list-indicators':
            get_export_list_command(args)
        elif active_command == 'ip':
            return_results(search_ip_command(**args))
        elif active_command == 'domain':
            return_results(search_domain_command(args))
        elif active_command == 'url':
            return_results(search_url_command(**args))
        elif active_command == 'file':
            return_results(search_file_command(**args))

    except Exception as e:
        return_error(f'Unexpected error: {e}.\ntraceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

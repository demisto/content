import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
API_KEY = PARAMS.get('api_key')
# Remove trailing slash to prevent wrong URL path to service
SERVER = 'https://autofocus.paloaltonetworks.com'
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
PROXY = PARAMS.get('proxy')
# Service base URL
BASE_URL = SERVER + '/api/v1.0'
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
        'SHA256': 'sha256',
        'Time': 'tstamp',
        'Upload source': 'upload_srcPossible'
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
        'fileurl': 'FileURL'
    }
}
ANALYSIS_LINE_KEYS = {
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
ANALYSIS_COVERAGE_KEYS = {
    'wf_av_sig': {
        'displayName': 'wildfire_signatures',
        'fields': ['name', 'create_date']
    },
    'fileurl_sig': {
        'displayName': 'wildfire_signatures',
        'fields': ['name', 'create_date']
    },
    'dns_sig': {
        'displayName': 'dns_signatures',
        'fields': ['name', 'create_date']
    },
    'url_cat': {
        'displayName': 'url_categories',
        'fields': ['url', 'cat']
    }
}
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
        return return_error(err_msg)
    # Unexpected errors (where no json object was received)
    except Exception as err:
        err_msg = f'{err_operation}: {err}'
        return return_error(err_msg)


def http_request(url_suffix, method='POST', data={}, err_operation=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    data.update({'apiKey': API_KEY})
    res = requests.request(
        method=method,
        url=BASE_URL + url_suffix,
        verify=USE_SSL,
        data=json.dumps(data),
        headers=HEADERS
    )
    return parse_response(res, err_operation)


def validate_sort_and_order(sort, order):
    if sort and not order:
        return_error('Please specify the order of sorting (Ascending or Descending).')
    if order and not sort:
        return_error('Please specify a field to sort by.')
    return sort and order


def do_search(search_object, query, scope, size=None, sort=None, order=None, err_operation=None):
    path = '/samples/search' if search_object == 'samples' else '/sessions/search'
    data = {
        'query': query,
        'size': size
    }
    if scope:
        data.update({'scope': API_PARAM_DICT['scope'][scope]})
    if validate_sort_and_order(sort, order):
        data.update({'sort': {API_PARAM_DICT['sort'][sort]: {'order': API_PARAM_DICT['order'][order]}}})

    # Remove nulls
    data = createContext(data, removeNull=True)
    result = http_request(path, data=data, err_operation=err_operation)
    return result


def run_search(search_object, query, scope=None, size=None, sort=None, order=None):
    result = do_search(search_object, query=json.loads(query), scope=scope, size=size, sort=sort, order=order,
                       err_operation='Search operation failed')
    in_progress = result.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    search_info = {
        'AFCookie': result.get('af_cookie'),
        'Status': status
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
        if key in af_params_dict:
            new_key = af_params_dict.get(key)
            new_object[new_key] = value
        else:
            new_object[key] = value
    return new_object


def parse_hits_response(hits, response_dict_name):
    parsed_objects = []
    for hit in hits:
        flattened_obj = {}
        flattened_obj.update(hit.get('_source'))
        flattened_obj['_id'] = hit.get('_id')
        parsed_obj = get_fields_from_hit_object(flattened_obj, response_dict_name)
        parsed_objects.append(parsed_obj)
    return parsed_objects


def get_search_results(search_object, af_cookie):
    results = run_get_search_results(search_object, af_cookie)
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
    category_indexes = ANALYSIS_LINE_KEYS.get(category).get('indexes')
    if category == 'behavior':
        risk_index = category_indexes.get('risk')
        risk = line_values[risk_index].strip()
        # only lines with risk higher the informational are considered
        return not risk == 'informational'
    elif category == 'registry':
        action_index = category_indexes.get('action')
        action = line_values[action_index].strip()
        # Only lines with actions SetValueKey, CreateKey or RegSetValueEx are considered
        return action == 'SetValueKey' or action == 'CreateKey' or action == 'RegSetValueEx'
    elif category == 'file':
        action_index = category_indexes.get('action')
        action = line_values[action_index].strip()
        benign_count = info_line.get('b')
        malicious_count = info_line.get('m')
        # Only lines with actions Create or CreateFileW where malicious count is grater than benign count are considered
        return (action == 'Create' or action == 'CreateFileW') and malicious_count > benign_count
    elif category == 'process':
        action_index = category_indexes.get('action')
        action = line_values[action_index].strip()
        # Only lines with actions created, CreateKey or CreateProcessInternalW are considered
        return action == 'created' or action == 'CreateProcessInternalW'
    else:
        return True


def get_data_from_line(line, category_name):
    category_indexes = ANALYSIS_LINE_KEYS.get(category_name).get('indexes')
    values = line.split(',')
    sub_categories = {}
    for sub_category in category_indexes:
        sub_category_index = category_indexes.get(sub_category)
        sub_categories.update({
            sub_category: values[sub_category_index]
        })
    return sub_categories


def parse_lines_from_category(category_name, os, data):
    info_lines = data.get(os)
    new_lines = []
    for info_line in info_lines:
        value = validate_if_line_needed(category_name, info_line)
        if value:
            new_sub_categories = get_data_from_line(info_line.get('line'), category_name)
            new_lines.append(new_sub_categories)
    category_dict = ANALYSIS_LINE_KEYS.get(category_name)
    new_category = {category_dict['display_name']: new_lines}
    return new_category


def parse_sample_analysis_response(resp, os):
    analysis = {}
    for category_name, data in resp.items():
        if category_name in ANALYSIS_LINE_KEYS:
            new_category = parse_lines_from_category(category_name, os, data)
            analysis.update(new_category)

    return analysis


def sample_analysis(sample_id, os):
    path = f'/sample/{sample_id}/analysis'
    data = {
        'platforms': [os],
        'coverage': 'true'
    }
    result = http_request(path, data=data, err_operation='Sample analysis failed')
    analysis_obj = parse_sample_analysis_response(result, os)
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
    ]
    new_tag_info = {}
    for field in fields_to_extract_from_tag_details:
        new_tag_info[field] = tag_details.get(field)
    return new_tag_info


def autofocus_tag_details(tag_name):
    path = f'/tag/{tag_name}'
    resp = http_request(path, err_operation='Tag details operation failed')
    tag_info = parse_tag_details_response(resp)
    return tag_info


def autofocus_top_tags_search(scope, tag_class, private, public, commodity, unit42):
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
    if private == 'True':
        tag_scopes.append('private')
    if public == 'True':
        tag_scopes.append('public')
    if commodity == 'True':
        tag_scopes.append('commodity')
    if unit42 == 'True':
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
    top_tags_list = []
    for tag in response.get('top_tags'):
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
    query = args.get('query')
    scope = args.get('scope')
    max_results = args.get('max_results')
    sort = args.get('sort')
    order = args.get('order')
    info = run_search('samples', query=query, scope=scope, size=max_results, sort=sort, order=order)
    # info = {
    #     'AFCookie': af_cookie,
    #     'Status': status
    # }
    md = tableToMarkdown(f'Search Samples Info:', info)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': info,
        'EntryContext': {'AutoFocus.SamplesSearch(val.AFCookie == obj.AFCookie)': info},
        'HumanReadable': md
    })


def search_sessions_command():
    args = demisto.args()
    query = args.get('query')
    max_results = args.get('max_results')
    sort = args.get('sort')
    order = args.get('order')
    info = run_search('sessions', query=query, size=max_results, sort=sort, order=order)
    # info = {
    #     'AFCookie': af_cookie,
    #     'Status': status
    # }
    md = tableToMarkdown(f'Search Sessions Info:', info)
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
    md = tableToMarkdown(f'Search Samples Results is {status}', results)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': {'AutoFocus.SamplesResults(val.ID == obj.ID)': results},
        'HumanReadable': md
    })


def sessions_search_results_command():
    args = demisto.args()
    af_cookie = args.get('af_cookie')
    results, status = get_search_results('sessions', af_cookie)
    md = tableToMarkdown(f'Search Sessions Results is {status}:', results)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': {'AutoFocus.SessionsResults(val.ID == obj.ID)': results},
        'HumanReadable': md
    })


def get_session_details_command():
    args = demisto.args()
    session_id = args.get('session_id')
    result = get_session_details(session_id)
    md = tableToMarkdown(f'Session {session_id}:', result)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': result,
        'EntryContext': {'AutoFocus.Sessions(val.ID == obj.ID)': result},
        'HumanReadable': md
    })


def sample_analysis_command():
    args = demisto.args()
    sample_id = args.get('sample_id')
    os = args.get('os')
    analysis = sample_analysis(sample_id, os)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': {'ID': sample_id},
        'HumanReadable': f'### Sample Analysis results for {sample_id}:'
    })
    for category_name, category_data in analysis.items():
        md = tableToMarkdown(f'{category_name}:', category_data,
                             headerTransform=string_to_table_header)
        context = createContext(category_data, keyTransform=string_to_context_key)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': analysis,
            'EntryContext': {f'AutoFocus.SampleAnalysis(val.ID == obj.ID).{sample_id}.{category_name}': context},
            'HumanReadable': md
        })


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
    private = args.get('private')
    public = args.get('public')
    commodity = args.get('commodity')
    unit42 = args.get('unit42')
    info = autofocus_top_tags_search(scope, tag_class, private, public, commodity, unit42)
    md = tableToMarkdown(f'Top tags search Info:', info)
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
        'EntryContext': {'AutoFocus.TopTagsResults(val.PublicTagName == obj.PublicTagName)': context},
        'HumanReadable': md
    })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    # Remove proxy if not set to true in params
    handle_proxy()
    active_command = demisto.command()
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


# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
    return_error(f'Unexpected error: {e}')

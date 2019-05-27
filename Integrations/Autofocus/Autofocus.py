import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

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

# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
    return_error(f'Unexpected error: {e}')

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests
import traceback
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
LAST_RUN_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_RESULTS_LIMIT = 50
MAX_TIMEOUT_MINUTES = 5
SESSION_VALIDITY_THRESHOLD = timedelta(minutes=MAX_TIMEOUT_MINUTES)
CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url']
                                          and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('unsecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/3.0'
# Request headers (preparation)
HEADERS = {}


''' HELPER FUNCTIONS '''


def verify_url(url):
    # validate url parameter format, extract port
    try:
        server, port = url.rsplit(':', 1)
        assert 0 < int(port) < 65536

    except (ValueError, AssertionError):
        return_error("Incorrect URL format. Use the following format: https://example.looker.com:19999\n"
                     "The default port for Looker API is 19999.")


def http_request(method, url_suffix, params=None, data=None, response_type='json'):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )

    # Handle error responses gracefully
    if res.status_code not in {200}:
        error_message = f'Error in API call to Looker [{res.status_code}] - {res.reason}'

        # Try to get detailed errors from looker json response
        if res.status_code in (400, 422):
            try:
                error_json = res.json()
                error_message += f"\n{error_json['message']}"

                if res.status_code == 422:
                    validation_error_message = ""
                    for validation_error in error_json['errors']:
                        validation_error_message += f"\n{validation_error['field']} {validation_error['message']}"
                    error_message += validation_error_message
            except (KeyError, ValueError):
                pass

        raise requests.exceptions.HTTPError(error_message)

    # Return by expected type
    if response_type != 'json':
        return res.content

    res_obj = res.json()

    # Handle non-http type error messages from looker
    if isinstance(res_obj, list) and len(res_obj) == 1 and \
            isinstance(res_obj[0], dict) and 'looker_error' in res_obj[0]:
        raise Exception(res_obj[0]['looker_error'])

    return res_obj


def get_new_token():
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response_json = http_request('POST', '/login', data=data)

    return {
        'token': response_json['access_token'],
        'expires': datetime.utcnow().timestamp() + response_json['expires_in']
    }


def get_session_token():
    global HEADERS
    ic = demisto.getIntegrationContext()

    if CLIENT_ID not in ic or 'expires' not in ic[CLIENT_ID] \
            or datetime.fromtimestamp(ic[CLIENT_ID]['expires']) < datetime.utcnow() + SESSION_VALIDITY_THRESHOLD:
        ic[CLIENT_ID] = get_new_token()
        if demisto.command() != 'test-module':
            demisto.setIntegrationContext(ic)

    HEADERS['Authorization'] = 'token {}'.format(ic[CLIENT_ID]['token'])


def get_limit():
    try:
        limit = int(demisto.args().get('limit', DEFAULT_RESULTS_LIMIT))
        return None if limit == 0 else limit

    except ValueError:
        return_error("limit must be a number")


def get_look_id_from_name(name):
    looks = search_looks_request({'title': name})
    if len(looks) < 1:
        raise Exception(f'No Look found with the name {name}.')
    if len(looks) > 1:
        raise Exception(f'There is more than one Look with the name {name}.'
                        f"Use look ID instead - It can be found in the Look's URL or by running looker-search-looks")

    return looks[0]['ID']


def full_path_headers(src_data, base_path):
    def to_full_path(k):
        return f"{base_path}.{k}"

    def full_path_headers_for_dict(src):
        if not isinstance(src, dict):
            return src

        return {to_full_path(k): v for k, v in src.items()}

    if not isinstance(src_data, list):
        src_data = [src_data]

    return [full_path_headers_for_dict(x) for x in src_data]


def parse_filters_arg(filters_arg_value):
    error_message = "'filters' argument format is invalid.\n"

    filters_list = argToList(filters_arg_value, ';')
    filters_list = [elem for elem in [x.strip() for x in filters_list] if elem]  # Remove empty elems
    if not filters_list:
        return

    filters = {}
    filters_and_indices_list = zip(range(len(filters_list)), filters_list)  # Track element index for error messages
    for i, elem in filters_and_indices_list:
        try:
            k, v = elem.split('=', 1)
            k = k.strip()
            if not k:
                return_error(f"{error_message}Filter in position {i+1}: field is empty.")
            v = v.strip()
            if not v:
                return_error(f"{error_message}Filter in position {i+1} ({k}): value is empty.")
            filters[k] = v
        except ValueError:
            return_error(f"{error_message}Filter in position {i+1} is missing '=' separator")

    return filters


def get_entries_for_search_results(contents, look_id=None, result_format='json'):
    entries = []
    if result_format == 'json':
        camelized = camelize(contents, delim='_')
        formatted_contents = replace_in_keys(camelized)
        if not isinstance(formatted_contents, list):
            formatted_contents = [formatted_contents]

        if look_id:
            context = {
                'LookerResults(val.LookID && val.LookID === obj.LookID)': {
                    'LookID': int(look_id),
                    'Results': formatted_contents
                }
            }
            hr_title = f'Results for look #{look_id}'
            full_path_header_content = full_path_headers(formatted_contents, 'LookerResults.Results')
        else:
            context = {'LookerResults.InlineQuery': formatted_contents}
            hr_title = 'Inline Query Results'
            full_path_header_content = full_path_headers(formatted_contents, 'LookerResults.InlineQuery')

        entries.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contents,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(hr_title, full_path_header_content, removeNull=True),
            'EntryContext': context
        })

        if contents:
            entries.append(
                'This command has dynamic output keys.\n'
                'To access them in the context, copy the key\'s path from the column header in the results table.'
            )

    elif result_format == 'csv':
        entries.append(fileResult('look_result.csv' if look_id else 'inline_query_result.csv', contents,
                                  entryTypes['entryInfoFile']))

    return entries


def get_query_args():
    str_args = ('model', 'view')
    list_args = ('fields', 'pivots', 'sorts')
    args_dict = {k: argToList(demisto.args()[k]) for k in list_args if k in demisto.args()}  # Parse list-type arguments
    args_dict.update({k: demisto.args()[k] for k in str_args})  # Add string-type arguments
    filters = parse_filters_arg(demisto.args().get('filters'))  # Handle special argument
    if filters:
        args_dict['filters'] = filters

    return args_dict


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to check connectivity and authentication
    """
    http_request('GET', '/user')


def run_look_command():
    look_id = demisto.args().get('id')
    look_name = demisto.args().get('name')
    if not any((look_id, look_name)):
        raise Exception('Provide Look id or name.')
    if look_name and not look_id:
        look_id = get_look_id_from_name(look_name)

    result_format = demisto.args()['result_format']
    limit = get_limit()
    fields = argToList(demisto.args().get('result_format'))

    contents = run_look_request(look_id, result_format, limit, fields)

    demisto.results(get_entries_for_search_results(contents, look_id, result_format))


def run_look_request(look_id, result_format, limit, fields):
    endpoint_url = f'/looks/{look_id}/run/{result_format}'
    params = {}
    if limit:
        params['limit'] = limit
    if fields:
        params['fields'] = fields
    return http_request('GET', endpoint_url, params=params, response_type=result_format)


def search_looks_command():
    command_args = ('space_id', 'user_id')  # Possible command arguments
    args_dict = {k: demisto.args()[k] for k in command_args if k in demisto.args()}  # Get args that were passed

    # Arguments with special logic
    args_dict['limit'] = get_limit()
    if 'name' in demisto.args():
        args_dict['title'] = demisto.args()['name']

    contents = search_looks_request(args_dict)
    context = {f'Looker.Look(val.ID && val.ID === {look["ID"]})': look for look in contents}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Look search results', contents, removeNull=True),
        'EntryContext': context
    })


def search_looks_request(args):
    endpoint_url = '/looks/search'
    params = {k: v for k, v in args.items() if v}
    params['fields'] = 'id, title, space, updated_at'
    response = http_request('GET', endpoint_url, params=params)

    if not isinstance(response, list):
        response = [response]

    return [
        {
            'ID': look['id'],
            'Name': look['title'],
            'SpaceID': look['space']['id'],
            'SpaceName': look['space']['name'],
            'LastUpdated': look['updated_at'].replace('+00:00', 'Z')
        } for look in response
    ]


def run_inline_query_command():
    result_format = demisto.args()['result_format']
    args_dict = get_query_args()

    args_dict['limit'] = get_limit()

    contents = run_inline_query_request(result_format, args_dict)

    demisto.results(get_entries_for_search_results(contents, result_format=result_format))


def run_inline_query_request(result_format, args_dict):
    return http_request(
        method='POST',
        url_suffix=f'/queries/run/{result_format}',
        data=json.dumps(args_dict),
        response_type=result_format
    )


def create_look_command():
    space_id = demisto.args()['look_space_id']
    try:
        space_id = int(space_id)
    except ValueError:
        return_error(f'space_id: invalid number: {space_id}')

    look_title = demisto.args()['look_title']
    look_description = demisto.args().get('look_description')
    args_dict = get_query_args()

    create_query_response = create_query_request(args_dict)
    query_id = create_query_response['id']

    contents = create_look_request(query_id, space_id, look_title, look_description)

    context = {f'Looker.Look(val.ID && val.ID === {contents["ID"]})': contents}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Look "{look_title}" created successfully', contents, removeNull=True),
        'EntryContext': context
    })


def create_query_request(args_dict):
    return http_request(method='POST', url_suffix='/queries', data=json.dumps(args_dict))


def create_look_request(query_id, space_id, look_title, look_description=""):
    data = {
        'title': look_title,
        'query_id': query_id,
        'space_id': space_id
    }
    if look_description:
        data['look_description'] = look_description

    look = http_request(method='POST', url_suffix='/looks', data=json.dumps(data))

    return {
        'ID': look['id'],
        'Name': look['title'],
        'SpaceID': look['space']['id'],
        'SpaceName': look['space']['name'],
        'LastUpdated': look['updated_at'].replace('+00:00', 'Z')
    }


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
try:
    handle_proxy()
    verify_url(SERVER)
    get_session_token()

    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'looker-run-look':
        run_look_command()
    elif demisto.command() == 'looker-search-looks':
        search_looks_command()
    elif demisto.command() == 'looker-run-inline-query':
        run_inline_query_command()
    elif demisto.command() == 'looker-create-look':
        create_look_command()

# Log exceptions
except Exception as e:
    LOG(e)
    LOG(traceback.format_exc())
    LOG.print_log(verbose=True)  # TODO: Remove verbosity
    demisto.results(e)

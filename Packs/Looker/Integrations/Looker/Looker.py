import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from typing import Dict
import requests
import traceback
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''
LAST_RUN_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_RESULTS_LIMIT = 50
MAX_TIMEOUT_MINUTES = 5


''' GLOBALS/PARAMS '''
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
HEADERS: Dict[str, str] = {}


''' HELPER FUNCTIONS '''


def verify_url(url):
    # validate url parameter format, extract port
    try:
        server, port = url.rsplit(':', 1)
        assert 0 < int(port) < 65536

    except (ValueError, AssertionError):
        raise ValueError("Incorrect URL format. Use the following format: https://example.looker.com:19999\n"
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


def get_new_token(client_id, client_secret):
    data = {
        'client_id': client_id,
        'client_secret': client_secret
    }

    try:
        response_json = http_request('POST', '/login', data=data)

        return {
            'token': response_json['access_token'],
            'expires': datetime.utcnow().timestamp() + response_json['expires_in']
        }

    except requests.exceptions.HTTPError as ex:
        if '[404]' in str(ex):
            raise Exception("Got 404 from server - check 'API3 Client ID' and 'API3 Client Secret' fields "
                            "in the instance configuration.")
        raise


def get_session_token(client_id, client_secret):
    ic = demisto.getIntegrationContext()

    if client_id not in ic or 'expires' not in ic[client_id] \
            or datetime.fromtimestamp(ic[client_id]['expires']) < datetime.utcnow() + SESSION_VALIDITY_THRESHOLD:
        ic[client_id] = get_new_token(client_id, client_secret)
        if demisto.command() != 'test-module':
            demisto.setIntegrationContext(ic)

    return 'token {}'.format(ic[client_id]['token'])


def get_limit():
    try:
        limit = int(demisto.args().get('limit', DEFAULT_RESULTS_LIMIT))
        return None if limit == 0 else limit

    except ValueError:
        raise ValueError("limit must be a number")


def get_look_id_from_name(name):
    looks = search_looks({'title': name})
    if len(looks) < 1:
        raise Exception(f'No Look found with the name {name}.')
    if len(looks) > 1:
        raise Exception(f'There is more than one Look with the name "{name}".'
                        f"\nUse look ID instead - It can be found in the Look's URL or by running looker-search-looks")

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
                raise ValueError(f"{error_message}Filter in position {i+1}: field is empty.")
            v = v.strip()
            if not v:
                raise ValueError(f"{error_message}Filter in position {i+1} ({k}): value is empty.")
            filters[k] = v
        except ValueError:
            raise ValueError(f"{error_message}Filter in position {i+1} is missing '=' separator")

    return filters


def get_entries_for_search_results(contents, look_id=None, result_format='json', look_name=''):
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
            hr_title = f'Results for look "{look_name}"' if look_name else f'Results for look #{look_id}'
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
            entries.append(  # type: ignore
                'This command has dynamic output keys.\n'  # type: ignore
                'To access them in the context, copy the key\'s path from the column header in the results table.'
            )

    elif result_format == 'csv':
        entries.append(fileResult('look_result.csv' if look_id else 'inline_query_result.csv', contents,
                                  entryTypes['entryInfoFile']))

    return entries


def get_query_args(demisto_args):
    str_args = ('model', 'view')
    list_args = ('fields', 'pivots', 'sorts')
    args_dict = {k: argToList(demisto_args[k]) for k in list_args if k in demisto_args}  # Parse list-type arguments
    args_dict.update({k: demisto_args[k] for k in str_args})  # Add string-type arguments
    filters = parse_filters_arg(demisto_args.get('filters'))  # Handle special argument
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

    contents = run_look(look_id, result_format, limit, fields)

    demisto.results(get_entries_for_search_results(contents, look_id, result_format, look_name))


def run_look(look_id, result_format, limit, fields):
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

    contents = search_looks(args_dict)
    context = {f'Looker.Look(val.ID && val.ID === {look["ID"]})': look for look in contents}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Look search results', contents, removeNull=True),
        'EntryContext': context
    })


def search_looks(args):
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
    args_dict = get_query_args(demisto.args())

    args_dict['limit'] = get_limit()

    contents = run_inline_query(result_format, args_dict)

    demisto.results(get_entries_for_search_results(contents, result_format=result_format))


def run_inline_query(result_format, args_dict):
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
        raise ValueError(f'space_id: invalid number: {space_id}')

    look_title = demisto.args()['look_title']
    look_description = demisto.args().get('look_description')
    args_dict = get_query_args(demisto.args())

    create_query_response = create_query(args_dict)
    query_id = create_query_response['id']

    contents = create_look(query_id, space_id, look_title, look_description)

    context = {f'Looker.Look(val.ID && val.ID === {contents["ID"]})': contents}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Look "{look_title}" created successfully', contents, removeNull=True),
        'EntryContext': context
    })


def create_query(args_dict):
    return http_request(method='POST', url_suffix='/queries', data=json.dumps(args_dict))


def create_look(query_id, space_id, look_title, look_description=""):
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


def main():
    LOG('Command being called is %s' % (demisto.command()))
    try:
        handle_proxy()
        verify_url(SERVER)
        HEADERS['Authorization'] = get_session_token(CLIENT_ID, CLIENT_SECRET)

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
        LOG.print_log()
        if demisto.command() == 'test-module':
            demisto.results(e)
        else:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

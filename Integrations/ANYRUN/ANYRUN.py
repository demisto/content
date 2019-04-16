import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from base64 import b64encode

''' GLOBAL VARS / INSTANCE CONFIGURATION '''

PARAMS = demisto.params()
USERNAME = PARAMS.get('credentials').get('identifier')
PASSWORD = PARAMS.get('credentials').get('password')
AUTH = (USERNAME + ':' + PASSWORD).encode('utf-8')
BASIC_AUTH = 'Basic ' + b64encode(AUTH).decode()
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS.get('url')
SERVER = SERVER[:-1] if (SERVER and SERVER.endswith('/')) else SERVER
# Service base URL
BASE_URL = SERVER + '/v1/'
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
PROXY = PARAMS.get('proxy')
# Headers to be sent in requests
HEADERS = {
    'Authorization': BASIC_AUTH
}
# Context fields that should always be uppercase
ALWAYS_UPPER_CASE = {
    'md5', 'sha1', 'sha-1', 'sha256', 'sha-256', 'sha512', 'sha-512', 'ssdeep',
    'pcap', 'ip', 'url'
}

''' SETUP '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Remove proxy if not set to true in params
if not PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''


def make_upper(the_string):
    """
    Make 'the_string' argument uppercase if it is a member of
    'ALWAYS_UPPER_CASE' global variable
    """
    if the_string.casefold() in ALWAYS_UPPER_CASE:
        return the_string.upper()
    else:
        return the_string


def make_capital(the_string):
    """Capitalize first letter of a string, leaving the rest of the string as is"""
    case_insensitive_string = the_string.casefold()

    if case_insensitive_string == 'os':
        return 'OS'
    if case_insensitive_string == 'id':
        return 'ID'

    if len(the_string) >= 1:
        return the_string[0:1].upper() + the_string[1:]
    else:
        err_msg = '"make_capital" function requires a string '
        err_msg += 'argument whose length is greater than or equal to one.'
        raise ValueError(err_msg)


def make_singular(word):
    """Relatively naive function to make a word singular - aka imperfect"""
    if not word or len(word) == 0:
        err_msg = '"make_singular" function requires a string '
        err_msg += 'argument whose length is greater than or equal to one.'
        raise ValueError(err_msg)

    word_as_lower = word.casefold()
    # Not a plural
    if not word_as_lower.endswith('s'):
        return word
    # Word ends in 's' and is therefore possibly plural
    else:
        es_endings = ('sses', 'shes', 'ches', 'xes', 'zes')
        if word_as_lower.endswith(es_endings):
            # Then the word was pluralized by adding 'es'
            return word[:-2]
        elif word_as_lower.endswith('ss'):
            # Then it's probably not a plural, e.g. 'assess' or 'process'
            return word
        elif len(word) <= 2:
            # Then it's probably not a plural, e.g. 'OS'
            return word
        elif word_as_lower.endswith('sis') or word_as_lower.endswith('us'):
            # Then it's probably singular like 'analysis' and 'cactus' and 'focus'
            return word
        else:
            # Assume regular noun pluralization of adding an 's'
            return word[:-1]


def recursive_format(obj, *formatting_functions):
    """Recursively format keys of a dictionary using the functions passed as positional arguments"""
    def format_dict(the_dict):
        new_dict = {}
        for key, val in the_dict.items():
            new_key = key
            for func in formatting_functions:
                new_key = func(new_key)
            if isinstance(val, dict) or isinstance(val, list):
                new_val = recursive_format(val, *formatting_functions)
            else:
                new_val = val
            new_dict[new_key] = new_val
        return new_dict

    if isinstance(obj, list):
        new_list = []
        for item in obj:
            new_item = format_dict(item) if isinstance(item, dict) else item
            new_list.append(new_item)
        return new_list
    elif isinstance(obj, dict):
        formatted_dict = format_dict(obj)
        return formatted_dict
    else:
        err_msg = 'Invalid type: the passed "obj" argument was not of type "dict" or "list".'
        raise TypeError(err_msg)


def argToBool(arg):
    if arg.lower() == 'true':
        return True
    return False


def report_to_context(response):
    data = response.get('data', {})
    environment = data.get('environments', {})
    analysis = data.get('analysis', {})
    process = data.get('processes', {})

    # Retrieve environment info from response
    os = environment.get('os', {})
    # os = {make_capital(key): val for key, val in os.items()}

    # Retrieve threat score + info from response
    score = analysis.get('scores', {})
    # verdict = score.get('verdict', {})
    # verdict = {make_capital(key): val for key, val in verdict.items()}
    # spec = score.get('specs', {})
    # spec = {make_capital(key): val for key, val in spec.items()}

    # Retrieve analysis time stuff
    start_epoch = analysis.get('creation')
    start_text = analysis.get('creationText')
    duration = analysis.get('duration')

    # Retrieve dropped file info from response
    content = analysis.get('content', {})
    main_object = content.get('mainObject', {})

    # Retrieve network details
    network = data.get('network', {})

    contents = {
        'Environment': {
            'OS': os
        },
        'Analysis': {
            'Score': score,
            'Submission': main_object,
            'Time': {
                'StartEpoch': start_epoch,
                'StartText': start_text,
                'Duration': duration
            }
        },
        'Network': network,
        'Process': process
    }
    return contents


def http_request(method, url_suffix, params=None, data=None, files=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        files=files,
        headers=HEADERS
    )

    j_son = res.json()

    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        err_msg = 'Error in API call to Example Integration {} - {}'.format(res.status_code, res.reason)
        if j_son.get('error'):
            err_msg += '\n{}'.format(j_son.get('message'))
        return_error(err_msg)

    return j_son


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_history()
    demisto.results('ok')


def get_history(args={}):
    filter = args.pop('filter', None)

    # API call
    url_suffix = 'analysis/'
    params = args
    response = http_request('GET', url_suffix=url_suffix, params=params)

    # Filter response
    tasks = response.get('data', {}).get('tasks', {})
    desired_fields = {'file', 'related', 'verdict', 'date'}
    filtered_tasks = []
    for task in tasks:
        name = task.get('name', None)
        hashes = task.get('hashes', None)
        if filter and filter not in {name, *hashes.values()}:
            continue
        filtered_task = {'name': name}
        for field in task:
            if field in desired_fields:
                filtered_task[field] = task.get(field, None)
        filtered_task['hashes'] = hashes
        filtered_tasks.append(filtered_task)

    return {'tasks': filtered_tasks}


def get_history_command():
    args = demisto.args()
    filter = args.get('filter', None)
    response = get_history(args)

    formatting_funcs = [underscoreToCamelCase, make_capital, make_singular, make_upper]
    formatted_response = recursive_format(response, *formatting_funcs)
    entry_context = {
        'ANYRUN': formatted_response
    }
    title = 'Task History - Filtered By "{}"'.format(filter) if filter else 'Task History'
    human_readable = tableToMarkdown(title, formatted_response, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


def get_report(task_id):
    url_suffix = 'analysis/' + task_id
    response = http_request('GET', url_suffix=url_suffix)
    return response


def get_report_command():
    args = demisto.args()
    task_id = args.get('task')
    response = get_report(task_id)

    contents = report_to_context(response)
    formatting_funcs = [underscoreToCamelCase, make_capital, make_singular, make_upper]
    contents = recursive_format(contents, *formatting_funcs)

    entry_context = {'ANYRUN': contents}

    title = 'Report for Task {}'.format(task_id)
    human_readable = tableToMarkdown(title, contents, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


def run_analysis(args):
    obj_type = args.get('obj_type')
    if obj_type == 'file':
        entry_id = args.get('file')
        cmd_res = demisto.getFilePath(entry_id)
        file_path = cmd_res.get('path')
        name = cmd_res.get('name')
        files = {
            'file': (name, open(path, 'rb'))
        }
    del args['file']
    env_bitness = int(args.get('env_bitness', 32))
    args['env_bitness'] = env_bitness
    env_version = args.get('env_version').lower()
    if env_version == 'windows vista':
        args['env_version'] = 'vista'
    elif env_version == 'windows 8.1':
        args['env_version'] = '8.1'
    elif env_version == 'windows 10':
        args['env_version'] = '10'
    else:
        args['env_version'] = '7'
    opt_network_connect = argToBool(args.get('opt_network_connect', 'true'))
    args['opt_network_connect'] = opt_network_connect
    opt_kernel_heavyevasion = argToBool(args.get('opt_kernel_heavyevasion', 'false'))
    args['opt_kernel_heavyevasion'] = opt_kernel_heavyevasion
    url_suffix = 'analysis'
    response = http_request('POST', url_suffix, params=args, files=files)
    return response




def run_analysis_command():
    args = demisto.args()
    response = run_analysis(args)
    task_id = response.get('data', {}).get('taskid')
    title = 'Analysis Task ID'
    human_readable = tableToMarkdown(title, task_id, removeNull=True)
    entry_context = {'ANYRUN.Task(val.ID && val.ID === obj.ID)': task_id}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


def get_environments():
    pass


def get_environments_command():
    pass


def get_user_limits():
    pass


def get_user_limits_command():
    pass


def get_items_command():
    """
    Gets details about a items using IDs or some other filters
    """
    # Init main vars
    headers = []
    contents = []
    context = {}
    context_entries = []
    title = ''
    # Get arguments from user
    item_ids = argToList(demisto.args().get('item_ids', []))
    is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
    limit = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    items = get_items_request(item_ids, is_active)
    # Parse response into context & content entries
    if items:
        if limit:
            items = items[:limit]
        title = 'Example - Getting Items Details'

        for item in items:
            contents.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'Created Date': item.get('createdDate')
            })
            context_entries.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'CreatedDate': item.get('createdDate')
            })

        context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_items_request(item_ids, is_active):
    # The service endpoint to request from
    endpoint_url = 'items'
    # Dictionary of params for the request
    params = {
        'ids': item_ids,
        'isActive': is_active
    }
    # Send a request using our http_request wrapper
    response = http_request('GET', endpoint_url, params)
    # Check if response contains errors
    if response.get('errors'):
        return_error(response.get('errors'))
    # Check if response contains any data to parse
    if 'data' in response:
        return response.get('data')
    # If neither was found, return back empty results
    return {}


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'anyrun-get-history': get_history_command,
    'anyrun-get-report': get_report_command,
    'anyrun-run-analysis': run_analysis_command,
    'anyrun-get-environments': get_environments_command,
    'anyrun-get-user-limits': get_user_limits_command
}


''' EXECUTION '''


def main():
    """Definition of Instance Parameters and Main Execution block """

    try:
        cmd_name = demisto.command()
        LOG('Command being called is {}'.format(cmd_name))

        if cmd_name in COMMANDS.keys():
            COMMANDS[cmd_name]()

    except Exception as e:
        # return_error(str(e))
        raise e

# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()

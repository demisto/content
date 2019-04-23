import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import re
import os
import json
import requests
from base64 import b64encode

''' GLOBAL VARS / INSTANCE CONFIGURATION '''

PARAMS = demisto.params()
USERNAME = PARAMS.get('credentials', {}).get('identifier', '')
PASSWORD = PARAMS.get('credentials', {}).get('password', '')
AUTH = (USERNAME + ':' + PASSWORD).encode('utf-8')
BASIC_AUTH = 'Basic ' + b64encode(AUTH).decode()
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS.get('url', '')
SERVER = SERVER[:-1] if (SERVER and SERVER.endswith('/')) else SERVER
# Service base URL
BASE_URL = SERVER + '/v1/'
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
PROXY = PARAMS.get('proxy', False)
# Headers to be sent in requests
HEADERS = {
    'Authorization': BASIC_AUTH
}
# Context fields that should always be uppercase
ALWAYS_UPPER_CASE = {
    'md5', 'sha1', 'sha256', 'sha512', 'ssdeep',
    'pcap', 'ip', 'url', 'id', 'pid', 'ppid', 'uuid', 'asn', 'mime'
}
THREAT_TEXT_TO_DBOTSCORE = {
    'no threats detected': 1,
    'suspicious activity': 2,
    'malicious activity': 3
}

''' SETUP '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Remove proxy if not set to true in params
if not PROXY:
    os.environ.pop('HTTP_PROXY')
    os.environ.pop('HTTPS_PROXY')
    os.environ.pop('http_proxy')
    os.environ.pop('https_proxy')

''' HELPER FUNCTIONS '''


def underscore_to_camel_case(s):
    """
    Convert an underscore separated string to camel case, leaving one-word strings untouched

    Parameters
    ----------
    s : str
        The string to convert (e.g. heLLo_world) (required).

    Returns
    -------
    str
        The converted string (e.g. heLLoWorld).
    """

    if not isinstance(s, STRING_TYPES):
        return s
    components = s.split('_')
    return ''.join(x.title() if i != 0 else x for i, x in enumerate(components))


def anyrun_threatlevel_to_dbotscore(threat_level):
    """Convert ANYRUN threat level to its equivalent DBotScore

    Parameters
    ----------
    threat_level : int
        Threat level from an ANYRUN task analysis verdict.

    Returns
    -------
    int
        Score to be used in a DBotScore object.
    """

    return threat_level + 1


def make_upper(string):
    """
    Make argument uppercase if it is a member of 'ALWAYS_UPPER_CASE' global variable

    Parameters
    ----------
    string : str
        The string to check and potentially make uppercase.

    Returns
    -------
    str
        Uppercased string (or original string if it didn't match the criteria).
    """

    if isinstance(string, str) and string.casefold() in ALWAYS_UPPER_CASE:
        return string.upper()
    else:
        return string


def make_capital(string):
    """Capitalize first letter of a string, leaving the rest of the string as is

    Parameters
    ----------
    string : str
        The string to capitalize (e.g. 'foRUm').

    Returns
    -------
    str
        The capitalized string (e.g. 'FoRUm').
    """

    if isinstance(string, str) and string:
        return string[:1].upper() + string[1:]
    else:
        err_msg = '"make_capital" function requires a string ' \
                'argument whose length is greater than or equal to one.'
        raise ValueError(err_msg)


def make_singular(word):
    """Relatively naive/imperfect function to make a word singular

    Parameters
    ----------
    word : str
        The string to make singular (e.g. 'zebras').

    Returns
    -------
    str
        The string in singular form (e.e. 'zebra').
    """

    if not word or len(word) == 0:
        err_msg = '"make_singular" function requires a string ' \
                'argument whose length is greater than or equal to one.'
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


def travel_object(obj, key_functions=[], val_functions=[]):
    """Recursively apply functions to the keys and values of a dictionary

    Parameters
    ----------
    obj : dict/list
        List or dict to recurse through.
    key_functions : list
        Functions to apply to the keys in 'obj'.
    val_functions : list
        Functions to apply to the values in 'obj'

    Returns
    -------
    list/dict
        A list or dict in which all nested keys and values have been
        altered by the key_functions and val_functions respectively.
    """

    def operate_on_dict(the_dict):
        new_dict = {}
        for key, val in the_dict.items():
            new_key = key
            for key_func in key_functions:
                new_key = key_func(new_key)
            if isinstance(val, dict) or isinstance(val, list):
                new_val = travel_object(val, key_functions=key_functions, val_functions=val_functions)
            else:
                new_val = val
                for val_func in val_functions:
                    new_val = val_func(val)
            new_dict[new_key] = new_val
        return new_dict

    if isinstance(obj, list):
        new_list = []
        for item in obj:
            new_item = operate_on_dict(item) if isinstance(item, dict) else item
            new_list.append(new_item)
        return new_list
    elif isinstance(obj, dict):
        altered_dict = operate_on_dict(obj)
        return altered_dict
    else:
        err_msg = 'Invalid type: the passed "obj" argument was not of type "dict" or "list".'
        raise TypeError(err_msg)


def generate_dbotscore(response):
    """Creates DBotScore object based on the contents of 'response' argument

    Parameters
    ----------
    response : dict
        Object returned by ANYRUN API call in 'get_report' function.

    Returns
    -------
    dict
        A DBotScore object.
    """

    analysis = response.get('data', {}).get('analysis', {})
    main_object = analysis.get('content', {}).get('mainObject', {})
    submission_type = main_object.get('type')
    submission_type = 'hash' if submission_type in {'file', 'download'} else submission_type
    threat_text = analysis.get('scores', {}).get('verdict', {}).get('threatLevelText', '').casefold()
    if submission_type == 'hash':
        hashes = main_object.get('hashes', {})
        indicator = hashes.get('sha256', hashes.get('sha1', hashes.get('md5')))
    else:
        indicator = main_object.get('url', '')
    dbot_score = {
        "DBotScore": {
            "Indicator": indicator,
            "Type": submission_type,
            "Vendor": "ANYRUN",
            "Score": THREAT_TEXT_TO_DBOTSCORE.get(threat_text, 0)
        }
    }
    return dbot_score


def add_malicious_key(entity, verdict):
    """Return the entity with the additional 'Malicious' key if determined as such by ANYRUN

    Parameters
    ----------
    entity : dict
        File or URL object.
    verdict : dict
        Task analysis verdict for a detonated file or url.

    Returns
    -------
    dict
        The modified entity if it was malicious, otherwise the original entity.
    """

    threat_level_text = verdict.get('threatLevelText', '')

    if threat_level_text.casefold() == 'malicious activity':
        entity['Malicious'] = {
            'Vendor': 'ANYRUN',
            'Description': threat_level_text
        }
    return entity


def ec_file(main_object):
    """Return File entity in Demisto format for use in entry context

    Parameters
    ----------
    main_object : dict
        The main object from a report's contents.

    Returns
    -------
    dict
        File object populated by report contents.
    """

    name = main_object.get('filename', None)
    hashes = main_object.get('hashes', {})
    md5 = hashes.get('md5', None)
    sha1 = hashes.get('sha1', None)
    sha256 = hashes.get('sha256', None)
    ssdeep = hashes.get('ssdeep', None)
    ext = main_object.get('info', {}).get('ext', None)

    file_ec = {
        'File': {
            'Name': name,
            'MD5': md5,
            'SHA1': sha1,
            'SHA256': sha256,
            'SSDeep': ssdeep,
            'Extension': ext
        }
    }
    return file_ec


def ec_url(main_object):
    """Return URL entity in Demisto format for use in entry context

    Parameters
    ----------
    main_object : dict
        The main object from a report's contents.

    Returns
    -------
    dict
        URL object populated by report contents.
    """

    url = main_object.get('url', None)

    url_ec = {
        'URL': {
            'Data': url
        }
    }
    return url_ec


def ec_entity(response):
    """
    Return URL or File entity in Demisto format for use in entry
    context depending on data in 'response' (the report)

    Parameters
    ----------
    response : dict
        Object returned by ANYRUN API call in 'get_report' function.

    Returns
    -------
    dict
        File or URL object populated by report contents.
    """

    analysis = response.get('data', {}).get('analysis', {})
    verdict = analysis.get('scores', {}).get('verdict', {})
    main_object = analysis.get('content', {}).get('mainObject', {})
    submission_type = main_object.get('type', None)
    entity = None
    if submission_type == 'url':
        entity = ec_url(main_object)
        entity['URL'] = add_malicious_key(entity.get('URL', {}), verdict)
    else:
        entity = ec_file(main_object)
        entity['File'] = add_malicious_key(entity.get('File', {}), verdict)
    return entity


def taskid_from_url(anyrun_url):
    """Extract task ID from ANYRUN url inside a 'task' result returned by the get_history command

    Parameters
    ----------
    anyrun_url : str
        URL that contains an ANYRUN task ID.

    Returns
    -------
    str
        An ANYRUN task ID.
    """

    pattern = r'tasks/(.*?)/'
    match = re.search(pattern, anyrun_url)
    if match:
        task_id = match.groups()[0]
    else:
        task_id = None
    return task_id


def contents_from_report(response):
    """Selectively retrieve content from an ANYRUN report

    Parameters
    ----------
    response : dict
        Object returned by ANYRUN API call in 'get_report' function.

    Returns
    -------
    dict
        Selected content from ANYRUN report.
    """

    data = response.get('data', {})
    environment = data.get('environments', {})
    analysis = data.get('analysis', {})
    processes = data.get('processes', [])
    incidents = data.get('incidents', [])
    status = data.get('status', '')

    # Retrieve environment info from response
    os = environment.get('os', {}).get('title')

    # Retrieve threat score + info from response
    score = analysis.get('scores', {})
    verdict = score.get('verdict', {})
    threat_level_text = verdict.get('threatLevelText', None)

    # Retrieve analysis time stuff
    start_text = analysis.get('creationText')

    # Retrieve submitted file info from response
    content = analysis.get('content', {})
    main_object = content.get('mainObject', {})
    info = main_object.get('info', {})
    mime = info.get('mime', None)
    file_info = info.get('file', None)
    hashes = main_object.get('hashes', None)

    # Retrieve network details
    network = data.get('network', {})
    threats = network.get('threats', [])
    connections = network.get('connections', [])
    http_reqs = network.get('httpRequests', [])
    dns_requests = network.get('dnsRequests', [])

    reformatted_threats = []
    for threat in threats:
        reformatted_threat = {
            'ProcessUUID': threat.get('process', None),
            'Message': threat.get('msg', None),
            'Class': threat.get('class', None),
            'SrcPort': threat.get('srcport', None),
            'DstPort': threat.get('dstport', None),
            'SrcIP': threat.get('srcip', None),
            'DstIP': threat.get('dstip', None)
        }
        reformatted_threats.append(reformatted_threat)
    network['threats'] = reformatted_threats

    reformatted_connections = []
    for connection in connections:
        reformatted_connection = {
            'Reputation': connection.get('reputation', None),
            'ProcessUUID': connection.get('process', None),
            'ASN': connection.get('asn', None),
            'Country': connection.get('country', None),
            'Protocol': connection.get('protocol', None),
            'Port': connection.get('port', None),
            'IP': connection.get('ip', None)
        }
        reformatted_connections.append(reformatted_connection)
    network['connections'] = reformatted_connections

    reformatted_http_reqs = []
    for http_req in http_reqs:
        reformatted_http_req = {
            'Reputation': http_req.get('reputation', None),
            'Country': http_req.get('country', None),
            'ProcessUUID': http_req.get('process', None),
            'Body': http_req.get('body', None),
            'HttpCode': http_req.get('httpCode', None),
            'Status': http_req.get('status', None),
            'ProxyDetected': http_req.get('proxyDetected', None),
            'Port': http_req.get('port', None),
            'IP': http_req.get('ip', None),
            'URL': http_req.get('url', None),
            'Host': http_req.get('host', None),
            'Method': http_req.get('method', None)
        }
        reformatted_http_reqs.append(reformatted_http_req)
    network['httpRequests'] = reformatted_http_reqs

    reformatted_dns_requests = []
    for dns_request in dns_requests:
        reformatted_dns_request = {
            'Reputation': dns_request.get('reputation', None),
            'IP': dns_request.get('ips', None),
            'Domain': dns_request.get('domain', None)
        }
        reformatted_dns_requests.append(reformatted_dns_request)
    network['dnsRequests'] = reformatted_dns_requests

    # Retrieve process details
    reformatted_processes = []
    for process in processes:
        context = process.get('context', {})
        reformatted_process = {
            'FileName': process.get('fileName', None),
            'PID': process.get('pid', None),
            'PPID': process.get('ppid', None),
            'ProcessUUID': process.get('uuid', None),
            'CMD': process.get('commandLine', None),
            'Path': process.get('image', None),
            'User': context.get('userName', None),
            'IntegrityLevel': context.get('integrityLevel', None),
            'ExitCode': process.get('exitCode', None),
            'MainProcess': process.get('mainProcess', None),
            'Version': process.get('versionInfo', {})
        }
        reformatted_processes.append(reformatted_process)

    # Retrieve incident details
    reformatted_incidents = []
    for incident in incidents:
        reformatted_incident = {
            'ProcessUUID': incident.get('process', None),
            'Category': incident.get('desc', None),
            'Action': incident.get('title', None),
            'ThreatLevel': incident.get('threatLevel', None)
        }
        reformatted_incidents.append(reformatted_incident)

    contents = {
        'OS': os,
        'AnalysisDate': start_text,
        'Verdict': threat_level_text,
        'MIME': mime,
        'FileInfo': file_info,
        'Process': reformatted_processes,
        'Behavior': reformatted_incidents,
        'Status': status
    }
    if hashes:
        for key, val in hashes.items():
            contents[key] = val
    if network:
        for key, val in network.items():
            contents[key] = val

    return contents


def humanreadable_from_report_contents(contents):
    """Make the selected contents pulled from a report suitable for war room output

    Parameters
    ----------
    contents : dict
        Contents selected from an ANYRUN report for Demisto output.

    Returns
    -------
    dict
        Contents formatted so that nested dicts/lists appear nicely in a war room
        entry.
    """

    def dict_to_string(nested_dict):
        return json.dumps(nested_dict).lstrip('{').rstrip('}').replace('\'', '').replace('\"', '')

    humanreadable_contents = {}
    for key, val in contents.items():
        if isinstance(val, dict):
            humanreadable_contents[key] = dict_to_string(val)
        elif isinstance(val, list):
            humanreadable_vals = []
            for item in val:
                if isinstance(item, dict):
                    humanreadable_vals.append(dict_to_string(item))
                else:
                    humanreadable_vals.append(item)
            humanreadable_contents[key] = humanreadable_vals
        else:
            humanreadable_contents[key] = val
    return humanreadable_contents


def contents_from_history(filter, response):
    """Return desired fields from filtered response

    Parameters
    ----------
    filter : str
        File name (for a file analysis), URL (for a URL analysis),
        Task ID, or hash by which to filter task history.
    response : dict
        Object returned by ANYRUN API call in 'get_history' function.

    Returns
    -------
    list
        List of Task summaries matching the filter.
    """

    # Filter response
    tasks = response.get('data', {}).get('tasks', {})
    desired_fields = {'related', 'verdict', 'date'}
    filtered_tasks = []
    for task in tasks:
        # First fetch fields that we can filter on
        name = task.get('name', None)
        hashes = task.get('hashes', None)
        file_url = task.get('file', None)
        task_id = taskid_from_url(file_url)

        if filter and filter not in {name, task_id, *hashes.values()}:
            continue

        # Reconstruct task dict with desired output fields if filter satisfied
        filtered_task = {'name': name, 'id': task_id, 'file': file_url, 'hashes': hashes}
        for field in task:
            if field in desired_fields:
                filtered_task[field] = task.get(field, None)
        filtered_tasks.append(filtered_task)

    return filtered_tasks


def http_request(method, url_suffix, params=None, data=None, files=None):
    """
    A wrapper for requests lib to send our requests and handle requests
    and responses better

    Parameters
    ----------
    method : str
        HTTP method, e.g. 'GET', 'POST' ... etc.
    url_suffix : str
        API endpoint.
    params : dict
        URL parameters.
    data : dict
        Data to be sent in a 'POST' request.
    files : dict
        File data to be sent in a 'POST' request.

    Returns
    -------
    dict
        Response JSON from having made the request.
    """

    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        files=files,
        headers=HEADERS
    )

    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        err_msg = 'Error in ANYRUN Integration API call [{}] - {}'.format(res.status_code, res.reason)
        try:
            if res.json().get('error'):
                err_msg += '\n{}'.format(res.json().get('message'))
            return_error(err_msg)
        except json.decoder.JSONDecodeError:
            return_error(err_msg)

    return res.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """Performs get_history API call to verify integration is operational

    Returns
    -------
    str
        'ok' message.
    """

    get_history(args={'limit': 1})
    demisto.results('ok')


def get_history(args={}):
    """Make API call to ANYRUN to get analysis history

    Parameters
    ----------
    args : dict
        URL parameters that determine which, and how many results are
        returned in the response.

    Returns
    -------
    dict
        Response JSON from ANYRUN API call.
    """

    url_suffix = 'analysis/'
    params = args
    response = http_request('GET', url_suffix=url_suffix, params=params)
    return response


def get_history_command():
    """Return ANYRUN task analysis history to Demisto"""

    args = demisto.args()
    filter = args.pop('filter', None)
    response = get_history(args)
    contents = contents_from_history(filter, response)

    formatting_funcs = [underscore_to_camel_case, make_capital, make_singular, make_upper]
    formatted_contents = travel_object(contents, key_functions=formatting_funcs)
    if contents:
        entry_context = {
            'ANYRUN.Task(val.ID && val.ID === obj.ID)': formatted_contents
        }
        title = 'Task History - Filtered By "{}"'.format(filter) if filter else 'Task History'
        human_readable = tableToMarkdown(title, formatted_contents, removeNull=True)
    else:
        human_readable = 'No results found.'
        entry_context = None

    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


def get_report(task_id):
    """Make API call to ANYRUN to get task report

    Parameters
    ----------
    task_id : str
        The unique task ID of the analysis whose report to fetch.

    Returns
    -------
    dict
        Response JSON from ANYRUN API call.
    """

    url_suffix = 'analysis/' + task_id
    response = http_request('GET', url_suffix=url_suffix)
    return response


def get_report_command():
    """Return ANYRUN analysis report to Demisto"""
    args = demisto.args()
    task_id = args.get('task')
    response = get_report(task_id)

    contents = contents_from_report(response)
    formatting_funcs = [underscore_to_camel_case, make_capital, make_singular, make_upper]
    formatted_contents = travel_object(contents, key_functions=formatting_funcs)

    dbot_score = generate_dbotscore(response)
    entity = ec_entity(response)

    entry_context = {
        'ANYRUN.Task(val.ID && val.ID === obj.ID)': {
            'ID': task_id,
            **formatted_contents
        },
        **dbot_score,
        **entity
    }

    title = 'Report for Task {}'.format(task_id)
    human_readable_content = humanreadable_from_report_contents(formatted_contents)
    human_readable = tableToMarkdown(title, human_readable_content, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


def run_analysis(args):
    """Make API call to ANYRUN to submit file or url for analysis

    Parameters
    ----------
    args : dict
        The analysis specifications and data.

    Returns
    -------
    dict
        Response JSON from ANYRUN API call.
    """

    obj_type = args.get('obj_type')
    entry_id = args.pop('file', None)
    files = None
    if obj_type == 'file':
        cmd_res = demisto.getFilePath(entry_id)
        file_path = cmd_res.get('path')
        name = cmd_res.get('name')
        files = {
            'file': (name, open(file_path, 'rb'))
        }

    # Format command arguments to API's parameter expectations
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
    url_suffix = 'analysis'
    response = http_request('POST', url_suffix, data=args, files=files)
    return response


def run_analysis_command():
    """Submit file or URL to ANYRUN for analysis and return task ID to Demisto"""

    args = demisto.args()
    response = run_analysis(args)
    task_id = response.get('data', {}).get('taskid')
    title = 'Analysis Task ID'
    human_readable = tableToMarkdown(title, {'Task': task_id}, removeNull=True)
    entry_context = {'ANYRUN.Task(val.ID && val.ID === obj.ID)': {'ID': task_id}}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=response)


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'anyrun-get-history': get_history_command,
    'anyrun-get-report': get_report_command,
    'anyrun-run-analysis': run_analysis_command
}

''' EXECUTION '''


def main():
    """Main Execution block"""

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

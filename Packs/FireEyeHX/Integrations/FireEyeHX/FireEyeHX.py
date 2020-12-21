import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""

IMPORTS

"""
import requests
import base64
import time
import json
import os
import re
# disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""

HANDLE PROXY

"""


def set_proxies():

    if not demisto.params().get('proxy', False):
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']


"""

GLOBAL VARS

"""
TOKEN = ''
SERVER_URL = demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
PASSWORD = PASSWORD.encode('utf-8')
USE_SSL = not demisto.params()['insecure']
VERSION = demisto.params()['version']
GET_HEADERS = {
    'Accept': 'application/json'
}
POST_HEADERS = {
    'Accept': 'application/json',
    'Content-type': 'application/json'
}
PATCH_HEADERS = {
    'Content-Type': 'text/plain'
}
BASE_PATH = '{}/hx/api/{}'.format(SERVER_URL, VERSION)
INDICATOR_MAIN_ATTRIBUTES = [
    'OS',
    'Name',
    'Created By',
    'Active Since',
    'Category',
    'Signature',
    'Active Condition',
    'Hosts With Alerts',
    'Source Alerts'
]
ALERT_MAIN_ATTRIBUTES = [
    'Alert ID',
    'Reported',
    'Event Type',
    'Agent ID'
]
HOST_MAIN_ATTRIBUTES = [
    'Host Name',
    'Host IP',
    'Agent ID',
    'Agent Version',
    'OS',
    'Last Poll',
    'Containment State',
    'Domain',
    'Last Alert'
]
HOST_SET_MAIN_ATTRIBUTES = [
    'Name',
    'ID',
    'Type'
]
# scripts for data acquisitions
STANDART_INVESTIGATIVE_DETAILS_OSX = {
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "disks"
        },
        {
            "name": "volumes"
        },
        {
            "name": "useraccounts"
        },
        {
            "name": "groups"
        },
        {
            "name": "files-api",
            "parameters": [
                {
                    "name": "Path",
                    "value": "/"
                },
                {
                    "name": "Regex",
                    "value": "^(?:Applications|Library|System|User|bin|cores|opt|private|sbin|usr)+"
                },
                {
                    "name": "Include Remote Locations",
                    "value": False
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "persistence",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                }
            ]
        },
        {
            "name": "tasks",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "processes-api"
        },
        {
            "name": "urlhistory",
            "parameters": [
                {
                    "name": "TargetBrowser",
                    "value": "Chrome"
                },
                {
                    "name": "TargetBrowser",
                    "value": "Firefox"
                },
                {
                    "name": "TargetBrowser",
                    "value": "Safari"
                }
            ]
        },
        {
            "name": "quarantine-events"
        },
        {
            "name": "ports"
        },
        {
            "name": "services",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "stateagentinspector",
            "parameters": [
                {
                    "name": "eventTypes",
                    "value": []
                }
            ]
        },
        {
            "name": "syslog"
        }
    ]
}
STANDART_INVESTIGATIVE_DETAILS_LINUX = {
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "files-api",
            "parameters": [
                {
                    "name": "Path",
                    "value": "/"
                },
                {
                    "name": "Regex",
                    "value": "^(?:usr|lib|lib64|opt|home|sbin|bin|etc|root)+"
                },
                {
                    "name": "Include Remote Locations",
                    "value": False
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "processes-api"
        },
        {
            "name": "ports"
        },
        {
            "name": "shell-history",
            "parameters": [
                {
                    "name": "ShellList",
                    "value": [
                        "bash",
                        "zsh",
                        "ksh93"
                    ]
                }
            ]
        }
    ]
}
STANDART_INVESTIGATIVE_DETAILS_WIN = {
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "disks",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "volumes",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "useraccounts",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "prefetch",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "files-raw",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "Active Files",
                    "value": True
                },
                {
                    "name": "Deleted Files",
                    "value": True
                },
                {
                    "name": "Parse NTFS INDX Buffers",
                    "value": True
                },
                {
                    "name": "Path",
                    "value": "%systemdrive%"
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Analyze Entropy",
                    "value": False
                },
                {
                    "name": "Enumerate Imports",
                    "value": False
                },
                {
                    "name": "Enumerate Exports",
                    "value": False
                },
                {
                    "name": "Analyze File Anomalies",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                },
                {
                    "name": "Strings",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Get Resources",
                    "value": False
                },
                {
                    "name": "Get Resource Data",
                    "value": False
                },
                {
                    "name": "Get Version Info",
                    "value": False
                }
            ]
        },
        {
            "name": "persistence",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Enumerate Imports",
                    "value": False
                },
                {
                    "name": "Enumerate Exports",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Analyze Entropy",
                    "value": False
                },
                {
                    "name": "Analyze File Anomalies",
                    "value": False
                },
                {
                    "name": "Get Resources",
                    "value": False
                },
                {
                    "name": "Get Version Info",
                    "value": False
                },
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "registry-raw",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "Type",
                    "value": "All"
                }
            ]
        },
        {
            "name": "tasks",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "raw mode",
                    "value": False
                }
            ]
        },
        {
            "name": "eventlogs",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "processes-memory",
            "parameters": [
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "MemD5",
                    "value": False
                },
                {
                    "name": "enumerate imports",
                    "value": True
                },
                {
                    "name": "enumerate exports",
                    "value": True
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "sections",
                    "value": True
                },
                {
                    "name": "ports",
                    "value": True
                },
                {
                    "name": "handles",
                    "value": True
                },
                {
                    "name": "detect injected dlls",
                    "value": True
                },
                {
                    "name": "raw mode",
                    "value": False
                },
                {
                    "name": "strings",
                    "value": False
                }
            ]
        },
        {
            "name": "urlhistory",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "GetThumbnails",
                    "value": False
                },
                {
                    "name": "GetIndexedPageContent",
                    "value": False
                }
            ]
        },
        {
            "name": "ports",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "services",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "raw mode",
                    "value": False
                }
            ]
        },
        {
            "name": "stateagentinspector",
            "parameters": [
                {
                    "name": "eventTypes",
                    "value": []
                }
            ]
        }
    ]
}

SYS_SCRIPT_MAP = {
    'osx': STANDART_INVESTIGATIVE_DETAILS_OSX,
    'win': STANDART_INVESTIGATIVE_DETAILS_WIN,
    'linux': STANDART_INVESTIGATIVE_DETAILS_LINUX
}

"""

COMMAND HANDLERS

"""


def get_token_request():

    """
    returns a token on successful request
    """

    url = '{}/token'.format(BASE_PATH)

    # basic authentication
    try:
        response = requests.request(
            'GET',
            url,
            headers=GET_HEADERS,
            verify=USE_SSL,
            auth=(USERNAME, PASSWORD)
        )
    except requests.exceptions.SSLError as e:
        LOG(e)
        raise ValueError('An SSL error occurred when trying to connect to the server.\
        Consider configuring unsecure connection in the integration settings')

    # handle request failure
    if response.status_code not in range(200, 205):
        message = parse_error_response(response)
        raise ValueError('Token request failed with status code {}\n{}'.format(response.status_code, message))
    # successful request
    response_headers = response.headers
    token = response_headers.get('X-FeApi-Token')
    return token


def get_token():

    token = get_token_request()
    if token:
        return token
    raise Exception('Failed to get a token, unexpected response structure from the server')


"""

HOST INFORMATION

"""


def get_host_by_agent_request(agent_id):

    """
    returns the response body

    raises an exception on:

        - http request failure
        - response status code different from 200
    """
    url = '{}/hosts/{}'.format(BASE_PATH, agent_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )

    # successful request
    try:
        return response.json()['data']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to get host information - unexpected response structure from the server.')


def get_host_information():

    """

    return the host information to the war room, given an agentId or hostName from input.

    """
    args = demisto.args()

    if not args.get('agentId') and not args.get('hostName'):
        raise ValueError('Please provide either agentId or hostName')

    host = {}  # type: Dict[str, str]
    if args.get('agentId'):
        host = get_host_by_agent_request(args.get('agentId'))
    else:
        host = get_host_by_name_request(args.get('hostName'))

    md_table = tableToMarkdown(
        'FireEye HX Get Host Information',
        host_entry(host),
        headers=HOST_MAIN_ATTRIBUTES
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': host,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Hosts(obj._id==val._id)": host,
            "Endpoint(obj.ID==val.ID)": collect_endpoint_contxt(host)
        }
    }
    demisto.results(entry)


def get_hosts_information():

    """

    return the host information to the war room, given an agentId or hostName from input.

    """

    offset = 0
    hosts = []  # type: List[Dict[str, str]]

    # get all hosts
    while True:
        hosts_partial_results = get_hosts_request(offset=offset, limit=1000)
        if not hosts_partial_results:
            break
        hosts.extend(hosts_partial_results)
        offset = len(hosts)

    hosts_entry = [host_entry(host) for host in hosts]
    md_table = tableToMarkdown(
        'FireEye HX Get Hosts Information',
        hosts_entry,
        headers=HOST_MAIN_ATTRIBUTES
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': hosts,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Hosts(obj._id==val._id)": hosts_entry,
            "Endpoint(obj.ID==val.ID)": [collect_endpoint_contxt(host)for host in hosts]
        }
    }
    demisto.results(entry)


def get_host_set_information():

    """
    return host set information to the war room according to given id or filters

    """
    args = demisto.args()

    url = '{}/host_sets/{}'.format(BASE_PATH, args.get('hostSetID', ''))
    url_params = {
        'limit': args.get('limit'),
        'offset': args.get('offset'),
        'search': args.get('search'),
        'sort': args.get('sort'),
        'name': args.get('name'),
        'type': args.get('type')
    }
    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS,
        url_params=url_params
    )
    host_set = []  # type: List[Dict[str, str]]
    try:
        if args.get('hostSetID'):
            data = response.json()['data']
            host_set = [data]
        else:
            data = response.json()['data']
            host_set = data.get('entries', [])
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to get host set information - unexpected response from the server.\n' + response.text)

    md_table = "No host sets found"
    if len(host_set) > 0:
        md_table = tableToMarkdown(
            'FireEye HX Get Host Sets Information',
            host_set_entry(host_set),
            headers=HOST_SET_MAIN_ATTRIBUTES
        )

    entry = {
        'Type': entryTypes['note'],
        'Contents': host_set,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.HostSets(obj._id==val._id)": host_set
        }
    }
    demisto.results(entry)


def get_hosts_request(limit=None, offset=None, has_active_threats=None, has_alerts=None,
                      agent_version=None, containment_queued=None, containment_state=None,
                      host_name=None, os_platform=None, reported_clone=None, time_zone=None):

    """
    returns the response body

    raises an exception on:

        - http request failure
        - response status code different from 200
    """
    url = '{}/hosts'.format(BASE_PATH)
    url_params = {
        'limit': limit,
        'offset': offset,
        'has_active_threats': has_active_threats,
        'has_alerts': has_alerts,
        'agent_version': agent_version,
        'containment_queued': containment_queued,
        'containment_state': containment_state,
        'hostname': host_name,
        'os.platform': os_platform,
        'reported_clone': reported_clone,
        'time_zone': time_zone
    }
    # remove None values
    url_params = {k: v for k, v in url_params.items() if v is not None}

    response = http_request(
        'GET',
        url,
        url_params=url_params,
        headers=GET_HEADERS
    )
    # successful request
    try:
        return response.json()['data']['entries']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to parse response body - unexpected response structure from the server.')


def get_host_by_name_request(host_name):

    try:
        return get_hosts_request(host_name=host_name, limit=1)[0]
    except Exception as e:
        LOG(e)
        raise ValueError('Host {} not found.'.format(host_name))


def get_all_agents_ids():

    """
    returns a list of all agents ids
    """
    offset = 0
    hosts = []  # type: List[Dict[str, str]]

    # get all hosts
    while True:
        hosts_partial_results = get_hosts_request(offset=offset, limit=1000)
        if not hosts_partial_results:
            break
        hosts.extend(hosts_partial_results)
        offset = len(hosts)
    return [host.get('_id') for host in hosts]


def get_agent_id(host_name):

    """
    returns the agent id given the host name

    raises an exception on:
        - unexpected response structure
        - empty results

    """
    host = get_host_by_name_request(host_name)
    try:
        return host['_id']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to get agent id for host {}'.format(host_name))


def collect_endpoint_contxt(host):

    return {
        'Hostname': host.get('hostname'),
        'ID': host.get('_id'),
        'IPAddress': host.get('primary_ip_address'),
        'Domain': host.get('domain'),
        'MACAddress': host.get('primary_mac'),
        'OS': host.get('os', {}).get('platform'),
        'OSVersion': host.get('os', {}).get('product_name')
    }


"""

HOST CONTAINMENT

"""


def containment_request(agent_id):

    """

    no return value on successful request

    """
    url = '{}/hosts/{}/containment'.format(BASE_PATH, agent_id)
    body = {
        'state': 'contain'
    }

    try:
        api_version = int(VERSION[-1])
    except Exception as exc:
        raise ValueError('Invalid version was set: {} - {}'.format(VERSION, str(exc)))
    if api_version > 3:
        http_request(
            'POST',
            url,
            headers=POST_HEADERS
        )
    else:
        http_request(
            'POST',
            url,
            body=body,
            headers=POST_HEADERS
        )
    # no exception raised - successful request


def containment():

    """

    returns a success message to the war room

    """

    args = demisto.args()

    # validate one of the arguments was passed
    if not args:
        raise ValueError('Please provide either agentId or hostName')

    # in case a hostName was given, set the agentId accordingly
    if args.get('hostName'):
        args['agentId'] = get_agent_id(args['hostName'])

    containment_request(args['agentId'])
    # no exceptions raised->successful request

    host = get_host_by_agent_request(args['agentId'])
    entry = {
        'Type': entryTypes['note'],
        'Contents': 'Containment rquest for the host was sent and approved successfully',
        'ContentsFormat': formats['text'],
        'EntryContext': {
            "FireEyeHX.Hosts(obj._id==val._id)": host,
            "Endpoint(obj.ID==val.ID)": collect_endpoint_contxt(host)
        }
    }
    demisto.results(entry)


def containment_cancellation_request(agent_id):

    """

    no return value on successful request

    """
    url = '{}/hosts/{}/containment'.format(BASE_PATH, agent_id)

    http_request(
        'DELETE',
        url,
        headers=GET_HEADERS
    )
    # no exceptions are raised - successful request


def containment_cancellation():

    """

    returns a success message to the war room

    """

    args = demisto.args()

    # validate one of the arguments was passed
    if not args:
        raise ValueError('Please provide either agentId or hostName')

    # in case a hostName was given, set the agentId accordingly
    if args.get('hostName'):
        args['agentId'] = get_agent_id(args['hostName'])

    containment_cancellation_request(args['agentId'])
    # no exceptions raised->successful request

    host = get_host_by_agent_request(args['agentId'])
    entry = {
        'Type': entryTypes['note'],
        'Contents': 'The host is released from containment.',
        'ContentsFormat': formats['text'],
        'EntryContext': {
            "FireEyeHX.Hosts(obj._id==val._id)": host,
            "Endpoint(obj.ID==val.ID)": collect_endpoint_contxt(host)
        }
    }
    demisto.results(entry)


"""

ALERTS

"""


def get_alert_request(alert_id):

    url = '{}/alerts/{}'.format(BASE_PATH, alert_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )
    return response.json().get('data')


def get_alert():

    alert_id = demisto.args().get('alertId')
    alert = get_alert_request(alert_id)

    alert_table = tableToMarkdown(
        'FireEye HX Get Alert # {}'.format(alert_id),
        alert_entry(alert),
        headers=ALERT_MAIN_ATTRIBUTES
    )

    event_type = alert.get('event_type')
    event_type = 'NewEvent' if not event_type else event_type
    event_type = re.sub("([a-z])([A-Z])", "\g<1> \g<2>", event_type).title()
    event_table = tableToMarkdown(
        event_type,
        alert.get('event_values')
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': alert,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '{}\n{}'.format(alert_table, event_table),
        'EntryContext': {
            "FireEyeHX.Alerts(obj._id==val._id)": alert
        }
    }
    demisto.results(entry)


def get_alerts_request(has_share_mode=None, resolution=None, agent_id=None, host_name=None,
                       condition_id=None, limit=None, offset=None, sort=None, min_id=None,
                       event_at=None, alert_id=None, matched_at=None, reported_at=None, source=None):

    """

    returns the response body on successful request

    """
    url = '{}/alerts'.format(BASE_PATH)

    body = {
        'has_share_mode': has_share_mode,
        'resolution': resolution,
        'agent._id': agent_id,
        'condition._id': condition_id,
        'event_at': event_at,
        'min_id': min_id,
        '_id': alert_id,
        'matched_at': matched_at,
        'reported_at': reported_at,
        'source': source,
        'limit': limit,
        'offset': offset,
        'sort': sort
    }

    # remove None values
    body = {k: v for k, v in body.items() if v is not None}

    response = http_request(
        'GET',
        url,
        url_params=body,
        headers=GET_HEADERS
    )
    try:
        return response.json()['data']['entries']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to parse response body')


def get_all_alerts(has_share_mode=None, resolution=None, agent_id=None, condition_id=None, limit=None,
                   sort=None, min_id=None, event_at=None, alert_id=None, matched_at=None, reported_at=None, source=None):

    """

    returns a list of alerts, all results up to limit

    """
    offset = 0
    alerts = []  # type: List[Dict[str, str]]

    max_records = limit or float('inf')

    while len(alerts) < max_records:
        alerts_partial_results = get_alerts_request(
            has_share_mode=has_share_mode,
            resolution=resolution,
            agent_id=agent_id,
            condition_id=condition_id,
            event_at=event_at,
            alert_id=alert_id,
            matched_at=matched_at,
            reported_at=reported_at,
            source=source,
            min_id=min_id,
            offset=offset,
            limit=limit or 100,
            sort=sort
        )
        # empty list
        if not alerts_partial_results:
            break
        alerts.extend(alerts_partial_results)
        offset = len(alerts)

    # remove access results
    if len(alerts) > max_records:
        alerts[int(max_records) - 1: -1] = []

    return alerts


def general_context_from_event(alert):

    def file_context(values):

        return {
            'Name': values.get('fileWriteEvent/fileName'),
            'MD5': values.get('fileWriteEvent/md5'),
            'Extension': values.get('fileWriteEvent/fileExtension'),
            'Path': values.get('fileWriteEvent/fullPath')
        }

    def ip_context(values):

        return {
            'Address': values.get('ipv4NetworkEvent/remoteIP')
        }

    def registry_key_context(values):

        return {
            'Path': values.get('regKeyEvent/path'),
            'Name': values.get('regKeyEvent/valueName'),
            'Value': values.get('regKeyEvent/value')
        }
    context_map = {
        'fileWriteEvent': file_context,
        'ipv4NetworkEvent': ip_context,
        'regKeyEvent': registry_key_context
    }

    if context_map.get(alert['event_type']) is not None:
        f = context_map[alert['event_type']]
        return f(alert['event_values'])
    return None


def collect_context(alerts):

    # collect_context
    files = []
    ips = []
    registry_keys = []

    for alert in alerts:
        event_type = alert.get('event_type')
        context = general_context_from_event(alert)
        if event_type == 'fileWriteEvent':
            files.append(context)
        elif event_type == 'ipv4NetworkEvent':
            ips.append(context)
        elif event_type == 'regKeyEvent':
            registry_keys.append(context)
    return (files, ips, registry_keys)


def get_alerts():

    """

    returns a list of alerts to the war room

    """

    args = demisto.args()
    source = []
    # add source type
    if args.get('MALsource'):
        source.append('mal')
    if args.get('EXDsource'):
        source.append('exd')
    if args.get('IOCsource'):
        source.append('ioc')

    sort_map = {
        'agentId': 'agent._id',
        'conditionId': 'condition._id',
        'eventAt': 'event_at',
        'alertId': '_id',
        'matchedAt': 'matched_at',
        'id': '_id',
        'reportedAt': 'reported_at'
    }

    if args.get('sort'):
        args['sort'] = '{}+{}'.format(sort_map.get(args['sort']), args.get('sortOrder', 'ascending'))

    if args.get('hostName'):
        args['agentId'] = get_agent_id(args.get('hostName'))

    if args.get('limit'):
        args['limit'] = int(args['limit'])

    alerts = get_all_alerts(
        has_share_mode=args.get("hasShareMode"),
        resolution=args.get('resolution'),
        agent_id=args.get('agentId'),
        condition_id=args.get('conditionId'),
        event_at=args.get('eventAt'),
        alert_id=args.get('alertId'),
        matched_at=args.get('matchedAt'),
        reported_at=args.get('reportedAt'),
        source=source,
        min_id=args.get('min_id'),
        limit=args.get('limit'),
        sort=args.get('sort')
    )

    # parse each alert to a record displayed in the human readable table
    alerts_entries = [alert_entry(alert) for alert in alerts]

    files, ips, registry_keys = collect_context(alerts)

    md_table = tableToMarkdown(
        'FireEye HX Get Alerts',
        alerts_entries,
        headers=ALERT_MAIN_ATTRIBUTES
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': alerts,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Alerts(obj._id==val._id)": alerts,
            'File': files,
            'RegistryKey': registry_keys,
            'IP': ips
        }
    }
    demisto.results(entry)


def suppress_alert_request(alert_id):

    """

    no return value on successful request

    """

    url = '{}/alerts/{}'.format(BASE_PATH, alert_id)

    http_request(
        'DELETE',
        url
    )


def suppress_alert():

    """

    returns a success message to the war room

    """

    alert_id = demisto.args().get('alertId')

    suppress_alert_request(alert_id)
    # no exceptions raised->successful request

    entry = {
        'Type': entryTypes['note'],
        'Contents': 'Alert {} suppressed successfully.'.format(alert_id),
        'ContentsFormat': formats['text']
    }
    demisto.results(entry)


"""

INDICATORS

"""


def new_indicator_request(category):

    """
    Create a new indicator
    """
    url = '{}/indicators/{}'.format(BASE_PATH, category)

    response = http_request(
        'POST',
        url,
        headers=GET_HEADERS
    )
    try:
        return response.json().get('data')
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to parse response body, unexpected response structure from the server.')


def create_indicator():

    """
    Get new indicator details
    returns a success message to the war room
    """

    category = demisto.args().get('category')

    response = new_indicator_request(category)

    md_table = {
        'ID': response.get('_id'),
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FireEye HX New Indicator created successfully', md_table),
        'EntryContext': {
            "FireEyeHX.Indicators(obj._id===val._id)": response
        }
    }
    demisto.results(entry)


def append_conditions_request(name, category, body):

    """
    Append conditions to indicator request
    """

    url = '{}/indicators/{}/{}/conditions'.format(BASE_PATH, category, name)

    response = http_request(
        'PATCH',
        url,
        conditions_params=body,
        headers=PATCH_HEADERS
    )

    return response.json()


def append_conditions():

    """
    Append conditions to indicator
    no return value on successfull request
    """
    name = demisto.args().get('name')
    category = demisto.args().get('category')
    body = demisto.args().get('condition')

    body = body.replace(',', '\n')

    response = append_conditions_request(name, category, body)

    md_table = {
        'Name': name,
        'Category': category,
        'Conditions': body
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('The conditions were added successfully', md_table)
    }
    demisto.results(entry)


def get_indicator_request(category, name):

    """

    returns a json object representing an indicator

    """

    url = '{}/indicators/{}/{}'.format(BASE_PATH, category, name)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS,
    )
    return response.json().get('data')


def get_indicator_conditions_request(category, name, limit=None, offset=None, enabled=None, has_alerts=None):

    """

    returns a list of json objects, each representing an indicator condition
    if no results are found- returns None

    """
    url = '{}/indicators/{}/{}/conditions'.format(BASE_PATH, category, name)
    url_params = {
        'limit': limit,
        'offset': offset,
        'enabled': enabled,
        'has_alerts': has_alerts
    }
    # remove None values
    url_params = {k: v for k, v in url_params.items() if v is not None}

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS,
        url_params=url_params
    )
    try:
        return response.json()['data']['entries']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to parse response body')


def get_all_enabled_conditions(indicator_category, indicator_name):

    offset = 0
    conditions = []   # type: List[Dict[str, str]]

    # get all results
    while True:
        conditions_partial_results = get_indicator_conditions_request(
            indicator_category,
            indicator_name,
            enabled=True,
            offset=offset
        )
        if not conditions_partial_results:
            break
        conditions.extend(conditions_partial_results)
        offset = len(conditions)
    return conditions


def get_indicator_conditions():

    """

    returns a list of enabled conditions assosiated with a specific indicator to the war room

    """

    args = demisto.args()

    conditions = get_all_enabled_conditions(
        args.get('category'),
        args.get('name')
    )

    conditions_entries = [condition_entry(condition) for condition in conditions]

    md_table = tableToMarkdown(
        'Indicator "{}" Alerts on'.format(args.get('name')),
        conditions_entries
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': conditions,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Conditions(obj._id==val._id)": conditions
        }
    }
    demisto.results(entry)


def get_indicator():

    args = demisto.args()

    indicator = get_indicator_request(
        args.get('category'),
        args.get('name')
    )

    md_table = tableToMarkdown(
        'FireEye HX Get Indicator- {}'.format(args.get('name')),
        indicator_entry(indicator),
        headers=INDICATOR_MAIN_ATTRIBUTES
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': indicator,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Indicators(obj._id==val._id)": indicator
        }
    }
    demisto.results(entry)


def get_indicators_request(category=None, search=None, limit=None, offset=None,
                           share_mode=None, sort=None, created_by=None, alerted=None):

    url = '{}/indicators'.format(BASE_PATH)
    if category:
        url = url + '/' + category

    url_params = {
        'search': search,
        'limit': limit,
        'offset': offset,
        'category.share_mode': share_mode,
        'sort': sort,
        'created_by': created_by,
        'stats.alerted_agents': alerted
    }

    # remove None value
    url_params = {k: v for k, v in url_params.items() if v}

    response = http_request(
        'GET',
        url,
        url_params=url_params,
        headers=GET_HEADERS,
    )
    try:
        response_body = response.json()
        data = response_body['data']
        # no results found
        if data['total'] == 0:
            return None
        return data['entries']
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to parse response body')


def get_all_indicators(category=None, search=None, share_mode=None, sort=None, created_by=None, alerted=None, limit=None):

    max_records = limit or float('inf')
    offset = 0
    indicators = []   # type: List[Dict[str, str]]

    # get all results
    while len(indicators) < max_records:
        indicators_partial_results = get_indicators_request(
            category=category,
            search=search,
            offset=offset,
            share_mode=share_mode,
            sort=sort,
            created_by=created_by,
            alerted=alerted,
            limit=limit or 100
        )
        if not indicators_partial_results:
            break
        indicators.extend(indicators_partial_results)
        offset = len(indicators)

    # remove access results
    if len(indicators) > max_records:
        indicators[int(max_records) - 1: -1] = []

    return indicators


def get_indicators():

    args = demisto.args()

    sort_map = {
        'category': 'category',
        'activeSince': 'active_since',
        'createdBy': 'created_by',
        'alerted': 'stats.alerted_agents'
    }

    if args.get('limit'):
        args['limit'] = int(args['limit'])
    if args.get('alerted'):
        args['alerted'] = args['alerted'] == 'yes'
    if args.get('sort'):
        args['sort'] = sort_map.get(args.get('sort'))

    # get all results
    indicators = get_all_indicators(
        category=args.get('category'),
        search=args.get('searchTerm'),
        share_mode=args.get('shareMode'),
        sort=args.get('sort'),
        created_by=args.get('createdBy'),
        alerted=args.get('alerted'),
        limit=args.get('limit')
    )

    indicators_entries = [indicator_entry(indicator) for indicator in indicators]

    md_table = tableToMarkdown(
        'FireEye HX Get Indicator- {}'.format(args.get('name')),
        indicators_entries,
        headers=INDICATOR_MAIN_ATTRIBUTES
    )

    entry = {
        'Type': entryTypes['note'],
        'Contents': indicators,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md_table,
        'EntryContext': {
            "FireEyeHX.Indicators(obj._id==val._id)": indicators
        }
    }
    demisto.results(entry)


"""

SEARCH

"""


def search_request(query, host_set=None, hosts=None, exhaustive=False):

    url = '{}/searches'.format(BASE_PATH)

    body = {'query': query}

    if host_set:
        body['host_set'] = {'_id': int(host_set)}
    elif hosts:
        body['hosts'] = [{'_id': host} for host in hosts]

    if exhaustive:
        body['exhaustive'] = True

    try:
        response = http_request(
            'POST',
            url,
            headers=POST_HEADERS,
            body=body
        )
    except Exception as e:
        raise e
    if response.status_code == 409:
        raise ValueError('Request unsuccessful because the search limits \
        (10 existing searches or 5 running searches) have been exceeded')
    return response.json().get('data')


def get_search_information_request(search_id):

    """

    returns the search information represented by a json object.

    """

    url = '{}/searches/{}'.format(BASE_PATH, search_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )
    return response.json().get('data')


def get_search_results_request(search_id):

    """

    returns the search results represented by a json object.

    """

    url = '{}/searches/{}/results'.format(BASE_PATH, search_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )
    return response.json().get('data', {}).get('entries', [])


def stop_search_request(search_id):

    """

    returns the search information represented by a json object.

    """

    url = '{}/searches/{}/actions/stop'.format(BASE_PATH, search_id)

    response = http_request(
        'POST',
        url,
        headers=POST_HEADERS
    )
    return response.json()


def delete_search_request(search_id):

    """

    no return value on successful request

    """

    url = '{}/searches/{}'.format(BASE_PATH, search_id)
    http_request(
        'DELETE',
        url
    )


def search_results_to_context(results, search_id):

    for res in results:
        res["SearchID"] = search_id
        res["HostID"] = res.get("host", {}).get("_id")
        res["HostName"] = res.get("host", {}).get("hostname")
        res["HostUrl"] = res.get("host", {}).get("url")
        del res['host']
        res["Results"] = res.get("results")
        del res["results"]
        for resData in res.get("Results"):
            resData.update(resData.get("data", {}))
            del resData['data']
    return results


def start_search():

    args = demisto.args()

    '''
    to search all hosts past none of the arguments?

    # validate at list one of the arguments 'agentsIds', 'hostsNames', 'hostSet' was passed
    if not any([args.get('agentsIds'), args.get('hostsNames'), args.get('hostSet'), args.get('searchAllHosts')]):
        raise ValueError('Please provide one of the followings: agentsIds, hostsNames, hostSet')
    '''

    agents_ids = []  # type: List[Dict[str, str]]
    if args.get('agentsIds'):
        agents_ids = args['agentsIds'].split(',')
    elif args.get('hostsNames'):
        names = args.get('hostsNames').split(',')
        for name in names:
            try:
                agent_id = get_agent_id(name)
                agents_ids.append(agent_id)
            except Exception as e:
                LOG(e)
                pass
        if not agents_ids:
            raise ValueError('None of the host names were matched with an agent')

    # limit can't exceed 1000.
    limit = args.get('limit')
    if not limit or limit > 1000:
        limit = 1000

    arg_to_query_field_map = {
        'dnsHostname': 'DNS Hostname',
        'fileFullPath': 'File Full Path',
        'fileMD5Hash': 'File MD5 Hash',
        'ipAddress': 'IP Address'
    }

    query = []
    for arg in arg_to_query_field_map.keys():
        if not args.get(arg):
            continue
        field_filter = {
            'field': arg_to_query_field_map[arg],
            'operator': args['{}Operator'.format(arg)],
            'value': args[arg]
        }
        query.append(field_filter)

    search = search_request(
        query,
        hosts=agents_ids,
        host_set=args.get('hostSet'),
        exhaustive=args.get('exhaustive') == 'yes'
    )

    search_id = search.get('_id')

    '''
    loop to get search status once a minute. break on: search has stopped, matched
    results exceeded limit, or no more pending hosts.
    '''

    while True:
        search_info = get_search_information_request(search_id)
        matched = search_info.get('stats', {}).get('search_state', {}).get('MATCHED', 0)
        pending = search_info.get('stats', {}).get('search_state', {}).get('PENDING', 0)
        if search_info.get('state') == 'STOPPED' or matched >= limit or pending == 0:
            break
        time.sleep(60)  # pylint: disable=sleep-exists

    results = get_search_results_request(search_id)
    md_entries = [host_results_md_entry(host_results) for host_results in results]

    entry = {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '## Search Results\n' + '\n'.join(md_entries),
        'EntryContext': {
            "FireEyeHX.Search": search_results_to_context(results, search_id)
        }
    }
    demisto.results(entry)

    # finally stop or delete the search
    possible_error_message = None
    try:
        if args.get('stopSearch') == 'stop':
            possible_error_message = 'Failed to stop search'
            stop_search_request(search_id)
        # no need to stop a search before deleting it.
        if args.get('stopSearch') == 'stopAndDelete':
            possible_error_message = 'Failed to delete search'
            delete_search_request(search_id)
        possible_error_message = None
    except Exception as e:
        LOG('{}\n{}'.format(possible_error_message, e))
        pass
    # add warning entry if necessary
    if possible_error_message:
        warning_entry = {
            'Type': entryTypes['note'],
            'Contents': possible_error_message,
            'ContentsFormat': formats['text'],
        }
        demisto.results(warning_entry)


"""

ACQUISITIONS

"""


def file_acquisition_request(agent_id, file_name, file_path, comment=None, external_id=None, req_use_api=None):

    url = '{}/hosts/{}/files'.format(BASE_PATH, agent_id)

    body = {
        'req_path': file_path,
        'req_filename': file_name,
        'comment': comment,
        'external_id': external_id,
        'req_use_api': req_use_api
    }

    # remove None values
    body = {k: v for k, v in body.items() if v is not None}

    response = http_request(
        'POST',
        url,
        body=body,
        headers=POST_HEADERS
    )

    return response.json().get('data')


def file_acquisition_package_request(acquisition_id):

    url = '{}/acqs/files/{}.zip'.format(BASE_PATH, acquisition_id)

    response = http_request(
        'GET',
        url
    )

    return response.content


def file_acquisition_information_request(acquisition_id):

    url = '{}/acqs/files/{}'.format(BASE_PATH, acquisition_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )

    return response.json().get('data')


def delete_file_acquisition_request(acquisition_id):

    """

    no return value on successful request

    """

    url = '{}/acqs/files/{}'.format(BASE_PATH, acquisition_id)

    http_request(
        'DELETE',
        url
    )


def delete_file_acquisition():

    """

    returns a success message to the war room

    """
    acquisition_id = demisto.args().get('acquisitionId')
    delete_file_acquisition_request(acquisition_id)
    # successful request

    return {
        'Type': entryTypes['note'],
        'Contents': 'file acquisition {} deleted successfully'.format(acquisition_id),
        'ContentsFormat': formats['text'],
    }


def file_acquisition():

    args = demisto.args()

    if not args.get('hostName') and not args.get('agentId'):
        raise ValueError('Please provide either agentId or hostName')

    if args.get('hostName'):
        args['agentId'] = get_agent_id(args['hostName'])

    use_api = args.get('acquireUsing') == 'API'

    acquisition_info = file_acquisition_request(
        args.get('agentId'),
        args.get('fileName'),
        args.get('filePath'),
        req_use_api=use_api
    )

    acquisition_id = acquisition_info.get('_id')

    LOG('acquisition request was successful. Waiting for acquisition process to be complete.')
    while True:
        acquisition_info = file_acquisition_information_request(acquisition_id)
        state = acquisition_info.get('state')
        if state in ['COMPLETE', 'ERROR', 'FAILED']:
            break
        time.sleep(10)  # pylint: disable=sleep-exists
    LOG('acquisition process has been complete. Fetching zip file.')

    acquired_file = file_acquisition_package_request(acquisition_id)

    message = '{} acquired successfully'.format(args.get('fileName'))
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    entry = {
        'Type': entryTypes['note'],
        'Contents': '{}\nacquisition ID: {}'.format(message, acquisition_id),
        'ContentsFormat': formats['text'],
        'EntryContext': {
            "FireEyeHX.Acquisitions.Files(obj._id==val._id)": acquisition_info
        }
    }

    demisto.results(entry)
    demisto.results(fileResult('{}.zip'.format(os.path.splitext(args.get('fileName'))[0]), acquired_file))


def data_acquisition_request(agent_id, script_name, script):

    url = '{}/hosts/{}/live'.format(BASE_PATH, agent_id)

    body = {
        'name': script_name,
        'script': {'b64': script}
    }

    response = http_request(
        'POST',
        url,
        body=body
    )

    return response.json()['data']


def data_acquisition_information_request(acquisition_id):

    url = '{}/acqs/live/{}'.format(BASE_PATH, acquisition_id)

    response = http_request(
        'GET',
        url,
        headers=GET_HEADERS
    )

    return response.json()['data']


def data_collection_request(acquisition_id):

    url = '{}/acqs/live/{}.mans'.format(BASE_PATH, acquisition_id)

    response = http_request(
        'GET',
        url
    )

    return response.content


def data_acquisition():
    """

    returns the mans file to the war room

    """

    args = demisto.args()

    # validate the host name or agent ID was passed
    if not args.get('hostName') and not args.get('agentId'):
        raise ValueError('Please provide either agentId or hostName')

    if not args.get('defaultSystemScript') and not args.get('script'):
        raise ValueError('If the script is not provided, defaultSystemScript must be specified.')

    if args.get('script') and not args.get('scriptName'):
        raise ValueError('If the script is provided, script name must be specified as well.')

    if args.get('hostName'):
        args['agentId'] = get_agent_id(args['hostName'])

    # determine whether to use the default script
    sys = args.get('defaultSystemScript')
    if sys:
        args['script'] = json.dumps(SYS_SCRIPT_MAP[sys])
        args['scriptName'] = '{}DefaultScript'.format(sys)

    acquisition_info = data_acquisition_request(
        args['agentId'],
        args['scriptName'],
        base64.b64encode(args['script'])
    )

    acquisition_id = acquisition_info.get('_id')

    LOG('Acquisition request was successful. Waiting for acquisition process to be complete.')
    # loop to inquire acquisition state every 30 seconds
    # break when state is complete
    while True:
        acquisition_info = data_acquisition_information_request(acquisition_id)
        if acquisition_info.get('state') == 'COMPLETE':
            break
        time.sleep(30)  # pylint: disable=sleep-exists
    LOG('Acquisition process has been complete. Fetching mans file.')

    message = '{} acquired successfully'.format(args.get('fileName'))
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    # output file and acquisition information to the war room
    data = data_collection_request(acquisition_id)
    entry = {
        'Type': entryTypes['note'],
        'Contents': '{}\nacquisition ID: {}'.format(message, acquisition_id),
        'ContentsFormat': formats['text'],
        'EntryContext': {
            "FireEyeHX.Acquisitions.Data(obj._id==val._id)": acquisition_info
        }
    }
    demisto.results(entry)
    demisto.results(fileResult('agent_{}_data.mans'.format(args['agentId']), data))


def delete_data_acquisition_request(acquisition_id):

    """

    no return value on successful request

    """

    url = '{}/acqs/live/{}'.format(BASE_PATH, acquisition_id)

    http_request(
        'DELETE',
        url
    )


def delete_data_acquisition():

    """

    returns a success message to the war room

    """
    acquisition_id = demisto.args().get('acquisitionId')
    delete_data_acquisition_request(acquisition_id)
    # successful request

    return {
        'Type': entryTypes['note'],
        'Contents': 'data acquisition {} deleted successfully'.format(acquisition_id),
        'ContentsFormat': formats['text'],
    }


"""

FETCH INCIDENTS

"""


def fetch_incidents():

    last_run = demisto.getLastRun()
    alerts = []  # type: List[Dict[str, str]]
    if last_run and last_run.get('min_id'):
        # get all alerts with id greater than min_id
        alerts = get_all_alerts(
            min_id=last_run.get('min_id'),
            sort='_id+ascending'
        )
        # results are sorted in ascending order - the last alert holds the greatest id
        min_id = alerts[-1].get('_id') if alerts else None
    else:
        # get the last 100 alerts
        alerts = get_all_alerts(
            sort='_id+descending',
            limit=100
        )
        # results are sorted in descending order - the first alert holds the greatest id
        min_id = alerts[0].get('_id') if alerts else None

    incidents = [parse_alert_to_incident(alert) for alert in alerts]
    demisto.incidents(incidents)
    if min_id is not None:
        demisto.setLastRun({'min_id': min_id})


@logger
def parse_alert_to_incident(alert):

    event_type = alert.get('event_type')
    event_type = 'NewEvent' if not event_type else event_type
    event_values = alert.get('event_values', {})
    event_indicators_map = {
        'fileWriteEvent': 'fileWriteEvent/fileName',
        'ipv4NetworkEvent': 'ipv4NetworkEvent/remoteIP',
        'dnsLookupEvent': 'dnsLookupEvent/hostname',
        'regKeyEvent': 'regKeyEvent/valueName'
    }
    event_indicator = event_indicators_map.get(event_type)
    event_indicator = 'No Indicator' if not event_indicator else event_indicator

    indicator = ''
    if isinstance(event_values, dict):
        indicator = event_values.get(event_indicator)

    incident_name = '{event_type_parsed}: {indicator}'.format(
        event_type_parsed=re.sub("([a-z])([A-Z])", "\g<1> \g<2>", event_type).title(),
        indicator=indicator
    )

    incident = {
        'name': incident_name,
        'rawJSON': json.dumps(alert)
    }
    return incident


"""

ENTRY ENTITIES

"""


def indicator_entry(indicator):

    indicator_entry = {
        'OS': ', '.join(indicator.get('platforms', [])),
        'Name': indicator.get('name'),
        'Created By': indicator.get('created_by'),
        'Active Since': indicator.get('active_since'),
        'Category': indicator.get('category', {}).get('name'),
        'Signature': indicator.get('signature'),
        'Active Condition': indicator.get('stats', {}).get('active_conditions'),
        'Hosts With Alerts': indicator.get('stats', {}).get('alerted_agents'),
        'Source Alerts': indicator.get('stats', {}).get('source_alerts')
    }
    return indicator_entry


def host_entry(host):

    host_entry = {
        'Host Name': host.get('hostname'),
        'Last Poll': host.get('last_poll_timestamp'),
        'Agent ID': host.get('_id'),
        'Agent Version': host.get('agent_version'),
        'Host IP': host.get('primary_ip_address'),
        'OS': host.get('os', {}).get('platform'),
        'Containment State': host.get('containment_state'),
        'Domain': host.get('domain'),
        'Last Alert': host.get('last_alert')
    }
    return host_entry


def host_set_entry(host_sets):
    host_set_entries = [{
        'Name': host_set.get('name'),
        'ID': host_set.get('_id'),
        'Type': host_set.get('type')
    } for host_set in host_sets]
    return host_set_entries


def alert_entry(alert):

    alert_entry = {
        'Alert ID': alert.get('_id'),
        'Reported': alert.get('reported_at'),
        'Event Type': alert.get('event_type'),
        'Agent ID': alert.get('agent', {}).get('_id')
    }
    return alert_entry


def condition_entry(condition):

    indicator_entry = {
        'Event Type': condition.get('event_type'),
        'Operator': condition.get('tests', {})[0].get('operator'),
        'Value': condition.get('tests', {})[0].get('value'),

    }
    return indicator_entry


def host_results_md_entry(host_entry):

    results = host_entry.get('results', [])
    host_info = host_entry.get('host', {})
    entries = []
    for result in results:
        data = result.get('data', {})
        entry = {
            'Item Type': result.get('type'),
            'Summary': ' '.join(['**{}** {}'.format(k, v) for k, v in data.items()])
        }
        entries.append(entry)

    md_table = tableToMarkdown(
        host_info.get('hostname'),
        entries,
        headers=['Item Type', 'Summary']
    )
    return md_table


"""

ADDITIONAL FUNCTIONS

"""


def http_request(method, url, body=None, headers={}, url_params=None, conditions_params=None):
    """

    returns the http response

    """

    # add token to headers
    headers['X-FeApi-Token'] = TOKEN

    request_kwargs = {
        'headers': headers,
        'verify': USE_SSL
    }

    # add optional arguments if specified
    if body:
        # request_kwargs['data'] = ' '.join(format(x, 'b') for x in bytearray(json.dumps(body)))
        request_kwargs['data'] = json.dumps(body)
    if url_params:
        request_kwargs['params'] = url_params
    if conditions_params:
        request_kwargs['data'] = conditions_params

    LOG('attempting {} request sent to {} with arguments:\n{}'.format(method, url, json.dumps(request_kwargs, indent=4)))
    try:
        response = requests.request(
            method,
            url,
            **request_kwargs
        )
    except requests.exceptions.SSLError as e:
        LOG(e)
        raise ValueError('An SSL error occurred when trying to connect to the server. Consider configuring unsecure connection in \
        the integration settings.')

    # handle request failure
    if response.status_code not in range(200, 205):
        message = parse_error_response(response)
        raise ValueError('Request failed with status code {}\n{}'.format(response.status_code, message))

    return response


def logout():

    url = '{}/token'.format(BASE_PATH)

    try:
        http_request(
            'DELETE',
            url
        )
    except ValueError as e:
        LOG('Failed to logout with token')
        raise e
    LOG('logout successfully')


def parse_error_response(response):

    try:
        res = response.json()
        msg = res.get('message')
        if res.get('details') is not None and res.get('details')[0].get('message') is not None:
            msg = msg + "\n" + json.dumps(res.get('details')[0])
    except Exception as e:
        LOG(e)
        return response.text
    return msg


def return_error_entry(message):

    error_entry = {
        'Type': entryTypes['error'],
        'Contents': message,
        'ContentsFormat': formats['text']
    }

    demisto.results(error_entry)


"""

EXECUTION

"""


def main():
    global TOKEN
    set_proxies()

    command = demisto.command()
    LOG('Running command "{}"'.format(command))

    # ask for a token using user credentials
    TOKEN = get_token()

    try:
        if command == 'test-module':
            # token generated - credentials are valid
            demisto.results('ok')
        elif command == 'fetch-incidents':
            fetch_incidents()
        elif command == 'fireeye-hx-get-alerts':
            get_alerts()
        elif command == 'fireeye-hx-cancel-containment':
            containment_cancellation()
        elif command == 'fireeye-hx-host-containment':
            containment()
        elif command == 'fireeye-hx-create-indicator':
            create_indicator()
        elif command == 'fireeye-hx-get-indicator':
            get_indicator()
            get_indicator_conditions()
        elif command == 'fireeye-hx-get-indicators':
            get_indicators()
        elif command == 'fireeye-hx-suppress-alert':
            suppress_alert()
        elif command == 'fireeye-hx-get-host-information':
            get_host_information()
        elif command == 'fireeye-hx-get-alert':
            get_alert()
        elif command == 'fireeye-hx-file-acquisition':
            file_acquisition()
        elif command == 'fireeye-hx-delete-file-acquisition':
            delete_file_acquisition()
        elif command == 'fireeye-hx-data-acquisition':
            data_acquisition()
        elif command == 'fireeye-hx-delete-data-acquisition':
            delete_data_acquisition()
        elif command == 'fireeye-hx-search':
            start_search()
        elif command == 'fireeye-hx-get-host-set-information':
            get_host_set_information()
        elif command == 'fireeye-hx-append-conditions':
            append_conditions()
        elif command == 'fireeye-hx-get-all-hosts-information':
            get_hosts_information()
    except ValueError as e:
        return_error(e)
    finally:
        logout()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

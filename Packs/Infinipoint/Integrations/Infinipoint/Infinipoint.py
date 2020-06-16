#!/usr/bin/env python3

import time
import sys
import requests
import jwt
import math

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, List

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


PROXY = demisto.params().get('proxy')
INSECURE = demisto.params().get('insecure')
BASE_URL = demisto.params().get('url')
ACCESS_KEY = demisto.params().get('access_key')
PRIVATE_KEY = demisto.params().get('private_key')
PAGE_SIZE = 10

# if not demisto.params().get('proxy', False):
#     del os.environ['HTTP_PROXY']
#     del os.environ['HTTPS_PROXY']
#     del os.environ['http_proxy']
#     del os.environ['https_proxy']


'''HELPER FUNCTIONS'''


def http_request(method, token, route, page_index=0, content=None):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body = ""
    if content:
        content['page'] = page_index
        body = json.dumps(content)
    r = requests.request(
        method,
        BASE_URL + route,
        data=body,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code != 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    return r.json()


def add_to_results(current_results_array, request_result):
    """
    function to add the current API call results to the results array
    input: original results array, request object as json
    output: merged arrays
    """
    try:
        return current_results_array + request_result['items']
    except Exception as e:
        print(f"Failed to add results!\nError message:\n{e}")
        sys.exit(1)

# # Allows nested keys to be accesible
# def makehash():
#     return collections.defaultdict(makehash)


def call_api(method, route, token, query):
    """
    loop pagination in case the total items count is bigger that PAGE_SIZE
    """
    results: List[Dict[str, Any]] = []
    res = http_request(method, token, route, content=query)
    results = add_to_results(results, res)
    for i in range(1, math.ceil(res['itemsTotal'] / PAGE_SIZE)):
        res = http_request(method, token, route, i, query)
        results = add_to_results(results, res)
    return results


def create_jwt_token(secret, access_key):
    try:
        jwt_payload = {
            "iat": int(time.time()),
            "sub": access_key
        }
        return jwt.encode(jwt_payload, secret, 'ES256').decode("utf-8")
    except Exception as e:
        print(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")
        sys.exit(1)


'''MAIN FUNCTIONS'''


def test_module(token, json=None):
    route = "/health"
    method = "GET"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    r = requests.request(
        method,
        BASE_URL + route,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code != 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))


def get_cve_command(token, cve_id):
    method = "GET"
    route = f"/vulnerability/{cve_id}/details"
    res = http_request(method, token, route)
    LOG('res %s' % (res,))
    if "cve_id" in res:
        command_results = CommandResults(
            outputs_prefix='Cve.Details',
            outputs_key_field='ReportID',
            outputs=res
        )
        return_results(command_results)
        #   demisto.results(res)


def get_assets_programs_command(token, name, publisher, version):
    method = "POST"
    route = "/assets/programs"
    rules = [{
        "field": "$type",
        "operator": "=",
        "value": "csv"
    }]

    if name:
        name_node = {
            "field": "name",
            "operator": "contains",
            "value": f"{name}"
        }
        rules.append(name_node)

    if publisher:
        publisher_node = {
            "field": "publisher",
            "operator": "contains",
            "value": f"{publisher}"
        }
        rules.append(publisher_node)

    if version:
        version_node = {
            "field": "version",
            "operator": "contains",
            "value": f"{version}"
        }
        rules.append(version_node)

    query = {
        "pageSize": PAGE_SIZE,
        "page": 0,
        "ruleSet": {
            "condition": "AND",
            "rules": rules
        }
    }

    res = call_api(method, route, token, query)
    LOG('results %s' % (res,))

    if res:
        command_results = CommandResults(
            outputs_prefix='Assets.Programs',
            outputs_key_field='itemsTotal',
            outputs=res
        )
        return_results(command_results)
        #   demisto.results(res)


def get_devices_command(token, host, os_type, os_name, status, agent_version):
    method = "POST"
    route = "/devices/search"
    rules = []
    if host:
        host_node = {
            'field': 'host',
            'operator': 'contains',
            'value': f'{host}'
        }
        rules.append(host_node)

    if os_type:
        os_type_node = {
            'field': 'osType',
            'operator': '=',
            'value': f'{os_type}'
        }
        rules.append(os_type_node)

    if os_name:
        os_name_node = {
            'field': 'osName',
            'operator': 'contains',
            'value': f'{os_name}'
        }
        rules.append(os_name_node)

    if status:
        status_node = {
            'field': 'status',
            'operator': '=',
            'value': f'{status}'
        }
        rules.append(status_node)

    if agent_version:
        agent_version_node = {
            'field': 'agentVersion',
            'operator': '=',
            'value': f'{agent_version}'
        }
        rules.append(agent_version_node)

    query = {
        'pageSize': PAGE_SIZE,
        'page': 0,
        'ruleSet': {
            'condition': 'AND',
            'rules': rules
        }
    }

    res = call_api(method, route, token, query)
    LOG('res %s' % (res,))

    if res:
        command_results = CommandResults(
            outputs_prefix='Device.Search',
            outputs_key_field='itemsTotal',
            outputs=res
        )
        return_results(command_results)
        #   demisto.results(res)


def get_vulnerable_devices_command(token, device_os, device_risk):
    method = "POST"
    route = "/vulnerability/devices"
    rules = []
    if device_os:
        device_os_node = {
            'field': 'device_os',
            'operator': '=',
            'value': f'{device_os}'
        }
        rules.append(device_os_node)

    if device_risk:
        device_risk_node = {
            'field': 'device_risk',
            'operator': '>=',
            'value': f'{device_risk}'
        }
        rules.append(device_risk_node)

    query = {
        'pageSize': PAGE_SIZE,
        'page': 0,
        'ruleSet': {
            'condition': 'AND',
            'rules': rules
        }
    }

    res = call_api(method, route, token, query)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Vulnerability.Devices',
            outputs_key_field='$host',
            outputs=res
        )
        return_results(command_results)
        #   demisto.results(res)


''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))
try:

    token = create_jwt_token(PRIVATE_KEY, ACCESS_KEY)
    if demisto.command() == 'test-module':
        test_module(token)
        demisto.results('ok')

    elif demisto.command() == 'infinipoint-get-cve':
        cve_id = demisto.args().get('cve_id')
        get_cve_command(token, cve_id)

    elif demisto.command() == 'infinipoint-get-assets-programs':
        name = demisto.args().get('name')
        publisher = demisto.args().get('publisher')
        version = demisto.args().get('version')
        # type = demisto.args().get('type')

        get_assets_programs_command(token, name, publisher, version)

    elif demisto.command() == 'infinipoint-get-device':
        host = demisto.args().get('host')
        os_type = demisto.args().get('osType')
        os_name = demisto.args().get('osName')
        status = demisto.args().get('status')
        agent_version = demisto.args().get('agentVersion')

        get_devices_command(token, host, os_type, os_name, status, agent_version)

    elif demisto.command() == 'infinipoint-get-vulnerable-devices':
        device_os = demisto.args().get('device_os')
        device_risk = demisto.args().get('device_risk')

        get_vulnerable_devices_command(token, device_os, device_risk)


except Exception as e:
    print(e)
    demisto.debug('The Senate? I am the Senate!')
    LOG(e)
    LOG.print_log()
    return_error(e)

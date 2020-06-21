
import jwt
import math
import struct

import demistomock as demisto
from CommonServerPython import *
# from CommonServerUserPython import *
from typing import Any, Dict, List

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

PAGE_SIZE = 10
PROXY = demisto.params().get('proxy')
INSECURE = demisto.params().get('insecure')
BASE_URL = demisto.params().get('url')
ACCESS_KEY = demisto.params().get('access_key')
PRIVATE_KEY = demisto.params().get('private_key')

'''HELPER FUNCTIONS'''


def http_request(method, token, route, page_index=0, content=None, use_pagination=True):
    """
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if content and use_pagination:
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


def call_api(method, route, client, rules, use_pagination=True):
    """
    loop pagination in case the total items count is bigger that PAGE_SIZE
    """
    # results = []
    if not use_pagination:
        res = http_request(method, client, route, content=rules, use_pagination=False)
        return res
    else:
        query = {
            'pageSize': PAGE_SIZE,
            'page': 0,
            'ruleSet': {
                'condition': 'AND',
                'rules': rules
            }
        }
        results: List[Dict[str, Any]] = []
        res = http_request(method, client, route, content=query)
        results = add_to_results(results, res)
        for i in range(1, math.ceil(res['itemsTotal'] / PAGE_SIZE)):
            res = http_request(method, client, route, i, query)
            results = add_to_results(results, res)
        return results


def create_jwt_token(secret, access_key):
    """
    function to sign a jwt token with a jwt secret.
    input: jwt secret, jwt access-key
    output: a signed token.
    """
    try:
        jwt_payload = {
            "iat": int(time.time()),
            "sub": access_key
        }
        return jwt.encode(jwt_payload, secret, 'ES256').decode("utf-8")
    except Exception as e:
        print(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")
        sys.exit(1)


def convert_string_to_ip(ip):
    """
    """
    convert_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
    convert_ip -= (1 << 32)
    return convert_ip


'''MAIN FUNCTIONS'''


def test_module(token, json=None):
    """Tests API connectivity and authentication'
    Returning '200' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
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


def get_cve_command(token, args):
    cve_id = args.get('cve_id')
    method = "GET"
    route = f"/vulnerability/{cve_id}/details"
    res = http_request(method, token, route)
    LOG('res %s' % (res,))
    if "cve_id" in res:
        command_results = CommandResults(
            outputs_prefix='Cve.Details',
            outputs_key_field='ReportID',
            outputs=res)
        return command_results
        #   demisto.results(res)


def get_assets_programs_command(token, args):
    name = args.get('name')
    publisher = args.get('publisher')
    version = args.get('version')
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

    res = call_api(method, route, token, rules)
    LOG('results %s' % (res,))

    if res:
        command_results = CommandResults(
            outputs_prefix='Assets.Programs',
            outputs_key_field='itemsTotal',
            outputs=res)
        return command_results


def get_assets_hardware_command(token, args):
    host = args.get('host')
    os_type = args.get('os_type')
    method = "POST"
    route = "/assets/hardware"
    rules = [{
        "field": "$type",
        "operator": "=",
        "value": "csv"
    }]

    if host:
        host_node = {
            "field": "$host",
            "operator": "contains",
            "value": f"{host}"
        }
        rules.append(host_node)

    if os_type:
        os_type_node = {
            "field": "os_type",
            "operator": "contains",
            "value": f"{os_type}"
        }
        rules.append(os_type_node)

    res = call_api(method, route, token, rules)
    LOG('results %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Assets.Programs',
            outputs_key_field='itemsTotal',
            outputs=res)
        return command_results


def get_assets_cloud_command(token, args):
    host = args.get('host')
    os_type = args.get('os_type')
    source = args.get('source')
    method = "POST"
    route = "/assets/cloud"
    rules = [{
        "field": "$type",
        "operator": "=",
        "value": "csv"
    }]

    if host:
        host_node = {
            "field": "$host",
            "operator": "contains",
            "value": f"{host}"
        }
        rules.append(host_node)

    if os_type:
        os_type_node = {
            "field": "os_type",
            "operator": "contains",
            "value": f"{os_type}"
        }
        rules.append(os_type_node)

    if source:
        source_node = {
            "field": "source",
            "operator": "contains",
            "value": f"{source}"
        }
        rules.append(source_node)

    res = call_api(method, route, token, rules)
    LOG('results %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Assets.Cloud',
            outputs_key_field='$host',
            outputs=res)
        return command_results


def get_assets_user_command(token, args):
    host = args.get('host')
    username = args.get('username')
    method = "POST"
    route = "/assets/users"
    rules = [{
        "field": "$type",
        "operator": "=",
        "value": "csv"
    }]

    if host:
        host_node = {
            "field": "$host",
            "operator": "contains",
            "value": f"{host}"
        }
        rules.append(host_node)

    if username:
        username_node = {
            "field": "username",
            "operator": "contains",
            "value": f"{username}"
        }
        rules.append(username_node)

    res = call_api(method, route, token, rules)
    LOG('results %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Assets.Users',
            outputs_key_field='$host',
            outputs=res)
        return command_results


def get_devices_command(token, args):
    host = args.get('host')
    os_type = args.get('osType')
    os_name = args.get('osName')
    status = args.get('status')
    agent_version = args.get('agentVersion')
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

    res = call_api(method, route, token, rules)
    LOG('res %s' % (res,))

    if res:
        command_results = CommandResults(
            outputs_prefix='Device.Search',
            outputs_key_field='itemsTotal',
            outputs=res)
        return (command_results)
        #   demisto.results(res)


def get_vulnerable_devices_command(token, args):
    device_os = args.get('device_os')
    device_risk = args.get('device_risk')
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

    res = call_api(method, route, token, rules)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Vulnerability.Devices',
            outputs_key_field='$host',
            outputs=res)
        return command_results
        #   demisto.results(res)


def get_tag_command(token, args):
    name = args.get('name')
    method = "POST"
    route = "/tags"
    rules = []

    if name:
        name_node = {
            'field': 'name',
            'operator': '=',
            'value': f'{name}'
        }
        rules.append(name_node)

    res = call_api(method, route, token, rules)
    LOG('res %s' % (res,))
    if res:
        # demisto.results(res)
        command_results = CommandResults(
            outputs_prefix='Tags',
            outputs_key_field='tagId',
            outputs=res)
        return command_results


def get_networks_command(token, args):
    alias = args.get('alias')
    gateway_ip = args.get('gateway_ip')
    cidr = args.get('cidr')
    method = "POST"
    route = "/networks"
    rules = []

    if alias:
        alias_node = {
            'field': 'alias',
            'operator': '=',
            'value': f'{alias}'
        }
        rules.append(alias_node)

    if gateway_ip:
        gateway_ip_node = {
            'field': 'gatewayIp',
            'operator': '=',
            'value': f'{convert_string_to_ip(gateway_ip)}'
        }
        rules.append(gateway_ip_node)

    if cidr:
        cidr_node = {
            'field': 'cidr',
            'operator': '=',
            'value': f'{cidr}'
        }
        rules.append(cidr_node)

    res = call_api(method, route, token, rules)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Networks.Info',
            outputs_key_field='alias',
            outputs=res)
        return command_results


def run_script_command(token, args):
    script_id = args.get('script_id')
    method = "POST"
    route = "/scripts/execute"

    script_id_node = {
        "scriptId": f"{script_id}"
    }

    res = call_api(method, route, token, script_id_node, False)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Scripts.Execute',
            outputs_key_field='actionId',
            outputs=res)
        return command_results


def get_action_command(token, args):
    action_id = args.get('action_id')
    method = "POST"
    route = f"/responses/{action_id}"
    # rules = []

    res = call_api(method, route, token, [])
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Responses',
            outputs_key_field='$host',
            outputs=res)
        return command_results


''' EXECUTION '''


def main():

    # PROXY = demisto.params().get('proxy')
    # INSECURE = demisto.params().get('insecure')
    # BASE_URL = demisto.params().get('url')
    # ACCESS_KEY = demisto.params().get('access_key')
    # PRIVATE_KEY = demisto.params().get('private_key')
    # verify_certificate = not demisto.params().get('insecure', False)
    # proxy = demisto.params().get('proxy', False)

    # if not demisto.params().get('proxy', False):
    #     del os.environ['HTTP_PROXY']
    #     del os.environ['HTTPS_PROXY']
    #     del os.environ['http_proxy']
    #     del os.environ['https_proxy']

    demisto.info('command is %s' % (demisto.command(), ))

    try:
        token = create_jwt_token(PRIVATE_KEY, ACCESS_KEY)

        if demisto.command() == 'test-module':
            test_module(token)
            demisto.results('ok')

        elif demisto.command() == 'infinipoint-get-cve':
            return_results(get_cve_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-assets-programs':
            return_results(get_assets_programs_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-assets-hardware':
            return_results(get_assets_hardware_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-assets-cloud':
            return_results(get_assets_cloud_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-assets-user':
            return_results(get_assets_user_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-device':
            return_results(get_devices_command(token, demisto.args()))

        elif demisto.command() == 'infinipoint-get-vulnerable-devices':
            return_results(get_vulnerable_devices_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-get-tag":
            return_results(get_tag_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-get-networks":
            return_results(get_networks_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-run-script":
            return_results(run_script_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-get-action":
            return_results(get_action_command(token, demisto.args()))

    except Exception as e:
        err_msg = f'Error - Infinipoint Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

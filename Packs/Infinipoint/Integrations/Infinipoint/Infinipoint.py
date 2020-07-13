from CommonServerPython import *
from typing import Any, Dict, List, Optional, cast


''' IMPORTS '''
import jwt
import math
import struct
import dateparser

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''HELPER FUNCTIONS'''


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def http_request(method, token, route, page_index=0, content=None, use_pagination=True):
    """
    """
    body = None
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    if content and use_pagination:
        content['page'] = page_index

    if content is not None:
        body = json.dumps(content)

    r = requests.request(
        method,
        BASE_URL + route,
        data=body,
        headers=headers,
        verify=False
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
        # print(f"Failed to add results!\nError message:\n{e}")
        return_error(f"Failed to add results!\nError message:\n{e}")
        # sys.exit(1)


def call_api(method, route, client, rules, use_pagination=True, condition='AND'):
    """
    loop pagination in case the total items count is bigger that PAGE_SIZE
    """

    if not use_pagination:
        res = http_request(method, client, route, content=rules, use_pagination=False)
        return res
    else:
        query = {
            'pageSize': PAGE_SIZE,
            'page': 0,
            'ruleSet': {
                'condition': condition,
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

        return jwt.encode(jwt_payload, secret.replace('\\n', '\n'), 'ES256').decode("utf-8")
    except Exception as e:
        # print(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")
        # sys.exit(1)
        return_error(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")


def convert_string_to_ip(ip):
    """
    """
    convert_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
    convert_ip -= (1 << 32)
    return convert_ip


def fetch_incidents(token: Any, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int]):
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    args = {
        'limit': max_results,
        'offset': last_fetch
    }

    alerts = get_non_compliance_device_command(token, args)

    if not isinstance(alerts, List):
        for alert in alerts.outputs:
            # If no created_time set is as epoch (0). We use time in ms so we must
            # convert it from the HelloWorld API response
            incident_created_time = int(alert.get('timestamp', '0'))
            incident_created_time_ms = incident_created_time * 1000

            # If no name is present it will throw an exception
            incident_name = "infinipoint - non compliant device"

            incident = {
                'name': incident_name + " - " + alert.get('hostname'),
                'details': ', '.join([d.get('issueType', None) for d in alert['issues']]),
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(alert),
                'severity': 2
            }

            incidents.append(incident)

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


''' GLOBALS/PARAMS '''

PAGE_SIZE = arg_to_int(arg=demisto.params().get('page_size'), arg_name='page_size', required=False)
INSECURE = demisto.params().get('insecure', False)
BASE_URL = demisto.params().get('url')
ACCESS_KEY = demisto.params().get('access_key')
PRIVATE_KEY = demisto.params().get('private_key')
FIRST_FETCH_TIME = arg_to_timestamp(arg=demisto.params().get('first_fetch', '3 days'),
                                    arg_name='First fetch time', required=True)
MAX_INCIDENTS_TO_FETCH = 1000


'''MAIN FUNCTIONS'''


def test_module(token, json=None):
    """Tests API connectivity and authentication'
    Returning '200' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    route = "/auth/health/"
    method = "POST"
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
    res = http_request(method, token, route, use_pagination=False)
    LOG('res %s' % (res,))
    if "cve_id" in res:
        command_results = CommandResults(
            outputs_prefix='Infinipoint.Cve.Details',
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
            outputs_prefix='Infinipoint.Assets.Programs',
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
            outputs_prefix='Infinipoint.Assets.Hardware',
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
            outputs_prefix='Infinipoint.Assets.Cloud',
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
            outputs_prefix='Infinipoint.Assets.User',
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
    # route = "/devices/search"
    route = "/devices"
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
            outputs_prefix='Infinipoint.Devices',
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
            outputs_prefix='Infinipoint.Vulnerability.Devices',
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
            outputs_prefix='Infinipoint.Tags',
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
            outputs_prefix='Infinipoint.Networks.Info',
            outputs_key_field='alias',
            outputs=res)
        return command_results


def get_action_command(token, args):
    action_id = args.get('action_id')
    method = "POST"
    route = f"/responses/{action_id}"
    rules = [
        {
            "field": "$type",
            "operator": "=",
            "value": "csv"
        },
        {
            "field": "$type",
            "operator": "=",
            "value": "raw"
        }
    ]

    res = call_api(method, route, token, rules, condition='OR')
    if res:
        command_results = CommandResults(
            outputs_prefix='Infinipoint.Responses',
            outputs_key_field='$host',
            outputs=res)
        return command_results


def get_queries_command(token, args):
    name = args.get('name')
    method = "POST"
    route = "/all-scripts/search"
    rules = []

    if name:
        name_node = {
            'field': 'name',
            'operator': 'contains',
            'value': f'{name}'
        }
        rules.append(name_node)

    res = call_api(method, route, token, rules)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Infinipoint.Scripts.Search',
            outputs_key_field='actionId',
            outputs=res)
        return command_results


def run_queries_command(token, args):
    id = args.get('id')
    target = args.get('target')
    method = "POST"
    route = "/all-scripts/execute"
    node = {'id': id}

    if target:
        node['target'] = {'ids': target}

    res = call_api(method, route, token, node, False)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Infinipoint.Scripts.execute',
            outputs_key_field='actionId',
            outputs=res)
        return command_results


def get_non_compliance_device_command(token, args):
    offset = args.get('offset')
    limit = args.get('limit')
    method = "POST"
    route = "/compliance/incidents"
    node = {'offset': offset,
            'limit': limit}

    res = call_api(method, route, token, node, False)
    LOG('res %s' % (res,))
    if res:
        command_results = CommandResults(
            outputs_prefix='Infinipoint.Compliance.Incidents',
            outputs_key_field='deviceID',
            outputs=res)
        return command_results

    return res


''' EXECUTION '''


def main():

    demisto.info('command is %s' % (demisto.command(), ))

    try:
        token = create_jwt_token(PRIVATE_KEY, ACCESS_KEY)

        if demisto.command() == 'test-module':
            test_module(token)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                token,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=FIRST_FETCH_TIME
            )
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)

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

        elif demisto.command() == "infinipoint-get-queries":
            return_results(get_queries_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-run-queries":
            return_results(run_queries_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-get-action":
            return_results(get_action_command(token, demisto.args()))

        elif demisto.command() == "infinipoint-get-non-compliance":
            return_results(get_non_compliance_device_command(token, demisto.args()))

    except Exception as e:
        err_msg = f'Error - Infinipoint Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

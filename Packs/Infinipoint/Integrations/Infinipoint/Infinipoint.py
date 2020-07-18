from CommonServerPython import *
from typing import Any, Dict, List, Optional, cast


''' IMPORTS '''
import jwt
import math
import struct
import dateparser

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):

    def call_command(self, url_suffix: str, args: Dict[str, Any], pagination=True, page_index=0, method='POST')\
            -> Dict[str, Any]:
        """
        """

        if args and pagination:
            args['page'] = page_index

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=args
        )

    def call_api(self, route, rules, pagination=True, condition='AND', method='POST'):
        """
        loop pagination in case the total items count is bigger that PAGE_SIZE
        """

        if not pagination:
            res = self.call_command(route, rules, pagination=pagination, method=method)
            return res
        else:
            query = {
                'pageSize': 100,
                'page': 0,
                'ruleSet': {
                    'condition': condition,
                    'rules': rules
                }
            }
            results: List[Dict[str, Any]] = []
            res = self.call_command(route, query, method=method)
            results = results + res['items']

            for i in range(1, math.ceil(res['itemsTotal'] / 100)):
                res = self.call_command(route, query, page_index=i, method=method)
                results = results + res['items']
            return results


'''HELPER FUNCTIONS'''


def get_auth_headers(access_key, private_key):
    """
    function to sign a jwt token with a jwt secret.
    output: request headers with a signed token
    """
    try:
        payload = {
            "iat": int(time.time()),
            "sub": access_key
        }
        token = jwt.encode(payload, private_key.replace('\\n', '\n'), 'ES256').decode("utf-8")
        return {"Content-Type": "application/json",
                "Authorization": f"Bearer {token}"}
    except Exception as e:
        return_error(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        return int(arg)

    if isinstance(arg, str):
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


def add_to_results(current_results_array, request_result):
    """
    function to add the current API call results to the results array
    input: original results array, request object as json
    output: merged arrays
    """
    try:
        return current_results_array + request_result['items']
    except Exception as e:
        return_error(f"Failed to add results!\nError message:\n{e}")


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
        return_error(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")


def convert_string_to_ip(ip):
    """
    """
    convert_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
    convert_ip -= (1 << 32)
    return convert_ip


def fetch_incidents(client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int]):

    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents: List[Dict[str, Any]] = []

    args = {
        'limit': max_results,
        'offset': last_fetch
    }

    alerts = get_non_compliance_device_command(client, '/api/compliance/incidents', args,
                                               'Infinipoint.Compliance.Incidents', 'deviceID')

    if not isinstance(alerts, List):
        for alert in alerts.outputs:
            incident_created_time = int(alert.get('timestamp', '0'))
            incident_created_time_ms = incident_created_time * 1000
            incident_name = "infinipoint - non compliant device"

            incident = {
                'name': f'{incident_name} - {alert.get("hostname")}',
                'details': ', '.join([d.get('issueType', None) for d in alert['issues']]),
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(alert)
            }

            incidents.append(incident)
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


'''MAIN FUNCTIONS'''


def test_module(route, base_url, insecure, headers):
    """Tests API connectivity and authentication'
    Returning '200' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    r = requests.request(
        "POST",
        base_url + route,
        headers=headers,
        verify=insecure
    )
    if r.status_code != 200:
        return_error(f'Error in API call [{r.status_code}] - {r.reason}')


def infinipoint_command(client, route, args, outputs_prefix, outputs_key_field, pagination=True):
    rules = []

    for arg in ['name', 'publisher', 'version', 'host', 'os_type', 'source', 'username', 'osType', 'osName',
                'status',
                'agentVersion', 'device_os', 'device_risk', 'alias',
                'gateway_ip', 'action_id', 'id', 'actionId', 'query_id']:
        if args.get(arg):
            rules.append({"field": arg, "operator": "contains", "value": f"{args[arg]}"})

    res = client.call_api(route, rules, pagination=pagination)

    if res:
        for node in res:
            if '$time' in node and isinstance(node['$time'], int):
                created_time_ms = int(node.get('$time', '0')) * 1000
                node['$time'] = timestamp_to_datestring(created_time_ms)

        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results


def get_devices_command(client, route, args, outputs_prefix, outputs_key_field, pagination=True):
    host = args.get('host')
    os_type = args.get('osType')
    os_name = args.get('osName')
    status = args.get('status')
    agent_version = args.get('agentVersion')
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

    res = client.call_api(route, rules, pagination=pagination)

    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return (command_results)


def get_vulnerable_devices_command(client, route, args, outputs_prefix, outputs_key_field, pagination=True):
    device_os = args.get('device_os')
    device_risk = args.get('device_risk')
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

    res = client.call_api(route, rules, pagination=pagination)

    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results


def get_networks_command(client, route, args, outputs_prefix, outputs_key_field, pagination=True):
    alias = args.get('alias')
    gateway_ip = args.get('gateway_ip')
    cidr = args.get('cidr')
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

    res = client.call_api(route, rules, pagination=pagination)

    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results


def get_action_command(client, args, outputs_prefix, outputs_key_field):
    route = f"/api/responses/{args.get('action_id')}"
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

    res = client.call_api(route, rules, condition='OR')
    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results


def run_queries_command(client, route, args, outputs_prefix, outputs_key_field):
    id = args.get('id')
    target = args.get('target')
    node = {'id': id}

    if target:
        node['target'] = {'ids': target}

    res = client.call_api(route, node, pagination=False)
    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results


def get_non_compliance_device_command(client, route, args, outputs_prefix, outputs_key_field):
    offset = args.get('offset')
    limit = args.get('limit')
    node = {'offset': offset,
            'limit': limit}

    res = client.call_api(route, node, pagination=False)

    if res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res)
        return command_results

    return res


def get_cve_command(client, args, outputs_prefix, outputs_key_field):
    res = client.call_api(f"/api/vulnerability/{args.get('cve_id')}/details", None, pagination=False, method="GET")

    if "cve_id" in res:
        cve = Common.CVE(
            id=res['cve_id'],
            cvss=res['cve_dynamic_data']['base_metric_v2']['base_score'],
            description=res['cve_description'],
            published='',
            modified=''
        )

        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res,
            indicators=[cve]
        )
        return command_results


def get_device_details_command(client, args, outputs_prefix, outputs_key_field):

    res = client.call_api(f"/api/discover/{args.get('discoveryId')}/details", None, pagination=False, method="GET")

    if "$device" in res:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=res
        )
        return command_results


''' EXECUTION '''


def main():
    INSECURE = demisto.params().get('insecure', False)
    BASE_URL = demisto.params().get('url')
    ACCESS_KEY = demisto.params().get('access_key')
    PRIVATE_KEY = demisto.params().get('private_key')
    FIRST_FETCH_TIME = arg_to_timestamp(arg=demisto.params().get('first_fetch', '3 days'),
                                        arg_name='First fetch time', required=True)
    PROXY = demisto.params().get('proxy', False)
    MAX_INCIDENTS_TO_FETCH = 1000

    demisto.info(f'command is {demisto.command()}')

    try:
        headers = get_auth_headers(ACCESS_KEY, PRIVATE_KEY)
        client = Client(
            base_url=BASE_URL,
            verify=INSECURE,
            headers=headers,
            proxy=PROXY)

        if demisto.command() == 'test-module':
            test_module("/api/auth/health/", BASE_URL, INSECURE, headers)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=FIRST_FETCH_TIME
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'infinipoint-get-cve':
            return_results(get_cve_command(client, demisto.args(), 'Infinipoint.Cve.Details', 'ReportID'))

        elif demisto.command() == 'infinipoint-get-assets-programs':
            return_results(infinipoint_command(client, '/api/assets/programs', demisto.args(), 'Infinipoint.Assets.Programs',
                                               'name'))

        elif demisto.command() == 'infinipoint-get-assets-hardware':
            return_results(infinipoint_command(client, '/api/assets/hardware', demisto.args(), 'Infinipoint.Assets.Hardware',
                                               '$host'))

        elif demisto.command() == 'infinipoint-get-assets-cloud':
            return_results(infinipoint_command(client, '/api/assets/cloud', demisto.args(), 'Infinipoint.Assets.Cloud',
                                               '$host'))

        elif demisto.command() == 'infinipoint-get-assets-users':
            return_results(infinipoint_command(client, '/api/assets/users', demisto.args(), 'Infinipoint.Assets.User', '$host'))

        elif demisto.command() == 'infinipoint-get-device':
            return_results(get_devices_command(client, '/api/devices', demisto.args(), 'Infinipoint.Devices', 'osName'))

        elif demisto.command() == 'infinipoint-get-vulnerable-devices':
            return_results(get_vulnerable_devices_command(client, '/api/vulnerability/devices', demisto.args(),
                                                          'Infinipoint.Vulnerability.Devices', '$host'))

        elif demisto.command() == "infinipoint-get-tag":
            return_results(infinipoint_command(client, '/api/tags', demisto.args(), 'Infinipoint.Tags', 'tagId'))

        elif demisto.command() == "infinipoint-get-networks":
            return_results(get_networks_command(client, '/api/networks', demisto.args(),
                                                'Infinipoint.Networks.Info', 'alias'))

        elif demisto.command() == "infinipoint-get-queries":
            return_results(infinipoint_command(client, '/api/all-scripts/search', demisto.args(), 'Infinipoint.Scripts.Search',
                                               'actionId'))

        elif demisto.command() == "infinipoint-run-queries":
            return_results(run_queries_command(client, '/api/all-scripts/execute', demisto.args(),
                                               'Infinipoint.Scripts.execute', 'actionId'))

        elif demisto.command() == "infinipoint-get-action":
            return_results(get_action_command(client, demisto.args(), 'Infinipoint.Responses', '$host'))

        elif demisto.command() == "infinipoint-get-non-compliance":
            return_results(get_non_compliance_device_command(client, "/api/compliance/incidents", demisto.args(),
                                                             'Infinipoint.Compliance.Incidents', 'deviceID'))

        elif demisto.command() == "infinipoint-get-device-details":
            return_results(get_device_details_command(client, demisto.args(), 'Infinipoint.Device.Details', '$device'))

    except Exception as e:
        err_msg = f'Error - Infinipoint Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

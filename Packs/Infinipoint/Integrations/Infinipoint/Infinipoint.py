from CommonServerPython import *
from typing import Any, cast


''' IMPORTS '''
import jwt
import math
import dateparser
from datetime import UTC

# disable insecure warnings
import urllib3
urllib3.disable_warnings()


''' GLOBAL VARS '''
BASE_URL = "https://console.infinipoint.io"
MAX_INCIDENTS_TO_FETCH = 1000
COMMANDS_CONFIG = {
    "infinipoint-get-assets-programs": {
        "args": {
            "name": "contains",
            "device_risk": "contains",
            "publisher": "contains",
            "version": "contains"
        },
        "route": "/api/assets/programs",
        "outputs_prefix": "Infinipoint.Assets.Programs",
        "outputs_key_field": "name"
    },

    "infinipoint-get-vulnerable-devices": {
        "args": {
            "device_os": "=",
            "device_risk": ">="
        },
        "route": "/api/vulnerability/devices",
        "outputs_prefix": "Infinipoint.Vulnerability.Devices",
        "outputs_key_field": "$host"
    },

    "infinipoint-get-cve": {
        "args": {
            "cve_id": "="
        },
        "route": "/api/vulnerability/{cve_id}/details",
        "outputs_prefix": "Infinipoint.Cve.Details",
        "outputs_key_field": "ReportID",
        "pagination": False,
        "get_req": True
    },

    "infinipoint-get-device": {
        "args": {
            "host": "contains",
            "osType": "=",
            "osName": "contains",
            "status": "=",
            "agentVersion": "="
        },
        "route": "/api/devices",
        "outputs_prefix": "Infinipoint.Devices",
        "outputs_key_field": "osName"
    },

    "infinipoint-get-tag": {
        "args": {
            "name": "contains"
        },
        "route": "/api/tags",
        "outputs_prefix": "Infinipoint.Tags",
        "outputs_key_field": "tagId"
    },

    "infinipoint-get-networks": {
        "args": {
            "alias": "=",
            "cidr": "="
        },
        "route": "/api/networks",
        "outputs_prefix": "Infinipoint.Networks.Info",
        "outputs_key_field": "alias"
    },

    "infinipoint-get-assets-devices": {
        "args": {
            "$host": "contains",
            "os_type": "contains"
        },
        "route": "/api/assets/hardware",
        "outputs_prefix": "Infinipoint.Assets.Hardware",
        "outputs_key_field": "$host"
    },

    "infinipoint-get-assets-cloud": {
        "args": {
            "host": "contains",
            "os_type": "contains",
            "source": "contains"
        },
        "route": "/api/assets/cloud",
        "outputs_prefix": "Infinipoint.Assets.Cloud",
        "outputs_key_field": "$host"
    },

    "infinipoint-get-assets-users": {
        "args": {
            "host": "contains",
            "username": "contains"
        },
        "route": "/api/assets/users",
        "outputs_prefix": "Infinipoint.Assets.User",
        "outputs_key_field": "$host"
    },

    "infinipoint-get-queries": {
        "args": {
            "name": "contains"
        },
        "route": "/api/all-scripts/search",
        "outputs_prefix": "Infinipoint.Scripts.Search",
        "outputs_key_field": "actionId"
    },

    "infinipoint-execute-action": {
        "args": {
            "id": "contains",
            "target": "contains"
        },
        "route": "/api/all-scripts/execute",
        "outputs_prefix": "Infinipoint.Scripts.execute",
        "outputs_key_field": "actionId",
        "pagination": False,
        "pass_args": True
    },

    "infinipoint-get-non-compliance": {
        "args": {
            "offset": "contains",
            "limit": "contains"
        },
        "route": "/api/demisto/events",
        "outputs_prefix": "Infinipoint.Compliance.Incidents",
        "outputs_key_field": "deviceID",
        "pagination": False,
        "pass_args": True
    },

    "infinipoint-get-device-details": {
        "args": {
            "discoveryId": "contains"
        },
        "route": "/api/discover/details/{discoveryId}",
        "outputs_prefix": "Infinipoint.Device.Details",
        "outputs_key_field": "$device",
        "pagination": False,
        "get_req": True,
    },

    "infinipoint-get-action-results": {
        "args": {
            "action_id": "contains"
        },
        "route": "/api/responses/{action_id}",
        "outputs_prefix": "Infinipoint.Responses",
        "outputs_key_field": "$host",
        "format_route": True
    },

    "infinipoint-get-compliance-status": {
        "args": {
            "device_id": "="
        },
        "route": "/api/compliance/device/{device_id}",
        "outputs_prefix": "Infinipoint.Compliance.Device",
        "outputs_key_field": "success",
        "pagination": False,
        "get_req": True
    }
}


class Client(BaseClient):

    def call_command(self, url_suffix: str, args: dict[str, Any], pagination=True, page_index=0, method='POST') \
            -> dict[str, Any]:
        """
        function to send a request to Infinipoint's API.
        """

        if args and pagination:
            args['page'] = page_index

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=args
        )

    def call_api(self, route: str, rules, pagination=True, condition='AND', method='POST'):
        """
        loop pagination in case the total items count is bigger that page size (100)
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
            results: list[dict[str, Any]] = []
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
        token = str(jwt.encode(payload, private_key.replace('\\n', '\n'), 'ES256'))
        return {"Content-Type": "application/json",
                "Authorization": f"Bearer {token}"}
    except Exception as e:
        return_error(f"Error while signing JWT token - check your private/access keys!\nError message:\n{e}")


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        return int(arg)

    if isinstance(arg, str):
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})

        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())

    if isinstance(arg, int | float):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> int | None:

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


def fetch_incidents(client, last_run: dict[str, int], first_fetch_time: int | None):
    max_results = arg_to_int(
        arg=demisto.params().get('max_fetch'),
        arg_name='max_fetch',
        required=False
    )

    if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    last_fetch = last_run.get('last_fetch', None)
    subscription = demisto.params().get('incident_type', ["event", "alert"])

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents: list[dict[str, Any]] = []

    args = {
        'limit': max_results,
        'offset': last_fetch
    }

    alerts = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-non-compliance'])

    if alerts:
        for alert in alerts.outputs:
            if alert.get("subscription") in subscription:
                incident_created_epoch_time = int(alert.get('timestamp', '0'))
                incident_created_time = datetime.fromtimestamp(int(alert.get('timestamp', '0')), UTC)

                incident = {
                    'name': f'Infinipoint {alert.get("name")}',
                    'type': f'Infinipoint {alert.get("type")}',
                    'occurred': incident_created_time.isoformat(),
                    'rawJSON': json.dumps(alert.get('rawJSON'))
                }

                incidents.append(incident)
                if incident_created_epoch_time > latest_created_time:
                    latest_created_time = incident_created_epoch_time

    next_run = {'last_fetch': latest_created_time}

    demisto.setLastRun(next_run)
    demisto.incidents(incidents)


'''MAIN FUNCTIONS'''


def test_module(route, base_url, insecure, headers):
    """Tests API connectivity and authentication'
    Returning '200' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    res = requests.request(
        "POST",
        base_url + route,
        headers=headers,
        verify=insecure
    )
    res.raise_for_status()


def infinipoint_command(client: Client, args=None, optional_args=None, pagination=True):
    rules = None
    cve = None
    method = "POST"

    # Cancel pagination if necessary
    if "pagination" in optional_args:
        pagination = optional_args['pagination']

    # Pass arguments as is
    if "pass_args" in optional_args:
        rules = args
    # Move request type to GET
    elif "get_req" in optional_args:
        optional_args['route'] = optional_args['route'].format(**args)
        method = "GET"

    # Change url - Post request
    elif "format_route" in optional_args:
        optional_args['route'] = optional_args['route'].format(**args)

    else:
        rules = []
        for k, v in optional_args['args'].items():
            if args.get(k):
                rules.append({'field': k, "operator": v, "value": f"{args[k]}"})

    res = client.call_api(optional_args['route'], rules, pagination=pagination, method=method)

    if res:
        for node in res:
            # Handle time format - convert to ISO from epoch
            if '$time' in node and isinstance(node['$time'], int):
                created_time = datetime.fromtimestamp(int(node.get('$time', '0')), UTC)
                node['$time'] = created_time.isoformat()

        # CVE reputation
        if "cve_id" in res:
            cve = Common.CVE(
                id=res['cve_id'],
                cvss=res['cve_dynamic_data']['base_metric_v2']['base_score'],
                description=res['cve_description'],
                published='',
                modified=''
            )

        return CommandResults(outputs_prefix=optional_args['outputs_prefix'],
                              outputs_key_field=optional_args['outputs_key_field'],
                              outputs=res,
                              indicator=cve)
    return None


def run_queries_command(client: Client, args: dict, optional_args=None):
    target = args.get('target')
    node = {'id': args.get('id')}
    if target:
        node['target'] = {'ids': argToList(args.get('target'))}
    res = client.call_api(route=optional_args['route'], rules=node, pagination=False)
    if res:
        command_results = CommandResults(
            outputs_prefix=optional_args['outputs_prefix'],
            outputs_key_field=optional_args['outputs_key_field'],
            outputs=res)
        return command_results
    return None


''' EXECUTION '''


def main():
    verify_ssl = not demisto.params().get('insecure', False)
    access_key = demisto.params().get('access_key')
    private_key = demisto.params().get('private_key')
    first_fetch_time = arg_to_timestamp(arg=demisto.params().get('first_fetch', '3 days'),
                                        arg_name='First fetch time', required=True)
    proxy = demisto.params().get('proxy', False)

    demisto.info(f'command is {demisto.command()}')

    try:
        headers = get_auth_headers(access_key, private_key)
        client = Client(
            base_url=BASE_URL,
            verify=verify_ssl,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            test_module("/api/auth/health/", BASE_URL, verify_ssl, headers)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

        elif demisto.command() == "infinipoint-execute-action":
            return_results(run_queries_command(client=client, args=demisto.args(),
                                               optional_args=COMMANDS_CONFIG["infinipoint-execute-action"]))

        elif demisto.command() in COMMANDS_CONFIG:
            return_results(infinipoint_command(client=client, args=demisto.args(),
                                               optional_args=COMMANDS_CONFIG[demisto.command()]))

    except Exception as e:
        err_msg = f'Error - Infinipoint Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

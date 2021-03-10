import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import traceback
from typing import Dict, Any, Tuple
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_INCIDENTS_TO_FETCH = 50
CURRENT_VERSION_OF_THE_POLICY_API = 2  # this is the current version of the policy api
COMMAND_NOT_IMPELEMENTED_MSG = 'Command not implemented'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxies, api_key, api_secret_key, policy_api_key, policy_api_secret_key,
                 organization_key):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.organization_key = organization_key
        self.headers = {'X-Auth-Token': f'{api_secret_key}/{api_key}', 'Content-Type': 'application/json'}
        self.policy_headers = {'X-Auth-Token': f'{policy_api_secret_key}/{policy_api_key}',
                               'Content-Type': 'application/json'}
        super(Client, self).__init__(base_url, verify, proxies)

    def test_module_request(self):
        suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        return self._http_request('POST', url_suffix=suffix_url, headers=self.headers, json_data={})

    def policy_test_module_request(self):
        suffix_url = 'integrationServices/v3/policy'
        return self._http_request('GET', url_suffix=suffix_url, headers=self.policy_headers)

    def search_alerts_request(self, suffix_url_path: str = None, minimum_severity: int = None, create_time: Dict = None,
                              policy_id: List = None, device_username: List = None, device_id: List = None,
                              process_sha256: List = None, alert_type: List = None, query: str = None,
                              alert_category: List = None, sort_field: str = "first_event_time",
                              sort_order: str = "ASC", limit: int = 50) -> Dict:
        if suffix_url_path == "all":
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        else:
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/{suffix_url_path}/_search'
        body = {
            'criteria': assign_params(
                minimum_severity=minimum_severity,
                create_time=create_time,
                policy_id=policy_id,
                device_username=device_username,
                device_id=device_id,
                process_sha256=process_sha256,
                type=alert_type,
                category=alert_category
            ),
            'sort': [
                {
                    'field': sort_field,
                    'order': sort_order
                }
            ],
            'rows': limit,
        }
        if query:
            body['query'] = query
        return self._http_request('POST', suffix_url, headers=self.headers, json_data=body)

    # Policies API
    def create_new_policy(self, name: str, description: str, priority_level: str, policy: dict):
        suffix_url = 'integrationServices/v3/policy'
        body = {
            "policyInfo": assign_params(
                name=name,
                description=description,
                priorityLevel=priority_level,
                policy=policy,
                version=CURRENT_VERSION_OF_THE_POLICY_API
            )
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=body)

    def get_policies(self):
        suffix_url = 'integrationServices/v3/policy'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def get_policy_by_id(self, policy_id: int):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def set_policy(self, policy_id: int, policy_info: dict):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=policy_info)

    def update_policy(self, policy_id: int, description: str, name: str, priority_level: str, policy: dict):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        body = assign_params(
            policyInfo=assign_params(
                id=policy_id,
                name=name,
                description=description,
                priorityLevel=priority_level,
                policy=policy,
                version=CURRENT_VERSION_OF_THE_POLICY_API
            )
        )
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=body)

    def delete_policy(self, policy_id: int):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    def add_rule_to_policy(self, policy_id: int, action: str, operation: str, required: str, rule_id: int, type: str,
                           value: str):
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule'
        body = {
            'ruleInfo': assign_params(
                action=action,
                operation=operation,
                required=required,
                id=rule_id,
                application=assign_params(
                    type=type,
                    value=value
                )
            )
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def update_rule_in_policy(self, policy_id: int, action: str, operation: str, required: str, rule_id: int, type: str,
                              value: str):
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule/{rule_id}'
        body = {
            'ruleInfo': assign_params(
                action=action,
                operation=operation,
                required=required,
                id=rule_id,
                application=assign_params(
                    type=type,
                    value=value
                )
            )
        }
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def delete_rule_from_policy(self, policy_id: int, rule_id: int):
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    # The events API
    def get_events(self, alert_category: list[str], blocked_hash: list[str], device_external_ip: list[str],
                   device_id: list[int], device_internal_ip: list[int], device_name: list[str], device_os: list[str],
                   event_type: list[str], parent_hash: list[str], parent_name: list[str], parent_reputation: list[str],
                   process_cmdline: list[str], process_guid: list[str], process_hash: list[str],
                   process_name: list[str], process_pid: list[int], process_reputation: list[str],
                   process_start_time: list[str], process_terminated: list[str], process_username: list[str],
                   sensor_action: list[str], query: str = None, start: int = None, time_range: dict = None,
                   rows: int = None):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs'
        body = assign_params(
            criteria=assign_params(  # one of the arguments (query or criteria) is required
                alert_category=alert_category,
                blocked_hash=blocked_hash,
                device_external_ip=device_external_ip,
                device_id=device_id,
                device_internal_ip=device_internal_ip,
                device_name=device_name,
                device_os=device_os,
                event_type=event_type,
                parent_hash=parent_hash,
                parent_name=parent_name,
                parent_reputation=parent_reputation,
                process_cmdline=process_cmdline,
                process_guid=process_guid,
                process_hash=process_hash,
                process_name=process_name,
                process_pid=process_pid,
                process_reputation=process_reputation,
                process_start_time=process_start_time,
                process_terminated=process_terminated,
                process_username=process_username,
                sensor_action=sensor_action
            ),
            query=query,  # one of the arguments (query or criteria/exclusion) is required
            rows=rows,
            start=start,
            time_range=time_range
        )
        if not body.get('criteria') and not body.get('query'):
            return "One of the required arguments is missing"
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_results(self, job_id: str, rows: int = 10):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs/{job_id}/results' \
                     f'?rows={rows}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_events_details(self, event_ids: list[str]):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs'
        body = assign_params(
            event_ids=event_ids
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_details_results(self, job_id: str):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs/{job_id}/results'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Processes API
    def get_processes(self, alert_category: list[str], blocked_hash: list[str], device_external_ip: list[str],
                      device_id: list[int], device_internal_ip: list[int], device_name: list[str], device_os: list[str],
                      device_timestamp: list[str], event_type: list[str], parent_hash: list[str],
                      parent_name: list[str], parent_reputation: list[str], process_cmdline: list[str],
                      process_guid: list[str], process_hash: list[str], process_name: list[str], process_pid: list[int],
                      process_reputation: list[str], process_start_time: list[str], process_terminated: list[str],
                      process_username: list[str], sensor_action: list[str], query: str = None, start: int = None,
                      time_range: str = None, rows: int = None):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs'
        body = assign_params(
            criteria=assign_params(
                alert_category=alert_category,
                blocked_hash=blocked_hash,
                device_external_ip=device_external_ip,
                device_id=device_id,
                device_internal_ip=device_internal_ip,
                device_name=device_name,
                device_os=device_os,
                device_timestamp=device_timestamp,
                event_type=event_type,
                parent_hash=parent_hash,
                parent_name=parent_name,
                parent_reputation=parent_reputation,
                process_cmdline=process_cmdline,
                process_guid=process_guid,
                process_hash=process_hash,
                process_name=process_name,
                process_pid=process_pid,
                process_reputation=process_reputation,
                process_start_time=process_start_time,
                process_terminated=process_terminated,
                process_username=process_username,
                sensor_action=sensor_action,
            ),
            query=query,
            rows=rows,
            start=start,
            time_range=time_range
        )
        if not body.get('criteria') and not body.get('query'):
            return "One of the required arguments is missing"
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_process_results(self, job_id: str, rows: int = 10):
        suffix_url = f"api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs/{job_id}/results?rows=" \
                     f"{rows}"
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Alerts API
    def get_alerts(self, alert_type: str, category: list[str] = None, device_id: List[int] = None,
                   first_event_time: dict = None, policy_id: List[int] = None, process_sha256: List[str] = None,
                   reputation: List[str] = None, tag: List[str] = None, device_username: List[str] = None,
                   query: str = None, rows: int = None, start: int = None):
        if alert_type == "all":
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        else:
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_type.lower()}/_search'
        body = assign_params(
            criteria=assign_params(
                category=category,
                device_id=device_id,
                first_event_time=first_event_time,
                policy_id=policy_id,
                process_sha256=process_sha256,
                reputation=reputation,
                tag=tag,
                device_username=device_username,
            ),
            query=query,
            rows=rows,
            start=start
        )
        return self._http_request(method='POST',
                                  url_suffix=suffix_url,
                                  headers=self.headers,
                                  json_data=body)

    def get_alert_by_id(self, alert_id: str) -> dict:
        res = self._http_request(method='GET',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_id}',
                                 headers=self.headers)
        return res

    # Devices API
    def get_devices(self, device_id: List = None, status: List = None, device_os: List = None,
                    last_contact_time: Dict[str, Optional[Any]] = None, target_priority: List = None, query: str = None,
                    rows: int = None) -> Dict:
        suffix_url = f'/appservices/v6/orgs/{self.organization_key}/devices/_search'
        body = assign_params(
            criteria=assign_params(
                id=device_id,
                status=status,
                os=device_os,
                last_contact_time=last_contact_time,
                target_priority=target_priority
            ),
            query=query,
            rows=rows
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def execute_an_action_on_the_device(self, device_id: list[int], action_type: str, options: dict) -> str:
        suffix_url = f'appservices/v6/orgs/{self.organization_key}/device_actions'
        body = assign_params(
            action_type=action_type,
            device_id=device_id,
            options=options
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body,
                                  resp_type='text')


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        api_key = params.get('api_key')
        api_secret_key = params.get('api_secret_key')
        policy_api_key = params.get('policy_api_key')
        policy_api_secret_key = params.get('policy_api_secret_key')
        organization_key = params.get('organization_key')
        is_fetch = params.get('isFetch')

        if api_key and api_secret_key and organization_key or policy_api_key and policy_api_secret_key and not is_fetch:
            if api_key and api_secret_key and organization_key:
                client.test_module_request()
                message = 'ok'
                if is_fetch:
                    client.search_alerts_request("all")
                    message = 'ok'
            if policy_api_key and policy_api_secret_key:
                client.policy_test_module_request()
                message = 'ok'
        else:
            message = 'Missing required parameters'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, filters: dict) -> Tuple[List,
                                                                                                               Dict]:
    last_fetched_alert_create_time = last_run.get('last_fetched_alert_create_time')
    last_fetched_alert_id = last_run.get('last_fetched_alert_id', '')
    if not last_fetched_alert_create_time:
        last_fetched_alert_create_time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.000Z')
    latest_alert_create_date = last_fetched_alert_create_time
    latest_alert_id = last_fetched_alert_id

    incidents = []

    response = client.search_alerts_request(
        suffix_url_path=filters.get('suffix_url_path'),
        alert_category=filters.get('category'),
        device_id=filters.get('device_id'),
        policy_id=filters.get('policy_id'),
        process_sha256=filters.get('process_sha256'),
        device_username=filters.get('device_username'),
        alert_type=filters.get('alert_type'),
        query=filters.get('query'),
        sort_field='first_event_time',
        sort_order='ASC',
        create_time=assign_params(
            start=last_fetched_alert_create_time,
            end=datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ),
        limit=fetch_limit
    )
    alerts = response.get('results', [])

    for alert in alerts:
        alert_id = alert.get('id')
        if alert_id == last_fetched_alert_id:
            # got an alert we already fetched, skipping it
            continue

        alert_create_date = alert.get('create_time')
        incident = {
            'name': f'Carbon Black Defense alert {alert_id}',
            'occurred': alert_create_date,
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)

        datetime_type_alert_create_date = dateparser.parse(alert_create_date)
        if datetime_type_alert_create_date:
            latest_alert_create_date = datetime.strftime(datetime_type_alert_create_date + timedelta(seconds=1),
                                                         '%Y-%m-%dT%H:%M:%S.000Z')
        latest_alert_id = alert_id

    res = {'last_fetched_alert_create_time': latest_alert_create_date, 'last_fetched_alert_id': latest_alert_id}
    return incidents, res


def create_policy_command(client: Client, args: dict):
    name = args.get('name')
    description = args.get('description')
    priority_level = args.get('priorityLevel')
    policy = args.get('policy')

    if not name or not description or not priority_level or not policy:
        return "Missing required arguments."
    res = client.create_new_policy(name, description, priority_level, json.loads(policy))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': res.get('policyId')})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def get_policies_command(client: Client, args: dict):
    res = client.get_policies()
    human_readable = []
    policies = res.get('results', [])
    headers = ["id", "priorityLevel", "systemPolicy", "latestRevision", "version"]

    if not policies:
        return 'No policy found.'
    for policy in policies:
        human_readable.append({
            "id": policy.get('id'),
            "priorityLevel": policy.get('priorityLevel'),
            "systemPolicy": policy.get('systemPolicy'),
            "latestRevision": timestamp_to_datestring(policy.get('latestRevision')),
            "version": policy.get('version')
        })

    readable_output = tableToMarkdown('Carbon Black Defense Policies',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=policies,
        readable_output=readable_output,
        raw_response=res
    )


def get_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    headers = ["id", "description", "name", "latestRevision", "version", "priorityLevel", "systemPolicy"]

    if not policy_id:
        return "Missing required arguments."
    res = client.get_policy_by_id(policy_id)

    policy_info = dict(res.get('policyInfo'))
    if not policy_info:
        return "Policy not found."
    del policy_info['policy']
    policy_info['latestRevision'] = timestamp_to_datestring(policy_info['latestRevision'])

    readable_output = tableToMarkdown('Carbon Black Defense Policy',
                                      policy_info,
                                      headers=headers,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=res.get('policyInfo'),
        readable_output=readable_output,
        raw_response=res
    )


def set_policy_command(client: Client, args: dict):
    policy_id = args.get('policy')
    policy_info = args.get('keyValue')

    if not policy_id or not policy_info:
        return "Missing required arguments."
    res = client.set_policy(policy_id, json.loads(policy_info))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def update_policy_command(client: Client, args: dict):
    policy_id = args.get('id')
    name = args.get('name')
    description = args.get('description')
    priority_level = args.get('priorityLevel')
    policy = args.get('policy')

    if not policy_id or not name or not description or not priority_level or not policy:
        return "Missing required arguments."
    res = client.update_policy(policy_id, description, name, priority_level, json.loads(policy))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def delete_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')

    if not policy_id:
        return "Missing required arguments."
    res = client.delete_policy(policy_id)

    return CommandResults(
        readable_output=tableToMarkdown("The Delete Policy Response", res, headerTransform=string_to_table_header),
        raw_response=res
    )


def add_rule_to_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    rule_id = args.get('id')
    type = args.get('type')
    value = args.get('value')

    if not policy_id or not action or not operation or not required or not rule_id or not type or not value:
        return "Missing required arguments."
    res = client.add_rule_to_policy(policy_id, action, operation, required, rule_id, type, value)

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def update_rule_in_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    rule_id = args.get('id')
    type = args.get('type')
    value = args.get('value')

    if not policy_id or not action or not operation or not required or not rule_id or not type or not value:
        return "Missing required arguments."
    res = client.update_rule_in_policy(policy_id, action, operation, required, rule_id, type, value)

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def delete_rule_from_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    rule_id = args.get('ruleId')

    if not policy_id or not rule_id:
        return "Missing required arguments."
    res = client.delete_rule_from_policy(int(policy_id), int(rule_id))
    readable_output = tableToMarkdown("Carbon Black Defense Delete Rule From Policy",
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_command(client: Client, args: dict):
    alert_category = argToList(args.get('alert_category'))
    blocked_hash = argToList(args.get('blocked_hash'))
    device_external_ip = argToList(args.get('device_external_ip'))
    device_id = argToList(args.get('device_id'))
    device_internal_ip = argToList(args.get('device_internal_ip'))
    device_name = argToList(args.get('device_name'))
    device_os = argToList(args.get('device_os'))
    event_type = argToList(args.get('event_type'))
    parent_hash = argToList(args.get('parent_hash'))
    parent_name = argToList(args.get('parent_name'))
    parent_reputation = argToList(args.get('parent_reputation'))
    process_cmdline = argToList(args.get('process_cmdline'))
    process_guid = argToList(args.get('process_guid'))
    process_hash = argToList(args.get('process_hash'))
    process_name = argToList(args.get('process_name'))
    process_pid = argToList(args.get('process_pid'))
    process_reputation = argToList(args.get('process_reputation'))
    process_start_time = argToList(args.get('process_start_time'))
    process_terminated = argToList(args.get('process_terminated'))
    process_username = argToList(args.get('process_username'))
    sensor_action = argToList(args.get('sensor_action'))
    query = args.get('query')
    rows = args.get('rows')
    start = args.get('start')
    time_range = args.get('timerange')

    if time_range:
        time_range = json.loads(time_range)

    res = client.get_events(alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                            device_name, device_os, event_type, parent_hash, parent_name,
                            parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                            process_pid, process_reputation, process_start_time, process_terminated,
                            process_username, sensor_action, query, start, time_range, rows)

    if type(res) is str:
        return res

    readable_output = tableToMarkdown('Carbon Black Defense Events Search',
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Events.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_results_command(client: Client, args: dict):
    job_id = args.get('job_id')
    rows = args.get('rows')
    if not job_id:
        return CommandResults(
            readable_output="The job id can't be empty",
            raw_response="The job id can't be empty"
        )
    if not rows:
        rows = 10
    res = client.get_events_results(job_id, rows)

    headers = ['event_id', 'device_id', 'event_network_remote_port', 'event_network_remote_ipv4',
               'event_network_local_ipv4', 'enriched_event_type']

    human_readable = res.get('results')
    readable_output = tableToMarkdown('Carbon Black Defense Event Results',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Events.Results',
        outputs_key_field='results.event_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_command(client: Client, args: dict):
    event_ids = argToList(args.get('event_ids'))
    if not event_ids or len(event_ids) == 0:
        return CommandResults(
            readable_output="The event id can't be empty",
            raw_response="The event id can't be empty"
        )

    res = client.get_events_details(event_ids)
    readable_output = tableToMarkdown('Carbon Black Defense Event Details Search',
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.EventDetails.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_results_command(client: Client, args: dict):
    job_id = args.get('job_id')
    if not job_id:
        return CommandResults(
            readable_output="The job id can't be empty",
            raw_response="The job id can't be empty"
        )

    res = client.get_events_details_results(job_id)
    headers = ['event_id', 'device_id', 'event_network_remote_port', 'event_network_remote_ipv4',
               'event_network_local_ipv4', 'enriched_event_type']

    human_readable = res.get('results')
    readable_output = tableToMarkdown('Carbon Black Defense Event Details Results',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.EventDetails.Results',
        outputs_key_field='results.event_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_processes_command(client: Client, args: dict):
    alert_category = argToList(args.get('alert_category'))
    blocked_hash = argToList(args.get('blocked_hash'))
    device_external_ip = argToList(args.get('device_external_ip'))
    device_id = argToList(args.get('device_id'))
    device_internal_ip = argToList(args.get('device_internal_ip'))
    device_name = argToList(args.get('device_name'))
    device_os = argToList(args.get('device_os'))
    device_timestamp = argToList(args.get('device_timestamp'))
    event_type = argToList(args.get('event_type'))
    parent_hash = argToList(args.get('parent_hash'))
    parent_name = argToList(args.get('parent_name'))
    parent_reputation = argToList(args.get('parent_reputation'))
    process_cmdline = argToList(args.get('process_cmdline'))
    process_guid = argToList(args.get('process_guid'))
    process_hash = argToList(args.get('process_hash'))
    process_name = argToList(args.get('process_name'))
    process_pid = argToList(args.get('process_pid'))
    process_reputation = argToList(args.get('process_reputation'))
    process_start_time = argToList(args.get('process_start_time'))
    process_terminated = argToList(args.get('process_terminated'))
    process_username = argToList(args.get('process_username'))
    sensor_action = argToList(args.get('sensor_action'))
    query = args.get('query')
    rows = args.get('rows')
    start = args.get('start')
    time_range = args.get('time_range')

    if time_range:
        time_range = json.loads(time_range)

    res = client.get_processes(alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                               device_name, device_os, device_timestamp, event_type, parent_hash, parent_name,
                               parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                               process_pid, process_reputation, process_start_time, process_terminated,
                               process_username, sensor_action, query, start, time_range, rows)

    if type(res) is str:
        return res
    readable_output = tableToMarkdown('Carbon Black Defense Processes Search',
                                      res,
                                      headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Process.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_processes_results_command(client: Client, args: dict):
    job_id = args.get('job_id')
    rows = args.get('rows')

    if not job_id:
        return CommandResults(
            readable_output="The job id can't be empty",
            raw_response="The job id can't be empty"
        )

    if not rows:
        rows = 10
    res = client.get_process_results(job_id, rows)
    headers = ['device_id', 'device_name', 'process_name', 'device_policy_id', 'enriched_event_type']

    human_readable = res.get('results')
    readable_output = tableToMarkdown('The Results For The Process Search',
                                      human_readable,
                                      headers=headers,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Process.Results',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def alerts_search_command(client: Client, args: dict):
    alert_type = args.get('type', 'all')
    category = argToList(args.get('category'))
    device_id = argToList(args.get('device_id'))
    first_event_time = args.get('first_event_time')
    policy_id = argToList(args.get('policy_id'))
    process_sha256 = argToList(args.get('process_sha256'))
    reputation = argToList(args.get('reputation'))
    tag = argToList(args.get('tag'))
    device_username = args.get('device_username')
    query = args.get('query')
    rows = args.get('rows')
    start = args.get('start')
    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
               'process_name', 'type', 'severity']
    human_readable = []

    if first_event_time:
        first_event_time = json.loads(first_event_time)
    res = client.get_alerts(alert_type, category, device_id, first_event_time, policy_id, process_sha256, reputation,
                            tag, device_username, query, rows, start)

    alerts = res.get('results', [])
    if not alerts:
        return 'No alerts were found.'
    for alert in alerts:
        human_readable.append({
            'id': alert.get('id'),
            'category': alert.get('category'),
            'device_id': alert.get('device_id'),
            'device_name': alert.get('device_name'),
            'device_username': alert.get('device_username'),
            'create_time': alert.get('create_time'),
            'ioc_hit': alert.get('ioc_hit'),
            'policy_name': alert.get('policy_name'),
            'process_name': alert.get('process_name'),
            'type': alert.get('type'),
            'severity': alert.get('severity')
        })

    readable_output = tableToMarkdown('Carbon Black Defense Alerts List Results', human_readable, headers,
                                      headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=alerts,
        readable_output=readable_output,
        raw_response=res
    )


def get_alert_details_command(client: Client, args: dict):
    alert_id = args.get('alertId')

    if not alert_id:
        return "Missing required arguments."
    res = client.get_alert_by_id(alert_id)

    if 'id' not in res.keys():
        return 'The alert you requested was not found'

    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
               'process_name', 'type', 'severity']
    readable_output = tableToMarkdown('Carbon Black Defense Get Alert Details',
                                      res,
                                      headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def device_search_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    device_os = argToList(args.get('os'))
    device_status = argToList(args.get('status'))
    last_location = {
        'start': args.get('start_time'),
        'end': args.get('end_time')
    }
    target_priority = argToList(args.get('target_priority'))
    query = args.get('query')
    rows = args.get('rows')
    human_readable = []
    headers = ['ID', 'Name', 'OS', 'PolicyName', 'Quarantined', 'status', 'TargetPriority', 'LastInternalIpAddress',
               'LastExternalIpAddress', 'LastContactTime', 'LastLocation']

    result = client.get_devices(device_id, device_status, device_os, last_location, target_priority, query, rows)

    devices = result.get('results', [])
    if not devices:
        return 'No devices were found.'
    for device in devices:
        human_readable.append({
            'ID': device.get('id'),
            'Name': device.get('name'),
            'OS': device.get('os'),
            'LastInternalIpAddress': device.get('last_internal_ip_address'),
            'LastExternalIpAddress': device.get('last_external_ip_address'),
            'LastContactTime': device.get('last_contact_time'),
            'LastLocation': device.get('last_location'),
            'PolicyName': device.get('policy_name'),
            'Quarantined': device.get('quarantined'),
            'status': device.get('status'),
            'TargetPriority': device.get('target_priority')
        })

    readable_output = tableToMarkdown('Carbon Black Defense Devices List Results', human_readable, headers,
                                      removeNull=True)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Device',
        outputs_key_field='id',
        outputs=devices,
        readable_output=readable_output,
        raw_response=result
    )


def device_quarantine_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "ON"})

    return CommandResults(
        readable_output="Device quarantine successfully",
        raw_response="Device quarantine successfully"
    )


def device_unquarantine_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Device unquarantine successfully",
        raw_response="Device unquarantine successfully"
    )


def device_background_scan_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "ON"})

    return CommandResults(
        readable_output="Background scan started successfully",
        raw_response="Background scan started successfully"
    )


def device_background_scan_stop_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Background scan stopped successfully",
        raw_response="Background scan stopped successfully"
    )


def device_bypass_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "ON"})

    return CommandResults(
        readable_output="Device bypass successfully",
        raw_response="Device bypass successfully"
    )


def device_unbypass_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    if not device_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Device unbypass successfully",
        raw_response="Device unbypass successfully"
    )


def device_policy_update_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    policy_id = args.get('policy_id')

    if not device_id or not policy_id:
        return "Missing required arguments"
    client.execute_an_action_on_the_device(device_id, 'UPDATE_POLICY', {"policy_id": policy_id})

    return CommandResults(
        readable_output="Policy updated successfully",
        raw_response="Policy updated successfully"
    )


def device_update_sensor_version_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    sensor_version = args.get('sensor_version')

    if not device_id or not sensor_version:
        return "Missing required parameters"
    client.execute_an_action_on_the_device(device_id, 'UPDATE_SENSOR_VERSION',
                                           {"sensor_version": json.loads(sensor_version)})
    return CommandResults(
        readable_output=f"Version update to {sensor_version} was successful",
        raw_response=f"Version update to {sensor_version} was successful"
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    command = demisto.command()

    # Get the parameters
    params = demisto.params()
    base_url = params.get('url')
    api_key = params.get('api_key')
    api_secret_key = params.get('api_secret_key')
    policy_api_key = params.get('policy_api_key')
    policy_api_secret_key = params.get('policy_api_secret_key')
    organization_key = params.get('organization_key')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxies=proxy,
            api_key=api_key,
            api_secret_key=api_secret_key,
            policy_api_key=policy_api_key,
            policy_api_secret_key=policy_api_secret_key,
            organization_key=organization_key
        )

        commands = {
            'cbd-create-policy': create_policy_command,
            'cbd-get-policies': get_policies_command,
            'cbd-get-policy': get_policy_command,
            'cbd-set-policy': set_policy_command,
            'cbd-update-policy': update_policy_command,
            'cbd-delete-policy': delete_policy_command,
            'cbd-add-rule-to-policy': add_rule_to_policy_command,
            'cbd-update-rule-in-policy': update_rule_in_policy_command,
            'cbd-delete-rule-from-policy': delete_rule_from_policy_command,
            'cbd-find-events': find_events_command,
            'cbd-find-events-results': find_events_results_command,
            'cbd-find-events-details': find_events_details_command,
            'cbd-find-events-details-results': find_events_details_results_command,
            'cbd-find-processes': find_processes_command,
            'cbd-find-processes-results': find_processes_results_command,
            'cbd-alerts-search': alerts_search_command,
            'cbd-get-alert-details': get_alert_details_command,
            'cbd-device-search': device_search_command,
            'cbd-device-quarantine': device_quarantine_command,
            'cbd-device-unquarantine': device_unquarantine_command,
            'cbd-device-background-scan': device_background_scan_command,
            'cbd-device-background-scan-stop': device_background_scan_stop_command,
            'cbd-device-bypass': device_bypass_command,
            'cbd-device-unbypass': device_unbypass_command,
            'cbd-device-policy-update': device_policy_update_command,
            'cbd-device-update-sensor-version': device_update_sensor_version_command
        }

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'fetch-incidents':
            fetch_time = demisto.params().get('first_fetch', '7 days')
            fetch_limit = demisto.params().get('max_fetch', 50)
            filters = {
                'suffix_url_path': params.get('suffix_url_path', 'all'),
                'category': argToList(params.get('category')),
                'device_id': argToList(params.get('device_id')),
                'policy_id': argToList(params.get('policy_id')),
                'process_sha256': argToList(params.get('process_sha256')),
                'device_username': argToList(params.get('device_username')),
                'query': params.get('query'),
            }
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents, last_run = fetch_incidents(client, fetch_time, fetch_limit, last_run=demisto.getLastRun(),
                                                  filters=filters)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        elif command in commands:
            command_results = commands[command](client, demisto.args())
            return_results(command_results)
        else:
            raise NotImplementedError(f'{COMMAND_NOT_IMPELEMENTED_MSG}: {command}')

    # Log exceptions and return error
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

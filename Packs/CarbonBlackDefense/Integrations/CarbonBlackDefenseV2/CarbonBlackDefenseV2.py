"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxies, api_secret_key, api_key, organization_key):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.api_secret_key = api_secret_key
        self.api_key = api_key
        self.organization_key = organization_key
        self.headers = {'X-Auth-Token': f'{self.api_secret_key}/{self.api_key}',
                        'Content-Type': 'application/json'}
        self.policy_headers = {'X-Auth-Token': 'KVF23QPL519V1B928FZ5JC87/Z73IUKC37S',
                               'Content-Type': 'application/json'}
        super(Client, self).__init__(base_url, verify, proxies)

    # For the test module
    def get_alerts(self):
        res = self._http_request(method='POST',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/_search',
                                 headers=self.headers,
                                 json_data={})
        return res

    # Policies API
    def create_new_policy(self, name: str, description: str, priority_level: str, policy: object):
        suffix_url = f'integrationServices/v3/policy'
        body = {
            "policyInfo": assign_params(
                name=name,
                description=description,
                priorityLevel=priority_level,
                policy=policy,
                version=2  # this is the current version of the api
            )
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=body)

    def get_policies(self):
        suffix_url = 'integrationServices/v3/policy'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def get_policy_by_id(self, policy_id):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def set_policy(self, policy_id, policy_info):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=policy_info)

    def delete_policy(self, policy_id):
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    def add_rule_to_policy(self, policy_id, action, operation, required, rule_id, type, value):
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

    def update_rule_in_policy(self, policy_id, action, operation, required, rule_id, type, value):
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

    def delete_rule_from_policy(self, policy_id, rule_id):
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    # The events API
    def get_events(self, alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                   device_name, device_os, event_type, parent_hash, parent_name,
                   parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                   process_pid, process_reputation, process_start_time, process_terminated,
                   process_username, sensor_action, query, rows, start, time_range):
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
            timerange=time_range
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_status(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs/{job_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_events_results(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs/{job_id}/results'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_events_details(self, job_ids):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs'
        body = assign_params(
            event_ids=job_ids
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_details_status(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs/{job_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_events_details_results(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs/{job_id}/results'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Processes API
    def get_processes(self, alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                      device_name, device_os, device_timestamp, event_type, parent_hash, parent_name,
                      parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                      process_pid, process_reputation, process_start_time, process_terminated,
                      process_username, sensor_action, query, rows, start, time_range):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs'
        body = {
            "criteria": assign_params(
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
            "query": query if query else " ",
            "rows": rows if rows else 10,
            "start": start if start else 0,
            "timerange": time_range
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_process_status(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs/{job_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_process_results(self, job_id):
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs/{job_id}/results'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Alert API
    def get_alert_by_id(self, alert_id) -> dict:
        res = self._http_request(method='GET',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_id}',
                                 headers=self.headers)
        return res

    # Devices API
    def get_devices(self, device_id: List = None, status: List = None, device_os: List = None,
                    last_contact_time: Dict[str, Optional[Any]] = None,
                    target_priority: List = None, query: str = None) -> Dict:
        suffix_url = f'/appservices/v6/orgs/{self.organization_key}/devices/_search'
        body = {
            "criteria": assign_params(
                id=device_id,
                status=status,
                os=device_os,
                last_contact_time=last_contact_time,
                target_priority=target_priority
            ),
            'start': 0,
            'query': query if query else ''
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def execute_an_action_on_the_device(self, device_id: list = None, action_type: str = None,
                                        options: dict = None) -> str:
        suffix_url = f'appservices/v6/orgs/{self.organization_key}/device_actions'
        headers = {'X-Auth-Token': f'{self.api_secret_key}/{self.api_key}', 'Content-Type': 'application/json'}
        body = assign_params(
            action_type=action_type,
            device_id=device_id,
            options=options
        )
        return self._http_request(method='POST', url_suffix=suffix_url,
                                  headers=headers, json_data=body, resp_type='text')


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        demisto.info(client.get_alerts())
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:

            raise e
    return message


def create_policy_command(client, args):
    name = args.get('name')  # it must to be unique
    description = args.get('description')
    priority_level = args.get('priorityLevel')
    policy = args.get('policy')

    res = client.create_new_policy(name, description, priority_level, json.loads(policy))
    new_policy_id = res.get('policyId')

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.CreatePolicy.PolicyId',
        outputs=new_policy_id,
        outputs_key_field=str(new_policy_id),
        readable_output=f"The new policies id is {new_policy_id}",
        raw_response=res
    )


def get_policies_command(client, args):
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
            "latestRevision": policy.get('latestRevision'),
            "version": policy.get('version')
        })

    readable_output = tableToMarkdown('Carbon Black Defense Get Policies',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.GetPolicies',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def get_policy_command(client, args):
    policy_id = args.get('policyId')
    res = client.get_policy_by_id(policy_id)

    readable_output = tableToMarkdown('Carbon Black Defense Get Policies By Id',
                                      res.get("policyInfo"),
                                      removeNull=True)

    return CommandResults(
        outputs_prefix=f'CarbonBlackDefense.GetPolicyByID',
        outputs_key_field='policyinfo.id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def set_policy_command(client, args):
    policy_id = args.get('policy')
    policy_info = args.get('keyValue')

    res = client.set_policy(policy_id, json.loads(policy_info))

    # I have to return the new policy this means that I have to call the get_policy_by_id method of client
    return CommandResults(
        readable_output=tableToMarkdown("The Set Policy Response", res),
        raw_response=res
    )


def update_policy_command(client, args):
    policy_id = args.get('policy')
    policy_info = args.get('keyValue')

    res = client.set_policy(policy_id, json.loads(policy_info))

    # I have to return the new policy this means that I have to call the get_policy_by_id method of client
    return CommandResults(
        readable_output=tableToMarkdown("The Set Policy Response", res),
        raw_response=res
    )


def delete_policy_command(client, args):
    policy_id = args.get('policyId')
    res = client.delete_policy(policy_id)

    return CommandResults(
        raw_response=res
    )


def add_rule_to_policy_command(client, args):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    rule_id = args.get('id')
    type = args.get('type')
    value = args.get('value')

    res = client.add_rule_to_policy(policy_id, action, operation, required, rule_id, type, value)

    return CommandResults(
        raw_response=res
    )


def update_rule_in_policy_command(client, args):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    rule_id = args.get('id')
    type = args.get('type')
    value = args.get('value')

    res = client.update_rule_in_policy(policy_id, action, operation, required, rule_id, type, value)

    return CommandResults(
        raw_response=res
    )


def delete_rule_from_policy_command(client, args):
    policy_id = args.get('policyId')
    rule_id = args.get('ruleId')

    res = client.delete_rule_from_policy(policy_id, rule_id)

    return CommandResults(
        raw_response=res
    )


def find_events_command(client, args):
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
    rows = argToList(args.get('rows'))
    start = argToList(args.get('start'))
    time_range = argToList(args.get('timerange'))

    res = client.get_events(alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                            device_name, device_os, event_type, parent_hash, parent_name,
                            parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                            process_pid, process_reputation, process_start_time, process_terminated,
                            process_username, sensor_action, query, rows, start, time_range)

    readable_output = tableToMarkdown('Carbon Black Defense Events Search', res)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Events',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_status_command(client, args):
    job_id = args.get('job_id')

    res = client.get_events_status(job_id)
    readable_output = tableToMarkdown('Carbon Black Defense Events Search', res)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_results_command(client, args):
    job_id = args.get('job_id')

    res = client.get_events_results(job_id)
    readable_output = tableToMarkdown('Carbon Black Defense Events Search', res)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_command(client, args):
    job_ids = argToList(args.get('event_ids'))

    res = client.get_events_details(job_ids)
    readable_output = tableToMarkdown('Carbon Black Defense Events Details Search', res)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_status_command(client, args):
    job_id = args.get('job_id')

    res = client.get_events_details_status(job_id)
    readable_output = tableToMarkdown('Carbon Black Defense Events Details Status Search', res)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_results_command(client, args):
    job_id = args.get('job_id')

    res = client.get_events_details_results(job_id)
    readable_output = tableToMarkdown('Carbon Black Defense Events Details Results Search', res)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def processes_search_command(client, args):
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
    rows = argToList(args.get('rows'))
    start = argToList(args.get('start'))
    time_range = argToList(args.get('time_range'))

    res = client.get_processes(alert_category, blocked_hash, device_external_ip, device_id, device_internal_ip,
                               device_name, device_os, device_timestamp, event_type, parent_hash, parent_name,
                               parent_reputation, process_cmdline, process_guid, process_hash, process_name,
                               process_pid, process_reputation, process_start_time, process_terminated,
                               process_username, sensor_action, query, rows, start, time_range)

    readable_output = tableToMarkdown('Carbon Black Defense Processes Search', res)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Process',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def processes_status_command(client, args):
    job_id = args.get('job_id')
    res = client.get_process_status(job_id)

    readable_output = tableToMarkdown('The Status For a Process Search',
                                      res,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.ProcessStatus',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def processes_results_command(client, args):
    job_id = args.get('job_id')
    res = client.get_process_results(job_id)

    readable_output = tableToMarkdown('The Results For a Process Search',
                                      res,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.ProcessResult',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def get_alert_details_command(client, args):
    alert_id = args.get('alertId')
    res = client.get_alert_by_id(alert_id)

    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
               'process_name', 'type', 'severity']
    readable_output = tableToMarkdown('Carbon Black Defense Get Alert Details',
                                      res,
                                      headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.GetAlertDetails',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def device_search_command(client, args):
    device_id = argToList(args.get('device_id'))
    device_os = argToList(args.get('os'))
    device_status = argToList(args.get('status'))
    last_location = {
        'start': args.get('start_time'),
        'end': args.get('end_time')
    }
    target_priority = argToList(args.get('target_priority'))
    query = args.get('query')
    human_readable = []
    headers = ['ID', 'Name', 'OS', 'PolicyName', 'Quarantined', 'status', 'TargetPriority', 'LastInternalIpAddress',
               'LastExternalIpAddress', 'LastContactTime', 'LastLocation']

    result = client.get_devices(device_id, device_status, device_os, last_location, target_priority, query)

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


def device_quarantine_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "ON"})
        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_unquarantine_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "OFF"})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_background_scan_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "ON"})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_background_scan_stop_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "OFF"})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_bypass_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "ON"})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_unbypass_command(client, args):
    device_id = argToList(args.get('device_id'))
    try:
        client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "OFF"})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_policy_update_command(client, args):
    device_id = argToList(args.get('device_id'))
    policy_id = args.get('policy_id')
    try:
        client.execute_an_action_on_the_device(device_id, 'UPDATE_POLICY', {"policy_id": policy_id})

        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


def device_update_sensor_version_command(client, args):
    device_id = argToList(args.get('device_id'))
    sensor_version = args.get('sensor_version')
    try:
        client.execute_an_action_on_the_device(device_id, 'UPDATE_SENSOR_VERSION',
                                               {"sensor_version": json.loads(sensor_version)})
        return CommandResults(
            readable_output="success",
            raw_response="success"
        )
    except Exception as e:
        return CommandResults(
            raw_response=f'failed{e}'
        )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('apikey')

    params = demisto.params()
    # get the service API url
    base_url = params.get('url')
    api_key = params.get('api_key')
    api_secret_key = params.get('api_secret_key')
    organization_key = params.get('organization_key')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxies=proxy,
            api_secret_key=api_secret_key,
            api_key=api_key,
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
            'cbd-find-events-status': find_events_status_command,
            'cbd-find-events-results': find_events_results_command,
            'cbd-find-events-details': find_events_details_command,
            'cbd-find-events-details-status': find_events_details_status_command,
            'cbd-find-events-details-results': find_events_details_results_command,
            'cbd-find-processes': processes_search_command,
            'cbd-find-processes-status': processes_status_command,
            'cbd-find-processes-results': processes_results_command,
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
        command = demisto.command()

        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            command_results = commands[command](client, demisto.args())
            return_results(command_results)

        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

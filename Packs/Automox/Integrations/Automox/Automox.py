"""Automox Integration for Cortex XSOAR (aka Demisto)

This integration empowers users of Cortex XSOAR with the
capabilities provided by the Automox API.

Organization, group, device, policy, and patch management all at your fingertips.

For API reference, visit: https://developer.automox.com/
"""

import base64
import json
import string
import traceback
from ipaddress import ip_address
from tokenize import String
from typing import Any, Dict, List

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
VERSION = "1.0.0"
USER_AGENT = f'ax:automox-PaloAltoNetworks-XSOAR-plugin/{VERSION}'
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

    def action_on_vulnerability_sync_batch(self, org_id: int, batch_id: int, action: string):
        url_suffix = f"/orgs/{org_id}/tasks/batches/{batch_id}"

        if action == "accept":
            url_suffix += "/accept"
        elif action == "reject":
            url_suffix += "/reject"
        else:
            raise ValueError("Action argument must be a string equal to either 'accept' or 'reject'")

        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
        )

    def action_on_vulnerability_sync_task(self, org_id: int, task_id: int, action: string):
        payload = {
            "action": action
        }

        return self._http_request(
            method='PATCH',
            url_suffix=f"/orgs/{org_id}/tasks/{task_id}",
            payload=payload,
        )

    def delete_device(self, org_id: int, device_id: int) -> List[Dict]:
        params = {
            "o" : org_id
        }

        return self._http_request(
            method='DELETE',
            url_suffix='/servers/{device_id}',
            params=params
        )

    def delete_group(self, org_id: int, group_id: int) -> List[Dict]:
        params = {
            "o" : org_id
        }

        return self._http_request(
            method='DELETE',
            url_suffix='/servergroups/{group_id}',
            params=params
        )

    def get_vulnerability_sync_batch(self, org_id: int, batch_id: int) -> List[Dict]:
        return self._http_request(
            method="GET",
            url_suffix=f"/orgs/{org_id}/tasks/batches/{batch_id}",
        )

    def list_devices(self, org_id: int, group_id: int) -> List[Dict]:
        params = {
            "o": org_id,
            "groupId": group_id
        }

        return self._http_request(
            method='GET',
            url_suffix='/servers',
            params=params
        )

    def list_groups(self, org_id: int) -> List[Dict]:
        params = {
            "o" : org_id
        }

        return self._http_request(
            method='GET',
            url_suffix='/servergroups',
            params=params
        )

    def list_organization_users(self, org_id:  int) -> List[Dict]:
        params = {
            "o": org_id
        }

        return self._http_request(
            method='GET',
            url_suffix='/users',
            params=params
        )

    def list_organizations(self) -> List[Dict]:
        return self._http_request(
            method='GET',
            url_suffix="/orgs",
        )

    def list_policies(self, org_id, limit, page) -> List[Dict]:
        params = {
            "limit" : limit,
            "page" : page,
            "o" : org_id
        }

        return self._http_request(
            method='GET',
            url_suffix="/policies",
            params=params,
        )

    def list_vulnerability_sync_batches(self, org_id, limit, page) -> List[Dict]:
        params = {
            "limit" : limit,
            "page" : page,
        }

        return self._http_request(
            method='GET',
            url_suffix=f"/orgs/{org_id}/tasks/batches",
            params=params,
        )

    def list_vulnerability_sync_tasks(self, org_id, batch_id, status, limit, page) -> List[Dict]:
        params = {
            "limit" : limit,
            "page" : page,
            "batch_id": batch_id,
            "status": status
        }

        return self._http_request(
            method='GET',
            url_suffix=f"/orgs/{org_id}/tasks",
            params=params,
        )

    def run_command(self, org_id, device_id, payload) -> List[Dict]:
        params = {"o": org_id}

        return self._http_request(
            method='POST',
            url_suffix=f"/servers/{device_id}/queues",
            params=params,
            data=payload,
        )

    def update_device(self, org_id, device_id, payload) -> List[Dict]:
        params = {
            "o": org_id
        }

        return self._http_request(
            method='PUT',
            url_suffix=f"/servers/{device_id}",
            params=params,
            data=payload,
        )

    def update_group(self, org_id, group_id, payload) -> List[Dict]:
        params = {"o": org_id}

        return self._http_request(
            method='PUT',
            url_suffix=f"/servergroups/{group_id}",
            params=params,
            data=payload,
        )

    def upload_vulnerability_sync_file(self, org_id, type, payload, files) -> List[Dict]:
        return self._http_request(
            method='POST',
            url_suffix=f"/orgs/{org_id}/tasks/{type}/batches/upload",
            data=payload,
            files=files,
        )

''' HELPER FUNCTIONS '''

def get_default_server_group_id(client: Client):
    default_server_group_id = 0
    groups = client.list_groups()

    for group in groups:
        if not group.get("name"):
            default_server_group_id = group.get("id")
            break

    return default_server_group_id

''' COMMAND FUNCTIONS '''

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
        client.list_organizations()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

def action_on_vulnerability_sync_batch(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    batch_id = args.get('batch_id', None)
    action = args.get('action', None)

    result = client.action_on_vulnerability_sync_batch(org_id, batch_id, action)

    return CommandResults(
        mark_as_note=True,
        readable_output=f"Action: {action} successfully performed on Automox batch ID: {batch_id}"
    )

def action_on_vulnerability_sync_task(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    task_id = args.get('task_id', None)
    action = args.get('action', None)

    result = client.action_on_vulnerability_sync_task(org_id, task_id, action)

    return CommandResults(
        mark_as_note=True,
        readable_output=f"Action: {action} successfully performed on Automox task ID: {task_id}"
    )

def delete_device(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)

    result = client.delete_device(org_id)

    return CommandResults(
        outputs_prefix="Automox",
        outputs_key_field='',
        outputs=result,
    )

def delete_group(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)

    result = client.delete_group(org_id)

    return CommandResults(
        outputs_prefix="Automox",
        outputs_key_field='',
        outputs=result,
    )

def get_vulnerability_sync_batch(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    batch_id = args.get('batch_id', None)

    result = client.get_vulnerability_sync_batch(org_id, batch_id)

    return CommandResults(
        outputs_prefix="Automox.VulnSyncBatch",
        outputs_key_field='id',
        outputs=result,
    )

def list_devices(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    group_id = args.get('group_id', None)

    result = client.list_devices(org_id, group_id)

    return CommandResults(
        outputs_prefix="Automox.Devices",
        outputs_key_field='',
        outputs=result,
    )

def list_groups(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)

    result = client.list_groups(org_id)

    return CommandResults(
        outputs_prefix="Automox",
        outputs_key_field='',
        outputs=result,
    )

def list_organization_users(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)

    result = client.list_organization_users(org_id)

    excluded_keys = [
        'features',
        'prefs',
    ]

    for user in result:
        try:
            for key in excluded_keys:
                user.pop(key)
        except Exception as e:
            demisto.error(f"Key '{key}' not found in Automox organization user list response.")

    return CommandResults(
        outputs_prefix="Automox.Users",
        outputs_key_field='',
        outputs=result,
    )

def list_organizations(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.list_organizations()

    return CommandResults(
        outputs_prefix="Automox.Organizations",
        outputs_key_field='',
        outputs=result,
    )

def list_policies(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)

    result = client.list_policies(org_id)

    return CommandResults(
        outputs_prefix="Automox.Policies",
        outputs_key_field='',
        outputs=result,
    )

def list_vulnerability_sync_batches(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    limit = args.get('limit', None)
    page = args.get('page', None)

    result = client.list_vulnerability_sync_batches(org_id, limit, page)

    return CommandResults(
        outputs_prefix="Automox.VulnSyncBatches",
        outputs_key_field='id',
        outputs=result['data'],
    )

def list_vulnerability_sync_tasks(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    batch_id = args.get('batch_id', None)
    status = args.get('status', None)
    limit = args.get('limit', None)
    page = args.get('page', None)

    result = client.list_vulnerability_sync_tasks(org_id, batch_id, status, limit, page)

    excluded_keys = [
        'partner_user_id',
    ]

    try:
        for task in result['data']:
            for key in excluded_keys:
                task.pop(key)
    except Exception as e:
        demisto.error(f"Key '{key}' not found in Automox Vulnerability Sync task list response.")

    return CommandResults(
        outputs_prefix="Automox.VulnSyncTasks",
        outputs_key_field='id',
        outputs=result['data'],
    )

def run_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    device_id = args.get('device_id', None)
    command_type_name = args.get('command', None)
    args = args.get('args', None)

    payload = {
        'command_type_name' : command_type_name,
        'args' : args
    }

    client.run_command(org_id, device_id, payload)

    return CommandResults(
        mark_as_note=True,
        readable_output=f"Command: {command_type_name} successfully sent to Automox device ID: {device_id}"
    )

def update_device(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    device_id = args.get('device_id', None)
    server_group_id = args.get('server_group_id', None)
    custom_name = args.get('custom_name', None)
    tags = args.get('tags', None)
    ip_addrs = args.get('ip_addrs', None)
    exception = args.get('exception', None)

    payload = {
        "server_group_id" : server_group_id,
        "ip_addrs" : ip_addrs,
        "exception" : exception,
        "tags" : tags,
        "custom_name" : custom_name,
    }

    result = client.update_device(org_id, device_id, payload)

    return CommandResults(
        outputs_prefix="Automox",
        outputs_key_field='',
        outputs=result,
    )

def update_group(client: Client, args: Dict[str, Any]) -> CommandResults:
    #server_group_id, custom_name, tags, ip_addrs, exception=False
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    group_id = args.get('group_id', None)
    color = args.get('color', None)
    name = args.get('name', None)
    notes = args.get('notes', None)
    parent_server_group_id = args.get('parent_server_group_id', None)
    policies = args.get('policies', None)
    refresh_interval = args.get('refresh_interval', None)

    payload = {
        "color" : color,
        "name" : name,
        "notes" : notes,
        "parent_server_group_id" : parent_server_group_id,
        "policies" : policies,
        "refresh_interval" : refresh_interval,
    }

    result = client.update_group(org_id, group_id, payload)

    return CommandResults(
        outputs_prefix="Automox",
        outputs_key_field='',
        outputs=result,
    )

def upload_vulnerability_sync_file(client: Client, args: Dict[str, Any]) -> CommandResults:
    #server_group_id, custom_name, tags, ip_addrs, exception=False
    org_id = args.get('org_id', None) or demisto.params().get('org_id', None)
    report_source = args.get('report_source', None)
    csv_file = args.get('csv_file', None)
    csv_file_name = args.get('csv_file_name', None)
    task_type = args.get('type', None) or "patch"

    try:
        csv_file = base64.b64decode(csv_file)
    except:
        demisto.error("CSV file could not be decoded from BASE64.")

    payload = {
        "report_source" : report_source,
    }

    files = [
        ('file', (csv_file_name, csv_file, 'text/csv'))
    ]

    result = client.upload_vulnerability_sync_file(org_id, task_type, payload, files)

    return CommandResults(
        outputs_prefix="Automox.VulnUpload",
        outputs_key_field='id',
        outputs=result,
    )

''' MAIN FUNCTION '''
def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = "https://console.automox.com/api"

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {
            "Authorization" : f"Bearer {api_key}",
            "User-Agent" : USER_AGENT
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'automox-vulnerability-sync-batch-action':
            return_results(action_on_vulnerability_sync_batch(client, demisto.args()))
        elif demisto.command() == 'automox-vulnerability-sync-task-action':
            return_results(action_on_vulnerability_sync_task(client, demisto.args()))
        elif demisto.command() == 'automox-group-create':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-device-delete':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-group-delete':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-vulnerability-sync-batch-get':
            return_results(get_vulnerability_sync_batch(client, demisto.args()))
        elif demisto.command() == 'automox-devices-list':
            return_results(list_devices(client, demisto.args()))
        elif demisto.command() == 'automox-groups-list':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-organization-users-list':
            return_results(list_organization_users(client, demisto.args()))
        elif demisto.command() == 'automox-organizations-list':
            return_results(list_organizations(client, demisto.args()))
        elif demisto.command() == 'automox-policies-list':
            return_results(list_policies(client, demisto.args()))
        elif demisto.command() == 'automox-vulnerability-sync-batches-list':
            return_results(list_vulnerability_sync_batches(client, demisto.args()))
        elif demisto.command() == 'automox-vulnerability-sync-tasks-list':
            return_results(list_vulnerability_sync_tasks(client, demisto.args()))
        elif demisto.command() == 'automox-command-run':
            return_results(run_command(client, demisto.args()))
        elif demisto.command() == 'automox-device-update':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-group-update':
            # return_results(list_devices(client, demisto.args()))
            return
        elif demisto.command() == 'automox-vulnerability-sync-file-upload':
            return_results(upload_vulnerability_sync_file(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

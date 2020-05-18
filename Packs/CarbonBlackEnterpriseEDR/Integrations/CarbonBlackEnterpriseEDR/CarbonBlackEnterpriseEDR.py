from typing import Union, Dict, Optional, Any

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# GLOBALS
CB_ORG_KEY = demisto.params().get('organization_key')


def convert_unix_to_timestamp(timestamp):
    """
    Convert millise since epoch to date formatted MM/DD/YYYYTHH:MI:SS
    """
    if timestamp:
        date_time = datetime.utcfromtimestamp(timestamp / 1000)
        return date_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return ''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool, token=None):
        self.token = token
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json',
                                                                             'Content-Type': 'application/json'})
        if self.token:
            self._headers.update({'X-Auth-Token': self.token})

    def test_module_request(self):
        url_suffix = f'/appservices/v6/orgs/{CB_ORG_KEY}/alerts/_search'
        body = {
            "criteria": {
                "group_results": True,
                "minimum_severity": 3
            },
            "sort": [{"field": "first_event_time", "order": "DESC"}],
            "rows": 1,
            "start": 0
        }

        return self._http_request('POST', url_suffix=url_suffix, json_data=body)

    def search_alerts_request(self, group_results: bool, minimum_severity: int, create_time: dict,
                              device_os_version: str, policy_id: int, alert_tag: str, alert_id: str,
                              device_username: str, device_id: int, device_os: str, process_sha256: str,
                              policy_name: str, reputation: str, alert_type: str, alert_category: str, workflow: str,
                              device_name: str, process_name: str, sort_field: str, sort_order: str,
                              limit: int) -> dict:

        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/alerts/_search'
        body = {
            'criteria': assign_params(
                group_results=group_results,
                minimum_severity=minimum_severity,
                create_time=create_time,
                device_os_version=device_os_version,
                policy_id=policy_id,
                tag=alert_tag,
                id=alert_id,
                device_username=device_username,
                device_id=device_id,
                device_os=device_os,
                process_sha256=process_sha256,
                policy_name=policy_name,
                reputation=reputation,
                type=alert_type,
                category=alert_category,
                workflow=workflow,
                device_name=device_name,
                process_name=process_name
            ),
            'sort': [
                {
                    'field': sort_field,
                    'order': sort_order
                }
            ],
            'rows': limit,
            'start': 0
        }
        return self._http_request('POST', suffix_url, json_data=body)

    def alert_workflow_update_request(self, alert_id: str, state: str, comment: str,
                                      remediation_state: str) -> Dict[str, Any]:

        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/alerts/{alert_id}/workflow'
        body = assign_params(
            state=state,
            comment=comment,
            remediation_state=remediation_state
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def devices_list_request(self, device_id: Union[list, str], status: str, device_os: str,
                             last_contact_time: Dict[str, Optional[Any]], ad_group_id: int, policy_id: int,
                             target_priority: str, limit: int, sort_field: str, sort_order: str) -> dict:

        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/devices/_search'

        body = {
            'criteria': {
                'id': device_id,
                'status': status,
                'os': device_os,
                'last_contact_time': last_contact_time,
                'ad_group_id': ad_group_id,
                'policy_id': policy_id,
                'target_priority': target_priority
            },
            'rows': limit,
            'start': 0,
            'sort': [
                {
                    'field': sort_field,
                    'order': sort_order
                }
            ]
        }

        return self._http_request('POST', suffix_url, json_data=body)

    def device_quarantine_request(self, device_id: Union[list, str]) -> None:

        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unquarantine_request(self, device_id: Union[list, str]) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_bypass_request(self, device_id: Union[list, str]) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unbypass_request(self, device_id: Union[list, str]) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request(self, device_id: Union[list, str]) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request_stop(self, device_id: Union[list, str]) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_policy_update(self, device_id: Union[list, str], policy_id: str) -> None:
        suffix_url = f'/appservices/v6/orgs/{CB_ORG_KEY}/device_actions'

        body = {
            'action_type': 'UPDATE_POLICY',
            'device_id': device_id,
            'options': {
                'policy_id': policy_id
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def list_watchlists_request(self) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists'
        return self._http_request('GET', suffix_url)

    def get_watchlist_by_id_request(self, watchlist_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}'
        return self._http_request('GET', suffix_url)

    def delete_watchlist_request(self, watchlist_id: str) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}'
        return self._http_request('DELETE', suffix_url, resp_type='content')

    def watchlist_alert_status_request(self, watchlist_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}/alert'
        return self._http_request('GET', suffix_url)

    def enable_watchlist_alert_request(self, watchlist_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}/alert'
        return self._http_request('PUT', suffix_url)

    def disable_watchlist_alert_request(self, watchlist_id: str) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}/alert'
        return self._http_request('DELETE', suffix_url, resp_type='content')

    def create_watchlist_request(self, watchlist_name: str, description: str, tags_enabled: bool, alerts_enabled: bool,
                                 report_ids: Union[list, str], classifier: dict) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists'
        body = assign_params(
            name=watchlist_name,
            description=description,
            tags_enabled=tags_enabled,
            alerts_enabled=alerts_enabled,
            report_ids=report_ids,
            classifier=classifier
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def update_watchlist_request(self, watchlist_id: str, watchlist_name: str, description: str, tags_enabled: bool,
                                 alerts_enabled: bool, report_ids: Union[list, str], classifier: dict) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/watchlists/{watchlist_id}'
        body = assign_params(
            name=watchlist_name,
            description=description,
            tags_enabled=tags_enabled,
            alerts_enabled=alerts_enabled,
            report_ids=report_ids,
            classifier=classifier
        )

        return self._http_request('PUT', suffix_url, json_data=body)

    def get_ignore_ioc_status_request(self, report_id: str, ioc_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id})/iocs/{ioc_id}/ignore'

        return self._http_request('GET', suffix_url)

    def ignore_ioc_request(self, report_id: str, ioc_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}/iocs/{ioc_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_ioc_request(self, report_id: str, ioc_id: str) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id})/iocs/{ioc_id}/ignore'

        return self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_request(self, report_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}'

        return self._http_request('GET', suffix_url)

    def create_report_request(self, title: str, description: str, tags: Union[list, str], severity: int,
                              iocs: dict) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports'

        body = assign_params(
            titls=title,
            description=description,
            severity=severity,
            iocs_v2=iocs,
            tags=tags
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def ignore_report_request(self, report_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_report_request(self, report_id: str) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}/ignore'

        return self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_ignore_status_request(self, report_id: str) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}/ignore'
        return self._http_request('GET', suffix_url)

    def remove_report_request(self, report_id: str) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{CB_ORG_KEY}/reports/{report_id}'

        return self._http_request('DELETE', suffix_url, resp_type='content')


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Carbon Black Enterprise EDR  client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.test_module_request()
    return 'ok'


def alert_list_command(client: Client, args: dict) -> CommandResults:

    group_results = args.get('group_results')
    minimum_severity = args.get('minimum_severity')
    create_time = assign_params(
        start=args.get('start_time'),
        end=args.get('end_time')
    )
    device_os_version = argToList(args.get('device_os_version'))
    policy_id = argToList(args.get('policy_id'))
    alert_tag = argToList(args.get('alert_tag'))
    alert_id = argToList(args.get('alert_id'))
    device_username = argToList(args.get('device_username'))
    device_id = argToList(args.get('device_id'))
    device_os = argToList(args.get('device_os'))
    process_sha256 = argToList(args.get('process_sha256'))
    policy_name = argToList(args.get('policy_name'))
    reputation = argToList(args.get('reputation'))
    alert_type = argToList(args.get('alert_type'))
    alert_category = argToList(args.get('alert_category'))
    workflow = argToList(args.get('workflow'))
    device_name = argToList(args.get('device_name'))
    process_name = argToList(args.get('process_name'))
    sort_field = args.get('sort_field')
    sort_order = args.get('sort_order')
    limit = args.get('limit')
    contents = []

    result = client.search_alerts_request(group_results, minimum_severity, create_time,
                                          device_os_version, policy_id, alert_tag, alert_id, device_username,
                                          device_id, device_os, process_sha256, policy_name,
                                          reputation, alert_type, alert_category, workflow, device_name,
                                          process_name, sort_field, sort_order, limit)

    alerts = result.get('results')
    if not alerts:
        return 'No alerts were found'
    for alert in alerts:
        contents.append({
            'AlertID': alert.get('id'),
            'CreateTime': alert.get('create_time'),
            'DeviceName': alert.get('device_name'),
            'DeviceOS': alert.get('device_os'),
            'PolicyName': alert.get('policy_name'),
            'ProcessName': alert.get('process_name'),
            'Type': alert.get('type'),
            'WorkflowState': alert.get('workflow', {}).get('state')
        })

    readable_output = tableToMarkdown('Alerts list results', contents)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Alert',
        outputs_key_field='id',
        outputs=alerts,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def alert_workflow_update_command(client: Client, args: dict) -> CommandResults:

    alert_id = args.get('alert_id')
    state = args.get('state')
    comment = args.get('comment')
    remediation_state = args.get('remediation_state')

    result = client.alert_workflow_update_request(alert_id, state, comment, remediation_state)

    readable_output = tableToMarkdown(f'Successfully updated the alert: "{alert_id}"', result)
    outputs = {
        'AlertID': alert_id,
        'State': result.get('state'),
        'Remediation': result.get('remediation'),
        'LastUpdateTime': result.get('last_update_time'),
        'Comment': result.get('comment'),
        'ChangedBy': result.get('changed_by')
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Alert',
        outputs_key_field='AlertID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def list_devices_command(client: Client, args: dict) -> CommandResults:
    device_id = argToList(args.get('device_id'))
    status = argToList(args.get('status'))
    device_os = argToList(args.get('device_os'))
    last_contact_time = {
        'start': args.get('start_time'),
        'end': args.get('end_time')
    }
    args.get('last_contact_time')
    ad_group_id = argToList(args.get('ad_group_id'))
    policy_id = argToList(args.get('policy_id'))
    target_priority = argToList(args.get('target_priority'))
    limit = args.get('limit')
    sort_field = args.get('sort_field', '')
    sort_order = args.get('sort_order')
    contents = []

    result = client.devices_list_request(device_id, status, device_os, last_contact_time, ad_group_id, policy_id,
                                         target_priority, limit, sort_field, sort_order)
    devices = result.get('results')
    if not devices:
        return 'No devices were found.'
    for device in devices:
        contents.append({
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

    readable_output = tableToMarkdown('Devices list results', contents)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Device',
        outputs_key_field='id',
        outputs=devices,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def device_quarantine_command(client: Client, args: dict) -> str:

    device_id = argToList(args.get('device_id'))
    client.device_quarantine_request(device_id)

    return f'The device {device_id} has been quarantined successfully.'


def device_unquarantine_command(client: Client, args: dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_unquarantine_request(device_id)

    return f'The device {device_id} has been unquarantined successfully.'


def device_bypass_command(client: Client, args: dict) -> str:

    device_id = argToList(args.get('device_id'))
    client.device_bypass_request(device_id)

    return f'The device {device_id} bypass has been enabled successfully.'


def device_unbypass_command(client: Client, args: dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_unbypass_request(device_id)

    return f'The device {device_id} bypass has been disabled successfully.'


def device_background_scan_command(client: Client, args: dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_background_scan_request(device_id)

    return f'The device {device_id} background scan has been enabled successfully.'


def device_background_scan_stop_command(client: Client, args: dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_background_scan_request_stop(device_id)

    return f'The device {device_id} background scan has been disabled successfully.'


def device_policy_update_command(client: Client, args: dict) -> str:
    device_id = argToList(args.get('device_id'))
    policy_id = args.get('policy_id')

    client.device_policy_update(device_id, policy_id)

    return f'The policy {policy_id} has been assigned to device {device_id} successfully.'


def list_watchlists_command(client: Client) -> CommandResults:

    contents = []
    headers = ['ID', 'Name', 'Description', 'create_timestamp', 'Alerts_enabled', 'Tags_enabled', 'Report_ids',
               'Last_update_timestamp', 'Classifier']
    result = client.list_watchlists_request()
    watchlists = result.get('results')
    if not watchlists:
        return 'No watchlists were found.'

    for watchlist in watchlists:
        contents.append({
            'Name': watchlist.get('name'),
            'ID': watchlist.get('id'),
            'Description': watchlist.get('description'),
            'Tags_enabled': watchlist.get('tags_enabled'),
            'Alerts_enabled': watchlist.get('alerts_enabled'),
            'create_timestamp': convert_unix_to_timestamp(watchlist.get('create_timestamp')),
            'Last_update_timestamp': convert_unix_to_timestamp(watchlist.get('last_update_timestamp')),
            'Report_ids': watchlist.get('report_ids'),
            'Classifier': watchlist.get('classifier')
        })

    readable_output = tableToMarkdown('Watchlists list ', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=contents,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_watchlist_by_id_command(client: Client, args: dict) -> CommandResults:

    watchlist_id = args.get('watchlist_id')
    result = client.get_watchlist_by_id_request(watchlist_id)
    headers = ['ID', 'Name', 'Description', 'create_timestamp', 'Alerts_enabled', 'Tags_enabled', 'Report_ids',
               'Last_update_timestamp', 'Classifier']

    contents = {
        'Name': result.get('name'),
        'ID': result.get('id'),
        'Description': result.get('description'),
        'Tags_enabled': result.get('tags_enabled'),
        'Alerts_enabled': result.get('alerts_enabled'),
        'create_timestamp': convert_unix_to_timestamp(result.get('create_timestamp')),
        'Last_update_timestamp': convert_unix_to_timestamp(result.get('last_update_timestamp')),
        'Report_ids': result.get('report_ids'),
        'Classifier': result.get('classifier')
    }

    readable_output = tableToMarkdown(f'Watchlist {watchlist_id} information', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=contents,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def watchlist_alert_status_command(client: Client, args: dict) -> str:
    watchlist_id = args.get('watchlist_id')
    result = client.watchlist_alert_status_request(watchlist_id)

    if not result.get('alert'):
        return f'Watchlist {watchlist_id} alert status is false'
    else:
        return f'Watchlist {watchlist_id} alert status is true'


def enable_watchlist_alert_command(client: Client, args: dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.enable_watchlist_alert_request(watchlist_id)

    return f'Watchlist {watchlist_id} alert was enabled successfully.'


def disable_watchlist_alert_command(client: Client, args: dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.disable_watchlist_alert_request(watchlist_id)

    return f'Watchlist {watchlist_id} alert was disabled successfully.'


def create_watchlist_command(client: Client, args: dict) -> CommandResults:

    watchlist_name = args.get('watchlist_name')
    description = args.get('description')
    tags_enabled = args.get('tags_enabled')
    alerts_enabled = args.get('alerts_enabled')
    report_ids = argToList(args.get('report_ids'))
    classifier = {
        'key': args.get('classifier_key'),
        'value': args.get('classifier_value')
    }

    if classifier and report_ids:
        raise Exception('Please specify report or classifier but not both.')

    headers = ['Name', 'ID', 'Description', 'Create_timestamp', 'Tags_enabled', 'Alerts_enabled', 'Report_ids',
               'Classifier']

    result = client.create_watchlist_request(watchlist_name, description, tags_enabled, alerts_enabled, report_ids,
                                             classifier)
    contents = {
        'Name': result.get('name'),
        'ID': result.get('id'),
        'Description': result.get('description'),
        'Tags_enabled': result.get('tags_enabled'),
        'Alerts_enabled': result.get('alerts_enabled'),
        'Create_timestamp': convert_unix_to_timestamp(result.get('create_timestamp')),
        'Report_ids': result.get('report_ids'),
        'Classifier': result.get('classifier')
    }

    readable_output = tableToMarkdown(f'The watchlist "{watchlist_name}" created successfully.', contents, headers,
                                      removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=contents,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def delete_watchlist_command(client: Client, args: dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    return f'The watchlist {watchlist_id} was deleted successfully.'


def update_watchlist_command(client: Client, args: dict) -> CommandResults:
    watchlist_id = args.get('watchlist_id')
    watchlist_name = args.get('watchlist_name')
    description = args.get('description')
    tags_enabled = args.get('tags_enabled')
    alerts_enabled = args.get('alerts_enabled')
    report_ids = argToList(args.get('report_ids'))
    classifier = {
        'key': args.get('classifier_key'),
        'value': args.get('classifier_value')
    }

    if classifier and report_ids:
        raise Exception('Please specify report or classifier but not both.')

    headers = ['Name', 'ID', 'Description', 'Create_timestamp', 'Tags_enabled', 'Alerts_enabled', 'Report_ids',
               'Classifier']

    result = client.update_watchlist_request(watchlist_id, watchlist_name, description, tags_enabled, alerts_enabled,
                                             report_ids, classifier)
    contents = {
        'Name': result.get('name'),
        'ID': result.get('id'),
        'Description': result.get('description'),
        'Tags_enabled': result.get('tags_enabled'),
        'Alerts_enabled': result.get('alerts_enabled'),
        'Create_timestamp': convert_unix_to_timestamp(result.get('create_timestamp')),
        'Report_ids': result.get('report_ids'),
        'Classifier': result.get('classifier')
    }

    readable_output = tableToMarkdown(f'The watchlist "{watchlist_id}" was updated successfully.', contents, headers,
                                      removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=contents,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_report_command(client: Client, args: dict) -> CommandResults:

    report_id = args.get('report_id')
    result = client.get_report_request(report_id)
    headers = ['ID', 'Title', 'Timestamp', 'Description', 'Severity', 'Link', 'IOCs_v2', 'Tags', 'Visibility']
    ioc_contents = []
    contents = {
        'ID': result.get('id'),
        'Timestamp': convert_unix_to_timestamp(result.get('timestamp')),
        'Title': result.get('title'),
        'Description': result.get('description'),
        'Severity': result.get('severity'),
        'Link': result.get('link'),
        'Tags': result.get('tags'),
        'Visibility': result.get('visibility')
    }

    context = {
        'ID': result.get('id'),
        'Timestamp': convert_unix_to_timestamp(result.get('timestamp')),
        'Title': result.get('title'),
        'Description': result.get('description'),
        'Severity': result.get('severity'),
        'Link': result.get('link'),
        'Tags': result.get('tags'),
        'IOCs': result.get('iocs_v2'),
        'Visibility': result.get('visibility')
    }

    iocs = result.get('iocs_v2')
    for ioc in iocs:
        ioc_contents.append({
            'ID': ioc.get('id'),
            'Match_type': ioc.get('match_type'),
            'Values': ioc.get('values'),
            'Field': ioc.get('field'),
            'Link': ioc.get('link')
        })

    readable_output = tableToMarkdown(f'Report "{report_id}" information', contents, headers, removeNull=True)
    ioc_output = tableToMarkdown(f'The IOCs for the report', ioc_contents, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Report',
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_output + ioc_output,
        raw_response=result
    )
    return results


def get_ignore_ioc_status_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    result = client.get_ignore_ioc_status_request(report_id, ioc_id)

    if not result.get('ignored'):
        return f'IOC {ioc_id} status is false'
    else:
        return f'IOC {ioc_id} status is true'


def ignore_ioc_command(client: Client, args: dict) -> str:

    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    client.ignore_ioc_request(report_id, ioc_id)

    return f'The IOC {ioc_id} for report {report_id} will not match future events for any watchlist.'


def reactivate_ioc_command(client: Client, args: dict) -> str:

    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    client.reactivate_ioc_request(report_id, ioc_id)

    return f'IOC {ioc_id} for report {report_id} will match future events for all watchlists.'


def create_report_command(client: Client, args: dict) -> CommandResults:

    title = args.get('title')
    description = args.get('description')
    tags = argToList(args.get('tags'))
    ioc_list = argToList(args.get('ioc_list'))
    ioc_query = args.get('ioc_query')
    severity = args.get('severity')
    ioc_contents = []

    if ioc_list:
        match_type = 'equality'
        values = ioc_list

    elif ioc_query:
        match_type = 'query'
        values = ioc_query

    iocs = assign_params(
        match_type=match_type,
        values=values
    )

    headers = ['ID', 'Title', 'Timestamp', 'Description', 'Severity', 'Link', 'IOCs_v2', 'Tags', 'Visibility']
    result = client.create_report_request(title, description, tags, severity, iocs)

    contents = {
        'ID': result.get('id'),
        'Timestamp': convert_unix_to_timestamp(result.get('timestamp')),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'Visibility': result.get('visibility')
    }

    context = {
        'ID': result.get('id'),
        'Timestamp': convert_unix_to_timestamp(result.get('timestamp')),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'IOCs': result.get('iocs_v2'),
        'Visibility': result.get('visibility')
    }

    iocs = result.get('iocs_v2')
    for ioc in iocs:
        ioc_contents.append({
            'ID': ioc.get('id'),
            'Match_type': ioc.get('match_type'),
            'Values': ioc.get('values'),
            'Field': ioc.get('field'),
            'Link': ioc.get('link')
        })

    readable_output = tableToMarkdown(f'The report was created successfully.', contents, headers, removeNull=True)
    ioc_output = tableToMarkdown(f'The IOCs for the report', ioc_contents, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Report',
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_output + ioc_output,
        raw_response=result
    )
    return results


def ignore_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    client.ignore_report_request(report_id)

    return f'The report with report_id "{report_id}" and all contained IOCs will not match future events ' \
        f'for any watchlist.'


def reactivate_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    client.reactivate_report_request(report_id)

    return f'Report with report_id "{report_id}" and all contained IOCs will match future events for all watchlists'


def get_report_ignore_status_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    result = client.get_report_ignore_status_request(report_id)

    if not result.get('ignored'):
        return f'ignore status for report with report_id "{report_id}" is false.'
    else:
        return f'ignore status for report with report_id "{report_id}" is true.'


def remove_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')
    client.remove_report_request(report_id)

    return f'The report "{report_id}"" was deleted successfully.'

# def fetch_incidents(client, last_run, first_fetch_time):
#     """
#     This function will execute each interval (default is 1 minute).
#
#     Args:
#         client (Client): HelloWorld client
#         last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
#         first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
#
#     Returns:
#         next_run: This will be last_run in the next fetch-incidents
#         incidents: Incidents that will be created in Demisto
#     """
#     # Get the last fetch time, if exists
#     last_fetch = last_run.get('last_fetch')
#
#     # Handle first time fetch
#     if last_fetch is None:
#         last_fetch, _ = dateparser.parse(first_fetch_time)
#     else:
#         last_fetch = dateparser.parse(last_fetch)
#
#     latest_created_time = last_fetch
#     incidents = []
#     items = client.list_incidents()
#     for item in items:
#         incident_created_time = dateparser.parse(item['created_time'])
#         incident = {
#             'name': item['description'],
#             'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
#             'rawJSON': json.dumps(item)
#         }
#
#         incidents.append(incident)
#
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_created_time > latest_created_time:
#             latest_created_time = incident_created_time
#
#     next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
#     return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    cb_custom_key = demisto.params().get('custom_key')
    cb_custom_id = demisto.params().get('custom_id')
    token = f'{cb_custom_key}/{cb_custom_id}'
    # get the service API url
    base_url = demisto.params().get('url')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            token=token,
            use_proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # elif demisto.command() == 'fetch-incidents':
        #     # Set and define the fetch incidents command to run after activated via integration settings.
        #     next_run, incidents = fetch_incidents(
        #         client=client,
        #         last_run=demisto.getLastRun(),
        #         first_fetch_time=first_fetch_time)
        #
        #     demisto.setLastRun(next_run)
        #     demisto.incidents(incidents)
        elif demisto.command() == 'cb-eedr-list-alerts':
            return_results(alert_list_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-alert-workflow-update':
            return_results(alert_workflow_update_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-devices-list':
            return_results(list_devices_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-quarantine':
            return_results(device_quarantine_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-unquarantine':
            return_results(device_unquarantine_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-background-scan-stop':
            return_results(device_background_scan_stop_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-background-scan':
            return_results(device_background_scan_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-bypass':
            return_results(device_bypass_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-unbypass':
            return_results(device_unbypass_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-device-policy-update':
            return_results(device_policy_update_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-list':
            return_results(list_watchlists_command(client))

        elif demisto.command() == 'cb-eedr-get-watchlist-by-id':
            return_results(get_watchlist_by_id_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-alerts-status':
            return_results(watchlist_alert_status_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-alerts-enable':
            return_results(enable_watchlist_alert_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-alerts-disable':
            return_results(disable_watchlist_alert_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-create':
            return_results(create_watchlist_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-delete':
            return_results(delete_watchlist_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-watchlist-update':
            return_results(update_watchlist_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-get':
            return_results(get_report_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-ioc-ignore-status':
            return_results(get_ignore_ioc_status_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-ioc-ignore':
            return_results(ignore_ioc_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-ioc-reactivate':
            return_results(reactivate_ioc_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-create':
            return_results(create_report_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-ignore':
            return_results(ignore_report_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-reactivate':
            return_results(reactivate_report_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-ignore-status':
            return_results(get_report_ignore_status_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-report-remove':
            return_results(remove_report_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

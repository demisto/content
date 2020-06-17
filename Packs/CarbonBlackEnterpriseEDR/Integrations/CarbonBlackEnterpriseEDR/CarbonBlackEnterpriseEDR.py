from typing import Union, Dict, Optional, Any, Tuple, List

import dateparser

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool, token=None, cb_org_key=None):
        self.token = token
        self.cb_org_key = cb_org_key
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json',
                                                                             'Content-Type': 'application/json',
                                                                             'X-Auth-Token': self.token})

    def test_module_request(self):
        url_suffix = f'/appservices/v6/orgs/{self.cb_org_key}/alerts/_search'
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

    def search_alerts_request(self, group_results: bool = None, minimum_severity: int = None, create_time: Dict = None,
                              device_os_version: List = None, policy_id: List = None, alert_tag: List = None,
                              alert_id: List = None, device_username: List = None, device_id: List = None,
                              device_os: List = None, process_sha256: List = None, policy_name: List = None,
                              reputation: List = None, alert_type: List = None, alert_category: List = None,
                              workflow: List = None, device_name: List = None, process_name: List = None,
                              sort_field: str = None, sort_order: str = None, limit: str = None) -> Dict:

        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/alerts/_search'
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

    def alert_workflow_update_request(self, alert_id: str = None, state: str = None, comment: str = None,
                                      remediation_state: str = None) -> Dict:

        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/alerts/{alert_id}/workflow'
        body = assign_params(
            state=state,
            comment=comment,
            remediation_state=remediation_state
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def devices_list_request(self, device_id: List = None, status: List = None, device_os: List = None,
                             last_contact_time: Dict[str, Optional[Any]] = None, ad_group_id: List = None,
                             policy_id: List = None, target_priority: List = None, limit: int = None,
                             sort_field: str = None, sort_order: str = None) -> Dict:

        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/devices/_search'

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

    def device_quarantine_request(self, device_id: List = None) -> None:

        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unquarantine_request(self, device_id: List = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_bypass_request(self, device_id: List = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unbypass_request(self, device_id: List = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request(self, device_id: List = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request_stop(self, device_id: List = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_policy_update(self, device_id: List = None, policy_id: str = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'UPDATE_POLICY',
            'device_id': device_id,
            'options': {
                'policy_id': policy_id
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def list_watchlists_request(self) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists'
        return self._http_request('GET', suffix_url)

    def get_watchlist_by_id_request(self, watchlist_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}'
        return self._http_request('GET', suffix_url)

    def delete_watchlist_request(self, watchlist_id: str = None) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}'
        self._http_request('DELETE', suffix_url, resp_type='content')

    def watchlist_alert_status_request(self, watchlist_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        return self._http_request('GET', suffix_url)

    def enable_watchlist_alert_request(self, watchlist_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        return self._http_request('PUT', suffix_url)

    def disable_watchlist_alert_request(self, watchlist_id: str = None) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        self._http_request('DELETE', suffix_url, resp_type='content')

    def create_watchlist_request(self, watchlist_name: str = None, description: str = None, tags_enabled: bool = None,
                                 alerts_enabled: bool = None, report_ids: List = None, classifier: Dict = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists'
        body = assign_params(
            name=watchlist_name,
            description=description,
            tags_enabled=tags_enabled,
            alerts_enabled=alerts_enabled,
            report_ids=report_ids,
            classifier=classifier
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def update_watchlist_request(self, watchlist_id: str = None, watchlist_name: str = None, description: str = None,
                                 tags_enabled: bool = None, alerts_enabled: bool = None, report_ids: List = None,
                                 classifier: Dict = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}'
        body = assign_params(
            name=watchlist_name,
            description=description,
            tags_enabled=tags_enabled,
            alerts_enabled=alerts_enabled,
            report_ids=report_ids,
            classifier=classifier
        )
        return self._http_request('PUT', suffix_url, json_data=body)

    def get_ignore_ioc_status_request(self, report_id: str = None, ioc_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id})/iocs/{ioc_id}/ignore'

        return self._http_request('GET', suffix_url)

    def ignore_ioc_request(self, report_id: str = None, ioc_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/iocs/{ioc_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_ioc_request(self, report_id: str = None, ioc_id: str = None) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id})/iocs/{ioc_id}/ignore'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_request(self, report_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}'

        return self._http_request('GET', suffix_url)

    def create_report_request(self, title: str = None, description: str = None, tags: List = None, severity: int = None,
                              iocs: Dict = None, timestamp: int = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports'

        body = assign_params(
            title=title,
            description=description,
            severity=severity,
            iocs=iocs,
            tags=tags,
            timestamp=timestamp
        )
        return self._http_request('POST', suffix_url, json_data=body)

    def ignore_report_request(self, report_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_report_request(self, report_id: str = None) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_ignore_status_request(self, report_id: str = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'
        return self._http_request('GET', suffix_url)

    def remove_report_request(self, report_id: str = None) -> None:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def update_report_request(self, report_id: str = None, title: str = None, description: str = None,
                              severity: int = None, iocs: Dict = None, tags: List = None,
                              timestamp: int = None) -> Dict:

        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}'
        body = assign_params(
            title=title,
            description=description,
            severity=severity,
            iocs=iocs,
            tags=tags,
            timestamp=timestamp
        )
        return self._http_request('PUT', suffix_url, json_data=body)

    def get_file_device_summary_request(self, sha256: str = None) -> Dict:

        suffix_url = f'ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/summary/device'
        return self._http_request('GET', suffix_url)

    def get_file_metadata_request(self, sha256: str = None) -> Dict:
        suffix_url = f'ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/metadata'
        return self._http_request('GET', suffix_url)

    def get_file_request(self, sha256: List = None, expiration_seconds: int = None) -> Dict:

        suffix_url = f'/ubs/v1/orgs/{self.cb_org_key}/file/_download'
        body = assign_params(
            sha256=sha256,
            expiration_seconds=expiration_seconds
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def get_file_path_request(self, sha256: str = None) -> Dict:

        suffix_url = f'/ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/summary/file_path'
        return self._http_request('GET', suffix_url)


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


def alert_list_command(client: Client, args: Dict) -> Union[CommandResults, str]:

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
    headers = ['AlertID', 'CreateTime', 'DeviceID', 'DeviceName', 'DeviceOS', 'PolicyName', 'ProcessName', 'Type',
               'WorkflowState']

    result = client.search_alerts_request(group_results, minimum_severity, create_time,
                                          device_os_version, policy_id, alert_tag, alert_id, device_username,
                                          device_id, device_os, process_sha256, policy_name,
                                          reputation, alert_type, alert_category, workflow, device_name,
                                          process_name, sort_field, sort_order, limit)

    alerts = result.get('results', [])
    if not alerts:
        return 'No alerts were found'
    for alert in alerts:
        contents.append({
            'AlertID': alert.get('id'),
            'CreateTime': alert.get('create_time'),
            'DeviceID': alert.get('device_id'),
            'DeviceName': alert.get('device_name'),
            'DeviceOS': alert.get('device_os'),
            'PolicyName': alert.get('policy_name'),
            'ProcessName': alert.get('process_name'),
            'Type': alert.get('type'),
            'WorkflowState': alert.get('workflow', {}).get('state')
        })

    readable_output = tableToMarkdown('Alerts list results', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Alert',
        outputs_key_field='id',
        outputs=alerts,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def alert_workflow_update_command(client: Client, args: Dict) -> CommandResults:

    alert_id = args.get('alert_id')
    state = args.get('state')
    comment = args.get('comment')
    remediation_state = args.get('remediation_state')

    result = client.alert_workflow_update_request(alert_id, state, comment, remediation_state)

    readable_output = tableToMarkdown(f'Successfully updated the alert: "{alert_id}"', result, removeNull=True)
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


def list_devices_command(client: Client, args: Dict) -> Union[CommandResults, str]:
    device_id = argToList(args.get('device_id'))
    status = argToList(args.get('status'))
    device_os = argToList(args.get('device_os'))
    last_contact_time = {
        'start': args.get('start_time'),
        'end': args.get('end_time')
    }
    if args.get('start_time') and not args.get('end_time'):
        last_contact_time = {
            'start': args.get('start_time'),
            'end': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        }
    ad_group_id = argToList(args.get('ad_group_id'))
    policy_id = argToList(args.get('policy_id'))
    target_priority = argToList(args.get('target_priority'))
    limit = args.get('limit')
    sort_field = args.get('sort_field', '')
    sort_order = args.get('sort_order')
    contents = []
    headers = ['ID', 'Name', 'OS', 'PolicyName', 'Quarantined', 'status', 'TargetPriority', 'LastInternalIpAddress',
               'LastExternalIpAddress', 'LastContactTime', 'LastLocation']

    result = client.devices_list_request(device_id, status, device_os, last_contact_time, ad_group_id, policy_id,
                                         target_priority, limit, sort_field, sort_order)
    devices = result.get('results', [])
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

    endpoint = Common.Endpoint(
        id=device.get('id'),
        os=device.get('os'),
        mac_address=device.get('mac_address'),
        os_version=device.get('os_version')
    )

    readable_output = tableToMarkdown('Devices list results', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Device',
        outputs_key_field='id',
        outputs=devices,
        readable_output=readable_output,
        raw_response=result,
        indicators=[endpoint]
    )
    return results


def device_quarantine_command(client: Client, args: Dict) -> str:

    device_id = argToList(args.get('device_id'))
    client.device_quarantine_request(device_id)

    return f'The device {device_id} has been quarantined successfully.'


def device_unquarantine_command(client: Client, args: Dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_unquarantine_request(device_id)

    return f'The device {device_id} has been unquarantined successfully.'


def device_bypass_command(client: Client, args: Dict) -> str:

    device_id = argToList(args.get('device_id'))
    client.device_bypass_request(device_id)

    return f'The device {device_id} bypass has been enabled successfully.'


def device_unbypass_command(client: Client, args: Dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_unbypass_request(device_id)

    return f'The device {device_id} bypass has been disabled successfully.'


def device_background_scan_command(client: Client, args: Dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_background_scan_request(device_id)

    return f'The device {device_id} background scan has been enabled successfully.'


def device_background_scan_stop_command(client: Client, args: Dict) -> str:
    device_id = argToList(args.get('device_id'))
    client.device_background_scan_request_stop(device_id)

    return f'The device {device_id} background scan has been disabled successfully.'


def device_policy_update_command(client: Client, args: Dict) -> str:
    device_id = argToList(args.get('device_id'))
    policy_id = args.get('policy_id')

    client.device_policy_update(device_id, policy_id)

    return f'The policy {policy_id} has been assigned to device {device_id} successfully.'


def list_watchlists_command(client: Client) -> Union[CommandResults, str]:

    contents = []
    headers = ['ID', 'Name', 'Description', 'create_timestamp', 'Alerts_enabled', 'Tags_enabled', 'Report_ids',
               'Last_update_timestamp', 'Classifier']
    result = client.list_watchlists_request()
    watchlists = result.get('results', [])
    if not watchlists:
        return 'No watchlists were found.'

    for watchlist in watchlists:
        contents.append({
            'Name': watchlist.get('name'),
            'ID': watchlist.get('id'),
            'Description': watchlist.get('description'),
            'Tags_enabled': watchlist.get('tags_enabled'),
            'Alerts_enabled': watchlist.get('alerts_enabled'),
            'create_timestamp': timestamp_to_datestring(watchlist.get('create_timestamp', 0) * 1000),
            'Last_update_timestamp': timestamp_to_datestring(watchlist.get('last_update_timestamp', 0) * 1000),
            'Report_ids': watchlist.get('report_ids'),
            'Classifier': watchlist.get('classifier')
        })

    readable_output = tableToMarkdown('Carbon Black Enterprise EDR Watchlists', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=watchlists,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_watchlist_by_id_command(client: Client, args: Dict) -> CommandResults:

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
        'create_timestamp': timestamp_to_datestring(result.get('create_timestamp', 0) * 1000),
        'Last_update_timestamp': timestamp_to_datestring(result.get('last_update_timestamp', 0) * 1000),
        'Report_ids': result.get('report_ids'),
        'Classifier': result.get('classifier')
    }

    readable_output = tableToMarkdown(f'Watchlist {watchlist_id} information', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='id',
        outputs=result,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def watchlist_alert_status_command(client: Client, args: Dict) -> str:
    watchlist_id = args.get('watchlist_id')
    result = client.watchlist_alert_status_request(watchlist_id)

    if not result.get('alert'):
        return f'Watchlist {watchlist_id} alert status is Off'
    else:
        return f'Watchlist {watchlist_id} alert status is On'


def enable_watchlist_alert_command(client: Client, args: Dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.enable_watchlist_alert_request(watchlist_id)

    return f'Watchlist {watchlist_id} alert was enabled successfully.'


def disable_watchlist_alert_command(client: Client, args: Dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.disable_watchlist_alert_request(watchlist_id)

    return f'Watchlist {watchlist_id} alert was disabled successfully.'


def create_watchlist_command(client: Client, args: Dict) -> CommandResults:

    watchlist_name = args.get('watchlist_name')
    description = args.get('description')
    tags_enabled = args.get('tags_enabled')
    alerts_enabled = args.get('alerts_enabled')
    report_ids = argToList(args.get('report_ids'))
    classifier = assign_params(
        key=args.get('classifier_key'),
        value=args.get('classifier_value')
    )

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
        'Create_timestamp': timestamp_to_datestring(result.get('create_timestamp', 0) * 1000),
        'Report_ids': result.get('report_ids'),
        'Classifier': result.get('classifier')
    }

    readable_output = tableToMarkdown(f'The watchlist "{watchlist_name}" created successfully.', contents, headers,
                                      removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Watchlist',
        outputs_key_field='ID',
        outputs=contents,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def delete_watchlist_command(client: Client, args: Dict) -> str:
    watchlist_id = args.get('watchlist_id')
    client.delete_watchlist_request(watchlist_id)

    return f'The watchlist {watchlist_id} was deleted successfully.'


def update_watchlist_command(client: Client, args: Dict) -> CommandResults:
    watchlist_id = args.get('watchlist_id')
    watchlist_name = args.get('watchlist_name')
    description = args.get('description')
    tags_enabled = args.get('tags_enabled')
    alerts_enabled = args.get('alerts_enabled')
    report_ids = argToList(args.get('report_ids'))
    classifier = assign_params(
        key=args.get('classifier_key'),
        value=args.get('classifier_value')
    )

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
        'Create_timestamp': timestamp_to_datestring(result.get('create_timestamp', 0) * 1000),
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


def get_report_command(client: Client, args: Dict) -> CommandResults:

    report_id = args.get('report_id')
    result = client.get_report_request(report_id)
    headers = ['ID', 'Title', 'Timestamp', 'Description', 'Severity', 'Link', 'IOCs_v2', 'Tags', 'Visibility']
    ioc_contents = []
    contents = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Title': result.get('title'),
        'Description': result.get('description'),
        'Severity': result.get('severity'),
        'Link': result.get('link'),
        'Tags': result.get('tags'),
        'Visibility': result.get('visibility')
    }

    context = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Title': result.get('title'),
        'Description': result.get('description'),
        'Severity': result.get('severity'),
        'Link': result.get('link'),
        'Tags': result.get('tags'),
        'IOCs': result.get('iocs_v2'),
        'Visibility': result.get('visibility')
    }

    iocs = result.get('iocs_v2', [])
    for ioc in iocs:
        ioc_contents.append({
            'ID': ioc.get('id'),
            'Match_type': ioc.get('match_type'),
            'Values': ioc.get('values'),
            'Field': ioc.get('field'),
            'Link': ioc.get('link')
        })

    readable_output = tableToMarkdown(f'Report "{report_id}" information', contents, headers, removeNull=True)
    ioc_output = tableToMarkdown(f'The IOCs for the report {report_id}', ioc_contents, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Report',
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_output + ioc_output,
        raw_response=result
    )
    return results


def get_ignore_ioc_status_command(client: Client, args: Dict) -> str:
    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    result = client.get_ignore_ioc_status_request(report_id, ioc_id)

    if not result.get('ignored'):
        return f'IOC {ioc_id} status is false'
    else:
        return f'IOC {ioc_id} status is true'


def ignore_ioc_command(client: Client, args: Dict) -> str:

    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    client.ignore_ioc_request(report_id, ioc_id)

    return f'The IOC {ioc_id} for report {report_id} will not match future events for any watchlist.'


def reactivate_ioc_command(client: Client, args: Dict) -> str:

    report_id = args.get('report_id')
    ioc_id = args.get('ioc_id')

    client.reactivate_ioc_request(report_id, ioc_id)

    return f'IOC {ioc_id} for report {report_id} will match future events for all watchlists.'


def create_report_command(client: Client, args: Dict) -> CommandResults:

    title = args.get('title')
    description = args.get('description')
    tags = argToList(args.get('tags'))
    ipv4 = argToList(args.get('ipv4'))
    ipv6 = argToList(args.get('ipv6'))
    dns = argToList(args.get('dns'))
    md5 = argToList(args.get('md5'))
    ioc_query = argToList(args.get('ioc_query'))
    severity = args.get('severity')
    timestamp = int(date_to_timestamp(args.get('timestamp')) / 1000)
    ioc_contents = []
    iocs = assign_params(
        ipv4=ipv4,
        ipv6=ipv6,
        dns=dns,
        md5=md5,
        query=ioc_query
    )
    headers = ['ID', 'Title', 'Timestamp', 'Description', 'Severity', 'Link', 'IOCs_v2', 'Tags', 'Visibility']
    result = client.create_report_request(title, description, tags, severity, iocs, timestamp)

    contents = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Description': result.get('description'),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'Visibility': result.get('visibility')
    }

    context = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Description': result.get('description'),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'IOCs': result.get('iocs_v2'),
        'Visibility': result.get('visibility')
    }

    iocs = result.get('iocs_v2', {})
    for ioc in iocs:
        ioc_contents.append({
            'ID': ioc.get('id'),
            'Match_type': ioc.get('match_type'),
            'Values': ioc.get('values'),
            'Field': ioc.get('field'),
            'Link': ioc.get('link')
        })

    readable_output = tableToMarkdown('The report was created successfully.', contents, headers, removeNull=True)
    ioc_output = tableToMarkdown('The IOCs for the report', ioc_contents, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Report',
        outputs_key_field='ID',
        outputs=context,
        readable_output=readable_output + ioc_output,
        raw_response=result
    )
    return results


def ignore_report_command(client: Client, args: Dict) -> str:
    report_id = args.get('report_id')

    client.ignore_report_request(report_id)

    return f'The report with report_id "{report_id}" and all contained IOCs will not match future events ' \
        f'for any watchlist.'


def reactivate_report_command(client: Client, args: Dict) -> str:
    report_id = args.get('report_id')

    client.reactivate_report_request(report_id)

    return f'Report with report_id "{report_id}" and all contained IOCs will match future events for all watchlists.'


def get_report_ignore_status_command(client: Client, args: Dict) -> str:
    report_id = args.get('report_id')

    result = client.get_report_ignore_status_request(report_id)

    if not result.get('ignored'):
        return f'ignore status for report with report_id "{report_id}" is disabled.'
    else:
        return f'ignore status for report with report_id "{report_id}" is enabled.'


def remove_report_command(client: Client, args: Dict) -> str:
    report_id = args.get('report_id')
    client.remove_report_request(report_id)

    return f'The report "{report_id}" was deleted successfully.'


def update_report_command(client: Client, args: Dict) -> CommandResults:
    report_id = args.get('report_id')
    title = args.get('title')
    description = args.get('description')
    timestamp = int(date_to_timestamp(args.get('timestamp')) / 1000)
    tags = argToList(args.get('tags'))
    ipv4 = argToList(args.get('ipv4'))
    ipv6 = argToList(args.get('ipv6'))
    dns = argToList(args.get('dns'))
    md5 = argToList(args.get('md5'))
    ioc_query = argToList(args.get('ioc_query'))
    severity = args.get('severity')
    ioc_contents = []

    iocs = assign_params(
        ipv4=ipv4,
        ipv6=ipv6,
        dns=dns,
        md5=md5,
        query=ioc_query
    )

    headers = ['ID', 'Title', 'Timestamp', 'Description', 'Severity', 'Link', 'IOCs_v2', 'Tags', 'Visibility']
    result = client.update_report_request(report_id, title, description, severity, iocs, tags, timestamp)

    contents = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Description': result.get('description'),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'Visibility': result.get('visibility')
    }

    context = {
        'ID': result.get('id'),
        'Timestamp': timestamp_to_datestring(result.get('timestamp', 0) * 1000),
        'Description': result.get('description'),
        'Title': result.get('title'),
        'Severity': result.get('severity'),
        'Tags': result.get('tags'),
        'Link': result.get('link'),
        'IOCs': result.get('iocs_v2'),
        'Visibility': result.get('visibility')
    }

    iocs = result.get('iocs_v2', {})
    for ioc in iocs:
        ioc_contents.append({
            'ID': ioc.get('id'),
            'Match_type': ioc.get('match_type'),
            'Values': ioc.get('values'),
            'Field': ioc.get('field'),
            'Link': ioc.get('link')
        })

    readable_output = tableToMarkdown('The report was updated successfully.', contents, headers, removeNull=True)
    ioc_output = tableToMarkdown('The IOCs for the report', ioc_contents, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Report',
        outputs_key_field='ID',
        outputs=context,
        readable_output=readable_output + ioc_output,
        raw_response=result
    )
    return results


def get_file_device_summary(client: Client, args: Dict) -> CommandResults:

    sha256 = args.get('sha256')
    result = client.get_file_device_summary_request(sha256)
    readable_output = tableToMarkdown('The file device summary', result)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.File',
        outputs_key_field='sha256',
        outputs=result,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_file_metadata_command(client: Client, args: Dict) -> CommandResults:
    sha256 = args.get('sha256')
    result = client.get_file_metadata_request(sha256)
    headers = ['SHA256', 'file_size', 'original_filename', 'internal_name', 'os_type', 'comments']
    contents = {
        'SHA256': result.get('sha256'),
        'file_size': result.get('file_size'),
        'internal_name': result.get('internal_name'),
        'original_filename': result.get('original_filename'),
        'comments': result.get('comments'),
        'os_type': result.get('os_type')
    }
    context = {
        'sha256': result.get('sha256'),
        'architecture': result.get('architecture'),
        'available_file_size': result.get('available_file_size'),
        'charset_id': result.get('charset_id'),
        'comments': result.get('comments'),
        'company_name': result.get('company_name'),
        'file_available': result.get('file_available'),
        'file_description': result.get('file_description'),
        'file_size': result.get('file_size'),
        'file_version': result.get('file_version'),
        'internal_name': result.get('internal_name'),
        'lang_id': result.get('lang_id'),
        'md5': result.get('md5'),
        'original_filename': result.get('original_filename'),
        'os_type': result.get('os_type'),
        'product_description': result.get('product_description'),
        'product_name': result.get('product_name'),
        'product_version': result.get('product_version')
    }

    readable_output = tableToMarkdown('The file metadata', contents, headers, removeNull=True)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.File',
        outputs_key_field='sha256',
        outputs=context,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_file_command(client: Client, args: Dict) -> CommandResults:
    sha256 = argToList(args.get('sha256'))
    expiration_seconds = args.get('expiration_seconds')
    download_to_xsoar = args.get('download_to_xsoar')

    result = client.get_file_request(sha256, expiration_seconds)
    contents = []

    found_files = result.get('found', [])
    for file_ in found_files:
        contents.append({
            'sha256': file_.get('sha256'),
            'url': f"[{file_.get('url')}]({file_.get('url')})"
        })

        if download_to_xsoar == 'true':
            request = requests.get(file_.get('url'))
            demisto.results(fileResult(f'{sha256}.zip', request.content))

    readable_output = tableToMarkdown('The file to download', contents)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.File',
        outputs_key_field='sha256',
        outputs=result,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_file_path_command(client: Client, args: Dict) -> CommandResults:
    sha256 = args.get('sha256')

    result = client.get_file_path_request(sha256)
    readable_output = tableToMarkdown('The file path for the sha256', result)
    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.File',
        outputs_key_field='sha256',
        outputs=result,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: str, last_run: Dict) -> Tuple[List, Dict]:
    last_fetched_alert_create_time = last_run.get('last_fetched_alert_create_time')
    last_fetched_alert_id = last_run.get('last_fetched_alert_id', '')
    if not last_fetched_alert_create_time:
        last_fetched_alert_create_time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.000Z')
    latest_alert_create_date = last_fetched_alert_create_time
    latest_alert_id = last_fetched_alert_id

    incidents = []

    response = client.search_alerts_request(
        sort_field='first_event_time',
        sort_order='ASC',
        create_time=assign_params(
            start=last_fetched_alert_create_time,
            end=datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ),
        limit=fetch_limit,
    )
    alerts = response.get('results', [])

    for alert in alerts:
        alert_id = alert.get('id')
        if alert_id == last_fetched_alert_id:
            # got an alert we already fetched, skipping it
            continue

        alert_create_date = alert.get('create_time')
        incident = {
            'name': f'Carbon Black Enterprise EDR alert {alert_id}',
            'occurred': alert_create_date,
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)
        latest_alert_create_date = datetime.strftime(dateparser.parse(alert_create_date) + timedelta(seconds=1),
                                                     '%Y-%m-%dT%H:%M:%S.000Z')
        latest_alert_id = alert_id

    return incidents, \
        {'last_fetched_alert_create_time': latest_alert_create_date, 'last_fetched_alert_id': latest_alert_id}


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    cb_custom_key = demisto.params().get('custom_key')
    cb_custom_id = demisto.params().get('custom_id')
    cb_org_key = demisto.params().get('organization_key')
    token = f'{cb_custom_key}/{cb_custom_id}'
    # get the service API url
    base_url = demisto.params().get('url')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            use_proxy=proxy,
            token=token,
            cb_org_key=cb_org_key)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            fetch_time = demisto.params().get('fetch_time', '3 days')
            fetch_limit = demisto.params().get('fetch_limit', '50')
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents, last_run = fetch_incidents(client, fetch_time, fetch_limit, last_run=demisto.getLastRun())
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)

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

        elif demisto.command() == 'cb-eedr-report-update':
            return_results(update_report_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-file-device-summary':
            return_results(get_file_device_summary(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-get-file-metadata':
            return_results(get_file_metadata_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-files-download-link-get':
            return_results(get_file_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-file-paths':
            return_results(get_file_path_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        err_msg = str(e)
        try:
            if 'MALFORMED_JSON' in err_msg:
                message = err_msg.split('\n')
                bad_field = json.loads(message[1]).get('field')
                return_error(f'Failed to execute {demisto.command()} command. \nError: The {bad_field} arguments is '
                             f'invalid. Make sure that the arguments is correct.')
        except Exception:
            return_error(f'Failed to execute {demisto.command()} command. Error: {err_msg}')
        return_error(f'Failed to execute {demisto.command()} command. Error: {err_msg}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

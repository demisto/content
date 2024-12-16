from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
from more_itertools import map_reduce


# Disable insecure warnings
urllib3.disable_warnings()
LOG_INIT = "CBEEDR - "


class Client(BaseClient):
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool, token=None, cb_org_key=None):
        self.token = token
        self.cb_org_key = cb_org_key
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json',
                                                                             'Content-Type': 'application/json',
                                                                             'X-Auth-Token': self.token})

    def test_module_request(self):
        url_suffix = f'/api/alerts/v7/orgs/{self.cb_org_key}/alerts/_search'
        body = {
            "criteria": {
                "group_results": True,
                "minimum_severity": 3
            },
            "sort": [{"field": "first_event_timestamp", "order": "DESC"}],
            "rows": 0,
            "start": 1
        }

        return self._http_request('POST', url_suffix=url_suffix, json_data=body)

    def search_alerts_request(self, minimum_severity: None | int = None, create_time: None | dict = None,
                              device_os_version: None | list = None, policy_id: None | list = None, alert_tag: None | list = None,
                              alert_id: None | list = None, device_username: None | list = None, device_id: None | list = None,
                              device_os: None | list = None, process_sha256: None | list = None, policy_name: None | list = None,
                              reputation: None | list = None, alert_type: None | list = None, device_name: None | list = None,
                              process_name: None | list = None, sort_field: None | str = None, sort_order: None | str = None,
                              limit: None | str = None) -> dict:
        suffix_url = f'/api/alerts/v7/orgs/{self.cb_org_key}/alerts/_search'
        body = {
            'criteria': assign_params(
                minimum_severity=minimum_severity,
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
            'start': 1
        }

        if create_time:
            body['time_range'] = create_time

        return self._http_request('POST', suffix_url, json_data=body)

    def alert_workflow_update_get_request(self, request_id: str) -> dict:
        suffix_url = f'jobs/v1/orgs/{self.cb_org_key}/jobs/{request_id}'
        response = self._http_request('GET', suffix_url)
        return response

    def alert_workflow_update_request(self, alert_id: str, state: None | str = None, comment: None | str = None,
                                      determination: None | str = None, time_range: None | str = None, start: None | str = None,
                                      end: None | str = None, closure_reason: None | str = None) -> dict:
        suffix_url = f'/api/alerts/v7/orgs/{self.cb_org_key}/alerts/workflow'
        body = assign_params(
            time_range=assign_params(start=start, end=end, range=time_range),
            criteria=assign_params(id=[alert_id]),
            determination=determination,
            closure_reason=closure_reason,
            status=state,
            note=comment,
        )

        demisto.debug(f"{LOG_INIT} {body=}")
        try:
            response = self._http_request('POST', suffix_url, json_data=body)
        except Exception as e:
            raise e
        return response

    def devices_list_request(self, device_id: None | list = None, status: None | list = None, device_os: None | list = None,
                             last_contact_time: dict[str, str | None] | None = None, ad_group_id: None | list = None,
                             policy_id: None | list = None, target_priority: None | list = None, limit: None | int = None,
                             sort_field: None | str = None, sort_order: None | str = None) -> dict:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/devices/_search'

        body: dict[str, Any] = {
            'criteria': {
                'id': device_id,
                'status': status,
                'os': device_os,
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
        # Ensure that last_contact_time is a dictionary with the expected structure
        if isinstance(last_contact_time, dict) and last_contact_time.get('start'):
            body['criteria'].update({'last_contact_time': last_contact_time})

        return self._http_request('POST', suffix_url, json_data=body)

    def device_quarantine_request(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unquarantine_request(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_bypass_request(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unbypass_request(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request_stop(self, device_id: None | list = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_policy_update(self, device_id: None | list = None, policy_id: None | str = None) -> None:
        suffix_url = f'/appservices/v6/orgs/{self.cb_org_key}/device_actions'

        body = {
            'action_type': 'UPDATE_POLICY',
            'device_id': device_id,
            'options': {
                'policy_id': policy_id
            }
        }

        self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def list_watchlists_request(self) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists'
        return self._http_request('GET', suffix_url)

    def get_watchlist_by_id_request(self, watchlist_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}'
        return self._http_request('GET', suffix_url)

    def delete_watchlist_request(self, watchlist_id: None | str = None) -> None:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}'
        self._http_request('DELETE', suffix_url, resp_type='content')

    def watchlist_alert_status_request(self, watchlist_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        return self._http_request('GET', suffix_url)

    def enable_watchlist_alert_request(self, watchlist_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        return self._http_request('PUT', suffix_url)

    def disable_watchlist_alert_request(self, watchlist_id: None | str = None) -> None:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/watchlists/{watchlist_id}/alert'
        self._http_request('DELETE', suffix_url, resp_type='content')

    def create_watchlist_request(self, watchlist_name: None | str = None, description: None | str = None,
                                 tags_enabled: None | bool = None, alerts_enabled: None | bool = None,
                                 report_ids: None | list = None, classifier: None | dict = None) -> dict:
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

    def update_watchlist_request(self, watchlist_id: None | str = None, watchlist_name: None | str = None,
                                 description: None | str = None, tags_enabled: None | bool = None,
                                 alerts_enabled: None | bool = None, report_ids: None | list = None,
                                 classifier: None | dict = None) -> dict:
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

    def get_ignore_ioc_status_request(self, report_id: None | str = None, ioc_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id})/iocs/{ioc_id}/ignore'

        return self._http_request('GET', suffix_url)

    def ignore_ioc_request(self, report_id: None | str = None, ioc_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/iocs/{ioc_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_ioc_request(self, report_id: None | str = None, ioc_id: None | str = None) -> None:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id})/iocs/{ioc_id}/ignore'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_request(self, report_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}'

        return self._http_request('GET', suffix_url)

    def create_report_request(self, title: None | str = None, description: None | str = None, tags: None | list = None,
                              severity: None | int = None,
                              iocs: None | dict = None, timestamp: None | int = None) -> dict:
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

    def ignore_report_request(self, report_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'

        return self._http_request('PUT', suffix_url)

    def reactivate_report_request(self, report_id: None | str = None) -> None:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def get_report_ignore_status_request(self, report_id: None | str = None) -> dict:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}/ignore'
        return self._http_request('GET', suffix_url)

    def remove_report_request(self, report_id: None | str = None) -> None:
        suffix_url = f'/threathunter/watchlistmgr/v3/orgs/{self.cb_org_key}/reports/{report_id}'

        self._http_request('DELETE', suffix_url, resp_type='content')

    def update_report_request(self, report_id: None | str = None, title: None | str = None, description: None | str = None,
                              severity: None | int = None, iocs: None | dict = None, tags: None | list = None,
                              timestamp: None | int = None) -> dict:
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

    def get_file_device_summary_request(self, sha256: None | str = None) -> dict:
        suffix_url = f'ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/summary/device'
        return self._http_request('GET', suffix_url)

    def get_file_metadata_request(self, sha256: None | str = None) -> dict:
        suffix_url = f'ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/metadata'
        return self._http_request('GET', suffix_url)

    def get_file_request(self, sha256: None | list = None, expiration_seconds: None | int = None) -> dict:
        suffix_url = f'/ubs/v1/orgs/{self.cb_org_key}/file/_download'
        body = assign_params(
            sha256=sha256,
            expiration_seconds=expiration_seconds
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def get_file_path_request(self, sha256: None | str = None) -> dict:
        suffix_url = f'/ubs/v1/orgs/{self.cb_org_key}/sha256/{sha256}/summary/file_path'
        return self._http_request('GET', suffix_url)

    def create_search_process_request(self, process_hash: str, process_name: str, event_id: str, query: str,
                                      limit: None | int = None, start_time: None | str = None,
                                      end_time: None | str = None, start: None | int = 0) -> dict:
        if not process_hash and not process_name and not event_id and not query:
            raise Exception("To perform an process search, please provide at least one of the following: "
                            "'process_hash', 'process_name', 'event_id' or 'query'")
        suffix_url = f'/api/investigate/v2/orgs/{self.cb_org_key}/processes/search_jobs'
        process_hash_list = argToList(process_hash)
        process_name_list = argToList(process_name)
        body = assign_params(criteria=assign_params(
            process_hash=process_hash_list,
            process_name=process_name_list,
            event_id=[event_id]
        ),
            query=query,
            rows=limit,
            start=start,

        )

        if not event_id:
            del body['criteria']['event_id']

        timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        start_iso = parse_date_range(start_time, date_format=timestamp_format)[0]
        if end_time:
            end_iso = parse_date_range(end_time, date_format=timestamp_format)[0]
        else:
            end_iso = datetime.now().strftime(timestamp_format)
        time_range = {
            "end": end_iso,
            "start": start_iso
        }
        body['time_range'] = time_range
        return self._http_request('POST', suffix_url, json_data=body)

    def get_search_process_request(self, job_id) -> dict:
        suffix_url = f'/api/investigate/v2/orgs/{self.cb_org_key}/processes/search_jobs/{job_id}/results'

        return self._http_request('GET', suffix_url)

    def create_search_event_by_process_request(self, process_guid: str, event_type: str,
                                               query: str, limit: int, start_time: str, end_time: None | str = None,
                                               start: int = 0) -> dict:
        if event_type and event_type not in ['filemod', 'netconn', 'regmod', 'modload', 'crossproc', 'childproc']:
            raise Exception("Only the following event types can be searched: "
                            "'filemod', 'netconn', 'regmod', 'modload', 'crossproc', 'childproc'")
        if not event_type and not query:
            raise Exception("To perform an event search, please provide either event_type or query.")
        suffix_url = f'api/investigate/v2/orgs/{self.cb_org_key}/events/{process_guid}/_search'
        body = assign_params(
            criteria=assign_params(event_type=argToList(event_type)),
            query=query,
            rows=limit,
            start=start
        )
        timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        start_iso = parse_date_range(start_time, date_format=timestamp_format)[0]
        if end_time:
            end_iso = parse_date_range(end_time, date_format=timestamp_format)[0]
        else:
            end_iso = datetime.now().strftime(timestamp_format)
        time_range = {
            "end": end_iso,
            "start": start_iso
        }
        body['time_range'] = time_range

        response = self._http_request('POST', suffix_url, json_data=body)
        return response

    def update_threat_tags(self, threat_id: None | str = None, tags: None | list = None) -> dict:

        suffix_url = f'api/alerts/v7/orgs/{self.cb_org_key}/threats/{threat_id}/tags'

        body = {
            "tags": tags
        }

        return self._http_request('POST', suffix_url, json_data=body)

    def create_threat_notes(self, threat_id: None | str = None, notes: None | str = None) -> dict:

        suffix_url = f'api/alerts/v7/orgs/{self.cb_org_key}/threats/{threat_id}/notes'
        body = {
            "note": notes
        }
        return self._http_request('POST', suffix_url, json_data=body)

    def update_alert_notes(self, alert_id: None | str = None, notes: None | str = None) -> dict:

        suffix_url = f'api/alerts/v7/orgs/{self.cb_org_key}/alerts/{alert_id}/notes'

        body = {
            "note": notes
        }

        return self._http_request('POST', suffix_url, json_data=body)

    def get_threat_tags(self, threat_id: None | str = None) -> dict:

        suffix_url = f'api/alerts/v7/orgs/{self.cb_org_key}/threats/{threat_id}/tags'

        return self._http_request('GET', suffix_url)


def check_get_last_run(last_run: dict) -> dict:
    """
    Checks if the 'last_run' format is outdated and updates it to the latest version format if necessary.
    (version 1.1.34 vs 1.1.35 and later).

    Args:
        last_run (dict): The last run dictionary to check and potentially update.

    Returns:
        dict: An updated 'last_run' dictionary that conforms to the latest version format.
    """
    if 'last_fetched_alert_id' in last_run:
        demisto.info("Changing last_run format to the most updated version.")
        last_run['last_fetched_alerts_ids'] = [last_run.pop('last_fetched_alert_id')]
    return last_run


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


def alert_list_command(client: Client, args: dict) -> CommandResults | str:
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
    device_name = argToList(args.get('device_name'))
    process_name = argToList(args.get('process_name'))
    sort_field = args.get('sort_field')
    sort_order = args.get('sort_order')
    limit = args.get('limit')
    contents = []
    headers = ['AlertID', 'CreateTime', 'DeviceID', 'DeviceName', 'DeviceOS', 'PolicyName', 'ProcessName', 'Type',
               'WorkflowState']

    result = client.search_alerts_request(minimum_severity, create_time,
                                          device_os_version, policy_id, alert_tag, alert_id, device_username,
                                          device_id, device_os, process_sha256, policy_name,
                                          reputation, alert_type, device_name,
                                          process_name, sort_field, sort_order, limit)

    alerts = result.get('results', [])
    if not alerts:
        return 'No alerts were found'
    for alert in alerts:

        # The new API version returns status instead of state,
        # mapping this for the output to look the same.
        alert['workflow']['state'] = alert['workflow']['status']
        alert['first_event_time'] = alert['first_event_timestamp']

        contents.append({
            'AlertID': alert.get('id'),
            'CreateTime': alert.get('backend_timestamp'),
            'DeviceID': alert.get('device_id'),
            'DeviceName': alert.get('device_name'),
            'DeviceOS': alert.get('device_os'),
            'PolicyName': alert.get('device_policy'),
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


@polling_function(name='cb-eedr-alert-workflow-update', interval=60, requires_polling_arg=False)
def alert_workflow_update_command_with_polling(args: dict, client: Client) -> PollResult:
    """
       Updates the given alret's workflow. This is a polling function.

    Args:
        args (dict): Including alert_id and fields to update.
        client (Client): The client.

    Returns:
        PollResult: If request status is COMPLETED will stop polling, otherwise will poll again.
    """
    request_id = arg_to_number(args.get('request_id'))
    alert_id = args['alert_id']

    demisto.debug(f'{LOG_INIT} Polling is running - got {request_id=}, {alert_id=}')

    if not request_id:  # if this is the first time
        demisto.debug(f'{LOG_INIT} Getting all relevant args for first run')
        determination = args.get('remediation_state')
        time_range = args.get('time_range')
        start = args.get('start')
        end = args.get('end')
        closure_reason = args.get('closure_reason')
        comment = args.get('comment')
        status = args.get('state')

        # The new API version (v7) does not support 'DISMISSED', instead need to use 'CLOSED'
        if str(status).lower() == 'dismissed':
            status = 'CLOSED'
        if status == "open":
            "OPEN"

        if not determination and not status:
            raise DemistoException('Must specify at least one of \"remediation_state\" or \"state\".')

        if start or end:
            if not start or not end:
                raise DemistoException('Need to specify start and end timestamps')
            if start > end:
                raise DemistoException('start timestamp needs to be before end timestamp')

        demisto.debug(f'{LOG_INIT} calling alert_workflow_update_request function')
        response = client.alert_workflow_update_request(
            alert_id, status, comment, determination, time_range, start, end, closure_reason)

        demisto.debug(f'{LOG_INIT} Recieved response: type= {type(response)}, len= {len(response)}')

        return PollResult(
            partial_result=CommandResults(readable_output="running polling"),
            response=None,
            continue_to_poll=True,
            args_for_next_run={"request_id": response['request_id']} | args
        )

    request_id = args['request_id']

    demisto.debug(f'{LOG_INIT} Calling the second endpoint')
    response = client.alert_workflow_update_get_request(
        request_id)
    demisto.debug(f'{LOG_INIT} {response=}')

    request_status = response['status']
    demisto.debug(f'{LOG_INIT} {request_status=}')

    if request_status == 'CREATED':
        message = CommandResults(
            readable_output="Checking again in 60 seconds...")
        demisto.debug(f'{LOG_INIT} returning PollResult with continue_to_poll=True')
        return PollResult(
            partial_result=message,
            response=None,
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id,

                               **args})

    elif request_status == 'COMPLETED':
        changed_by = response['job_parameters']['job_parameters']['userWorkflowDto']['changed_by']
        status_HR = response['job_parameters']['job_parameters']['request']['status'] if args.get('state') else None
        message = CommandResults(
            outputs={'AlertID': alert_id, 'ChangedBy': changed_by, 'Comment': args.get('comment'),
                     'LastUpdateTime': response['last_update_time'], 'State': status_HR,
                     'RemediationState': args.get('remediation_state')},
            outputs_prefix='CarbonBlackEEDR.Alert',
            readable_output=tableToMarkdown(f'Successfully updated the alert: "{alert_id}"',
                                            {'changed_by': changed_by,
                                             'last_update_time': response['last_update_time'],
                                             'determination': args.get('determination'),
                                             'comment': args.get('comment'),
                                             'closure reason': args.get('closure_reason'),
                                             'state': status_HR}, removeNull=True),
            outputs_key_field='AlertID')
        demisto.debug(f'{LOG_INIT} returning PollResult with continue_to_poll=False')
        return PollResult(
            response=message,
            continue_to_poll=False)

    # Status is failed
    else:  # The status of the response can be COMPLETED, CREATED or FAILED.
        raise DemistoException(f"Failed to update the alerts workflow. Request's Status: {request_status}\
             response keys: {response.keys()}")


def list_devices_command(client: Client, args: dict) -> CommandResults | str:
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
    sort_field = args.get('sort_field', 'last_contact_time')
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
        indicator=endpoint
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


def list_watchlists_command(client: Client) -> CommandResults | str:
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


def watchlist_alert_status_command(client: Client, args: dict) -> str:
    watchlist_id = args.get('watchlist_id')
    result = client.watchlist_alert_status_request(watchlist_id)

    if not result.get('alert'):
        return f'Watchlist {watchlist_id} alert status is Off'
    else:
        return f'Watchlist {watchlist_id} alert status is On'


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


def get_report_command(client: Client, args: dict) -> CommandResults:
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


def ignore_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    client.ignore_report_request(report_id)

    return f'The report with report_id "{report_id}" and all contained IOCs will not match future events ' \
           f'for any watchlist.'


def reactivate_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    client.reactivate_report_request(report_id)

    return f'Report with report_id "{report_id}" and all contained IOCs will match future events for all watchlists.'


def get_report_ignore_status_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')

    result = client.get_report_ignore_status_request(report_id)

    if not result.get('ignored'):
        return f'ignore status for report with report_id "{report_id}" is disabled.'
    else:
        return f'ignore status for report with report_id "{report_id}" is enabled.'


def remove_report_command(client: Client, args: dict) -> str:
    report_id = args.get('report_id')
    client.remove_report_request(report_id)

    return f'The report "{report_id}" was deleted successfully.'


def update_report_command(client: Client, args: dict) -> CommandResults:
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


def get_file_device_summary(client: Client, args: dict) -> CommandResults:
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


def get_file_metadata_command(client: Client, args: dict) -> CommandResults:
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


def get_file_command(client: Client, args: dict) -> CommandResults:
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


def get_file_path_command(client: Client, args: dict) -> CommandResults:
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


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: str, last_run: Dict) -> tuple[List[Dict], Dict]:
    """
    Fetch incidents from the client based on the given fetch time and limit.

    Args:
        client (Client): The client to fetch incidents from.
        fetch_time (str): The time range to fetch incidents from.
        fetch_limit (str): The maximum number of incidents to fetch.
        last_run (Dict): The dictionary containing the last run information.

    Returns:
        Tuple[List[Dict], Dict]: A tuple containing the list of incidents and the updated last run dictionary.
    """
    if not (int_fetch_limit := arg_to_number(fetch_limit)):
        raise ValueError("limit cannot be empty.")

    # When using the last alert timestamp from the previous run as the start timestamp,
    # the API will return at least one alert that has already been received, which will be filtered out.
    # Therefore, we increase the limit by one to meet the original requested limit.
    if last_run:
        int_fetch_limit += 1

    last_fetched_alert_create_time = last_run.get('last_fetched_alert_create_time')
    last_fetched_alerts_ids = last_run.get('last_fetched_alerts_ids', [])
    if not last_fetched_alert_create_time:
        last_fetched_alert_create_time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.000Z')
        demisto.debug(f'No last_fetched_alert_create_time, setting it to {last_fetched_alert_create_time}')

    incidents = []

    response = client.search_alerts_request(
        sort_field='backend_timestamp',
        sort_order='ASC',
        create_time=assign_params(
            start=last_fetched_alert_create_time,
            end=datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ),
        limit=str(int_fetch_limit),
    )

    alerts = response.get('results', [])
    demisto.debug(f'{LOG_INIT} got {len(alerts)} alerts from server')

    if alerts:
        for alert in alerts:
            alert_id = alert.get('id')

            #  dedup
            if alert_id in last_fetched_alerts_ids:
                demisto.debug(f'{LOG_INIT} got previously fetched alert {alert_id}, skipping it')
                continue

            alert_create_date = alert.get('backend_timestamp')
            incident = {
                'name': f'Carbon Black Enterprise EDR alert {alert_id}',
                'occurred': alert_create_date,
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)

            parsed_date = dateparser.parse(alert_create_date)
            assert parsed_date is not None, f'Failed parsing {alert_create_date}'

        # Group alerts by their backend_timestamp to handle deduplication
        alert_ids_grouped_by_backend_timestamp = map_reduce(alerts, lambda x: x['backend_timestamp'])
        last_fetched_alert_create_time = alerts[-1]['backend_timestamp']
        # All IDs of alerts that share the same timestamp as the last one.
        last_fetched_alerts_ids = [
            alert['id'] for alert in alert_ids_grouped_by_backend_timestamp[last_fetched_alert_create_time]
        ]

    last_run = {
        'last_fetched_alert_create_time': last_fetched_alert_create_time,
        'last_fetched_alerts_ids': last_fetched_alerts_ids
    }

    demisto.debug(f'{LOG_INIT} sending {len(incidents)} incidents')

    return incidents, last_run


@polling_function(
    name='cb-eedr-process-search',
    interval=arg_to_number(demisto.args().get('interval_in_seconds')) or 60,
    timeout=arg_to_number(demisto.args().get('timeout')) or 600,
    requires_polling_arg=False
)
def process_search_command_with_polling(args: dict, client: Client) -> PollResult:
    """
        Returns the process search results. This is a polling function.

    Args:
        args (dict): The input arguments from the user.
        client (Client): The client.

    Returns:
        PollResult: If the job's status is COMPLETED will stop polling, otherwise will poll again.
    """
    job_id = args.get('job_id')
    interval_in_seconds = arg_to_number(args.get('interval_in_seconds'))
    demisto.debug(f'{LOG_INIT} in process_search_command_with_polling function, {job_id=}')

    if not job_id:  # if this is the first time
        process_name = args.get('process_name', '')
        process_hash = args.get('process_hash', '')
        event_id = args.get('event_id', '')
        query = args.get('query', '')
        start_time = str(args.get('start_time', '1 day'))
        end_time = str(args.get('end_time', ''))
        limit = arg_to_number(args.get('limit'))
        start = arg_to_number(args.get('start'))

        response = client.create_search_process_request(process_name=process_name, process_hash=process_hash,
                                                        event_id=event_id, query=query, limit=limit,
                                                        start_time=start_time, end_time=end_time, start=start)
        demisto.debug(f'{LOG_INIT} got {response=}')
        return PollResult(partial_result=CommandResults(readable_output=f"job_id is {response.get('job_id')}."),
                          response=None,
                          continue_to_poll=True,
                          args_for_next_run={"job_id": response['job_id']} | args
                          )

    # this is not the first time, there is a job_id
    response = client.get_search_process_request(job_id=args['job_id'])
    if response.get('contacted'):
        #  The response has no 'status' field. If contacted equals to completed then the status is completed, else we are still \
        # in progress. If there is no 'contacted' or no 'completed' fields then it means that something failed in server.
        status = 'Completed' if response.get('contacted') == response.get('completed') else 'In Progress'
    else:
        status = None
    if status == 'In Progress':
        message = CommandResults(
            readable_output=f"Checking again in {interval_in_seconds} seconds...")
        return PollResult(
            partial_result=message,
            response=None,
            continue_to_poll=True,
            args_for_next_run={"job_id": job_id,
                               **args})

    elif status == 'Completed':
        output = {'status': status, 'job_id': job_id, 'results': response.get('results')}
        title = "Completed Search Results:"
        headers = ["process_hash", "process_name", "device_name", "device_timestamp", "process_pid", "process_username"]
        human_readable = tableToMarkdown(name=title, t=output.get('results'), removeNull=True, headers=headers)
        message = CommandResults(outputs_prefix='CarbonBlackEEDR.SearchProcess',
                                 outputs=output,
                                 outputs_key_field='job_id',
                                 raw_response=response,
                                 readable_output=human_readable)
        return PollResult(
            response=message,
            continue_to_poll=False)

    else:
        raise DemistoException(f'Failed to run process search. response keys: {response.keys()}')


def process_search_command_without_polling(client: Client, args: dict) -> CommandResults:
    """
    Gets arguments for a process search task, and returns the task's id and status.
    """
    process_name = args.get('process_name', '')
    process_hash = args.get('process_hash', '')
    event_id = args.get('event_id', '')
    query = args.get('query', '')
    start_time = str(args.get('start_time', '1 day'))
    end_time = str(args.get('end_time', ''))
    limit = args.get('limit')
    if not limit:
        limit = 20
    try:
        limit = int(limit)
    except ValueError:
        raise ValueError("Please provide a number as limit.")

    raw_respond = client.create_search_process_request(process_name=process_name, process_hash=process_hash,
                                                       event_id=event_id, query=query, limit=limit,
                                                       start_time=start_time, end_time=end_time)
    readable_output = f"job_id is {raw_respond.get('job_id')}."
    output = {'job_id': raw_respond.get('job_id'), 'status': 'In Progress'}
    return CommandResults(outputs_prefix='CarbonBlackEEDR.SearchProcess', raw_response=raw_respond,
                          outputs=output, outputs_key_field='job_id', readable_output=readable_output)


def event_by_process_search_command(client: Client, args: dict) -> CommandResults:
    """
    Gets arguments for an event-by-process search task, and returns the task's results.
    """
    process_guid = args.get('process_guid', '')
    event_type = args.get('event_type', '')
    query = args.get('query', '')
    limit = args.get('limit', 20)
    start = args.get('start', 0)
    start_time = str(args.get('start_time', '1 day'))
    end_time = str(args.get('end_time', ''))

    if str(limit).isdigit():
        limit = int(limit)
    else:
        raise ValueError("Please provide a number as limit.")

    if str(start).isdigit():
        start = int(start)
    else:
        raise ValueError("Please provide a number as a start index.")

    result = client.create_search_event_by_process_request(
        process_guid=process_guid, event_type=event_type,
        query=query, limit=limit, start_time=start_time, end_time=end_time, start=start)

    readable = tableToMarkdown(name="Results Found.", t=result.get('results'), removeNull=True)
    found_num_readable = f"Total of {result.get('num_found')} items found. "
    found_num_readable += f"Showing items {start} - {min(start + limit - 1, result.get('num_found'))}." if result.get(
        'num_found') else ""
    readable += found_num_readable

    return CommandResults(outputs_prefix='CarbonBlackEEDR.SearchEvent',
                          outputs=result.get('results'), outputs_key_field='event_guid',
                          raw_response=result, readable_output=readable)


def process_search_get_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Gets a process search task's id, and returns the task's results.
    """
    job_ids = argToList(args.get('job_id'))
    job_result_list = []
    for job in job_ids:
        raw_result = client.get_search_process_request(job_id=job)
        status = 'Completed' if raw_result.get('contacted') == raw_result.get('completed') else 'In Progress'
        output = {'status': status, 'job_id': job, 'results': raw_result.get('results')}
        title = f"{status} Search Results:"
        headers = ["process_hash", "process_name", "device_name", "device_timestamp", "process_pid", "process_username"]
        human_readable = tableToMarkdown(name=title, t=output.get('results'), removeNull=True, headers=headers)
        job_result_list.append(CommandResults(outputs_prefix='CarbonBlackEEDR.SearchProcess',
                                              outputs=output, outputs_key_field='job_id',
                                              raw_response=raw_result,
                                              readable_output=human_readable))
    return job_result_list


def add_threat_tags_command(client: Client, args: dict) -> CommandResults:
    tags = argToList(args.get("tags"))
    threat_id = args.get("threat_id")
    result = client.update_threat_tags(threat_id, tags)

    readable_output = tableToMarkdown(f'Successfully updated threat: "{threat_id}"', result, removeNull=True)
    outputs = {
        'ThreatID': threat_id,
        'Tags': result.get('tags')
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Threat',
        outputs_key_field='tags',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def add_threat_notes_command(client: Client, args: dict) -> CommandResults:
    notes = args.get("notes")
    threat_id = args.get("threat_id")
    result = client.create_threat_notes(threat_id, notes)

    readable_output = tableToMarkdown(f'Successfully added notes to threat: "{threat_id}"', result, removeNull=True)
    outputs = {
        'ThreatID': threat_id,
        'Notes': notes
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Threat',
        outputs_key_field='ThreatID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def add_alert_notes_command(client: Client, args: dict) -> CommandResults:
    notes = args.get("notes")
    alert_id = args.get("alert_id")
    result = client.update_alert_notes(alert_id, notes)

    readable_output = tableToMarkdown(f'Successfully added notes to alert: "{alert_id}"', result, removeNull=True)
    outputs = {
        'AlertID': alert_id,
        'Notes': notes
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Threat',
        outputs_key_field='AlertID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def get_threat_tags_command(client: Client, args: dict) -> CommandResults:
    threat_id = args.get("threat_id")
    result = client.get_threat_tags(threat_id)

    readable_output = tableToMarkdown(f'Successfully sent for threat: "{threat_id}"', result, removeNull=True)
    outputs = {
        'ThreatID': threat_id,
        'Tags': result.get('list')
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Threat',
        outputs_key_field='ThreatID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )
    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    cb_custom_key = demisto.params().get('credentials_custom', {}).get('password') or demisto.params().get('custom_key')
    cb_custom_id = demisto.params().get('credentials_custom', {}).get('identifier') or demisto.params().get('custom_id')
    if not (cb_custom_key and cb_custom_id):
        raise DemistoException('Custom ID and Custom key must be provided.')
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
            incidents, last_run = fetch_incidents(client, fetch_time, fetch_limit,
                                                  last_run=check_get_last_run(demisto.getLastRun()))
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)

        elif demisto.command() == 'cb-eedr-list-alerts':
            return_results(alert_list_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-alert-workflow-update':
            # args have to be sent before client because this is a polling function!
            return_results(alert_workflow_update_command_with_polling(demisto.args(), client))

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

        elif demisto.command() == 'cb-eedr-process-search':
            polling = argToBoolean(demisto.args().get('polling'))
            if polling:
                # args have to be sent before client because this is a polling function!!
                return return_results(process_search_command_with_polling(demisto.args(), client))
            else:
                return return_results(process_search_command_without_polling(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-process-search-results':
            for command_result_item in process_search_get_command(client, demisto.args()):
                return_results(command_result_item)

        elif demisto.command() == 'cb-eedr-events-by-process-get':
            return_results(event_by_process_search_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-add-threat-tags':
            return_results(add_threat_tags_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-add-threat-notes':
            return_results(add_threat_notes_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-add-alert-notes':
            return_results(add_alert_notes_command(client, demisto.args()))

        elif demisto.command() == 'cb-eedr-get-threat-tags':
            return_results(get_threat_tags_command(client, demisto.args()))

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

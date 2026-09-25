import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import traceback
import urllib3
from datetime import datetime, timezone
from typing import Any

urllib3.disable_warnings()

SEVERITY_MAP = {
    0: 'Low',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical',
}


class XSIAMClient(BaseClient):

    def __init__(self, base_url: str, api_key: str, api_key_id: str, verify: bool, proxy: bool):
        headers = {
            'x-xdr-auth-id': api_key_id,
            'Authorization': api_key,
            'Content-Type': 'application/json',
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def insert_parsed_alerts(self, alerts: list) -> dict:
        body = {'request_data': {'alerts': alerts}}
        demisto.debug(f'Inserting {len(alerts)} parsed alert(s) into XSIAM')
        return self._http_request(
            method='POST',
            url_suffix='/public_api/v1/alerts/insert_parsed_alerts',
            json_data=body,
        )


class XSOAR6Client(BaseClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def search_incidents(self, query: str = '', size: int = 100, page: int = 0,
                         from_date: str | None = None, to_date: str | None = None) -> list:
        filter_body: dict[str, Any] = {}
        if query:
            filter_body['query'] = query
        if from_date:
            filter_body['fromDate'] = from_date
        if to_date:
            filter_body['toDate'] = to_date

        body: dict[str, Any] = {
            'filter': filter_body,
            'page': page,
            'size': size,
            'sort': [{'field': 'created', 'asc': True}],
        }
        response = self._http_request(
            method='POST',
            url_suffix='/incidents/search',
            json_data=body,
        )
        return response.get('data') or []


def map_severity(xsoar_severity: int, elevate_low: bool = False) -> str:
    severity = SEVERITY_MAP.get(xsoar_severity, 'Low')
    if elevate_low and severity == 'Low':
        return 'Medium'
    return severity


def parse_date_to_epoch_ms(date_str: str | None) -> int:
    if not date_str:
        return int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    try:
        dt = arg_to_datetime(date_str)
        if dt:
            return int(dt.timestamp() * 1000)
    except Exception:
        demisto.debug(f'Failed to parse date string: {date_str}')
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def build_description(incident: dict) -> str:
    status_names = {0: 'Active', 1: 'Done', 2: 'Archive'}
    severity_names = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
    lines: list[str] = []

    lines.append(f'XSOAR Incident ID: {incident.get("id", "")}')
    lines.append(f'Name: {incident.get("name", "")}')
    lines.append(f'Type: {incident.get("type", "")}')
    status_val = incident.get('status')
    lines.append(f'Status: {status_names.get(status_val, str(status_val))}')
    sev = incident.get('severity', 0)
    lines.append(f'Severity: {severity_names.get(sev, str(sev))}')
    lines.append(f'Owner: {incident.get("owner", "")}')
    lines.append(f'Occurred: {incident.get("occurred", "")}')
    lines.append(f'Created: {incident.get("created", "")}')
    lines.append(f'Modified: {incident.get("modified", "")}')
    lines.append(f'Closed: {incident.get("closed", "")}')
    lines.append(f'Close Reason: {incident.get("closeReason", "")}')
    lines.append(f'Close Notes: {incident.get("closeNotes", "")}')
    lines.append(f'Phase: {incident.get("phase", "")}')
    lines.append(f'Playbook ID: {incident.get("playbookId", "")}')
    lines.append(f'Source Brand: {incident.get("sourceBrand", "")}')
    lines.append(f'Source Instance: {incident.get("sourceInstance", "")}')

    details = incident.get('details', '')
    if details:
        lines.append(f'Details: {details}')
    description = incident.get('description', '')
    if description:
        lines.append(f'Description: {description}')

    labels = incident.get('labels', [])
    if labels:
        lines.append('')
        lines.append('--- Labels ---')
        for label in labels:
            lines.append(f'  {label.get("type", "")}: {label.get("value", "")}')

    custom_fields = incident.get('CustomFields') or {}
    if custom_fields:
        lines.append('')
        lines.append('--- Custom Fields ---')
        for key, val in sorted(custom_fields.items()):
            if val is not None and val != '' and val != [] and val != {}:
                if isinstance(val, (dict, list)):
                    lines.append(f'  {key}: {json.dumps(val, default=str)}')
                else:
                    lines.append(f'  {key}: {val}')

    return '\n'.join(lines)


def build_raw_context(incident: dict) -> str:
    skip_keys = {'ShardID', 'allRead', 'allReadWrite', 'hasRole',
                 'previousAllRead', 'previousAllReadWrite', 'previousRoles',
                 'dbotCreatedBy', 'isPlayground', 'notifyTime'}
    filtered = {k: v for k, v in incident.items()
                if k not in skip_keys and v is not None and v != '' and v != [] and v != {}}
    return json.dumps(filtered, default=str)


def map_incident_to_alert(incident: dict, elevate_low: bool = False, timestamp_offset: int = 0) -> dict:
    event_timestamp = parse_date_to_epoch_ms(incident.get('occurred') or incident.get('created'))
    if timestamp_offset:
        event_timestamp += timestamp_offset * 60 * 1000
    severity = map_severity(incident.get('severity', 0), elevate_low)
    return {
        'product': 'XSOAR',
        'vendor': 'Palo Alto Networks',
        'local_ip': '0.0.0.0',
        'local_port': 1,
        'remote_ip': '0.0.0.0',
        'remote_port': 1,
        'event_timestamp': event_timestamp,
        'severity': severity,
        'alert_name': incident.get('name', ''),
        'alert_description': build_description(incident),
        'xsoar_incident_id': str(incident.get('id', '')),
        'xsoar_incident_type': incident.get('type', ''),
        'xsoar_incident_owner': incident.get('owner', ''),
        'xsoar_incident_status': str(incident.get('status', '')),
        'xsoar_occurred': incident.get('occurred', ''),
        'xsoar_created': incident.get('created', ''),
        'xsoar_closed': incident.get('closed', ''),
        'xsoar_close_reason': incident.get('closeReason', ''),
        'xsoar_source_brand': incident.get('sourceBrand', ''),
        'xsoar_source_instance': incident.get('sourceInstance', ''),
        'xsoar_raw_context': build_raw_context(incident),
    }


def search_incidents(xsoar_client: XSOAR6Client, query: str | None, max_incidents: int,
                     from_date: str | None = None, to_date: str | None = None) -> list[dict]:
    all_incidents: list[dict] = []
    page = 0
    while len(all_incidents) < max_incidents:
        batch_size = min(max_incidents - len(all_incidents), 100)
        demisto.debug(f'Searching incidents: page={page}, size={batch_size}, query={query}')
        data = xsoar_client.search_incidents(
            query=query or '', size=batch_size, page=page,
            from_date=from_date, to_date=to_date,
        )
        if not data:
            break
        all_incidents.extend(data)
        if len(data) < batch_size:
            break
        page += 1
    return all_incidents[:max_incidents]


def push_incidents_command(xsiam_client: XSIAMClient, xsoar_client: XSOAR6Client,
                           args: dict, default_query: str | None,
                           default_max: int, elevate_low: bool = False,
                           timestamp_offset: int = 0) -> CommandResults:
    query = args.get('query') or default_query
    max_incidents = arg_to_number(args.get('max_incidents')) or default_max
    from_date = args.get('from_date')
    to_date = args.get('to_date')

    incidents = search_incidents(xsoar_client, query, max_incidents, from_date, to_date)
    if not incidents:
        return CommandResults(
            readable_output='No incidents found matching the query.',
            outputs_prefix='XSIAMPush',
            outputs={'PushedCount': 0, 'Incidents': []},
        )

    alerts = [map_incident_to_alert(inc, elevate_low, timestamp_offset) for inc in incidents]
    xsiam_client.insert_parsed_alerts(alerts)

    pushed_summary = [
        {'ID': inc.get('id', ''), 'Name': inc.get('name', '')}
        for inc in incidents
    ]
    readable = tableToMarkdown(
        f'Successfully pushed {len(alerts)} incident(s) to XSIAM',
        pushed_summary, headers=['ID', 'Name'],
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix='XSIAMPush',
        outputs={'PushedCount': len(alerts), 'Incidents': pushed_summary},
    )


def push_single_incident_command(xsiam_client: XSIAMClient, xsoar_client: XSOAR6Client,
                                  args: dict, elevate_low: bool = False,
                                  timestamp_offset: int = 0) -> CommandResults:
    incident_id = args.get('incident_id')
    if not incident_id:
        raise DemistoException('incident_id argument is required.')

    data = xsoar_client.search_incidents(query=f'id:{incident_id}', size=1)
    if not data:
        raise DemistoException(f'Incident {incident_id} not found.')

    incident = data[0]
    alert = map_incident_to_alert(incident, elevate_low, timestamp_offset)
    xsiam_client.insert_parsed_alerts([alert])

    pushed_info = {
        'ID': incident.get('id', ''),
        'Name': incident.get('name', ''),
        'Severity': alert['severity'],
        'AlertName': alert['alert_name'],
    }
    readable = tableToMarkdown(
        f'Successfully pushed incident {incident_id} to XSIAM',
        pushed_info, headers=['ID', 'Name', 'Severity', 'AlertName'],
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix='XSIAMPush',
        outputs={'PushedIncident': pushed_info},
    )


def sync_new_incidents_command(xsiam_client: XSIAMClient, xsoar_client: XSOAR6Client,
                               args: dict, default_query: str | None,
                               default_max: int, elevate_low: bool = False,
                               timestamp_offset: int = 0) -> CommandResults:
    max_incidents = arg_to_number(args.get('max_incidents')) or default_max
    query = args.get('query') or default_query

    ctx = demisto.getIntegrationContext() or {}
    last_id = ctx.get('last_synced_id', 0)
    last_time = ctx.get('last_synced_time', '')

    from_date = args.get('from_date') or last_time or None

    incidents = search_incidents(xsoar_client, query, max_incidents, from_date=from_date)
    if not incidents:
        return CommandResults(
            readable_output=f'No new incidents found (last synced ID: {last_id}).',
            outputs_prefix='XSIAMSync',
            outputs={'SyncedCount': 0, 'Incidents': [], 'LastSyncedID': last_id},
        )

    new_incidents = [inc for inc in incidents if int(inc.get('id', 0)) > last_id]

    if not new_incidents:
        return CommandResults(
            readable_output=f'All incidents already synced (last synced ID: {last_id}).',
            outputs_prefix='XSIAMSync',
            outputs={'SyncedCount': 0, 'Incidents': [], 'LastSyncedID': last_id},
        )

    alerts = [map_incident_to_alert(inc, elevate_low, timestamp_offset) for inc in new_incidents]
    xsiam_client.insert_parsed_alerts(alerts)

    new_last_id = max(int(inc.get('id', 0)) for inc in new_incidents)
    new_last_time = max(inc.get('created', '') for inc in new_incidents)
    ctx['last_synced_id'] = new_last_id
    ctx['last_synced_time'] = new_last_time
    demisto.setIntegrationContext(ctx)

    pushed_summary = [
        {'ID': inc.get('id', ''), 'Name': inc.get('name', '')}
        for inc in new_incidents
    ]
    readable = tableToMarkdown(
        f'Synced {len(new_incidents)} new incident(s) to XSIAM (last ID: {new_last_id})',
        pushed_summary, headers=['ID', 'Name'],
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix='XSIAMSync',
        outputs={'SyncedCount': len(new_incidents), 'Incidents': pushed_summary, 'LastSyncedID': new_last_id},
    )


def reset_sync_command() -> CommandResults:
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Sync state has been reset. Next sync will send all incidents.')


def test_module(xsiam_client: XSIAMClient, xsoar_client: XSOAR6Client) -> str:
    xsoar_client.search_incidents(size=1)
    xsiam_client.insert_parsed_alerts([])
    return 'ok'


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    xsiam_url = params.get('xsiam_url', '').rstrip('/')
    xsiam_api_key = (params.get('xsiam_api_key') or {}).get('password', '')
    xsiam_api_key_id = params.get('xsiam_api_key_id', '')
    xsoar_url = params.get('xsoar_url', '').rstrip('/')
    xsoar_api_key = (params.get('xsoar_api_key') or {}).get('password', '')
    verify = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))
    default_max = arg_to_number(params.get('max_incidents')) or 100
    default_query = params.get('query')
    elevate_low = argToBoolean(params.get('elevate_low', False))
    timestamp_offset = arg_to_number(params.get('timestamp_offset')) or 0

    demisto.debug(f'Command being called is {command}')

    try:
        xsiam_client = XSIAMClient(
            base_url=xsiam_url, api_key=xsiam_api_key,
            api_key_id=xsiam_api_key_id, verify=verify, proxy=proxy,
        )
        xsoar_client = XSOAR6Client(
            base_url=xsoar_url, api_key=xsoar_api_key,
            verify=verify, proxy=proxy,
        )

        if command == 'test-module':
            result = test_module(xsiam_client, xsoar_client)
            return_results(result)
        elif command == 'xsiam-push-incidents':
            result = push_incidents_command(xsiam_client, xsoar_client, args, default_query, default_max, elevate_low, timestamp_offset)
            return_results(result)
        elif command == 'xsiam-push-incident':
            result = push_single_incident_command(xsiam_client, xsoar_client, args, elevate_low, timestamp_offset)
            return_results(result)
        elif command == 'xsiam-sync-new-incidents':
            result = sync_new_incidents_command(xsiam_client, xsoar_client, args, default_query, default_max, elevate_low, timestamp_offset)
            return_results(result)
        elif command == 'xsiam-reset-sync':
            result = reset_sync_command()
            return_results(result)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

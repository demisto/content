import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict, List, Tuple, Union

import urllib3
from dateparser import parse
from pytz import utc
from requests_ntlm import HttpNtlmAuth

from CommonServerUserPython import *

urllib3.disable_warnings()

SEVERITY_TRANSLATION = {
    'Low': 1,
    'Medium': 2,
    'High': 3
}


class Client(BaseClient):
    def get_suspicious_activity_request(self, suspicious_activity_id: str = '') -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/suspiciousActivities/{suspicious_activity_id}'
        )

    def get_suspicious_activity_details_request(self, suspicious_activity_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/suspiciousActivities/{suspicious_activity_id}/details'
        )

    def update_suspicious_activity_status_request(self,
                                                  suspicious_activity_id: str,
                                                  suspicious_activity_status: str
                                                  ) -> Dict[str, Any]:
        body = {
            'Status': suspicious_activity_status
        }

        return self._http_request(
            method='POST',
            url_suffix=f'/suspiciousActivities/{suspicious_activity_id}',
            json_data=body,
            ok_codes=(204,),
            resp_type='text'
        )

    def delete_suspicious_activity_request(self, suspicious_activity_id: str) -> Dict[str, Any]:
        body = {
            'shouldDeleteSametype': False
        }

        params = {
            'shouldDeleteSameType': 'false'
        }

        return self._http_request(
            method='DELETE',
            url_suffix=f'/suspiciousActivities/{suspicious_activity_id}',
            json_data=body,
            params=params,
            ok_codes=(204,),
            resp_type='text'
        )

    def get_monitoring_alert_request(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/monitoringAlerts'
        )

    def get_entity_request(self, entity_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/uniqueEntities/{entity_id}'
        )

    def get_entity_profile_request(self, entity_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/uniqueEntities/{entity_id}/profile'
        )


def test_module(client: Client) -> str:
    client.get_monitoring_alert_request()
    return 'ok'


def get_suspicious_activity(client: Client, args: Dict[str, str]) -> Union[CommandResults, str]:
    suspicious_activity_id = args.get('id', '')
    suspicious_activity_status = argToList(args.get('status', ''))
    suspicious_activity_severity = argToList(args.get('severity', ''))
    suspicious_activity_type = argToList(args.get('type', ''))
    suspicious_activity_start_time = parse(args.get('start_time', ''))
    suspicious_activity_end_time = parse(args.get('end_time', ''))
    limit = int(args.get('limit', '50'))

    raw_suspicious_activity = client.get_suspicious_activity_request(suspicious_activity_id)
    suspicious_activity_output = []
    if raw_suspicious_activity:
        suspicious_activities = raw_suspicious_activity if isinstance(raw_suspicious_activity, list) \
            else [raw_suspicious_activity]
        if not suspicious_activity_id and \
                any([suspicious_activity_status, suspicious_activity_severity, suspicious_activity_type,
                     suspicious_activity_start_time, suspicious_activity_end_time]):
            for activity in suspicious_activities:
                if suspicious_activity_status and activity.get('Status') not in suspicious_activity_status:
                    continue
                if suspicious_activity_severity and activity.get('Severity') not in suspicious_activity_severity:
                    continue
                if suspicious_activity_type and activity.get('Type') not in suspicious_activity_type:
                    continue
                start_time_date = parse(activity.get('StartTime'))  # type: ignore
                assert start_time_date is not None
                if suspicious_activity_start_time and start_time_date.replace(tzinfo=utc) < \
                        suspicious_activity_start_time.replace(tzinfo=utc):
                    continue
                end_time_date = parse(activity.get('EndTime'))  # type: ignore
                assert end_time_date is not None
                if suspicious_activity_end_time and end_time_date.replace(tzinfo=utc) > \
                        suspicious_activity_end_time.replace(tzinfo=utc):
                    continue
                suspicious_activity_output.append(activity)
        else:
            suspicious_activity_output = suspicious_activities
    suspicious_activity_output = suspicious_activity_output[:limit]
    if suspicious_activity_output:
        readable_output = tableToMarkdown(
            'Microsoft Advanced Threat Analytics Suspicious Activity',
            suspicious_activity_output,
            headers=['Id', 'Type', 'Status', 'Severity', 'StartTime', 'EndTime'],
            removeNull=True
        )
        if suspicious_activity_id:
            suspicious_activity_details = client.get_suspicious_activity_details_request(suspicious_activity_id)
            details_records = suspicious_activity_details.get('DetailsRecords', [])
            if details_records:
                suspicious_activity_output[0]['DetailsRecords'] = details_records
                readable_output += tableToMarkdown(
                    'Details Records',
                    details_records,
                    removeNull=True
                )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='MicrosoftATA.SuspiciousActivity',
            outputs_key_field='Id',
            outputs=suspicious_activity_output
        )
    else:
        return 'No results found.'


def update_suspicious_activity_status(client: Client, args: Dict[str, str]) -> str:
    suspicious_activity_id = args.get('id', '')
    suspicious_activity_status = args.get('status', '')

    if suspicious_activity_status == 'Delete':
        client.delete_suspicious_activity_request(suspicious_activity_id)
        return f'Suspicious activity {suspicious_activity_id} was deleted successfully.'
    else:
        client.update_suspicious_activity_status_request(suspicious_activity_id, suspicious_activity_status)
        return f'Suspicious activity {suspicious_activity_id} status was updated to ' \
               f'{suspicious_activity_status} successfully.'


def get_monitoring_alert(client: Client, args: Dict[str, str]) -> Union[CommandResults, str]:
    monitoring_alert_status = argToList(args.get('status', ''))
    monitoring_alert_severity = argToList(args.get('severity', ''))
    monitoring_alert_type = argToList(args.get('type', ''))
    monitoring_alert_start_time = parse(args.get('start_time', ''))
    monitoring_alert_end_time = parse(args.get('end_time', ''))
    limit = int(args.get('limit', '50'))

    raw_monitoring_alert = client.get_monitoring_alert_request()
    monitoring_alert_output = []
    if raw_monitoring_alert:
        monitoring_alerts = raw_monitoring_alert if isinstance(raw_monitoring_alert, list) else [raw_monitoring_alert]
        if any([monitoring_alert_status, monitoring_alert_severity, monitoring_alert_type,
                monitoring_alert_start_time, monitoring_alert_end_time]):
            for alert in monitoring_alerts:
                if monitoring_alert_status and alert.get('Status') not in monitoring_alert_status:
                    continue
                if monitoring_alert_severity and alert.get('Severity') not in monitoring_alert_severity:
                    continue
                if monitoring_alert_type and alert.get('Type') not in monitoring_alert_type:
                    continue
                start_time_date = parse(alert.get('StartTime')).replace(tzinfo=utc)  # type: ignore
                if monitoring_alert_start_time and start_time_date < \
                        monitoring_alert_start_time.replace(tzinfo=utc):
                    continue
                endtime_date = parse(alert.get('EndTime'))  # type: ignore
                assert endtime_date is not None
                if monitoring_alert_end_time and endtime_date.replace(tzinfo=utc) > \
                        monitoring_alert_end_time.replace(tzinfo=utc):
                    continue
                monitoring_alert_output.append(alert)
        else:
            monitoring_alert_output = monitoring_alerts
    monitoring_alert_output = monitoring_alert_output[:limit]
    if monitoring_alert_output:
        readable_output = tableToMarkdown(
            'Microsoft Advanced Threat Analytics Monitoring Alert',
            monitoring_alert_output,
            headers=['Id', 'Type', 'Status', 'Severity', 'StartTime', 'EndTime'],
            removeNull=True
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='MicrosoftATA.MonitoringAlert',
            outputs_key_field='Id',
            outputs=monitoring_alert_output
        )
    else:
        return 'No results found.'


def get_entity(client: Client, args: Dict[str, str]) -> Union[CommandResults, str]:
    entity_id = args.get('id', '')

    entity = client.get_entity_request(entity_id)

    if entity:
        readable_output = tableToMarkdown(
            f'Microsoft Advanced Threat Analytics Entity {entity_id}',
            entity,
            headers=['Id', 'SystemDisplayName', 'DistinguishedName', 'UpnName', 'Type', 'CreationTime'],
            removeNull=True
        )

        entity_profile = client.get_entity_profile_request(entity_id)
        if entity_profile:
            entity['Profile'] = entity_profile
            readable_output += tableToMarkdown(
                'Entity Profile',
                entity_profile,
                headers=['Type', 'SuspiciousActivitySeverityToCountMapping', 'UpdateTime', 'IsBehaviorChanged'],
                removeNull=True
            )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='MicrosoftATA.Entity',
            outputs_key_field='Id',
            outputs=entity
        )
    else:
        return 'No results found.'


def fetch_incidents(
        client: Client,
        last_run: Dict[str, str],
        first_fetch_time: str,
        max_results: int,
        activity_status_to_fetch: List,
        min_severity: int,
        activity_type_to_fetch: List
) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    last_fetch = last_run.get('last_fetch', '') if last_run.get('last_fetch') else first_fetch_time
    last_fetch_dt = parse(last_fetch).replace(tzinfo=utc)  # type: ignore
    latest_start_time = parse(last_fetch).replace(tzinfo=utc)  # type: ignore

    incidents_fetched = 0
    incidents: List[Dict[str, Any]] = []

    suspicious_activities = client.get_suspicious_activity_request()
    suspicious_activities_list = suspicious_activities if isinstance(suspicious_activities, list) \
        else [suspicious_activities]
    demisto.debug(suspicious_activities_list)
    for activity in suspicious_activities_list:
        if incidents_fetched == max_results:
            break
        activity_id = activity.get('Id', '')
        activity_status = activity.get('Status', '')
        activity_type = activity.get('Type', '')
        activity_severity = activity.get('Severity', '')
        if activity_status_to_fetch and activity_status not in activity_status_to_fetch:
            demisto.debug(f'Skipping suspicious activity {activity_id} with status {activity_status}')
            continue
        if activity_type_to_fetch and activity_type not in activity_type_to_fetch:
            demisto.debug(f'Skipping suspicious activity {activity_id} with type {activity_type}')
            continue
        if SEVERITY_TRANSLATION[activity_severity] < min_severity:
            demisto.debug(f'Skipping suspicious activity {activity_id} with severity {activity_severity}')
            continue
        activity_start_time = activity.get('StartTime', '')
        activity_start_time_date = parse(activity_start_time)
        assert activity_start_time_date is not None, f'could not parse {activity_start_time}'
        activity_start_time_dt = activity_start_time_date.replace(tzinfo=utc)
        if activity_start_time_dt > latest_start_time:
            incidents.append({
                'name': f'{activity_type} - {activity_id}',
                'occurred': activity_start_time,
                'rawJSON': json.dumps(activity)
            })
            if activity_start_time_dt > last_fetch_dt:
                last_fetch_dt = activity_start_time_dt
                last_fetch = activity_start_time
            incidents_fetched += 1
    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


def main() -> None:
    params = demisto.params()
    base_url = urljoin(params['url'], '/api/management')
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            auth=HttpNtlmAuth(username, password),
            verify=verify_certificate,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=params.get('first_fetch', '3 days'),
                max_results=int(params.get('max_fetch', '50')),
                activity_status_to_fetch=params.get('activity_status', ['Open']),
                min_severity=SEVERITY_TRANSLATION[params.get('min_severity', 'Low')],
                activity_type_to_fetch=argToList(params.get('activity_type', ''))
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'ms-ata-suspicious-activities-list':
            return_results(get_suspicious_activity(client, demisto.args()))
        elif demisto.command() == 'ms-ata-suspicious-activity-status-set':
            return_results(update_suspicious_activity_status(client, demisto.args()))
        elif demisto.command() == 'ms-ata-monitoring-alerts-list':
            return_results(get_monitoring_alert(client, demisto.args()))
        elif demisto.command() == 'ms-ata-entity-get':
            return_results(get_entity(client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

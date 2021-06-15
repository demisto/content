from typing import Tuple

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = 'FireEye Central Management'
INTEGRATION_COMMAND_NAME = 'fireeye-cm'
INTEGRATION_CONTEXT_NAME = 'FireEyeCM'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
FE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy)
        self._headers = {
            'X-FeApi-Token': self._generate_token(),
            'Accept': 'application/json',
        }

    @logger
    def _generate_token(self) -> str:
        resp = self._http_request(method='POST', url_suffix='auth/login', resp_type='response')
        if resp.status_code != 200:
            raise DemistoException(f'Token request failed with status code {resp.status_code}. message: {str(resp)}')
        return resp.headers['X-FeApi-Token']

    @logger
    def get_alerts_request(self, request_params: Dict[str, Any]) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix='alerts', params=request_params, resp_type='json')

    @logger
    def get_alert_details_request(self, alert_id: str) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix=f'alerts/alert/{alert_id}', resp_type='json')

    @logger
    def alert_acknowledge_request(self, uuid: str) -> Dict[str, str]:
        # data here is redundant, but without it we are getting an error.
        # "Bad Request" with Invalid input. code:ALRTCONF001
        return self._http_request(method='POST', url_suffix=f'alerts/alert/{uuid}',
                                  params={'schema_compatibility': True}, json_data={"annotation": "<test>"},
                                  resp_type='resp')

    @logger
    def get_artifacts_by_uuid_request(self, uuid: str, timeout: int) -> Dict[str, str]:
        self._headers.pop('Accept')  # returns a file, hence this header is disruptive
        return self._http_request(method='GET', url_suffix=f'artifacts/{uuid}', resp_type='content', timeout=timeout)

    @logger
    def get_artifacts_metadata_by_uuid_request(self, uuid: str) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix=f'artifacts/{uuid}/meta', resp_type='json')

    @logger
    def get_events_request(self, duration: str, end_time: str, mvx_correlated_only: bool) -> Dict[str, str]:
        return self._http_request(method='GET',
                                  url_suffix='events',
                                  params={
                                      'event_type': 'Ips Event',
                                      'duration': duration,
                                      'end_time': end_time,
                                      'mvx_correlated_only': mvx_correlated_only
                                  },
                                  resp_type='json')

    @logger
    def get_quarantined_emails_request(self, start_time: str, end_time: str, from_: str, subject: str,
                                       appliance_id: str, limit: int) -> Dict[str, str]:
        params = {
            'start_time': start_time,
            'end_time': end_time,
            'limit': limit
        }
        if from_:
            params['from'] = from_
        if subject:
            params['subject'] = subject
        if appliance_id:
            params['appliance_id'] = appliance_id

        return self._http_request(method='GET', url_suffix='emailmgmt/quarantine', params=params, resp_type='json')

    @logger
    def release_quarantined_emails_request(self, sensor_name: str, queue_ids: list):
        return self._http_request(method='POST',
                                  url_suffix='emailmgmt/quarantine/release',
                                  params={'sensorName': sensor_name},
                                  json_data={"queue_ids": queue_ids},
                                  resp_type='resp')

    @logger
    def delete_quarantined_emails_request(self, sensor_name: str, queue_ids: list):
        return self._http_request(method='POST',
                                  url_suffix='emailmgmt/quarantine/delete',
                                  params={'sensorName': sensor_name},
                                  json_data={"queue_ids": queue_ids},
                                  resp_type='resp')

    @logger
    def download_quarantined_emails_request(self, sensor_name: str, queue_id: str, timeout: str):
        self._headers.pop('Accept')  # returns a file, hence this header is disruptive
        return self._http_request(method='GET',
                                  url_suffix=f'emailmgmt/quarantine/{queue_id}',
                                  params={'sensorName': sensor_name},
                                  resp_type='content',
                                  timeout=timeout)

    @logger
    def get_reports_request(self, report_type: str, start_time: str, end_time: str, limit: str, interface: str,
                            alert_id: str, infection_type: str, infection_id: str, timeout: int):
        params = {
            'report_type': report_type,
            'start_time': start_time,
            'end_time': end_time
        }
        if limit:
            params['limit'] = limit
        if interface:
            params['interface'] = interface
        if alert_id:
            params['id'] = alert_id
        if infection_type:
            params['infection_type'] = infection_type
        if infection_id:
            params['infection_id'] = infection_id

        return self._http_request(method='GET',
                                  url_suffix='reports/report',
                                  params=params,
                                  resp_type='content',
                                  timeout=timeout)


@logger
def to_fe_datetime_converter(time_given: str = 'now') -> str:
    """Generates a string in the FireEye format, e.g: 2015-01-24T16:30:00.000-07:00

    Examples:
        >>> to_fe_datetime_converter('2021-05-14T01:08:04.000-02:00')
        2021-05-14T01:08:04.000-02:00
        >>> to_fe_datetime_converter('now')
        2021-05-23T06:45:16.688+00:00

    Args:
        time_given: the time given, if none given, the default is now.

    Returns:
        The time given in FireEye format.
    """
    date_obj = dateparser.parse(time_given)
    fe_time = date_obj.strftime(FE_DATE_FORMAT)
    fe_time += f'.{date_obj.strftime("%f")[:3]}'
    if not date_obj.tzinfo:
        given_timezone = '+00:00'
    else:
        given_timezone = f'{date_obj.strftime("%z")[:3]}:{date_obj.strftime("%z")[3:]}'  # converting the timezone
    fe_time += given_timezone
    return fe_time


@logger
def test_module(client: Client) -> str:
    # check get alerts for fetch purposes
    return 'ok'


@logger
def get_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    def parse_request_params(args: Dict[str, Any]) -> Dict:
        alert_id = args.get('alert_id', '')
        start_time = args.get('start_time', '')
        if start_time:
            start_time = to_fe_datetime_converter(start_time)
        end_time = args.get('end_time')
        if end_time:
            end_time = to_fe_datetime_converter(end_time)
        duration = args.get('duration')
        callback_domain = args.get('callback_domain', '')
        dst_ip = args.get('dst_ip', '')
        src_ip = args.get('src_ip', '')
        file_name = args.get('file_name', '')
        file_type = args.get('file_type', '')
        malware_name = args.get('malware_name', '')
        malware_type = args.get('malware_type', '')
        recipient_email = args.get('recipient_email', '')
        sender_email = args.get('sender_email', '')
        url_ = args.get('url', '')

        request_params = {
            'info_level': args.get('info_level', 'concise')
        }
        if start_time:
            request_params['start_time'] = start_time
        if end_time:
            request_params['end_time'] = end_time
        if duration:
            request_params['duration'] = duration
        if alert_id:
            request_params['alert_id'] = alert_id
        if callback_domain:
            request_params['callback_domain'] = callback_domain
        if dst_ip:
            request_params['dst_ip'] = dst_ip
        if src_ip:
            request_params['src_ip'] = src_ip
        if file_name:
            request_params['file_name'] = file_name
        if file_type:
            request_params['file_type'] = file_type
        if malware_name:
            request_params['malware_name'] = malware_name
        if malware_type:
            request_params['malware_type'] = malware_type
        if recipient_email:
            request_params['recipient_email'] = recipient_email
        if sender_email:
            request_params['sender_email'] = sender_email
        if url_:
            request_params['url'] = url_
        return request_params

    request_params = parse_request_params(args)
    limit = int(args.get('limit', '20'))

    raw_response = client.get_alerts_request(request_params)

    alerts = raw_response.get('alert')
    if not alerts:
        md_ = f'No alerts with the given arguments were found.\n Arguments {str(request_params)}'
    else:
        alerts = alerts[:limit]
        headers = ['id', 'occurred', 'product', 'name', 'malicious', 'severity', 'alertUrl']
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Alerts:', t=alerts, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Alerts',
        outputs_key_field='uuid',
        outputs=alerts,
        raw_response=raw_response
    )


@logger
def get_alert_details(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    alert_ids = argToList(args.get('alert_id'))
    command_results: List[CommandResults] = []

    headers = ['id', 'occurred', 'product', 'name', 'malicious', 'action', 'src', 'dst', 'severity', 'alertUrl']

    for alert_id in alert_ids:
        raw_response = client.get_alert_details_request(alert_id)

        alert_details = raw_response.get('alert')
        if not alert_details:
            md_ = f'Alert {alert_id} was not found.'
        else:
            md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Alerts:', t=alert_details, headers=headers, removeNull=True)

        command_results.append(CommandResults(
            readable_output=md_,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Alerts',
            outputs_key_field='uuid',
            outputs=alert_details,
            raw_response=raw_response
        ))

    return command_results


@logger
def alert_acknowledge(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids = argToList(args.get('uuid'))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        try:
            client.alert_acknowledge_request(uuid)
            md_ = f'Alert {uuid} was acknowledged successfully.'
        except Exception as err:
            if 'Error in API call [404]' in str(err):
                md_ = f'Alert {uuid} was not found or cannot update. It may have been acknowledged in the past.'
            else:
                raise

        command_results.append(CommandResults(
            readable_output=md_
        ))

    return command_results


@logger
def get_artifacts_by_uuid(client: Client, args: Dict[str, Any]):
    uuids = argToList(args.get('uuid'))
    timeout = int(args.get('timeout', '120'))

    for uuid in uuids:
        artifact = client.get_artifacts_by_uuid_request(uuid, timeout)
        demisto.results(fileResult(f'artifacts_{uuid}.zip', data=artifact, file_type=EntryType.ENTRY_INFO_FILE))


@logger
def get_artifacts_metadata_by_uuid(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids: List[str] = argToList(str(args.get('uuid')))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        raw_response = client.get_artifacts_metadata_by_uuid_request(uuid)

        outputs = raw_response
        outputs['uuid'] = uuid  # type: ignore
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} {uuid} Artifact metadata:',
                              t=raw_response.get('artifactsInfoList'), removeNull=True)

        command_results.append(CommandResults(
            readable_output=md_,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Alerts',
            outputs_key_field='uuid',
            outputs=outputs,
            raw_response=raw_response
        ))

    return command_results


@logger
def get_events(client: Client, args: Dict[str, Any]) -> CommandResults:
    duration = args.get('duration', '12_hours')
    end_time = to_fe_datetime_converter(args.get('end_time', 'now'))
    mvx_correlated_only = argToBoolean(args.get('mvx_correlated_only', 'false'))
    limit = int(args.get('limit', '20'))

    raw_response = client.get_events_request(duration, end_time, mvx_correlated_only)

    events = raw_response.get('events')
    if not events:
        md_ = 'No events in the given timeframe were found.'
    else:
        events = events[:limit]
        headers = ['occurred', 'ruleName', 'severity', 'malicious', 'cveId', 'eventId', 'srcIp', 'dstIp']
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Events:', t=events, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Events',
        outputs_key_field='eventId',
        outputs=events,
        raw_response=raw_response
    )


@logger
def get_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    start_time = to_fe_datetime_converter(args.get('start_time', '1 day'))
    end_time = to_fe_datetime_converter(args.get('end_time', 'now'))
    from_ = args.get('from', '')
    subject = args.get('subject', '')
    appliance_id = args.get('appliance_id', '')
    limit = (args.get('limit', '10000'))

    raw_response = client.get_quarantined_emails_request(start_time, end_time, from_, subject, appliance_id, limit)
    if not raw_response:
        md_ = 'No emails with the given query arguments were found.'
    else:
        headers = ['email_uuid', 'from', 'subject', 'message_id', 'completed_at']
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Quarantined emails:', t=raw_response,
                              headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.QuarantinedEmail',
        outputs_key_field='email_uuid',
        outputs=raw_response,
        raw_response=raw_response
    )


@logger
def release_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    sensor_name = args.get('sensor_name', '')
    queue_ids = argToList(args.get('queue_ids', ''))

    raw_response = client.release_quarantined_emails_request(sensor_name, queue_ids)

    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f'{INTEGRATION_NAME} released emails successfully.'
    return CommandResults(
        readable_output=md_,
        raw_response=raw_response
    )


@logger
def delete_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    sensor_name = args.get('sensor_name', '')
    queue_ids = argToList(args.get('queue_ids', ''))

    raw_response = client.delete_quarantined_emails_request(sensor_name, queue_ids)
    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f'{INTEGRATION_NAME} deleted emails successfully.'

    return CommandResults(
        readable_output=md_,
        raw_response=raw_response
    )


@logger
def download_quarantined_emails(client: Client, args: Dict[str, Any]):
    sensor_name = args.get('sensor_name', '')
    queue_id = args.get('queue_id', '')
    timeout = int(args.get('timeout', '120'))

    raw_response = client.download_quarantined_emails_request(sensor_name, queue_id, timeout)

    demisto.results(fileResult(f'quarantined_email_{queue_id}.eml', data=raw_response, file_type=EntryType.FILE))


@logger
def get_reports(client: Client, args: Dict[str, Any]):
    report_type = args.get('report_type', '')
    start_time = to_fe_datetime_converter(args.get('start_time', '1 week'))
    end_time = to_fe_datetime_converter(args.get('end_time', 'now'))
    limit = args.get('limit', '100')
    interface = args.get('interface', '')
    alert_id = args.get('alert_id', '')
    infection_id = args.get('infection_id', '')
    infection_type = args.get('infection_type', '')
    timeout = int(args.get('timeout', '120'))

    if report_type == 'alertDetailsReport':  # validate arguments
        # can use either alert_id, or infection_type and infection_id
        err_str = 'The alertDetailsReport can be retrieved using alert_id argument alone, ' \
                  'or by infection_type and infection_id'
        if alert_id:
            if infection_id or infection_type:
                raise DemistoException(err_str)
        else:
            if not infection_id and not infection_type:
                raise DemistoException(err_str)

    try:
        raw_response = client.get_reports_request(report_type, start_time, end_time, limit, interface, alert_id,
                                                  infection_type, infection_id, timeout)
        csv_reports = {'empsEmailAVReport', 'empsEmailHourlyStat', 'mpsCallBackServer', 'mpsInfectedHostsTrend',
                       'mpsWebAVReport'}
        prefix = 'csv' if report_type in csv_reports else 'pdf'
        demisto.results(fileResult(f'report_{report_type}_{datetime.now().timestamp()}.{prefix}', data=raw_response,
                                   file_type=EntryType.ENTRY_INFO_FILE))
    except Exception as err:
        if 'WSAPI_REPORT_ALERT_NOT_FOUND' in str(err):
            return CommandResults(readable_output=f'Report {report_type} was not found with the given arguments.')
        else:
            raise


@logger
def fetch_incidents(client: Client, last_run: dict, first_fetch: str, max_fetch: int = 50,
                    info_level: str = 'concise') -> Tuple[dict, list]:
    if not last_run:  # if first time fetching
        next_run = {
            'time': to_fe_datetime_converter(first_fetch),
            'last_alert_ids': []
        }
    else:
        next_run = last_run
    demisto.info(f'{INTEGRATION_NAME} executing fetch with: {str(next_run.get("time"))}')

    raw_response = client.get_alerts_request(request_params={
        'start_time': to_fe_datetime_converter(first_fetch),
        'info_level': info_level
    })
    all_alerts = raw_response.get('alert')

    if not all_alerts:
        demisto.info(f'{INTEGRATION_NAME} no alerts were fetched at: {str(last_run)}')
        # as no alerts occurred till now, update last_run time accordingly
        last_run['time'] = to_fe_datetime_converter('now')
        return last_run, []

    alerts = all_alerts[:max_fetch]
    last_alert_ids = last_run.get('last_alert_ids', [])
    if last_alert_ids:
        last_alert_ids = json.loads(last_alert_ids)  # unescape the dumped json
    incidents = []

    for alert in alerts:
        alert_id = str(alert.get('id'))
        if alert_id not in last_alert_ids:  # check that event was not fetched in the last fetch
            incident = {
                'name': f'{INTEGRATION_NAME} Alert: {alert_id}',
                'occurred': dateparser.parse(alert.get('occurred')).strftime(DATE_FORMAT),
                'severity': alert_severity_to_dbot_score(alert.get('severity')),
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)
            last_alert_ids.append(alert_id)

    if not incidents:
        demisto.info(f'{INTEGRATION_NAME} no new alerts were fetched at: {str(next_run)}')
        # as no alerts occurred till now, update last_run time accordingly
        next_run['time'] = to_fe_datetime_converter('now')
        return next_run, []

    # as alerts occurred till now, update last_run time accordingly to the that of latest fetched alert
    next_run = {
        'time': alerts[-1].get('occurred'),
        'last_alert_ids': json.dumps(last_alert_ids)  # save the alert IDs from the last fetch
    }
    demisto.info(f'{INTEGRATION_NAME} Fetched {len(incidents)}. last fetch at: {str(next_run)}')
    return next_run, incidents


def alert_severity_to_dbot_score(severity_str: str):
    severity = severity_str.lower()
    if severity == 'minr':
        return 1
    if severity == 'majr':
        return 2
    if severity == 'crit':
        return 3
    demisto.info(f'{INTEGRATION_NAME} incident severity: {severity} is not known. '
                 f'Setting as unknown(DBotScore of 0).')
    return 0


def main() -> None:
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    # there is also a v1.2.0 which holds different paths and params, we support only the newest API version
    base_url = urljoin(params.get('url'), '/wsapis/v2.0.0/')
    verify = not argToBoolean(params.get('insecure', 'false'))
    proxy = argToBoolean(params.get('proxy'))

    # # fetch params
    max_fetch = int(params.get('max_fetch', '50'))
    first_fetch = params.get('first_fetch', '3 days').strip()
    info_level = params.get('info_level', 'concise')

    command = demisto.command()
    args = demisto.args()
    LOG(f'Command being called is {command}')
    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify, proxy=proxy)
        commands = {
            f'{INTEGRATION_COMMAND_NAME}-get-alerts': get_alerts,
            f'{INTEGRATION_COMMAND_NAME}-get-alert-details': get_alert_details,
            f'{INTEGRATION_COMMAND_NAME}-alert-acknowledge': alert_acknowledge,
            f'{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid': get_artifacts_by_uuid,
            f'{INTEGRATION_COMMAND_NAME}-get-artifacts-metadata-by-uuid': get_artifacts_metadata_by_uuid,
            f'{INTEGRATION_COMMAND_NAME}-get-events': get_events,
            f'{INTEGRATION_COMMAND_NAME}-get-quarantined-emails': get_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-release-quarantined-emails': release_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-delete-quarantined-emails': delete_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-download-quarantined-emails': download_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-get-reports': get_reports,
        }
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                info_level=info_level
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid':
            get_artifacts_by_uuid(client, args)
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-reports':
            get_reports(client, args)
        elif command == f'{INTEGRATION_COMMAND_NAME}-download-quarantined-emails':
            download_quarantined_emails(client, args)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

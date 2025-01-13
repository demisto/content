from typing import Tuple

from CommonServerPython import *
# Disable insecure warnings
import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = 'FireEye Email Security'
INTEGRATION_COMMAND_NAME = 'fireeye-ex'
INTEGRATION_CONTEXT_NAME = 'FireEyeEX'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client:
    """
    The integration's client
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        self.fe_client: FireEyeClient = FireEyeClient(base_url=base_url, username=username, password=password,
                                                      verify=verify, proxy=proxy)


@logger
def run_test_module(client: Client) -> str:
    """
    Test module by getting alerts from the last day.
    """
    start_time = to_fe_datetime_converter('1 day')
    client.fe_client.get_alerts_request({
        'info_level': 'concise',
        'start_time': start_time,
        'duration': '24_hours',
    })
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

    raw_response = client.fe_client.get_alerts_request(request_params)

    alerts = raw_response.get('alert')
    if not alerts:
        md_ = f'No alerts with the given arguments were found.\n Arguments {str(request_params)}'
    else:
        alerts = alerts[:limit]
        headers = ['id', 'occurred', 'name', 'action', 'smtpMessage', 'src', 'dst', 'alertUrl']
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
    timeout = int(args.get('timeout', '30'))

    command_results: List[CommandResults] = []

    headers = ['id', 'occurred', 'name', 'action', 'smtpMessage', 'src', 'dst', 'alertUrl']

    for alert_id in alert_ids:
        raw_response = client.fe_client.get_alert_details_request(alert_id, timeout)

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
def get_artifacts_by_uuid(client: Client, args: Dict[str, Any]):
    uuids = argToList(args.get('uuid'))
    timeout = int(args.get('timeout', '120'))

    for uuid in uuids:
        artifact = client.fe_client.get_artifacts_by_uuid_request(uuid, timeout)
        demisto.results(fileResult(f'artifacts_{uuid}.zip', data=artifact, file_type=EntryType.ENTRY_INFO_FILE))


@logger
def get_artifacts_metadata_by_uuid(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids: List[str] = argToList(str(args.get('uuid')))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        raw_response = client.fe_client.get_artifacts_metadata_by_uuid_request(uuid)

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
def get_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    start_time = to_fe_datetime_converter(args.get('start_time', '1 day'))
    end_time = to_fe_datetime_converter(args.get('end_time', 'now'))
    from_ = args.get('from', '')
    subject = args.get('subject', '')
    appliance_id = args.get('appliance_id', '')
    limit = (args.get('limit', '10000'))

    raw_response = client.fe_client.get_quarantined_emails_request(start_time, end_time, from_, subject, appliance_id,
                                                                   limit)
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
    queue_ids = argToList(args.get('queue_ids', ''))

    raw_response = client.fe_client.release_quarantined_emails_request(queue_ids, '')

    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f'{INTEGRATION_NAME} released emails successfully.'
    return CommandResults(
        readable_output=md_,
        raw_response=""
    )


@logger
def delete_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    queue_ids = argToList(args.get('queue_ids', ''))

    raw_response = client.fe_client.delete_quarantined_emails_request(queue_ids)
    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f'{INTEGRATION_NAME} deleted emails successfully.'

    return CommandResults(
        readable_output=md_,
        raw_response=""
    )


@logger
def download_quarantined_emails(client: Client, args: Dict[str, Any]):
    queue_id = args.get('queue_id', '')
    timeout = int(args.get('timeout', '120'))

    raw_response = client.fe_client.download_quarantined_emails_request(queue_id, timeout)

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
        raw_response = client.fe_client.get_reports_request(report_type, start_time, end_time, limit, interface,
                                                            alert_id, infection_type, infection_id, timeout)
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
def list_allowedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    limit = int(args.get('limit', '20'))

    raw_response = client.fe_client.list_allowedlist_request(type_)
    allowed_list = []
    if not raw_response:
        md_ = f'No allowed lists with the given type {type_} were found.'
    else:
        allowed_list = raw_response[:limit]
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Allowed lists. showing {limit} of {len(raw_response)}:',
                              t=allowed_list, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Allowedlists',
        outputs_key_field='name',
        outputs=allowed_list,
        raw_response=raw_response
    )


@logger
def create_allowedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')
    matches = int(args.get('matches', '0'))

    # check that the entry_value does not exist
    current_allowed_list = client.fe_client.list_allowedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            raise DemistoException(str(f'Cannot create the entry_value {entry_value} as it is already exist in the '
                                       f'Allowedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.create_allowedlist_request(type_, entry_value, matches)

    return CommandResults(
        readable_output=f'Allowedlist entry {entry_value} of type {type_} was created.'
    )


@logger
def update_allowedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')
    matches = int(args.get('matches', '0'))

    # check that the entry_value does exist
    exist = False
    current_allowed_list = client.fe_client.list_allowedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise DemistoException(str(f'Cannot update the entry_value {entry_value} as it does not exist in the '
                                   f'Allowedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.update_allowedlist_request(type_, entry_value, matches)

    return CommandResults(
        readable_output=f'Allowedlist entry {entry_value} of type {type_} was updated.'
    )


@logger
def delete_allowedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')

    # check that the entry_value does exist
    exist = False
    current_allowed_list = client.fe_client.list_allowedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise DemistoException(str(f'Cannot delete the entry_value {entry_value} as it does not exist in the '
                                   f'Allowedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.delete_allowedlist_request(type_, entry_value)

    return CommandResults(
        readable_output=f'Allowedlist entry {entry_value} of type {type_} was deleted.'
    )


@logger
def list_blockedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    limit = int(args.get('limit', '20'))

    raw_response = client.fe_client.list_blockedlist_request(type_)
    blocked_list = []
    if not raw_response:
        md_ = f'No blocked lists with the given type {type_} were found.'
    else:
        blocked_list = raw_response[:limit]
        md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Blocked lists. showing {limit} of {len(raw_response)}:',
                              t=blocked_list, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Blockedlists',
        outputs_key_field='name',
        outputs=blocked_list,
        raw_response=raw_response
    )


@logger
def create_blockedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')
    matches = int(args.get('matches', '0'))

    # check that the entry_value does not exist
    current_blocked_list = client.fe_client.list_blockedlist_request(type_)
    for entry in current_blocked_list:
        if entry_value == entry.get('name'):
            raise DemistoException(str(f'Cannot create the entry_value {entry_value} as it is already exist in the '
                                       f'Blockedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.create_blockedlist_request(type_, entry_value, matches)

    return CommandResults(
        readable_output=f'Blockedlist entry {entry_value} of type {type_} was created.'
    )


@logger
def update_blockedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')
    matches = int(args.get('matches', '0'))

    # check that the entry_value does exist
    exist = False
    current_allowed_list = client.fe_client.list_blockedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise DemistoException(str(f'Cannot update the entry_value {entry_value} as it does not exist in the '
                                   f'Blockedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.update_blockedlist_request(type_, entry_value, matches)

    return CommandResults(
        readable_output=f'Blockedlist entry {entry_value} of type {type_} was updated.'
    )


@logger
def delete_blockedlist(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type', '')
    entry_value = args.get('entry_value', '')

    # check that the entry_value does exist
    exist = False
    current_allowed_list = client.fe_client.list_blockedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise DemistoException(str(f'Cannot delete the entry_value {entry_value} as it does not exist in the '
                                   f'Blockedlist of type {type_}.'))

    # gets 200 back without content if successful
    client.fe_client.delete_blockedlist_request(type_, entry_value)

    return CommandResults(
        readable_output=f'Blockedlist entry {entry_value} of type {type_} was deleted.'
    )


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
    raw_response = client.fe_client.get_alerts_request(request_params={
        'start_time': to_fe_datetime_converter(next_run['time']),  # type: ignore
        'info_level': info_level,
        'duration': '48_hours'
    })
    all_alerts = raw_response.get('alert')

    ten_minutes_date = dateparser.parse('10 minutes')
    assert ten_minutes_date is not None
    if not all_alerts:
        demisto.info(f'{INTEGRATION_NAME} no alerts were fetched from FireEye server at: {str(next_run)}')
        # as no alerts occurred in the window of 48 hours from the given start time, update last_run window to the next
        # 48 hours. If it is later than now -10 minutes take the latter (to avoid missing events).
        two_days_from_last_search = (dateparser.parse(next_run['time']) + timedelta(hours=48))  # type: ignore
        assert two_days_from_last_search is not None
        now_minus_ten_minutes = ten_minutes_date.astimezone(two_days_from_last_search.tzinfo)  # type: ignore
        next_search = min(two_days_from_last_search, now_minus_ten_minutes)
        assert next_search is not None
        next_run = {
            'time': next_search.isoformat(),  # type: ignore
            'last_alert_ids': []
        }
        demisto.info(f'{INTEGRATION_NAME} setting next run to: {str(next_run)}')
        return next_run, []

    alerts = all_alerts[:max_fetch]
    last_alert_ids = last_run.get('last_alert_ids', [])
    incidents = []

    for alert in alerts:
        alert_id = str(alert.get('id'))
        if alert_id not in last_alert_ids:  # check that event was not fetched in the last fetch
            incident = {
                'name': f'{INTEGRATION_NAME} Alert: {alert_id}',
                'occurred': dateparser.parse(alert.get('occurred'),
                                             settings={'TO_TIMEZONE': 'UTC'}).strftime(DATE_FORMAT),  # type: ignore
                'severity': alert_severity_to_dbot_score(alert.get('severity')),
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)
            last_alert_ids.append(alert_id)

    if not incidents:
        demisto.info(f'{INTEGRATION_NAME} no new alerts were collected at: {str(next_run)}.')
        # As no incidents were collected, we know that all the fetched alerts for 48 hours starting in the 'start_time'
        # already exists in our system, thus update last_run time to look for the next 48 hours. If it is later than
        # now -10 minutes take the latter (to avoid missing events)
        two_days_from_last_incident = dateparser.parse(alerts[-1].get('occurred')) + timedelta(hours=48)  # type: ignore
        now_minus_ten_minutes = ten_minutes_date.astimezone(two_days_from_last_incident.tzinfo)  # type: ignore
        next_search = min(two_days_from_last_incident, now_minus_ten_minutes)
        next_run['time'] = next_search.isoformat()  # type: ignore
        demisto.info(f'{INTEGRATION_NAME} Setting next_run to: {next_run["time"]}')
        return next_run, []

    # as alerts occurred till now, update last_run time accordingly to the that of latest fetched alert
    next_run = {
        'time': alerts[-1].get('occurred'),
        'last_alert_ids': last_alert_ids  # save the alert IDs from the last fetch
    }
    demisto.info(f'{INTEGRATION_NAME} Fetched {len(incidents)}. last fetch at: {str(next_run)}')
    return next_run, incidents


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
            f'{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid': get_artifacts_by_uuid,
            f'{INTEGRATION_COMMAND_NAME}-get-artifacts-metadata-by-uuid': get_artifacts_metadata_by_uuid,
            f'{INTEGRATION_COMMAND_NAME}-get-quarantined-emails': get_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-release-quarantined-emails': release_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-delete-quarantined-emails': delete_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-download-quarantined-emails': download_quarantined_emails,
            f'{INTEGRATION_COMMAND_NAME}-list-allowedlist': list_allowedlist,
            f'{INTEGRATION_COMMAND_NAME}-create-allowedlist': create_allowedlist,
            f'{INTEGRATION_COMMAND_NAME}-update-allowedlist': update_allowedlist,
            f'{INTEGRATION_COMMAND_NAME}-delete-allowedlist': delete_allowedlist,
            f'{INTEGRATION_COMMAND_NAME}-list-blockedlist': list_blockedlist,
            f'{INTEGRATION_COMMAND_NAME}-create-blockedlist': create_blockedlist,
            f'{INTEGRATION_COMMAND_NAME}-update-blockedlist': update_blockedlist,
            f'{INTEGRATION_COMMAND_NAME}-delete-blockedlist': delete_blockedlist,
        }
        if command == 'test-module':
            return_results(run_test_module(client))
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
        return_error(str(err), err)


from FireEyeApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

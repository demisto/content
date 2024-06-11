import hashlib
import uuid
from urllib.parse import urlencode

import urllib3

from CommonServerPython import *

urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
FETCH_INTERVAL_DEFAULT = 1
MAX_FETCH_DEFAULT = 10
SAAS_NAMES = [
    'office365_emails',
    'google_mail'
]
SAAS_APPS_TO_SAAS_NAMES = {
    'Microsoft Exchange': 'office365_emails',
    'Gmail': 'google_mail'
}
SEVERITY_VALUES = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'very low': 1
}
CP_DETECTION_VALUES = {
    'Phishing': 'cp_phishing',
    'Suspected Phishing': 'cp_ap_suspicious',
    'Malware': 'cp_malicious',
    'Suspected Malware': 'cp_av_suspicious',
    'Spam': 'cp_spam',
    'Clean': 'cp_clean',
    'DLP': 'cp_leak',
    'Malicious URL Click': 'cp_malicious_url_click',
    'Malicious URL': 'cp_malicious_url'
}
MS_DETECTION_VALUES = {
    'Malware': 'ms_malware',
    'High Confidence Phishing': 'ms_high_confidence_phishing',
    'Phishing': 'ms_phishing',
    'High Confidence Spam': 'ms_high_confidence_spam',
    'Spam': 'ms_spam',
    'Bulk': 'ms_bulk',
    'Clean': 'ms_clean'
}
CP_QUARANTINED_VALUES = {
    'Quarantined (Any source)': 'all',
    'Not Quarantined': 'cp_not_quarantined',
    'Quarantined by Check Point': 'cp_quarantined_by_cp',
    'Quarantined by CP Analyst': 'cp_quarantined_by_analyst',
    'Quarantined by Admin': 'cp_quarantined_by_admin'
}
MS_QUARANTINED_VALUES = {
    'Quarantined': 'ms_quarantined',
    'Not Quarantined': 'ms_not_quarantined',
    'Not Quarantined Delivered to Inbox': 'ms_delivered_inbox',
    'Not Quarantined Delivered to Junk': 'ms_delivered_junk'
}


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.api_version = 'v1.0'
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = float('-inf')
        self.is_infinity = 'cloudinfra' in base_url

    def _should_refresh_token(self) -> bool:
        return not self.token or time.time() >= self.token_expiry

    def _generate_infinity_token(self):
        if self._should_refresh_token():
            payload = {
                "clientId": self.client_id,
                "accessKey": self.client_secret
            }
            timestamp = time.time()

            res = self._http_request(
                method='POST',
                url_suffix='auth/external',
                json_data=payload
            )
            data = res['data']
            self.token = data.get('token')
            self.token_expiry = timestamp + float(data.get('expiresIn'))

        return self.token

    def _generate_signature(self, request_id: str, timestamp: str, request_string: str = None) -> str:
        if request_string:
            signature_string = f'{request_id}{self.client_id}{timestamp}{request_string}{self.client_secret}'
        else:
            signature_string = f'{request_id}{self.client_id}{timestamp}{self.client_secret}'
        signature_bytes = signature_string.encode('utf-8')
        signature_base64_bytes = base64.b64encode(signature_bytes)
        signature_hash = hashlib.sha256(signature_base64_bytes).hexdigest()
        return signature_hash

    def _get_headers(self, request_string: str = None, auth: bool = False) -> dict[str, str]:
        request_id = str(uuid.uuid4())
        if self.is_infinity:
            token = self._generate_infinity_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'x-av-req-id': request_id,
            }
        else:
            timestamp = datetime.utcnow().isoformat()
            headers = {
                'x-av-req-id': request_id,
                'x-av-app-id': self.client_id,
                'x-av-date': timestamp,
                'x-av-sig': self._generate_signature(request_id, timestamp, request_string),
            }
            if not auth:
                headers['x-av-token'] = self._get_token()
        return headers

    def _get_token(self) -> str:
        if self.token:
            return self.token

        self.token = self._http_request(
            'GET',
            url_suffix=f'{self.api_version}/auth',
            headers=self._get_headers(auth=True),
            resp_type='text',
        )
        return self.token or ''

    def _call_api(self, method: str, url_suffix: str, params: dict = None, json_data: dict = None) -> dict[str, Any]:
        if self.is_infinity:
            path = '/'.join(['app', 'hec-api', self.api_version, url_suffix])
            request_string = None
        else:
            path = '/'.join([self.api_version, url_suffix])
            request_string = f'/{path}'
            if params:
                request_string += f'?{urlencode(params)}'

        return self._http_request(
            method,
            url_suffix=path,
            headers=self._get_headers(request_string),
            params=params,
            json_data=json_data
        )

    def test_api(self) -> dict[str, bool]:
        return self._call_api(
            'GET',
            url_suffix='soar/test'
        )

    def query_events(self, start_date: str, end_date: str = None, saas_apps: List[str] = None, states: List[str] = None,
                     severities: List[int] = None, threat_types: List[str] = None) -> dict[str, Any]:
        request_data: dict[str, Any] = {
            'startDate': start_date,
            'endDate': end_date,
            'saas': saas_apps or SAAS_NAMES,
        }
        if states:
            request_data['eventStates'] = states
        if severities:
            request_data['severities'] = severities
        if threat_types:
            request_data['eventTypes'] = threat_types

        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='event/query',
            json_data=payload
        )

    def get_entity(self, entity: str) -> dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix=f'search/entity/{entity}'
        )

    def get_email(self, entity: str) -> dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix=f'soar/entity/{entity}'
        )

    def search_emails(self, start_date: str, end_date: str = None, saas: str = None, direction: str = None,
                      subject_contains: str = None, subject_match: str = None, sender_contains: str = None,
                      sender_match: str = None, domain: str = None, cp_detection: List[str] = None,
                      ms_detection: List[str] = None, detection_op: str = None, server_ip: str = None,
                      recipients_contains: str = None, recipients_match: str = None, links: str = None, message_id: str = None,
                      cp_quarantined_state: str = None, ms_quarantined_state: str = None, quarantined_state_op: str = None,
                      name_contains: str = None, name_match: str = None, client_ip: str = None, attachment_md5: str = None):
        entity_filter = {
            'saas': saas,
            'startDate': start_date,
        }
        if end_date:
            entity_filter['endDate'] = end_date
        extended_filter = []
        detection_resolution_filter: dict[str, Any] = {}
        if direction:
            extended_filter.append({
                'saasAttrName': f'entityPayload.is{direction}',
                'saasAttrOp': 'is',
                'saasAttrValue': 'true',
            })
        if subject_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.subject',
                'saasAttrOp': 'contains',
                'saasAttrValue': subject_contains
            })
        elif subject_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.subject',
                'saasAttrOp': 'is',
                'saasAttrValue': subject_match
            })
        if sender_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromEmail',
                'saasAttrOp': 'contains',
                'saasAttrValue': sender_contains
            })
        elif sender_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromEmail',
                'saasAttrOp': 'is',
                'saasAttrValue': sender_match
            })
        if domain:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromDomain',
                'saasAttrOp': 'is',
                'saasAttrValue': domain
            })
        if cp_detection:
            detection_resolution_filter['cpDetection'] = cp_detection
        if ms_detection:
            detection_resolution_filter['msDetection'] = ms_detection
        if cp_detection and ms_detection:
            detection_resolution_filter['detectionOp'] = detection_op
        if server_ip:
            extended_filter.append({
                'saasAttrName': 'entityPayload.senderServerIp',
                'saasAttrOp': 'is',
                'saasAttrValue': server_ip
            })
        if recipients_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.recipients',
                'saasAttrOp': 'contains',
                'saasAttrValue': recipients_contains
            })
        elif recipients_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.recipients',
                'saasAttrOp': 'is',
                'saasAttrValue': recipients_match
            })
        if links:
            extended_filter.append({
                'saasAttrName': 'entityPayload.emailLinks',
                'saasAttrOp': 'is',
                'saasAttrValue': links
            })
        if message_id:
            extended_filter.append({
                'saasAttrName': 'entityPayload.internetMessageId',
                'saasAttrOp': 'is',
                'saasAttrValue': message_id
            })
        if cp_quarantined_state:
            detection_resolution_filter['cpQuarantinedState'] = cp_quarantined_state
        if ms_quarantined_state:
            detection_resolution_filter['msQuarantinedState'] = ms_quarantined_state
        if cp_quarantined_state and ms_quarantined_state:
            detection_resolution_filter['quarantinedStateOp'] = quarantined_state_op
        if name_contains:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromName',
                'saasAttrOp': 'contains',
                'saasAttrValue': name_contains
            })
        elif name_match:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromName',
                'saasAttrOp': 'is',
                'saasAttrValue': name_match
            })
        if client_ip:
            extended_filter.append({
                'saasAttrName': 'entityPayload.senderClientIp',
                'saasAttrOp': 'is',
                'saasAttrValue': client_ip
            })
        if attachment_md5:
            extended_filter.append({
                'saasAttrName': 'entityPayload.attachments.MD5',
                'saasAttrOp': 'is',
                'saasAttrValue': attachment_md5
            })
        request_data: dict[str, Any] = {
            'entityFilter': entity_filter,
        }
        if extended_filter:
            request_data['entityExtendedFilter'] = extended_filter
        if detection_resolution_filter:
            request_data['entityDetectionResolutionFilter'] = detection_resolution_filter
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='search/query',
            json_data=payload
        )

    def send_action(self, entities: list, entity_type: str, action: str):
        request_data = {
            'entityIds': entities,
            'entityType': entity_type,
            'entityActionName': action,
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            'action/entity',
            json_data=payload,
        )

    def get_task(self, task: str):
        return self._call_api(
            'GET',
            f'task/{task}',
        )

    def send_notification(self, entity: str, emails: List[str]):
        payload = {
            'requestData': {
                'entityId': entity,
                'emails': emails
            }
        }
        return self._call_api(
            'POST',
            'soar/notify',
            json_data=payload
        )


def test_module(client: Client):
    result = client.test_api()
    return 'ok' if result.get('ok') else 'error'


def fetch_incidents(client: Client, first_fetch: str, saas_apps: List[str], states: List[str], severities: List[int],
                    threat_types: List[str], max_fetch: int, fetch_interval: int):
    now = datetime.utcnow()  # We get current time before processing
    last_run = demisto.getLastRun()
    if not (last_fetch := last_run.get('last_fetch')):
        if last_fetch := dateparser.parse(first_fetch, date_formats=[DATE_FORMAT]):
            last_fetch = last_fetch.isoformat()
        else:
            raise Exception('Could not get last fetch')
    result = client.query_events(
        start_date=last_fetch, states=states, saas_apps=saas_apps, severities=severities, threat_types=threat_types
    )
    events = result['responseData']

    counter = 0
    incidents: list[dict[str, Any]] = []
    for event in events:
        if (occurred := event.get('eventCreated')) <= last_fetch:
            continue

        threat_type = event.get('type')

        count_field = f'count_{threat_type}'
        count = last_run.get(count_field, 0) + 1
        last_run[count_field] = count

        incidents.append({
            'dbotMirrorId': event.get('eventId'),
            'details': event.get('description'),
            'name': f'Threat: {threat_type.replace("_", " ").title()} {count}',
            'occurred': occurred,
            'rawJSON': json.dumps(event),
        })

        if max_fetch == (counter := counter + 1):
            break

    if incidents:
        last_run['last_fetch'] = incidents[-1]['occurred']
    else:
        last_run['last_fetch'] = (now - timedelta(minutes=fetch_interval)).isoformat()

    demisto.setLastRun(last_run)
    demisto.incidents(incidents)


def checkpointhec_get_entity(client: Client, entity: str) -> CommandResults:
    result = client.get_entity(entity)
    if entities := result.get('responseData'):
        entity = entities[0]['entityPayload']
        human_readable = tableToMarkdown('entity', entity, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            outputs_key_field='internetMessageId',
            readable_output=human_readable,
            outputs=entity,
        )
    else:
        return CommandResults(
            readable_output=f'Entity with id {entity} not found'
        )


def checkpointhec_get_events(client: Client, start_date: str, end_date: str = None, saas_apps: List[str] = None,
                             states: List[str] = None, severities: List[int] = None, threat_types: List[str] = None,
                             limit: int = 100) -> CommandResults:
    result = client.query_events(
        start_date=start_date, end_date=end_date, saas_apps=saas_apps, states=states, severities=severities,
        threat_types=threat_types
    )
    if events := result.get('responseData'):
        _events = events[:min(limit, len(events))]
        human_readable = tableToMarkdown('events', _events, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Event',
            outputs_key_field='eventId',
            readable_output=human_readable,
            outputs=_events,
        )
    else:
        return CommandResults(
            readable_output='Events not found with the given criteria'
        )


def checkpointhec_get_scan_info(client: Client, entity: str) -> CommandResults:
    result = client.get_entity(entity)
    outputs = {}
    if entities := result.get('responseData'):
        sec_result = entities[0]['entitySecurityResult']
        for tool, verdict in sec_result['combinedVerdict'].items():
            if verdict not in (None, 'clean'):
                outputs[tool] = json.dumps(sec_result[tool])
        return CommandResults(
            outputs_prefix='CheckPointHEC.ScanResult',
            outputs=outputs
        )
    else:
        return CommandResults(
            readable_output=f'Entity with id {entity} not found'
        )


def checkpointhec_search_emails(client: Client, date_last: str = None, date_from: str = None, date_to: str = None,
                                saas: str = None, direction: str = None, subject_contains: str = None, subject_match: str = None,
                                sender_contains: str = None, sender_match: str = None, domain: str = None,
                                cp_detection: List[str] = None, ms_detection: List[str] = None, detection_op: str = None,
                                server_ip: str = None, recipients_contains: str = None, recipients_match: str = None,
                                links: str = None, message_id: str = None, cp_quarantined_state: str = None,
                                ms_quarantined_state: str = None, quarantined_state_op: str = None, name_contains: str = None,
                                name_match: str = None, client_ip: str = None, attachment_md5: str = None) -> CommandResults:
    end_date = None

    if date_last:
        if date_from or date_to:
            return CommandResults(
                readable_output=f'Argument {date_last=} cannot be used with {date_from=} or {date_to=}'
            )
        else:
            if _start_date := dateparser.parse(date_last, date_formats=[DATE_FORMAT]):
                start_date = _start_date.isoformat()
            else:
                return CommandResults(
                    readable_output=f'Could not establish start date with {date_last=}'
                )
    elif date_from:
        start_date = date_from
        if date_to:
            end_date = date_to
    else:
        return CommandResults(
            readable_output='Argument date_last and date_from cannot be both empty'
        )

    if subject_contains and subject_match:
        return CommandResults(
            readable_output=f'Argument {subject_contains=} and {subject_match=} cannot be both set'
        )

    if sender_contains and sender_match:
        return CommandResults(
            readable_output=f'Argument {sender_contains=} and {sender_match=} cannot be both set'
        )

    if recipients_contains and recipients_match:
        return CommandResults(
            readable_output=f'Argument {recipients_contains=} and {recipients_match=} cannot be both set'
        )

    if name_contains and name_match:
        return CommandResults(
            readable_output=f'Argument {name_contains=} and {name_match=} cannot be both set'
        )

    result = client.search_emails(start_date, end_date, saas, direction, subject_contains, subject_match, sender_contains,
                                  sender_match, domain, cp_detection, ms_detection, detection_op, server_ip, recipients_contains,
                                  recipients_match, links, message_id, cp_quarantined_state, ms_quarantined_state,
                                  quarantined_state_op, name_contains, name_match, client_ip, attachment_md5)
    if entities := result.get('responseData'):
        emails = []
        for entity in entities:
            email = entity['entityPayload']
            email['entityId'] = entity['entityInfo']['entityId']
            emails.append(email)
        human_readable = tableToMarkdown('emails', emails, removeNull=True)
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            readable_output=human_readable,
            outputs=emails
        )
    else:
        return CommandResults(
            readable_output='Emails with the specified parameters were not found'
        )


def checkpointhec_send_action(client: Client, entities: list, entity_type: str, action: str) -> CommandResults:
    result = client.send_action(entities, entity_type, action)
    if resp := result.get('responseData'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.Task',
            outputs={'task': resp[0]['taskId']}
        )
    else:
        return CommandResults(
            readable_output='Task not queued successfully'
        )


def checkpointhec_get_action_result(client: Client, task: str) -> CommandResults:
    result = client.get_task(task)
    if resp := result.get('responseData'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.ActionResult',
            outputs=resp
        )
    else:
        return CommandResults(
            readable_output=f'Cannot get results about task with id {task}'
        )


def checkpointhec_send_notification(client: Client, entity: str, emails: List[str]) -> CommandResults:
    result = client.send_notification(entity, emails)
    if result.get('ok'):
        return CommandResults(
            outputs_prefix='CheckPointHEC.Notification',
            outputs=result
        )
    else:
        return CommandResults(
            readable_output='Error sending notification email'
        )


def main() -> None:  # pragma: no cover
    args = demisto.args()
    params = demisto.params()
    base_url = params.get('url')
    client_id = params.get('client_id', {}).get('password')
    client_secret = params.get('client_secret', {}).get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(
        base_url,
        client_id,
        client_secret,
        verify,
        proxy
    )

    try:
        command = demisto.command()
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            kwargs = {
                'first_fetch': params.get('first_fetch'),
                'saas_apps': [SAAS_APPS_TO_SAAS_NAMES.get(x) for x in argToList(params.get('saas_apps'))],
                'states': [x.lower() for x in argToList(params.get('event_state'))],
                'severities': [SEVERITY_VALUES.get(x.lower()) for x in argToList(params.get('event_severity'))],
                'threat_types': [x.lower().replace(' ', '_') for x in argToList(params.get('threat_type'))],
                'max_fetch': int(params.get('max_fetch', MAX_FETCH_DEFAULT)),
                'fetch_interval': int(params.get('incidentFetchInterval', FETCH_INTERVAL_DEFAULT)),
            }
            fetch_incidents(client, **kwargs)
        elif command == 'checkpointhec-get-entity':
            entity = args.get('entity')
            return_results(checkpointhec_get_entity(client, entity))
        elif command == 'checkpointhec-get-events':
            kwargs = {
                'start_date': args.get('start_date'),
                'end_date': args.get('end_date'),
                'saas_apps': [SAAS_APPS_TO_SAAS_NAMES.get(x) for x in argToList(args.get('saas_apps'))],
                'states': [x.lower() for x in argToList(args.get('states'))],
                'severities': [SEVERITY_VALUES.get(x.lower()) for x in argToList(args.get('severities'))],
                'threat_types': [x.lower().replace(' ', '_') for x in argToList(args.get('threat_type'))],
                'limit': arg_to_number(args.get('limit', 1000)),
            }
            return_results(checkpointhec_get_events(client, **kwargs))
        elif command == 'checkpointhec-get-scan-info':
            entity = args.get('entity')
            return_results(checkpointhec_get_scan_info(client, entity))
        elif command == 'checkpointhec-search-emails':
            if saas := args.get('saas'):
                saas = SAAS_APPS_TO_SAAS_NAMES.get(saas)
            else:  # If no saas, we default to the first one from params
                if saas := argToList(params.get('saas_apps')):
                    saas = SAAS_APPS_TO_SAAS_NAMES.get(saas[0])
                else:  # If no params, we default to the first one from SAAS_NAMES
                    saas = SAAS_NAMES[0]

            kwargs = {
                'date_last': args.get('date_last'),
                'date_from': args.get('date_from'),
                'date_to': args.get('date_to'),
                'saas': saas,
                'direction': args.get('direction'),
                'subject_contains': args.get('subject_contains'),
                'subject_match': args.get('subject_match'),
                'sender_contains': args.get('sender_contains'),
                'sender_match': args.get('sender_match'),
                'domain': args.get('domain'),
                'cp_detection': [CP_DETECTION_VALUES.get(x) for x in argToList(args.get('cp_detection'))],
                'ms_detection': [MS_DETECTION_VALUES.get(x) for x in argToList(args.get('ms_detection'))],
                'detection_op': args.get('detection_op', 'OR'),
                'server_ip': args.get('server_ip'),
                'recipients_contains': args.get('recipients_contains'),
                'recipients_match': args.get('recipients_match'),
                'links': args.get('links'),
                'message_id': args.get('message_id'),
                'cp_quarantined_state': CP_QUARANTINED_VALUES.get(args.get('cp_quarantined_state')),
                'ms_quarantined_state': MS_QUARANTINED_VALUES.get(args.get('ms_quarantined_state')),
                'quarantined_state_op': args.get('quarantined_state_op', 'OR'),
                'name_contains': args.get('name_contains'),
                'name_match': args.get('name_match'),
                'client_ip': args.get('client_ip'),
                'attachment_md5': args.get('attachment_md5'),
            }
            return_results(checkpointhec_search_emails(client, **kwargs))
        elif command == 'checkpointhec-send-action':
            kwargs = {
                'entities': argToList(args.get('entity')),
                'entity_type': f"{SAAS_APPS_TO_SAAS_NAMES.get(args.get('saas'))}_email",
                'action': args.get('action'),
            }
            return_results(checkpointhec_send_action(client, **kwargs))
        elif command == 'checkpointhec-get-action-result':
            task_id = args.get('task')
            return_results(checkpointhec_get_action_result(client, task_id))
        elif command == 'checkpointhec-send-notification':
            kwargs = {
                'entity': args.get('entity'),
                'emails': argToList(args.get('emails')),
            }
            return_results(checkpointhec_send_notification(client, **kwargs))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

import hashlib
import uuid
from urllib.parse import urlencode

import urllib3

from CommonServerPython import *

urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SAAS_NAMES = ['office365_emails']


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.api_version = 'v1.0'
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None

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
        timestamp = datetime.utcnow().isoformat()
        headers = {
            'x-av-req-id': request_id,
            'x-av-app-id': self.client_id,
            'x-av-date': timestamp,
            'x-av-sig': self._generate_signature(request_id, timestamp, request_string)
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

    def query_events(self, start_date: str) -> dict[str, Any]:
        request_data = {
            'startDate': start_date,
            'saas': SAAS_NAMES
        }
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

    def search_emails(self, start_date: str, sender: str = None, subject: str = None):
        entity_filter = {
            'saas': SAAS_NAMES[0],
            'startDate': start_date
        }
        extended_filter = []
        if sender:
            extended_filter.append({
                'saasAttrName': 'entityPayload.fromEmail',
                'saasAttrOp': 'contains',
                'saasAttrValue': sender
            })
        if subject:
            extended_filter.append({
                'saasAttrName': 'entityPayload.subject',
                'saasAttrOp': 'contains',
                'saasAttrValue': subject
            })
        request_data = {
            'entityFilter': entity_filter,
            'entityExtendedFilter': extended_filter,
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='search/query',
            json_data=payload
        )

    def send_action(self, entities: list, action: str, scope: str):
        request_data = {
            'entityIds': entities,
            'entityType': 'office365_emails_email',
            'entityActionName': action,
            'scope': scope
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            'action/entity',
            json_data=payload
        )

    def get_task(self, task: str, scope: str):
        return self._call_api(
            'GET',
            f'task/{task}',
            params={'scope': scope}
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


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int):
    last_run = demisto.getLastRun()
    if not (last_fetch := last_run.get('last_fetch')):
        if last_fetch := dateparser.parse(first_fetch, date_formats=[DATE_FORMAT]):
            last_fetch = last_fetch.isoformat()
        else:
            raise Exception('Could not get last fetch')
    result = client.query_events(start_date=last_fetch)
    events = result['responseData'][:min(max_fetch, len(result['responseData']))]

    incidents: list[dict[str, Any]] = []
    for event in events:
        if (occurred := event.get('eventCreated')) <= last_fetch:
            continue

        event_id = event.get('eventId')
        threat_type = event.get('type')
        incidents.append({
            'name': f'Threat: {threat_type.title()}',
            'details': event.get('description'),
            'occurred': occurred,
            'rawJSON': json.dumps(event),
            'type': 'CheckPointHEC Security Event',
            'severity': int(event.get('severity')),
            'dbotMirrorId': event_id,
            'CustomFields': {
                'checkpointhecfarm': event.get('farm'),
                'checkpointheccustomer': event.get('customerId'),
                'checkpointhecsaas': event.get('saas'),
                'checkpointhecentity': event.get('entityId'),
                'checkpointhectype': threat_type,
                'state': event.get('state'),  # From CommonTypes Pack
            },
        })

    if incidents:
        last = incidents[-1]['occurred']
    else:
        last = (datetime.utcnow() - timedelta(minutes=10)).isoformat()

    demisto.setLastRun({
        'last_fetch': last
    })
    demisto.incidents(incidents)


def checkpointhec_get_entity(client: Client, entity: str) -> CommandResults:
    result = client.get_entity(entity)
    if entities := result['responseData']:
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            outputs_key_field='internetMessageId',
            outputs=entities[0]['entityPayload']
        )

    raise Exception(f'Entity with id {entity} not found')


def checkpointhec_get_email_info(client: Client, entity: str) -> CommandResults:
    result = client.get_email(entity)
    if entities := result['responseData']:
        return CommandResults(
            outputs_prefix='CheckPointHEC.Email',
            outputs_key_field='internetMessageId',
            outputs=entities[0]['entityPayload']
        )
    else:
        return CommandResults(
            readable_output=f'Entity with id {entity} not found'
        )


def checkpointhec_get_scan_info(client: Client, entity: str) -> CommandResults:
    result = client.get_entity(entity)
    outputs = {}
    if entities := result['responseData']:
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


def checkpointhec_search_emails(client: Client, date_range: str, sender: str = None, subject: str = None) -> CommandResults:
    if not sender and not subject:
        raise Exception('One param to search emails by sender or subject is required')

    start_date = dateparser.parse(date_range, date_formats=[DATE_FORMAT])
    if start_date:
        result = client.search_emails(start_date.isoformat(), sender, subject)
        if entities := result['responseData']:
            ids = [entity['entityInfo']['entityId'] for entity in entities]
            return CommandResults(
                outputs_prefix='CheckPointHEC.SearchResult',
                outputs={'ids': ids}
            )
        else:
            return CommandResults(
                readable_output=f'Error searching with {sender=} and/or {subject=}'
            )
    else:
        return CommandResults(
            readable_output=f'Could not establish start date with {date_range=} {sender=} and/or {subject=}'
        )


def checkpointhec_send_action(client: Client, farm: str, customer: str, entities: list, action: str) -> CommandResults:
    result = client.send_action(entities, action, scope=f'{farm}:{customer}')
    if resp := result['responseData']:
        return CommandResults(
            outputs_prefix='CheckPointHEC.Task',
            outputs={'task': resp[0]['taskId']}
        )
    else:
        return CommandResults(
            readable_output='Task not queued successfully'
        )


def checkpointhec_get_action_result(client: Client, farm: str, customer: str, task: str) -> CommandResults:
    result = client.get_task(task, scope=f'{farm}:{customer}')
    if resp := result['responseData']:
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
            first_fetch = params.get('first_fetch')
            max_fetch = int(args.get('max_fetch', 10))
            fetch_incidents(client, first_fetch, max_fetch)
        elif command == 'checkpointhec-get-entity':
            return_results(checkpointhec_get_entity(client, args.get('entity')))
        elif command == 'checkpointhec-get-email-info':
            return_results(checkpointhec_get_email_info(client, args.get('entity')))
        elif command == 'checkpointhec-get-scan-info':
            return_results(checkpointhec_get_scan_info(client, args.get('entity')))
        elif command == 'checkpointhec-search-emails':
            return_results(checkpointhec_search_emails(
                client, args.get('date_range'), args.get('sender'), args.get('subject')
            ))
        elif command == 'checkpointhec-send-action':
            entities = argToList(args.get('entity'))
            return_results(checkpointhec_send_action(
                client, args.get('farm'), args.get('customer'), entities, args.get('action')
            ))
        elif command == 'checkpointhec-get-action-result':
            return_results(checkpointhec_get_action_result(
                client, args.get('farm'), args.get('customer'), args.get('task')
            ))
        elif command == 'checkpointhec-send-notification':
            emails = argToList(args.get('emails'))
            return_results(checkpointhec_send_notification(client, args.get('entity'), emails))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

from CommonServerPython import *

import base64
import hashlib
import json
import urllib3
import uuid
from typing import Dict, List, Any

urllib3.disable_warnings()


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

    def _get_headers(self, request_string: str = None, auth: bool = False) -> Dict[str, str]:
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

    def _call_api(self, method: str, url_suffix: str, json_data: dict = None) -> Dict[str, str]:
        path = '/'.join([self.api_version, url_suffix])
        request_string = f'/{path}'
        return self._http_request(
            method,
            url_suffix=path,
            headers=self._get_headers(request_string),
            json_data=json_data
        )

    def get_scopes(self) -> Dict[str, str]:
        return self._call_api(
            'GET',
            url_suffix='scopes'
        )

    def query_events(self, start_date: str) -> Dict[str, Any]:
        saas = ['office365_emails']
        request_data = {
            'startDate': start_date,
            'saas': saas
        }
        payload = {
            'requestData': request_data
        }
        return self._call_api(
            'POST',
            url_suffix='event/query',
            json_data=payload
        )

    def get_entity(self, entity: str) -> Dict[str, Any]:
        return self._call_api(
            'GET',
            url_suffix=f'search/entity/{entity}'
        )


def test_module(client: Client):
    client.get_scopes()
    demisto.results('ok')


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', (datetime.utcnow() - timedelta(hours=1)).isoformat())
    result = client.query_events(start_date=last_fetch)

    incidents: List[Dict[str, Any]] = []
    for event in result['responseData']:
        event_id = event.get('eventId')
        incidents.append({
            'name': f'#CP Event: {event_id}',
            'details': event.get('description'),
            'occurred': event.get('eventCreated'),
            'rawJSON': json.dumps(event),
            'type': 'CheckPointHEC Security Event',
            'severity': int(event.get('severity')),
            'dbotMirrorId': event_id,
            'CustomFields': {
                'checkpointheccustomer': event.get('customerId'),
                'checkpointhecsaas': event.get('saas'),
                'checkpointhecentity': event.get('entityId'),
                'checkpointhecstate': event.get('state'),
                'checkpointhectype': event.get('type'),
            },
        })

    last = incidents[-1]['occurred'] if incidents else datetime.utcnow().isoformat()
    demisto.setLastRun({
        'last_fetch': last
    })
    demisto.incidents(incidents)


def checkpointhec_get_entity(client: Client, entity: str) -> CommandResults:
    result = client.get_entity(entity)
    if row := result['responseData']:
        return CommandResults(
            outputs_prefix='CheckPointHEC.Entity',
            outputs_key_field='entity_id',
            outputs=row[0]['entityPayload']
        )

    raise Exception(f'Entity with id {entity} not found')


def main() -> None:
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
            test_module(client)
        elif command == 'fetch-incidents':
            fetch_incidents(client)
        elif command == 'checkpointhec-get-entity':
            args = demisto.args()
            return_results(checkpointhec_get_entity(client, args.get('entity')))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

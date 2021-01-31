from collections import deque
from copy import copy
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import Dict

import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from pydantic import BaseModel
from uvicorn.logging import AccessFormatter

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]


class Incident(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    occurred: Optional[str] = None
    raw_json: Optional[Dict] = None


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: Dict) -> str:
        headers = scope.get('headers', [])
        user_agent_header = list(filter(lambda header: header[0].decode() == 'user-agent', headers))
        user_agent = ''
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):
        recordcopy = copy(record)
        scope = recordcopy.__dict__['scope']
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({'user_agent': user_agent})
        return super().formatMessage(recordcopy)


@app.post('/')
async def handle_post(
        incident: Incident,
        request: Request,
        credentials: HTTPBasicCredentials = Depends(basic_auth),
        token: APIKey = Depends(token_auth)
):
    credentials_param = demisto.params().get('credentials')
    if credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        auth_failed = False
        header_name = None
        if username.startswith('_header'):
            header_name = username.split(':')[1]
            token_auth.model.name = header_name
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (not (compare_digest(credentials.username, username)
                                   and compare_digest(credentials.password, password))):
            auth_failed = True
        if auth_failed:
            request_headers = dict(request.headers)
            secret_header = (header_name or 'Authorization').lower()
            if secret_header in request_headers:
                request_headers[secret_header] = '***'
            demisto.debug(f'Authorization failed - request headers {request_headers}')
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    raw_json = incident.raw_json or await request.json()
    incident = {
        'name': incident.name or 'Generic webhook triggered incident',
        'type': incident.type or demisto.params().get('incidentType'),
        'occurred': incident.occurred,
        'rawJSON': json.dumps(raw_json)
    }

    if demisto.params().get('store_samples'):
        try:
            sample_events_to_store.append(incident)
            integration_context = get_integration_context()
            sample_events = deque(json.loads(integration_context.get('sample_events', '[]')), maxlen=20)
            sample_events += sample_events_to_store
            integration_context['sample_events'] = list(sample_events)
            set_to_integration_context_with_retries(integration_context)
        except Exception as e:
            demisto.error(f'Failed storing sample events - {e}')

    return demisto.createIncidents([incident])


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get('sample_events', '[]'))
    demisto.incidents(sample_events)


def main() -> None:
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results('ok')
        elif demisto.command() == 'fetch-incidents':
            fetch_samples()
        elif demisto.command() == 'long-running-execution':
            while True:
                certificate = demisto.params().get('certificate', '')
                private_key = demisto.params().get('key', '')

                certificate_path = ''
                private_key_path = ''
                try:
                    ssl_args = dict()

                    if certificate and private_key:
                        certificate_file = NamedTemporaryFile(delete=False)
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, 'utf-8'))
                        certificate_file.close()
                        ssl_args['ssl_certfile'] = certificate_path

                        private_key_file = NamedTemporaryFile(delete=False)
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, 'utf-8'))
                        private_key_file.close()
                        ssl_args['ssl_keyfile'] = private_key_path

                        demisto.debug('Starting HTTPS Server')
                    else:
                        demisto.debug('Starting HTTP Server')

                    integration_logger = IntegrationLogger()
                    integration_logger.buffering = False
                    log_config = dict(uvicorn.config.LOGGING_CONFIG)
                    log_config['handlers']['default']['stream'] = integration_logger
                    log_config['handlers']['access']['stream'] = integration_logger
                    log_config['formatters']['access'] = {
                        '()': GenericWebhookAccessFormatter,
                        'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
                    }
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)
                except Exception as e:
                    demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
                    demisto.updateModuleHealth(f'An error occurred: {str(e)}')
                finally:
                    if certificate_path:
                        os.unlink(certificate_path)
                    if private_key_path:
                        os.unlink(private_key_path)
                    time.sleep(5)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

from io import StringIO
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import Dict

import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class Incident(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    occurred: Optional[str] = None
    raw_json: Optional[Dict] = None


app = FastAPI(logger=DebugLogger(), docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


@app.post('/')
async def handle_post(
        incident: Incident,
        request: Request,
        credentials: HTTPBasicCredentials = Depends(basic_auth),
        token: APIKey = Depends(token_auth)
):
    credentials_param = demisto.params().get('credentials')
    if credentials_param:
        username = credentials_param.get('identifier', '')
        password = credentials_param.get('password', '')
        auth_failed = False
        if username.startswith('_header'):
            header_name = username.split(':')[1]
            token_auth.model.name = header_name
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif not (compare_digest(credentials.username, username) and compare_digest(credentials.password, password)):
            auth_failed = True
        if auth_failed:
            demisto.debug(f'Authorization failed - request headers {request.headers}')
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    raw_json = incident.raw_json or await request.json()
    return demisto.createIncidents([{
        'name': incident.name or 'Generic webhook triggered incident',
        'type': incident.type or demisto.params().get('incidentType'),
        'occurred': incident.occurred,
        'rawJSON': json.dumps(raw_json)
    }])


def main() -> None:
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        default_log_stream = None
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results('ok')
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

                    default_log_stream = StringIO()
                    log_config = uvicorn.config.LOGGING_CONFIG
                    log_config['handlers']['default']['stream'] = default_log_stream
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, access_log=False, **ssl_args)
                except Exception as e:
                    demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
                    demisto.updateModuleHealth(f'An error occurred: {str(e)}')
                finally:
                    if default_log_stream:
                        default_log_stream.close()
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

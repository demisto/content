from io import StringIO
from traceback import format_exc
from typing import Dict

import uvicorn
from fastapi import FastAPI, Request, Response
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


@app.middleware('http')
async def verify_auth_header(request: Request, call_next):
    auth_header = demisto.params().get('auth_header')
    if auth_header and request.headers.get('Authorization') != auth_header:
        demisto.debug(f'Authorization failed - request headers {request.headers}')
        return Response(status_code=401, content='Authorization failed.')
    return await call_next(request)


@app.post('/')
async def handle_post(incident: Incident) -> List:
    return demisto.createIncidents([{
        'name': incident.name,
        'type': incident.type or demisto.params().get('incidentType'),
        'occurred': incident.occurred,
        'rawJSON': json.dumps(incident.raw_json)
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
                try:
                    default_log_stream = StringIO()
                    log_config = uvicorn.config.LOGGING_CONFIG
                    log_config['handlers']['default']['stream'] = default_log_stream
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, access_log=False)
                except Exception as e:
                    demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
                    demisto.updateModuleHealth(f'An error occurred: {str(e)}')
                finally:
                    if default_log_stream:
                        default_log_stream.close()
                    time.sleep(5)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

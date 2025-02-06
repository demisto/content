import sys
from json import JSONDecodeError

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from collections import deque
from copy import copy
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc

import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')
EVENTS = None


async def parse_incidents(request: Request) -> list[dict]:
    json_body = await request.json()
    demisto.debug(f'received body {sys.getsizeof(json_body)=}')
    incidents = json_body if isinstance(json_body, list) else [json_body]
    demisto.debug(f'received create incidents request of length {len(incidents)}')
    for incident in incidents:
        raw_json = incident.get('rawJson') or incident.get('raw_json') or copy(incident)
        if not incident.get('rawJson'):
            incident.pop('raw_json', None)
            incident['rawJson'] = raw_json
    return incidents


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
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
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    token: APIKey = Depends(token_auth)
):
    demisto.debug('generic webhook handling request')
    try:
        incidents = await parse_incidents(request)
    except JSONDecodeError as e:
        demisto.error(f'could not decode request {e}')
        return Response(status_code=status.HTTP_400_BAD_REQUEST,
                        content='Request, and rawJson field if exists must be in JSON format')
    header_name = None
    request_headers = dict(request.headers)

    credentials_param = demisto.params().get('credentials')

    if credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        auth_failed = False
        if username.startswith('_header'):
            header_name = username.split(':')[1]
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (not (compare_digest(credentials.username, username)
                                        and compare_digest(credentials.password, password))):
            auth_failed = True
        if auth_failed:
            secret_header = (header_name or 'Authorization').lower()
            if secret_header in request_headers:
                request_headers[secret_header] = '***'
            demisto.debug(f'Authorization failed - request headers {request_headers}')
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    secret_header = (header_name or 'Authorization').lower()
    request_headers.pop(secret_header, None)

    for incident in incidents:
        incident.get('rawJson', {})['headers'] = request_headers
        demisto.debug(f'{incident=}')

    incidents = [{
        'name': incident.get('name') or 'Generic webhook triggered incident',
        'type': incident.get('type') or demisto.params().get('incidentType'),
        'occurred': incident.get('occurred'),
        'rawJSON': json.dumps(incident.get('rawJson'))
    } for incident in incidents]

    demisto.debug('creating incidents')
    return_incidents = demisto.createIncidents(incidents)
    demisto.debug('created incidents')
    if demisto.params().get('store_samples'):
        try:
            sample_events_to_store.extend(incidents)
            demisto.debug(f'old events {len(sample_events_to_store)=}')
            integration_context = get_integration_context()
            sample_events = deque(json.loads(integration_context.get('sample_events', '[]')), maxlen=20)
            sample_events += sample_events_to_store
            demisto.debug(f'new events {len(sample_events_to_store)=}')
            integration_context['sample_events'] = list(sample_events)
            set_to_integration_context_with_retries(integration_context)
            demisto.debug('finished setting sample events')
        except Exception as e:
            demisto.error(f'Failed storing sample events - {e}')

    return return_incidents


def generate_events() -> str:
    global EVENTS
    if not EVENTS:
        events = []
        original_dict = {
        "attackData": {
            "clientIP": "192.0.2.82",
            "configId": "14227",
            "policyId": "qik1_26545",
            "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
            "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
            "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
            "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
            "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
            "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
            "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
        },
        "botData": {
            "botScore": "100",
            "responseSegment": "3"
        },
        "clientData": {
            "appBundleId": "com.mydomain.myapp",
            "appVersion": "1.23",
            "sdkVersion": "4.7.1",
            "telemetryType": "2"
        },
        "format": "json",
        "geo": {
            "asn": "14618",
            "city": "ASHBURN",
            "continent": "288",
            "country": "US",
            "regionCode": "VA"
        },
        "httpMessage": {
            "bytes": "266",
            "host": "www.hmapi.com",
            "method": "GET",
            "path": "/",
            "port": "80",
            "protocol": "HTTP/1.1",
            "query": "option=com_jce%20telnet.exe",
            "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
            "requestId": "1158db1758e37bfe67b7c09",
            "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
            "start": f"{int(time.time())}",
            "status": "200"
        },
        "type": "akamai_siem",
        "userRiskData": {
            "allow": "0",
            "general": "duc_1h:10|duc_1d:30",
            "originUserId": "jsmith007",
            "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
            "score": "75",
            "status": "0",
            "trust": "ugp:US",
            "username": "jsmith@example.com",
            "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
        },
        "version": "1.0"
        }
        import copy
        for i in range(3000):
            duplicated_dict = copy.deepcopy(original_dict)
            duplicated_dict["unique_id"] = i
            events.append(json.dumps(duplicated_dict))
        events.append(json.dumps({
            "total": 300000,
            "offset": "Hayun offset",
            "limit": 300000
        }))
        EVENTS = "\n".join(events)
    return EVENTS


@app.get('/50170')
def handle_get_request():
    """handle a regular get response.
    Args:
    Returns:
        Response:response object.
    """
    global EVENTS
    if not EVENTS:
        EVENTS = generate_events()
    return Response(status_code=status.HTTP_200_OK, content=EVENTS, media_type="application/json")


def setup_credentials():
    if credentials_param := demisto.params().get('credentials'):
        username = credentials_param.get('identifier')
        if username and username.startswith('_header:'):
            header_name = username.split(':')[1]
            demisto.debug(f'Overwriting Authorization parameter with {username}')
            token_auth.model.name = header_name


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get('sample_events', '[]'))
    demisto.incidents(sample_events)


def test_module(params: dict):
    """
    Assigns a temporary port for longRunningPort and returns 'ok'.
    """
    if not params.get('longRunningPort'):
        params['longRunningPort'] = '1111'
    return_results('ok')


def main() -> None:
    params = demisto.params()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            return test_module(params)
        try:
            port = int(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'fetch-incidents':
            fetch_samples()
        elif demisto.command() == 'long-running-execution':
            while True:
                certificate = demisto.params().get('certificate', '')
                private_key = demisto.params().get('key', '')

                certificate_path = ''
                private_key_path = ''
                try:
                    ssl_args = {}

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
                    setup_credentials()
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
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

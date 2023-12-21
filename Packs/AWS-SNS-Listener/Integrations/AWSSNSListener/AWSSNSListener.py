from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *
from tempfile import NamedTemporaryFile
from traceback import format_exc
from collections import deque
import uvicorn
from fastapi import FastAPI, Request
from fastapi.security import HTTPBasic
from fastapi.security.api_key import APIKeyHeader
import requests


sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


@app.post('/incident/aws/sns')
async def handle_post(request: Request):
    data = ''
    try:
        payload = await request.json()
        dump = json.dumps(payload)
    except Exception as e:
        demisto.error(f'Failed to extract request {e}')
        return
    if payload['Type'] == 'SubscriptionConfirmation':
        demisto.debug('SubscriptionConfirmation request')
        subscribe_url = payload['SubscribeURL']
        response = requests.get(subscribe_url)
        demisto.debug(f'Response from subscribe url: {response}')

    elif payload['Type'] == 'Notification':
        message = payload['Message']
        demisto.debug(f'Notification request msg: {message}')
        incident = {
            'name': payload['Subject'],
            'labels': [],
            'rawJSON': dump,
            'occurred': payload['Timestamp'],
            'details': message,
            'type': 'AWS-SNS'
        }
        demisto.debug(f'demisto.createIncidents with:{incident}')
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
        data = demisto.createIncidents(incidents=[incident])
        if not data:
            demisto.error('Failed creating incident')

    else:
        demisto.error(f"Failed handling AWS SNS request, unknown type: {payload['Type']}")

''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        try:
            port = int(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results("ok")
        elif demisto.command() == 'long-running-execution':
            demisto.debug('Started long-running-execution.')
            while True:
                certificate = params.get('certificate', '')
                private_key = params.get('key', '')

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
        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented.')
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

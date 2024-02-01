from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *
from tempfile import NamedTemporaryFile
from traceback import format_exc
from collections import deque
import uvicorn
from secrets import compare_digest
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKeyHeader
from fastapi.openapi.models import APIKey
import requests
import base64
from M2Crypto import X509


PARAMS: dict = demisto.params()
sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


def handle_teams_proxy_and_ssl():
    proxies = None
    use_ssl = not PARAMS.get('insecure', False)
    if not is_demisto_version_ge('8.0.0'):
        return proxies, use_ssl
    CRTX_HTTP_PROXY = os.environ.get('CRTX_HTTP_PROXY', None)
    demisto.debug(f"CRTX_HTTP_PROXY: {CRTX_HTTP_PROXY}")
    if CRTX_HTTP_PROXY:
        proxies = {
            "http": CRTX_HTTP_PROXY,
            "https": CRTX_HTTP_PROXY
        }
        use_ssl = True
    return proxies, use_ssl


PROXIES, USE_SSL = handle_teams_proxy_and_ssl()


def valid_sns_message(sns_payload):
    """
    Validates an incoming Amazon Simple Notification Service (SNS) message.

    Args:
        sns_payload (dict): The SNS payload containing relevant fields.

    Returns:
        bool: True if the message is valid, False otherwise.
    """
    # taken from https://github.com/boto/boto3/issues/2508
    # Can only be one of these types.
    if sns_payload["Type"] not in ["SubscriptionConfirmation", "Notification", "UnsubscribeConfirmation"]:
        demisto.error('Not a valid SNS message')
        return False

    # Amazon SNS currently supports signature version 1 or 2.
    if sns_payload["SignatureVersion"] not in ["1", "2"]:
        demisto.error('Not using the supported AWS-SNS SignatureVersion 1 or 2')
        return False

    # Fields for a standard notification.
    fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]

    # Determine the required fields based on message type
    if sns_payload["Type"] in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
        fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

    # Build the string to be signed.
    string_to_sign = ""
    for field in fields:
        string_to_sign += field + "\n" + sns_payload[field] + "\n"

    # Verify the signature
    decoded_signature = base64.b64decode(sns_payload["Signature"])
    try:
        resp = requests.get(sns_payload["SigningCertURL"], verify=USE_SSL, proxies=PROXIES)
        resp.raise_for_status()
        certificate = X509.load_cert_string(resp.text)
    except Exception as e:
        demisto.error(f'Exception validating sign cert url: {e}')
        return False

    public_key = certificate.get_pubkey()
    # Verify the signature based on SignatureVersion
    if sns_payload["SignatureVersion"] == "1":
        public_key.reset_context(md="sha1")
    else:  # version2
        public_key.reset_context(md="sha256")

    public_key.verify_init()
    public_key.verify_update(string_to_sign.encode())
    verification_result = public_key.verify_final(decoded_signature)

    if verification_result != 1:
        demisto.error('Signature verification failed.')
        return False

    demisto.debug('Signature verification succeeded.')
    return True


@app.post('/')
async def handle_post(request: Request,
                      credentials: HTTPBasicCredentials = Depends(basic_auth),
                      token: APIKey = Depends(token_auth)):
    data = ''
    header_name = None
    request_headers = dict(request.headers)

    credentials_param = demisto.params().get('credentials')

    if credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        auth_failed = False
        if username.startswith('_header'):
            header_name = username.split(':')[1]
            token_auth.model.name = header_name
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

    try:
        type = request_headers['x-amz-sns-message-type']
        payload = await request.json()
        raw_jason = json.dumps(payload)
    except Exception as e:
        demisto.error(f'Error in request parsing: {e}')
        return 'Failed parsing request'
    if not valid_sns_message(payload):
        return 'Validation of SNS message failed.'

    if type == 'SubscriptionConfirmation':
        demisto.debug('SubscriptionConfirmation request')
        subscribe_url = payload['SubscribeURL']
        try:
            response = requests.get(subscribe_url, verify=USE_SSL, proxies=PROXIES)
        except Exception as e:
            demisto.error(f'Failed handling SubscriptionConfirmation: {e}')
            return 'Failed handling SubscriptionConfirmation'
        demisto.debug(f'Response from subscribe url: {response}')
        return response
    elif type == 'Notification':
        message = payload['Message']
        demisto.debug(f'Notification request msg: {message}')
        incident = {
            'name': payload['Subject'],
            'labels': [],
            'rawJSON': raw_jason,
            'occurred': payload['Timestamp'],
            'details': f'ExternalID:{payload["MessageId"]} TopicArn:{payload["TopicArn"]} Message:{message}',
            'type': 'AWS-SNS Notification'
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
            data = 'Failed creating incident'
        return data
    elif type == 'UnsubscribeConfirmation':
        message = payload['Message']
        demisto.debug(f'UnsubscribeConfirmation request msg: {message}')
        return f'UnsubscribeConfirmation request msg: {message}'
    else:
        demisto.error(f'Failed handling AWS SNS request, unknown type: {payload["Type"]}')
        return f'Failed handling AWS SNS request, unknown type: {payload["Type"]}'

''' MAIN FUNCTION '''


def main():
    # PARAMS = demisto.params()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        try:
            port = PARAMS.get('longRunningPort')
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results("ok")
        elif demisto.command() == 'long-running-execution':
            demisto.debug('Started long-running-execution.')
            while True:
                certificate = PARAMS.get('certificate', '')
                private_key = PARAMS.get('key', '')

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

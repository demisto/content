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
import base64
from M2Crypto import X509


PARAMS: dict = demisto.params()
sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

PROXIES, USE_SSL = handle_proxy_for_long_running()


class AWS_SNS_CLIENT(BaseClient):  # pragma: no cover
    def __init__(self, base_url=None):
        if PROXIES:
            self.proxies = PROXIES
        elif PARAMS.get('proxy'):
            self.proxies = handle_proxy()
        headers = {'Accept': 'application/json'}
        super().__init__(base_url=base_url, proxy=bool(PROXIES), verify=USE_SSL, headers=headers)

    def get(self, full_url, resp_type='json'):
        return self._http_request(method='GET', full_url=full_url, proxies=PROXIES, resp_type=resp_type)


client = AWS_SNS_CLIENT()


class ServerConfig():  # pragma: no cover
    def __init__(self, certificate_path, private_key_path, log_config, ssl_args):
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.log_config = log_config
        self.ssl_args = ssl_args


class SNSCertificateManager():
    def __init__(self):
        self.cached_cert_url = None

    def is_valid_sns_message(self, sns_payload):
        """
        Validates an incoming Amazon Simple Notification Service (SNS) message.

        Args:
            sns_payload (dict): The SNS payload containing relevant fields.

        Returns:
            bool: True if the message is valid, False otherwise.
        """
        # taken from https://github.com/boto/boto3/issues/2508
        demisto.debug('In is_valid_sns_message')
        # Can only be one of these types.
        if sns_payload["Type"] not in ["SubscriptionConfirmation", "Notification", "UnsubscribeConfirmation"]:
            demisto.error('Not a valid SNS message')
            return False

        # Amazon SNS currently supports signature version 1 or 2.
        if sns_payload.get("SignatureVersion") not in ["1", "2"]:
            demisto.error('Not using the supported AWS-SNS SignatureVersion 1 or 2')
            return False
        demisto.debug(f'Handling Signature Version: {sns_payload.get("SignatureVersion")}')
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
        if (sns_payload["SigningCertURL"] == self.cached_cert_url):
            demisto.debug(f'Current SigningCertURL: {sns_payload["SigningCertURL"]} was verified already.')
            return True
        try:
            demisto.debug(f'sns_payload["SigningCertURL"] = {sns_payload["SigningCertURL"]}')
            response: requests.models.Response = client.get(full_url=sns_payload["SigningCertURL"], resp_type='response')
            response.raise_for_status()
            certificate = X509.load_cert_string(response.text)
        except Exception as e:
            demisto.error(f'Exception validating sign cert url: {e}')
            if "502" in str(e):
                demisto.error(f'SigningCertURL: {sns_payload["SigningCertURL"]}')
            elif "Verify that the server URL parameter" in str(e):
                demisto.error(f'client base url: {client._base_url}')
            elif "Proxy Error" in str(e):
                demisto.error(f'PROXIES = {PROXIES}')
            demisto.debug("SigningCertURL failed. Deleting the saved SigningCertURL.")
            self.cached_cert_url = None
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
            demisto.debug("SigningCertURL failed. Deleting the saved SigningCertURL.")
            self.cached_cert_url = None
            return False

        demisto.debug('Signature verification succeeded.')
        self.cached_cert_url = sns_payload["SigningCertURL"]
        return True


sns_cert_manager = SNSCertificateManager()


def is_valid_integration_credentials(credentials, request_headers, token):
    credentials_param = PARAMS.get('credentials')
    auth_failed = False
    header_name = None
    if credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
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
    if auth_failed:  # auth failed not valid credentials
        return False, header_name
    else:
        return True, header_name


def handle_subscription_confirmation(subscribe_url) -> requests.Response:  # pragma: no cover
    demisto.debug('SubscriptionConfirmation request')
    response: requests.models.Response = client.get(full_url=subscribe_url, resp_type='response')
    response.raise_for_status()
    return response


def handle_notification(payload, raw_json):
    message = payload['Message']
    demisto.debug(f'Notification request msg: {message}')
    return {
        'name': payload['Subject'],
        'labels': [],
        'rawJSON': raw_json,
        'occurred': payload['Timestamp'],
        'details': f'ExternalID:{payload["MessageId"]} TopicArn:{payload["TopicArn"]} Message:{message}',
        'type': 'AWS-SNS Notification'
    }


def store_samples(incident):  # pragma: no cover
    try:
        sample_events_to_store.append(incident)
        integration_context = get_integration_context()
        sample_events = deque(json.loads(integration_context.get('sample_events', '[]')), maxlen=20)
        sample_events += sample_events_to_store
        integration_context['sample_events'] = list(sample_events)
        set_to_integration_context_with_retries(integration_context)
    except Exception as e:
        demisto.error(f'Failed storing sample events - {e}')


@app.post(f'/{PARAMS.get("endpoint","")}')
async def handle_post(request: Request,
                      credentials: HTTPBasicCredentials = Depends(basic_auth),
                      token: APIKey = Depends(token_auth)):   # pragma: no cover
    """
    Handles incoming AWS-SNS POST requests.
    Supports SubscriptionConfirmation, Notification and UnsubscribeConfirmation.

    Args:
        request (Request): The incoming HTTP request.
        credentials (HTTPBasicCredentials): Basic authentication credentials.
        token (APIKey): API key for authentication.

    Returns:
        Union[Response, str]: Response data or error message.
    """
    data = ''
    request_headers = dict(request.headers)
    is_valid_credentials = False
    try:
        is_valid_credentials, header_name = is_valid_integration_credentials(credentials, request_headers, token)
    except Exception as e:
        demisto.error(f'Error handling auth failure: {e}')
    if not is_valid_credentials:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    secret_header = (header_name or 'Authorization').lower()
    request_headers.pop(secret_header, None)

    try:
        type = request_headers['x-amz-sns-message-type']
        payload = await request.json()
        raw_json = json.dumps(payload)
    except Exception as e:
        demisto.error(f'Error in request parsing: {e}')
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content='Failed parsing request.')
    if not sns_cert_manager.is_valid_sns_message(payload):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Validation of SNS message failed.')

    if type == 'SubscriptionConfirmation':
        demisto.debug('SubscriptionConfirmation request')
        subscribe_url = payload['SubscribeURL']
        try:
            response = handle_subscription_confirmation(subscribe_url=subscribe_url)
        except Exception as e:
            demisto.error(f'Failed handling SubscriptionConfirmation: {e}')
            return 'Failed handling SubscriptionConfirmation'
        demisto.debug(f'Response from subscribe url: {response}')
        return response
    elif type == 'Notification':
        incident = handle_notification(payload, raw_json)
        data = demisto.createIncidents(incidents=[incident])
        demisto.debug(f'Created incident: {incident}')
        if PARAMS.get('store_samples'):
            store_samples(incident)
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


def unlink_certificate(certificate_path, private_key_path):  # pragma: no cover
    if certificate_path:
        os.unlink(certificate_path)
    if private_key_path:
        os.unlink(private_key_path)
    time.sleep(5)


def setup_server():  # pragma: no cover
    certificate = PARAMS.get('certificate', '')
    private_key = PARAMS.get('key', '')

    certificate_path = ''
    private_key_path = ''
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
    return ServerConfig(log_config=log_config, ssl_args=ssl_args,
                        certificate_path=certificate_path, private_key_path=private_key_path)


def test_module():  # pragma: no cover
    """
    Assigns a temporary port for longRunningPort and returns 'ok'.
    """
    if not PARAMS.get('longRunningPort'):
        PARAMS['longRunningPort'] = '1111'
    return 'ok'


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            return return_results(test_module())
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'long-running-execution':
            demisto.debug('Started long-running-execution.')
            while True:
                server_config = setup_server()
                if not server_config:
                    raise DemistoException('Failed to configure server.')
                try:
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=server_config.log_config,  # type: ignore[arg-type]
                                **server_config.ssl_args)
                except Exception as e:
                    demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
                    demisto.updateModuleHealth(f'An error occurred: {str(e)}')
                finally:
                    unlink_certificate(server_config.certificate_path, server_config.private_key_path)
        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented.')
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

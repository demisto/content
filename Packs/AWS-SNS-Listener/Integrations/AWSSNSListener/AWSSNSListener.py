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
import base64
from M2Crypto import X509
PARAMS: dict = demisto.params()


sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


def handle_teams_proxy_and_ssl():
    demisto.error("DANF in handle_teams_proxy_and_ssl")
    proxies = None
    use_ssl = not PARAMS.get('insecure', False)
    if not is_demisto_version_ge('8.0.0'):
        return proxies, use_ssl
    CRTX_HTTP_PROXY = os.environ.get('CRTX_HTTP_PROXY', None)
    demisto.error(f"DANF CRTX_HTTP_PROXY: {CRTX_HTTP_PROXY}")
    if CRTX_HTTP_PROXY:
        proxies = {
            "http": CRTX_HTTP_PROXY,
            "https": CRTX_HTTP_PROXY
        }
        use_ssl = True
    return proxies, use_ssl


PROXIES, USE_SSL = handle_teams_proxy_and_ssl()


def valid_sns_message(sns_payload):
    demisto.error('DANF in valid_sns_message')

    # Can only be one of these types.
    if sns_payload["Type"] not in ["SubscriptionConfirmation", "Notification", "UnsubscribeConfirmation"]:
        demisto.error('not a valid SNS message')
        return False

    # Amazon SNS currently supports signature version 1.
    if sns_payload["SignatureVersion"] != "1":
        demisto.error('not using SignatureVersion 1')
        return False

    # Fields for a standard notification.
    fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]

    # Fields for subscribe or unsubscribe.
    if sns_payload["Type"] in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
        fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

    # Build the string to be signed.
    string_to_sign = ""
    for field in fields:
        string_to_sign += field + "\n" + sns_payload[field] + "\n"

    # Decode the signature from base64.
    decoded_signature = base64.b64decode(sns_payload["Signature"])
    demisto.error('DANF after base64')

    # Retrieve the certificate.
    certificate = X509.load_cert_string(requests.get(sns_payload["SigningCertURL"]).text)
    demisto.error('DANF after load cert string')

    # Extract the public key.
    public_key = certificate.get_pubkey()
    demisto.error('DANF after get pubkey')

    public_key.reset_context(md="sha1")
    demisto.error('DANF after reset context sha1')
    public_key.verify_init()
    demisto.error('DANF after verify init')

    # Sign the string.
    public_key.verify_update(string_to_sign.encode())
    demisto.error('DANF after verify update')

    # Verify the signature matches.
    verification_result = public_key.verify_final(decoded_signature)
    demisto.error('DANF after verify final')

    # M2Crypto uses EVP_VerifyFinal() from openssl as the underlying verification function.
    # 1 indicates success, anything else is either a failure or an error.
    if verification_result != 1:
        demisto.error('Signature verification failed.')
        return False

    demisto.error('DANF Signature verification succeeded.')
    return True


@app.post('/')
async def handle_post(request: Request):
    data = ''
    demisto.error('AWS-SNS-Listener got request')
    try:
        headers = dict(request.headers)
        type = headers['x-amz-sns-message-type']
        payload = await request.json()
        dump = json.dumps(payload)
    except Exception as e:
        demisto.error(f'Error in request parsing: {e}')
        return f'Error in request parsing: {e}'
    # if not valid_sns_message(payload):
    #     return 'Validation of SNS message failed.'
        # demisto.error('DANF in valid_sns_message')

    # Can only be one of these types.
    if type not in ["SubscriptionConfirmation", "Notification", "UnsubscribeConfirmation"]:
        demisto.error('DANF not a valid SNS message')
        # return False

    # Amazon SNS currently supports signature version 1.
    if payload["SignatureVersion"] != "1":
        demisto.error('DANF not using SignatureVersion 1')
        # return False

    # Fields for a standard notification.
    fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]

    # Fields for subscribe or unsubscribe.
    if payload["Type"] in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
        fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

    # Build the string to be signed.
    string_to_sign = ""
    for field in fields:
        string_to_sign += field + "\n" + payload[field] + "\n"

    # Decode the signature from base64.
    decoded_signature = base64.b64decode(payload["Signature"])
    demisto.error('DANF after base64')

    # Retrieve the certificate.
    try:
        certificate = X509.load_cert_string(requests.get(payload['SigningCertURL']).text)  # another request i need to get approved from Andrey Etush
    except Exception as e:
        demisto.error(f'DANF X509 error is: {e}')
        return 'X509 error'
    demisto.error('DANF after load cert string')

    # Extract the public key.
    public_key = certificate.get_pubkey()
    demisto.error('DANF after get pubkey')

    public_key.reset_context(md="sha1")
    demisto.error('DANF after reset context sha1')
    public_key.verify_init()
    demisto.error('DANF after verify init')

    # Sign the string.
    public_key.verify_update(string_to_sign.encode())
    demisto.error('DANF after verify update')

    # Verify the signature matches.
    verification_result = public_key.verify_final(decoded_signature)
    demisto.error('DANF after verify final')

    # M2Crypto uses EVP_VerifyFinal() from openssl as the underlying verification function.
    # 1 indicates success, anything else is either a failure or an error.
    if verification_result != 1:
        demisto.error('Signature verification failed.')
        return 'Signature verification failed.'

    demisto.error('DANF Signature verification succeeded.')
    if type == 'SubscriptionConfirmation':
        demisto.info('SubscriptionConfirmation request')
        subscribe_url = payload['SubscribeURL']
        try:
            response = requests.get(subscribe_url, verify=True, proxies=PROXIES)
        except Exception as e:
            demisto.error(f'Error in SubscribeURL: {e}')
            return f'Error in SubscribeURL: {e}'
        demisto.debug(f'Response from subscribe url: {response}')
        return response
    elif type == 'Notification':
        message = payload['Message']
        demisto.debug(f'Notification request msg: {message}')
        incident = {
            'name': payload['Subject'],
            'labels': [],
            'rawJSON': dump,
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
            longRunningPort = PARAMS.get('longRunningPort')
            print(longRunningPort) if longRunningPort else print('no longRunningPort')
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

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict
import tempfile
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxlclient.message import Event
from CommonServerUserPython import *


INTEGRATION_NAME = "McAfee DXL"
CONNECT_RETRIES = 1
RECONNECT_DELAY = 1
RECONNECT_DELAY_MAX = 10


class EventSender:
    TRUST_LEVEL = {
        'NOT_SET': '0',
        'KNOWN_MALICIOUS': '1',
        'MOST_LIKELY_MALICIOUS': '15',
        'MIGHT_BE_MALICIOUS': '30',
        'UNKNOWN': '50',
        'MIGHT_BE_TRUSTED': '70',
        'MOST_LIKELY_TRUSTED': '85',
        'KNOWN_TRUSTED': '99',
        'KNOWN_TRUSTED_INSTALLER': '100'
    }
    broker_ca_bundle = tempfile.NamedTemporaryFile().name
    cert_file = tempfile.NamedTemporaryFile().name
    private_key = tempfile.NamedTemporaryFile().name

    def __init__(self, params: Dict):
        with open(self.broker_ca_bundle, "w") as text_file:
            text_file.write(params['broker_ca_bundle'])
        with open(self.cert_file, "w") as text_file:
            text_file.write(params['cert_file'])
        with open(self.private_key, "w") as text_file:
            text_file.write(params['private_key'])

        if 'broker_urls' in params:
            self.broker_urls = params['broker_urls'].split(',')
        self.push_ip_topic = params.get('push_ip_topic')
        self.push_url_topic = params.get('push_url_topic')
        self.push_domain_topic = params.get('push_domain_topic')
        self.push_hash_topic = params.get('push_hash_topic')
        self.client = DxlClient(self.get_client_config())
        self.client.connect()

    def __del__(self):
        self.client.disconnect()

    def push_ip(self, ip, trust_level, topic):
        if not is_ip_valid(ip):
            raise ValueError(f'argument ip {ip} is not a valid IP')

        trust_level_key = self.TRUST_LEVEL[trust_level]
        if topic:
            self.push_ip_topic = topic

        self.send_event(self.push_ip_topic, f'ip:{ip};trust_level:{trust_level_key}')
        return f'Successfully pushed ip {ip} with trust level {trust_level}'

    def push_url(self, url, trust_level, topic):
        trust_level_key = self.TRUST_LEVEL[trust_level]
        if topic:
            self.push_url_topic = topic

        self.send_event(self.push_url_topic, f'url:{url};trust_level:{trust_level_key}')
        return f'Successfully pushed url {url} with trust level {trust_level}'

    def push_domain(self, domain, trust_level, topic):
        trust_level_key = self.TRUST_LEVEL[trust_level]
        if topic:
            self.push_domain_topic = topic

        self.send_event(self.push_domain_topic, f'domain:{domain};trust_level:{trust_level_key}')
        return f'Successfully pushed domain {domain} with trust level {trust_level}'

    def push_hash(self, hash_obj, trust_level, topic):
        trust_level_key = self.TRUST_LEVEL[trust_level]
        if topic:
            self.push_ip_topic = topic

        self.send_event(self.push_hash_topic, f'hash:{hash_obj};trust_level:{trust_level_key}')
        return f'Successfully pushed hash {hash_obj} with trust level {trust_level}'

    def get_client_config(self):
        config = DxlClientConfig(
            broker_ca_bundle=self.broker_ca_bundle,
            cert_file=self.cert_file,
            private_key=self.private_key,
            brokers=[Broker.parse(url) for url in self.broker_urls]
        )
        config.connect_retries = CONNECT_RETRIES
        config.reconnect_delay = RECONNECT_DELAY
        config.reconnect_delay_max = RECONNECT_DELAY_MAX
        return config

    def send_event(self, topic, payload):
        if not topic:
            raise Exception(f'Error in {demisto.command()} topic field is required')

        event = Event(topic)
        event.payload = str(payload).encode()
        self.client.send_event(event)

    def send_event_wrapper(self, topic, payload):
        self.send_event(topic, payload)
        return 'Successfully sent event'


def validate_certificates_format():
    if '-----BEGIN PRIVATE KEY-----' not in demisto.params()['private_key']:
        return_error(
            "The private key content seems to be incorrect as it doesn't start with -----BEGIN PRIVATE KEY-----")
    if '-----END PRIVATE KEY-----' not in demisto.params()['private_key']:
        return_error(
            "The private key content seems to be incorrect as it doesn't end with -----END PRIVATE KEY-----")
    if '-----BEGIN CERTIFICATE-----' not in demisto.params()['cert_file']:
        return_error("The client certificates content seem to be "
                     "incorrect as they don't start with '-----BEGIN CERTIFICATE-----'")
    if '-----END CERTIFICATE-----' not in demisto.params()['cert_file']:
        return_error(
            "The client certificates content seem to be incorrect as it doesn't end with -----END CERTIFICATE-----")
    if not demisto.params()['broker_ca_bundle'].lstrip(" ").startswith('-----BEGIN CERTIFICATE-----'):
        return_error(
            "The broker certificate seem to be incorrect as they don't start with '-----BEGIN CERTIFICATE-----'")
    if not demisto.params()['broker_ca_bundle'].rstrip(" ").endswith('-----END CERTIFICATE-----'):
        return_error(
            "The broker certificate seem to be incorrect as they don't end with '-----END CERTIFICATE-----'")


def main():
    args = demisto.args()
    command = demisto.command()
    try:
        event_sender = EventSender(demisto.params())
        result = ''
        if command == 'test-module':
            event_sender.send_event('TEST', 'test')
            result = 'ok'
        elif command == 'dxl-send-event':
            result = event_sender.send_event_wrapper(args.get('topic'), args.get('payload'))
        elif command == 'dxl-push-ip':
            result = event_sender.push_ip(args.get('ip'),
                                          args.get('trust_level'),
                                          args.get('topic'))
        elif command == 'dxl-push-url':
            result = event_sender.push_url(args.get('url'),
                                           args.get('trust_level'),
                                           args.get('topic'))
        elif command == 'dxl-push-domain':
            result = event_sender.push_domain(args.get('domain'),
                                              args.get('trust_level'),
                                              args.get('topic'))
        elif command == 'dxl-push-hash':
            result = event_sender.push_hash(args.get('hash'),
                                            args.get('trust_level'),
                                            args.get('topic'))
        else:
            raise Exception(f'{demisto.command()} is not a command')

        return_outputs(result)
    except Exception as error:
        validate_certificates_format()
        return_error(f'error in {INTEGRATION_NAME} {str(error)}.', error)


if __name__ in ('__builtin__', 'builtins'):
    main()

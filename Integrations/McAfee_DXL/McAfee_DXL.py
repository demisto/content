import demistomock as demisto
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxlclient.message import Event


class EventSender:
    TRUST_LEVELS = {
        '0': 'NOT_SET',
        '1': 'KNOWN_MALICIOUS',
        '15': 'MOST_LIKELY_MALICIOUS',
        '30': 'MIGHT_BE_MALICIOUS',
        '50': 'UNKNOWN',
        '70': 'MIGHT_BE_TRUSTED',
        '85': 'MOST_LIKELY_TRUSTED',
        '99': 'KNOWN_TRUSTED',
        '100': 'KNOWN_TRUSTED_INSTALLER'
    }
    broker_ca_bundle = './brokercerts.crt'
    cert_file = './cert_file.crt'
    private_key = './private_key.key'

    def __init__(self):
        with open(self.broker_ca_bundle, "w") as text_file:
            text_file.write(demisto.params().get('broker_ca_bundle'))
        with open(self.cert_file, "w") as text_file:
            text_file.write(demisto.params().get('cert_file'))
        with open(self.private_key, "w") as text_file:
            text_file.write(demisto.params().get('private_key'))

        self.broker_urls = demisto.params().get('broker_urls').split(',')
        self.push_ip_topic = demisto.params().get('push_ip_topic')
        self.push_url_topic = demisto.params().get('push_url_topic')
        self.push_domain_topic = demisto.params().get('push_domain_topic')
        self.push_hash_topic = demisto.params().get('push_hash_topic')

    def push_ip(self, ip, trust_level):
        if not (is_ip_valid(ip)):
            return create_error_entry(f'argument ip {ip} is not a valid IP')

        try:
            trust_level_key = get_trust_level_key(trust_level)
            self.send_event(self.push_ip_topic, f'ip:{ip};trust_level:{trust_level_key}')
            return f'Successfully pushed ip {ip} with trust level {trust_level}'
        except Exception as exception:
            return create_error_entry(str(exception))

    def push_url(self, url, trust_level):
        try:
            trust_level_key = get_trust_level_key(trust_level)
            self.send_event(self.push_url_topic, f'url:{url};trust_level:{trust_level_key}')
            return f'Successfully pushed url {url} with trust level {trust_level}'
        except Exception as exception:
            return create_error_entry(str(exception))

    def push_domain(self, domain, trust_level):
        try:
            trust_level_key = get_trust_level_key(trust_level)
            self.send_event(self.push_domain_topic, f'domain:{domain};trust_level:{trust_level_key}')
            return f'Successfully pushed domain {domain} with trust level {trust_level}'
        except Exception as exception:
            return create_error_entry(str(exception))

    def push_hash(self, hash_obj, trust_level):
        try:
            trust_level_key = get_trust_level_key(trust_level)
            self.send_event(self.push_hash_topic, f'hash:{hash_obj};trust_level:{trust_level_key}')
            return f'Successfully pushed hash {hash_obj} with trust level {trust_level}'
        except Exception as exception:
            return create_error_entry(str(exception))

    def get_client_config(self):
        config = DxlClientConfig(
            broker_ca_bundle=self.broker_ca_bundle,
            cert_file=self.cert_file,
            private_key=self.private_key,
            brokers=[Broker.parse(url) for url in self.broker_urls]
        )
        config.connect_retries = 1
        config.reconnect_delay = 1
        config.reconnect_delay_max = 10
        return config

    def validate(self):
        config = self.get_client_config()
        with DxlClient(config) as client:
            client.connect()
            client.disconnect()

    def send_event(self, topic, payload):
        config = self.get_client_config()
        with DxlClient(config) as client:
            client.connect()
            event = Event(topic)
            event.payload = str(payload).encode()
            client.send_event(event)

    def send_event_wrapper(self, topic, payload):
        try:
            self.send_event(topic, payload)
            return 'Successfully sent event'
        except Exception as exception:
            return create_error_entry(str(exception))


def get_trust_level_key(trust_level):
    for key, value in EventSender.TRUST_LEVELS.items():
        if value == trust_level:
            return key

    raise Exception(f'Illegal argument trust_level {trust_level}. Choose value from predefined values')


def create_error_entry(contents):
    return {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['error'],
        'Contents': contents
    }


def main():
    args = demisto.args()
    event_sender = EventSender()
    if demisto.command() == 'test-module':
        event_sender.validate()
        demisto.results('ok')
    elif demisto.command() == 'dxl-send-event':
        results = event_sender.send_event_wrapper(
            args.get('topic'),
            args.get('payload')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-ip':
        results = event_sender.push_ip(
            args.get('ip'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-url':
        results = event_sender.push_url(
            args.get('url'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-domain':
        results = event_sender.push_domain(
            args.get('domain'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-hash':
        results = event_sender.push_hash(
            args.get('hash'),
            args.get('trust_level')
        )
        demisto.results(results)


if __name__ in ("__builtin__", "builtins"):
    main()

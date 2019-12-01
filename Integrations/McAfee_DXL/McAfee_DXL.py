import demistomock as demisto
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxlclient.message import Event

# from datetime import datetime

broker_ca_bundle = './brokercerts.crt'
with open(broker_ca_bundle, "w") as text_file:
    text_file.write(demisto.params()['broker_ca_bundle'])

cert_file = './cert_file.crt'
with open(cert_file, "w") as text_file:
    text_file.write(demisto.params()['cert_file'])

private_key = './private_key.key'
with open(private_key, "w") as text_file:
    text_file.write(demisto.params()['private_key'])

broker_urls = demisto.params()['broker_urls'].split(',')

push_ip_topic = demisto.params()['push_ip_topic']
push_url_topic = demisto.params()['push_url_topic']
push_domain_topic = demisto.params()['push_domain_topic']
push_hash_topic = demisto.params()['push_ip_topic']


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


def get_trust_level_key(trust_level):
    trust_level_key = None
    for k, v in TRUST_LEVELS.iteritems():
        if v == trust_level:
            trust_level_key = k

    if not trust_level_key:
        raise Exception('illigale argument trust_level %s. Choose value from predefined values' % (trust_level, ))
    return trust_level_key


def create_error_entry(contents):
    return {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['error'],
        'Contents': contents
    }


def get_client_config():
    config = DxlClientConfig(
        broker_ca_bundle=broker_ca_bundle,
        cert_file=cert_file,
        private_key=private_key,
        brokers=[Broker.parse(url) for url in broker_urls]
    )

    config.connect_retries = 1
    config.reconnect_delay = 1
    config.reconnect_delay_max = 10

    return config


def test():
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        client.disconnect()


def send_event(topic, payload):
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        event = Event(topic)
        event.payload = str(payload).encode()
        client.send_event(event)


def send_event_wrapper(topic, payload):
    try:
        send_event(topic, payload)
        return 'Successfully sent event'
    except Exception as ex:
        return create_error_entry(str(ex))


def push_ip(ip, trust_level):
    if not (is_ip_valid(ip)):
        return create_error_entry('argument ip %s is not a valid IP' % (ip,))

    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_ip_topic, 'ip:%s;trust_level:%s' % (ip, trust_level_key))
        return 'Successfully pushed ip %s with trust level %s' % (ip, trust_level,)
    except Exception as ex:
        return create_error_entry(str(ex))


def push_url(url, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_url_topic, 'url:%s;trust_level:%s' % (url, trust_level_key))
        return 'Successfully pushed url %s with trust level %s' % (url, trust_level,)
    except Exception as ex:
        return create_error_entry(str(ex))


def push_domain(domain, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_domain_topic, 'domain:%s;trust_level:%s' % (domain, trust_level_key))
        return 'Successfully pushed domain %s with trust level %s' % (domain, trust_level,)
    except Exception as ex:
        return create_error_entry(str(ex))


def push_hash(hash, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_hash_topic, 'hash:%s;trust_level:%s' % (hash, trust_level_key))
        return 'Successfully pushed hash %s with trust level %s' % (hash, trust_level,)
    except Exception as ex:
        return create_error_entry(str(ex))


if __name__ == '__main__':
    args = demisto.args()
    if demisto.command() == 'test-module':
        test()
        demisto.results('ok')
        sys.exit(0)
    elif demisto.command() == 'dxl-send-event':
        results = send_event_wrapper(
            args.get('topic'),
            args.get('payload')
        )
        demisto.results(results)
        sys.exit(0)
    elif demisto.command() == 'dxl-push-ip':
        results = push_ip(
            args.get('ip'),
            args.get('trust_level')
        )
        demisto.results(results)
        sys.exit(0)
    elif demisto.command() == 'dxl-push-url':
        results = push_url(
            args.get('url'),
            args.get('trust_level')
        )
        demisto.results(results)
        sys.exit(0)
    elif demisto.command() == 'dxl-push-domain':
        results = push_domain(
            args.get('domain'),
            args.get('trust_level')
        )
        demisto.results(results)
        sys.exit(0)
    elif demisto.command() == 'dxl-push-hash':
        results = push_hash(
            args.get('hash'),
            args.get('trust_level')
        )
        demisto.results(results)
        sys.exit(0)

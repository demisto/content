import demistomock as demisto
import hashlib
from typing import Dict
from CommonServerPython import *
from dxlfiletransferclient import *
from dxlfiletransferservice import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxlclient.message import Event


# broker_ca_bundle = './brokercerts.crt'
# with open(broker_ca_bundle, "w") as text_file:
#     text_file.write(demisto.params()['broker_ca_bundle'])
#
#
# cert_file = './cert_file.crt'
# with open(cert_file, "w") as text_file:
#     text_file.write(demisto.params()['cert_file'])
#
#
# private_key = './private_key.key'
# with open(private_key, "w") as text_file:
#     text_file.write(demisto.params()['private_key'])
#
#
# broker_urls = 'ssl://content.demisto.works'
# broker_urls = demisto.params()['broker_urls'].split(',')
#
# push_ip_topic = demisto.params()['push_ip_topic']
# push_url_topic = demisto.params()['push_url_topic']
# push_domain_topic = demisto.params()['push_domain_topic']
# push_hash_topic = demisto.params()['push_ip_topic']


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
    for key, value in TRUST_LEVELS.items():
        if value == trust_level:
            return key

    raise Exception(f'Illegal argument trust_level {trust_level}. Choose value from predefined values')


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


def validate():
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
    except Exception as exception:
        return create_error_entry(str(exception))


def push_ip(ip, trust_level):
    if not (is_ip_valid(ip)):
        return create_error_entry(f'argument ip {ip} is not a valid IP')

    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_ip_topic, f'ip:{ip};trust_level:{trust_level_key}')
        return f'Successfully pushed ip {ip} with trust level {trust_level_key}'
    except Exception as exception:
        return create_error_entry(str(exception))


def push_url(url, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_url_topic, f'url:{url};trust_level:{trust_level_key}')
        return f'Successfully pushed url {url} with trust level {trust_level}'
    except Exception as exception:
        return create_error_entry(str(exception))


def push_domain(domain, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_domain_topic, f'domain:{domain};trust_level:{trust_level}')
        return f'Successfully pushed domain {domain} with trust level {trust_level}'
    except Exception as exception:
        return create_error_entry(str(exception))


def push_hash(hash_obj, trust_level):
    try:
        trust_level_key = get_trust_level_key(trust_level)
        send_event(push_hash_topic, f'hash:{hash_obj};trust_level:{trust_level_key}')
        return f'Successfully pushed hash {hash_obj} with trust level {trust_level_key}'
    except Exception as exception:
        return create_error_entry(str(exception))


def upload_file(topic: str, entry_id: str) -> Dict:
    result = {}
    config = get_client_config()
    with DxlClient(config) as dxl_client:
        dxl_client.connect()
        res_dict = {}
        file_params: Dict = demisto.getFilePath(entry_id)
        MAX_SEGMENT_SIZE = 50 * (2 ** 10)
        STORE_FILE_NAME = file_params.get('path')
        STORE_FILE_DIR = ''
        # Create client wrapper
        client = FileTransferClient(dxl_client)

        result = client.send_file_request(
            STORE_FILE_NAME,
            file_name_on_server=os.path.join(
                STORE_FILE_DIR, os.path.basename(STORE_FILE_NAME)),
            max_segment_size=MAX_SEGMENT_SIZE)

        # Print out the response (convert dictionary to JSON for pretty printing)
        print(result)

    return result


def main():
    args = demisto.args()
    if demisto.command() == 'test-module':
        validate()
        demisto.results('ok')
    elif demisto.command() == 'dxl-send-event':
        results = send_event_wrapper(
            args.get('topic'),
            args.get('payload')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-ip':
        results = push_ip(
            args.get('ip'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-url':
        results = push_url(
            args.get('url'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-domain':
        results = push_domain(
            args.get('domain'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-push-hash':
        results = push_hash(
            args.get('hash'),
            args.get('trust_level')
        )
        demisto.results(results)
    elif demisto.command() == 'dxl-upload-file':
        result = upload_file(
            args.get('topic'),
            args.get('EntryID')
        )
        demisto.results(result)


if __name__ in ("__builtin__", "builtins"):
    main()

broker_urls = ['ssl://content.demisto.works:8883']
private_key = '/Users/esharf/crt/dxl/private.key'
cert_file = '/Users/esharf/crt/dxl/dxl.crt'
broker_ca_bundle = '/Users/esharf/crt/dxl/dxl_chain.crt'

push_ip_topic = 'DXL_PUSH_IP'
push_url_topic = 'DXL_PUSH_URL'
push_domain_topic = 'DXL_PUSH_DOMAIN'
push_hash_topic = 'DXL_PUSH_HASH'

main()

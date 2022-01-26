import demistomock as demisto
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxltieclient import TieClient
from dxltieclient.constants import HashType
from datetime import datetime

VENDOR_NAME = 'McAfee Threat Intelligence Exchange'

HASH_TYPE_KEYS = {
    'md5': HashType.MD5,
    'sha1': HashType.SHA1,
    'sha256': HashType.SHA256
}

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

POVIDER = {
    '1': 'Global Threat Intelligence (GTI)',
    '3': 'Enterprise reputation',
    '5': 'Advanced Threat Defense (ATD)',
    '7': 'Web Gateway (MWG)'
}


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


def create_error_entry(contents):
    return {'ContentsFormat': formats['text'], 'Type': entryTypes['error'], 'Contents': contents}


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


def get_provider(provider_id):
    provider_id_str = str(provider_id)
    return POVIDER.get(provider_id_str, provider_id_str)


def parse_reputation(rep):
    # get trust level
    trust_level = str(rep.get('trustLevel'))
    verbose_trust_level = TRUST_LEVELS.get(trust_level, trust_level)

    # get provider
    provider_id = rep.get('providerId')
    provider = get_provider(provider_id)

    # get date
    create_date = rep.get('createDate')
    create_date_str = str(datetime.fromtimestamp(create_date))

    res = {
        'Trust level': trust_level,
        'Trust level (verbose)': verbose_trust_level,
        'Provider ID': provider_id,
        'Provider (verbose)': provider,
        'Created date': create_date_str
    }

    return res


def parse_reference(reference):
    agent_guid = reference.get('agentGuid')
    date = reference.get('date')
    try:
        date = datetime.fromtimestamp(date)
    except ValueError:
        date = datetime.fromtimestamp(date / 1000)

    return {
        'Date': str(date),
        'AgentGuid': agent_guid.replace('{', '').replace('}', '')  # remove brackets if exist
    }


def reputations_to_table(reputations):
    return [parse_reputation(rep) for rep in reputations]


def references_to_table(references):
    return [parse_reference(ref) for ref in references]


def trust_level_to_score(trust_level):
    if (trust_level >= 70):
        return 1
    elif (trust_level == 30):
        return 2
    elif (trust_level == 0 or trust_level == 50):
        return 0
    elif (trust_level < 30):
        return 3
    else:
        # Shouldn't reach here, as the API doesn't support 31-69 values except for 50)
        return 0


def get_thrust_level_and_score(reputations):
    trust_level = 101  # more than the highst possible trust level
    vendor = VENDOR_NAME

    for rep in reputations:
        rep_trust_level = rep.get('trustLevel', 0)
        if rep_trust_level != 0 and rep_trust_level < trust_level:
            trust_level = rep.get('trustLevel')
            vendor = get_provider(rep.get('providerId'))

    if trust_level == 101:
        # no trust_level found
        return {
            'trust_level': 0,
            'score': 0,
            'vendor': vendor
        }

    score = trust_level_to_score(trust_level)

    if (vendor == 'Enterprise reputation'):
        vendor = VENDOR_NAME
    return {
        'trust_level': trust_level,
        'score': score,
        'vendor': vendor
    }


def test():
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        client.disconnect()


def safe_get_file_reputation(tie_client, hash_param):
    try:
        res = tie_client.get_file_reputation(hash_param)
    except Exception as e:
        demisto.log("McAfee failed to get file reputation with error: " + str(e))
        return None
    return res


def file(hash_inputs):
    hash_list = []

    for hash_value in hash_inputs:
        config = get_client_config()
        with DxlClient(config) as client:
            client.connect()
            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            hash_type = get_hash_type(hash_value)
            hash_type_key = HASH_TYPE_KEYS.get(hash_type)
            if not hash_type_key:
                return create_error_entry('file argument must be sha1(40 charecters) or sha256(64 charecters)'
                                          ' or md5(32 charecters)')

            hash_param = {}
            reputations = {}
            context_file = {}
            hash_param[hash_type_key] = hash_value
            res = safe_get_file_reputation(tie_client, hash_param)
            if not res:
                dbot_score = [{'Indicator': hash_value, 'Type': 'hash', 'Vendor': VENDOR_NAME, 'Score': 0},
                              {'Indicator': hash_value, 'Type': 'file', 'Vendor': VENDOR_NAME, 'Score': 0}]
            else:
                reputations = res.values()

                # create context
                hash_type_uppercase = hash_type.upper()
                tl_score = get_thrust_level_and_score(reputations)

                context_file[hash_type_uppercase] = hash_value
                context_file['TrustLevel'] = tl_score['trust_level']
                context_file['Vendor'] = tl_score['vendor']

                dbot_score = [{'Indicator': hash_value, 'Type': 'hash', 'Vendor': tl_score['vendor'],
                               'Score': tl_score['score']},
                              {'Indicator': hash_value, 'Type': 'file', 'Vendor': tl_score['vendor'],
                               'Score': tl_score['score']}]
                if tl_score['score'] >= 2:
                    context_file['Malicious'] = {
                        'Vendor': tl_score['vendor'],
                        'Score': tl_score['score'],
                        'Description': 'Trust level is ' + str(tl_score['trust_level'])
                    }
            ec = {'DBotScore': dbot_score, outputPaths['file']: context_file}

        table = reputations_to_table(reputations)
        hash_list.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': reputations,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('McAfee TIE Hash Reputations For %s:' % (hash_value,), table),
            'EntryContext': ec
        })
    return hash_list


def file_references(hash):
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)

        hash_type = get_hash_type(hash)
        hash_type_key = HASH_TYPE_KEYS.get(hash_type)
        if not hash_type_key:
            return create_error_entry('file argument must be sha1(40 charecters) or sha256(64 charecters) or md5(32 charecters)')

        hash_param = {}
        hash_param[hash_type_key] = hash

        references = tie_client.get_file_first_references(hash_param)

        table = references_to_table(references)

        # creaet context
        context_file = {}
        hash_type_uppercase = hash_type.upper()

        context_file[hash_type_uppercase] = hash
        context_file['References'] = table
        ec = {}
        ec[outputPaths['file']] = context_file
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': references,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('References for hash %s' % (hash,), table),
            'EntryContext': ec
        }


def set_file_reputation(hash, trust_level, filename, comment):
    config = get_client_config()

    # find trust_level key
    trust_level_key = None
    for k, v in TRUST_LEVELS.iteritems():
        if v == trust_level:
            trust_level_key = k

    if not trust_level_key:
        return create_error_entry('illigale argument trust_level %s. Choose value from predefined values' % (trust_level, ))

    with DxlClient(config) as client:
        client.connect()
        tie_client = TieClient(client)

        hash_type = get_hash_type(hash)
        hash_type_key = HASH_TYPE_KEYS.get(hash_type)
        if not hash_type_key:
            return create_error_entry('file argument must be sha1(40 charecters) or sha256(64 charecters) or md5(32 charecters)')

        hash_param = {}
        hash_param[hash_type_key] = hash

        try:
            tie_client.set_file_reputation(trust_level_key, hash_param, filename, comment)
            return 'Successfully set file repuation'
        except Exception as ex:
            return create_error_entry(str(ex))


def main():
    try:
        args = demisto.args()
        if demisto.command() == 'test-module':
            test()
            demisto.results('ok')
        elif demisto.command() == 'file':
            results = file(argToList(args.get('file')))
            demisto.results(results)
        elif demisto.command() == 'tie-file-references':
            results = file_references(args.get('file'))
            demisto.results(results)
        elif demisto.command() == 'tie-set-file-reputation':
            results = set_file_reputation(
                args.get('file'),
                args.get('trust_level'),
                args.get('filename'),
                args.get('comment')
            )
            demisto.results(results)
    except Exception as e:
        validate_certificates_format()
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
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

    main()

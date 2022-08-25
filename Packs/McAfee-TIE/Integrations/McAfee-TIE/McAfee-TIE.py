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


def get_trust_level_and_score(reputations):
    trust_level = 101  # more than the highst possible trust level
    vendor = VENDOR_NAME

    for reputation in reputations:
        rep_trust_level = reputation.get('trustLevel', 0)
        if rep_trust_level != 0 and rep_trust_level < trust_level:
            trust_level = rep_trust_level
            vendor = get_provider(reputation.get('providerId'))

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


def test_module():
    """Tests if there is a connection with DxlClient(which is used for connection with McAfee TIE, instead of the Client class)"""
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        client.disconnect()
        return 'ok'


def safe_get_file_reputation(tie_client, api_input):
    try:
        res = tie_client.get_file_reputation(api_input)
    except Exception as e:
        print(str(e))
        demisto.info("McAfee failed to get file reputation with error: " + str(e))
        return None
    return res


def file(files_hash: List[str]) -> List[CommandResults]:
    # TODO Ask Dor how to add Common.File and if there is documentation
    command_results: List[CommandResults] = []
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)
        for file_hash in files_hash:
            hash_type = get_hash_type(file_hash)
            hash_type_key = HASH_TYPE_KEYS.get(hash_type)
            if not hash_type_key:
                raise Exception('The file format must be of type SHA-1, SHA-256 or MD5')

            file: Dict[str, Any] = {}
            reputations = {}
            hash_type_uppercase = hash_type.upper()
            file[hash_type_uppercase] = file_hash
            api_input = {hash_type_key: file_hash}
            raw_result = safe_get_file_reputation(tie_client, api_input)
            if not raw_result:
                dbot_score = {'Indicator': file_hash,
                              'Type': 'hash',
                              'Vendor': VENDOR_NAME,
                              'Score': 0,
                              }
                file['TrustLevel'] = 0
                file['Vendor'] = VENDOR_NAME
            else:
                reputations = raw_result.values()

                tl_score = get_trust_level_and_score(reputations)
                trust_level = tl_score['trust_level']
                vendor = tl_score['vendor']
                score = tl_score['score']

                file['TrustLevel'] = trust_level
                file['Vendor'] = vendor

                dbot_score = {'Indicator': file_hash,
                              'Type': 'hash',
                              'Vendor': vendor,
                              'Score': score,
                              'Reliability': demisto.params().get('integrationReliability', 'C - Fairly reliable'),
                              }
                    
                    # TODO Check if I need two entries for DBotScore
                    # {'Indicator': file_hash, 'Type': 'file', 'Vendor': tl_score['vendor'],
                    #     'Score': tl_score['score'], 'Reliability': demisto.params().get('integrationReliability')}

                if score >= 2:
                    file['Malicious'] = {'Vendor': vendor,
                                         'Score': score,
                                         'Description': 'Trust level is ' + str(tl_score['trust_level'])
                                         }
            entry_context = {'DBotScore': dbot_score, 'File': file}
            table = reputations_to_table(reputations)
            command_results.append(
                CommandResults(readable_output=tableToMarkdown('McAfee TIE Hash Reputations For %s:' % (file_hash,), table),
                               raw_response=raw_result,
                               outputs_prefix='McAfee.TIE',
                               outputs=entry_context,
                               )
            )
           
    return command_results


def file_references(hash):
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)

        hash_type = get_hash_type(hash)
        hash_type_key = HASH_TYPE_KEYS.get(hash_type)
        if not hash_type_key:
            return create_error_entry(
                'file argument must be sha1(40 charecters) or sha256(64 charecters) or md5(32 charecters)')

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
        return create_error_entry(
            'illigale argument trust_level %s. Choose value from predefined values' % (trust_level,))

    with DxlClient(config) as client:
        client.connect()
        tie_client = TieClient(client)

        hash_type = get_hash_type(hash)
        hash_type_key = HASH_TYPE_KEYS.get(hash_type)
        if not hash_type_key:
            return create_error_entry(
                'file argument must be sha1(40 charecters) or sha256(64 charecters) or md5(32 charecters)')

        hash_param = {}
        hash_param[hash_type_key] = hash

        try:
            tie_client.set_file_reputation(trust_level_key, hash_param, filename, comment)
            return 'Successfully set file repuation'
        except Exception as ex:
            return create_error_entry(str(ex))


def main():
    command = demisto.command()
    args = demisto.args()
    try:
        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            test_result = test_module()
            return_results(test_result)

        elif command == 'file':
            args_to_list = argToList(args.get('file'))
            results = file(args_to_list)
            return_results(results)

        elif command == 'tie-file-references':
            results = file_references(args.get('file'))
            return_results(results)
      
        elif command == 'tie-set-file-reputation':
            results = set_file_reputation(
                args.get('file'),
                args.get('trust_level'),
                args.get('filename'),
                args.get('comment')
            )
            return_results(results)

        else:
            raise NotImplementedError(f'Command {command} is not supported.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


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

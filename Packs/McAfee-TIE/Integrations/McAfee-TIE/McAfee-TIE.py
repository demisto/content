import demistomock as demisto
import tempfile
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxltieclient import TieClient
from datetime import datetime
from typing import NamedTuple
from dxltieclient.constants import FileReputationProp, FileGtiAttrib, FileEnterpriseAttrib, AtdAttrib, EpochMixin, TrustLevel,\
    HashType, EnterpriseAttrib, FileProvider

VENDOR_NAME = 'McAfee Threat Intelligence Exchange'
OUTPUT_PREFIX = 'McAfee.TIE'
LOWEST_TRUST_LEVEL_KEY = 'lowest_trust_level_key'
LOWEST_SCORE_KEY = 'lowest_score_key'


DXLConfigFiles = NamedTuple('DXLConfigFiles', [('broker_ca_bundle', str),
                                               ('cert_file', str),
                                               ('private_key', str),
                                               ('broker_urls', list[str]),
                                               ])


class McAfeeTieConstants(object):

    PROVIDERS = {
        FileProvider.GTI: 'Global Threat Intelligence (GTI)',
        FileProvider.ENTERPRISE: 'Enterprise reputation',
        FileProvider.ATD: 'Advanced Threat Defense (ATD)',
        FileProvider.MWG: 'Web Gateway (MWG)'
    }

    TRUST_LEVELS = {
        TrustLevel.KNOWN_TRUSTED_INSTALLER: 'KNOWN_TRUSTED_INSTALLER',
        TrustLevel.KNOWN_TRUSTED: 'KNOWN_TRUSTED',
        TrustLevel.MOST_LIKELY_TRUSTED: 'MOST_LIKELY_TRUSTED',
        TrustLevel.MIGHT_BE_TRUSTED: 'MIGHT_BE_TRUSTED',
        TrustLevel.UNKNOWN: 'UNKNOWN',
        TrustLevel.MIGHT_BE_MALICIOUS: 'MIGHT_BE_MALICIOUS',
        TrustLevel.MOST_LIKELY_MALICIOUS: 'MOST_LIKELY_MALICIOUS',
        TrustLevel.KNOWN_MALICIOUS: 'KNOWN_MALICIOUS',
        TrustLevel.NOT_SET: 'NOT_SET',
    }

    HASH_TYPE_KEYS = {
        'md5': HashType.MD5,
        'sha1': HashType.SHA1,
        'sha256': HashType.SHA256
    }


class GeneralFileReputationParser(object):
    GENERAL_REPUTATION_KEYS = {
        FileReputationProp.PROVIDER_ID: "Provider",
        FileReputationProp.TRUST_LEVEL: "Trust Level",
        FileReputationProp.CREATE_DATE: "Create Date",
    }

    # PROVOIDERS_FILE_REPUTATION_PARSER = {
    #     FileProvider.GTI: GtiFileReputationParser,
    #     FileProvider.ENTERPRISE: EnterpriseFileReputationParser,
    #     FileProvider.ATD: AtdFileReputationParser,
    # }

    @staticmethod
    def init(provider: int):
        if(provider == FileProvider.GTI):
            return GtiFileReputationParser()
        elif(provider == FileProvider.ENTERPRISE):
            return EnterpriseFileReputationParser()
        elif(provider == FileProvider.ATD):
            return AtdFileReputationParser()
        return None

    @abstractmethod
    def parse_data(self, reputation_data: Dict[str, Any]) -> Dict[str, Any]:
        # Every child class must implement this function
        pass

    def parse_attributes(self, attributes: Dict[str, Any], parsed_res: Dict[str, Any]):
        pass

    def parse_reputation_key(self, reputation_key: str, val: Any, parsed_res: Dict[str, Any]):
        if(reputation_key == FileReputationProp.PROVIDER_ID):
            parsed_res[self.GENERAL_REPUTATION_KEYS[reputation_key]] = McAfeeTieConstants.PROVIDERS[val]

        elif(reputation_key == FileReputationProp.CREATE_DATE):
            parsed_res[self.GENERAL_REPUTATION_KEYS[reputation_key]] = EpochMixin.to_localtime_string(val)

        elif(reputation_key in self.GENERAL_REPUTATION_KEYS):
            parsed_res[self.GENERAL_REPUTATION_KEYS[reputation_key]] = val

    # TODO Ask how to add type of fileReputationParser variable
    def parse_data_helper(self, fileReputationParser, reputation_data: Dict[str, Any]):
        parsed_res: Dict[str, Any] = {}
        for key, val in reputation_data.items():
            if(key == FileReputationProp.ATTRIBUTES):
                fileReputationParser.parse_attributes(attributes=val,
                                                      parsed_res=parsed_res,
                                                      )
            else:
                self.parse_reputation_key(reputation_key=key,
                                          val=val,
                                          parsed_res=parsed_res,
                                          )
        return parsed_res


class GtiFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        FileGtiAttrib.FIRST_CONTACT: "First Contact",
        FileGtiAttrib.PREVALENCE: "Prevalence",
        FileGtiAttrib.ORIGINAL_RESPONSE: "Original Response",
    }

    def parse_attributes(self, attributes: Dict[str, Any], parsed_res: Dict[str, Any]):
        for key, val in attributes.items():
            if(key == FileGtiAttrib.FIRST_CONTACT):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = EpochMixin.to_localtime_string(val)
            elif(key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

    def parse_data(self, reputation_data: Dict[str, Any]) -> Dict[str, Any]:
        return super().parse_data_helper(fileReputationParser=self,
                                         reputation_data=reputation_data)


class EnterpriseFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        FileEnterpriseAttrib.SERVER_VERSION: "Server Version",
        FileEnterpriseAttrib.FIRST_CONTACT: "First Contact",
        FileEnterpriseAttrib.PREVALENCE: "Prevalence",
        FileEnterpriseAttrib.ENTERPRISE_SIZE: "Enterprise Size",
        FileEnterpriseAttrib.MIN_LOCAL_REP: "Min Local Rep",
        FileEnterpriseAttrib.MAX_LOCAL_REP: "Max Local Rep",
        FileEnterpriseAttrib.AVG_LOCAL_REP: "Avg Local Rep",
        FileEnterpriseAttrib.PARENT_MIN_LOCAL_REP: "Parent Min Local Rep",
        FileEnterpriseAttrib.PARENT_MAX_LOCAL_REP: "Parent Max Local Rep",
        FileEnterpriseAttrib.PARENT_AVG_LOCAL_REP: "Parent Avg Local Rep",
        FileEnterpriseAttrib.FILE_NAME_COUNT: "File Name Count",
        FileEnterpriseAttrib.DETECTION_COUNT: "Detection Count",
        FileEnterpriseAttrib.LAST_DETECTION_TIME: "Last Detection Time",
        FileEnterpriseAttrib.IS_PREVALENT: "Is Prevalent",
        FileEnterpriseAttrib.CHILD_FILE_REPS: "Child File Reps",
        FileEnterpriseAttrib.PARENT_FILE_REPS: "Parent File Reps",
    }

    def parse_attributes(self, attributes: Dict[str, Any], parsed_res: Dict[str, Any]):
        for key, val in attributes.items():
            if(key == FileEnterpriseAttrib.FIRST_CONTACT or key == FileEnterpriseAttrib.LAST_DETECTION_TIME):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = EpochMixin.to_localtime_string(val)

            elif(key == FileEnterpriseAttrib.SERVER_VERSION):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = EnterpriseAttrib.to_version_string(val)

            elif(key == FileEnterpriseAttrib.CHILD_FILE_REPS or key == FileEnterpriseAttrib.PARENT_FILE_REPS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = FileEnterpriseAttrib.to_aggregate_tuple(val)

            elif(key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

    def parse_data(self, reputation_data: Dict[str, Any]) -> Dict[str, Any]:
        return super().parse_data_helper(fileReputationParser=self,
                                         reputation_data=reputation_data)


class AtdFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        AtdAttrib.GAM_SCORE: "GAM Score",
        AtdAttrib.AV_ENGINE_SCORE: "AV Engine Score",
        AtdAttrib.SANDBOX_SCORE: "Sandbox Score",
        AtdAttrib.VERDICT: "Verdict",
        AtdAttrib.BEHAVIORS: "Behaviors",
    }

    def parse_attributes(self, attributes: Dict[str, Any], parsed_res: Dict[str, Any]):
        # TODO Ask about the behaviors key
        for key, val in attributes.items():
            if(key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

    def parse_data(self, reputation_data: Dict[str, Any]) -> Dict[str, Any]:
        return super().parse_data_helper(fileReputationParser=self,
                                         reputation_data=reputation_data)


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


def get_client_config(dxl_config_files: DXLConfigFiles):
    config = DxlClientConfig(
        broker_ca_bundle=dxl_config_files.broker_ca_bundle,
        cert_file=dxl_config_files.cert_file,
        private_key=dxl_config_files.private_key,
        brokers=[Broker.parse(url) for url in dxl_config_files.broker_urls]
    )

    config.connect_retries = 1
    config.reconnect_delay = 1
    config.reconnect_delay_max = 10

    return config


def get_provider(provider_id):
    return McAfeeTieConstants.PROVIDERS[provider_id]


def parse_reputation_human_readable(reputation):
    # get trust level
    trust_level = reputation.get(FileReputationProp.TRUST_LEVEL)
    verbose_trust_level = McAfeeTieConstants.TRUST_LEVELS.get(trust_level, trust_level)

    # get provider
    provider_id = reputation.get(FileReputationProp.PROVIDER_ID)
    provider = get_provider(provider_id)

    # get date
    create_date = reputation.get(FileReputationProp.CREATE_DATE)
    create_date_str = EpochMixin.to_localtime_string(create_date)

    res = {
        'Trust level': trust_level,
        'Trust level (verbose)': verbose_trust_level,
        'Provider ID': provider_id,
        'Provider (verbose)': provider,
        'Created date': create_date_str
    }

    return res


def parse_reference_human_readable(reference):
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


def reputations_to_human_readable(reputations):
    return [parse_reputation_human_readable(rep) for rep in reputations]


def references_to_human_readable(references):
    return [parse_reference_human_readable(ref) for ref in references]


def trust_level_to_score(trust_level):
    if (trust_level >= TrustLevel.MIGHT_BE_TRUSTED):
        # return 1
        return Common.DBotScore.GOOD
    elif (trust_level == TrustLevel.MIGHT_BE_MALICIOUS):
        # return 2
        return Common.DBotScore.SUSPICIOUS
    elif (trust_level == TrustLevel.NOT_SET or trust_level == TrustLevel.UNKNOWN):
        # return 0
        return Common.DBotScore.NONE
    elif (trust_level < TrustLevel.MIGHT_BE_MALICIOUS):
        # return 3
        return Common.DBotScore.BAD
    else:
        # TODO Ask TPM what we should do in this case
        # Shouldn't reach here, as the API doesn't support 31-69 values except for 50)
        return Common.DBotScore.NONE


def test_module(dxl_config_files: DXLConfigFiles):
    """Tests if there is a connection with DxlClient(which is used for connection with McAfee TIE, instead of the Client class)"""
    config = get_client_config(dxl_config_files)
    with DxlClient(config) as client:
        client.connect()
        # client.disconnect()
        return 'ok'


def safe_get_file_reputation(tie_client: TieClient, api_input: Dict[str, str]):
    try:
        res = tie_client.get_file_reputation(api_input)
    except Exception as e:
        print(str(e))
        demisto.info(f'McAfee failed to get file reputation with error: {str(e)}')
        return None
    return res


def get_hash_type_key(file_hash: str):
    hash_type = get_hash_type(file_hash)
    return McAfeeTieConstants.HASH_TYPE_KEYS.get(hash_type, None)


# def get_lowest_trust_level_and_score(reputations):
#     max_trust_level = TrustLevel.KNOWN_TRUSTED_INSTALLER + 1
#     lowest_trust_level = max_trust_level  # more than the maximum possible trust level

#     for reputation in reputations:
#         rep_trust_level = reputation.get(FileReputationProp.TRUST_LEVEL, 0)
#         if rep_trust_level != 0 and rep_trust_level < lowest_trust_level:
#             lowest_trust_level = rep_trust_level

#     if lowest_trust_level == max_trust_level:
#         # No trust_level found
#         return {
#             LOWEST_TRUST_LEVEL_KEY: 0,
#             LOWEST_SCORE_KEY: 0,
#         }

#     score = trust_level_to_score(lowest_trust_level)

#     return {
#         LOWEST_TRUST_LEVEL_KEY: lowest_trust_level,
#         LOWEST_SCORE_KEY: score,
#     }


def parse_reputation(provider_id: int, reputation: Dict):
    # TODO Check if we should keep provider_id int or Any
    file_reputation_parser = GeneralFileReputationParser.init(provider=provider_id)
    if(file_reputation_parser is None):
        raise Exception('Unexpected provider ID returned')
    parsed_reputation = file_reputation_parser.parse_data(reputation_data=reputation)
    return parsed_reputation


def parse_raw_result(raw_result: Dict, file_hash: str, reliability: str, hash_type_key: str):
    context_data = {}
    parsed_reputation_data = {}
    max_trust_level = TrustLevel.KNOWN_TRUSTED_INSTALLER + 1  # more than the maximum possible trust level
    lowest_trust_level = max_trust_level
    reputations = raw_result.values()
    for reputation in reputations:
        # Parse the raw result of each reputation result
        provider_id = reputation[FileReputationProp.PROVIDER_ID]
        parsed_reputation_data[provider_id] = parse_reputation(provider_id=provider_id,
                                                               reputation=reputation)
        # Get the vendor's data with the lowest score
        rep_trust_level = reputation.get(FileReputationProp.TRUST_LEVEL, 0)
        if rep_trust_level != 0 and rep_trust_level < lowest_trust_level:
            lowest_trust_level = rep_trust_level
    if lowest_trust_level == max_trust_level:
        # TODO Check if we really need this since Trust Level is an essential return value by the API
        # No trust_level found
        lowest_tl_score = {
            LOWEST_TRUST_LEVEL_KEY: TrustLevel.NOT_SET,
            LOWEST_SCORE_KEY: Common.DBotScore.NONE
        }
    else:
        lowest_tl_score = {
            LOWEST_TRUST_LEVEL_KEY: lowest_trust_level,
            LOWEST_SCORE_KEY: trust_level_to_score(lowest_trust_level)
        }
    dbot_score = Common.DBotScore(indicator=file_hash,
                                  indicator_type=DBotScoreType.FILE,
                                  reliability=reliability,
                                  score=lowest_tl_score[LOWEST_SCORE_KEY],
                                  )
    file_instance = Common.File(dbot_score=dbot_score,
                                md5=file_hash if hash_type_key == HashType.MD5 else None,
                                sha1=file_hash if hash_type_key == HashType.SHA1 else None,
                                sha256=file_hash if hash_type_key == HashType.SHA256 else None)
    if lowest_tl_score[LOWEST_SCORE_KEY] >= Common.DBotScore.SUSPICIOUS:
        dbot_score.malicious_description = f"Trust level is {str(lowest_tl_score[LOWEST_TRUST_LEVEL_KEY])}"
    context_data = {file_hash: parsed_reputation_data}
    table = reputations_to_human_readable(reputations)
    return CommandResults(readable_output=tableToMarkdown(f'McAfee TIE Hash Reputations For {file_hash}:', table),
                          raw_response=raw_result,
                          outputs_prefix=OUTPUT_PREFIX,
                          outputs=context_data,
                          indicator=file_instance,
                          )


def file(hashes: List[str], dxl_config_files: DXLConfigFiles, reliability: str) -> List[CommandResults]:

    command_results: List[CommandResults] = []
    config = get_client_config(dxl_config_files)
    # TODO Make sure if you need to use the following function
    with DxlClient(config) as client:
        # TODO Add meaningful error message when you get an error in the connection or configuration phase
        client.connect()
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)
        for file_hash in hashes:
            
            hash_type_key = get_hash_type_key(file_hash=file_hash)
            if not hash_type_key:
                # TODO Check if I should raise Exception or DemistoException
                raise Exception('The file format must be of type SHA-1, SHA-256 or MD5')
            api_input = {hash_type_key: file_hash}
            raw_result = safe_get_file_reputation(tie_client, api_input)
            if not raw_result:
                dbot_score = Common.DBotScore(indicator=file_hash,
                                              indicator_type=DBotScoreType.FILE,
                                              reliability=reliability,
                                              integration_name=VENDOR_NAME,
                                              score=Common.DBotScore.NONE,
                                              )

                file_instance = Common.File(dbot_score=dbot_score,
                                            md5=file_hash if hash_type_key == HashType.MD5 else None,
                                            sha1=file_hash if hash_type_key == HashType.SHA1 else None,
                                            sha256=file_hash if hash_type_key == HashType.SHA256 else None)
                command_result = CommandResults(readable_output=tableToMarkdown(f'McAfee TIE Hash Reputations For {file_hash}:', None),
                                                raw_response=raw_result,
                                                outputs_prefix=OUTPUT_PREFIX,
                                                indicator=file_instance,
                                                )
                # TODO Ask what to do if we get no response from the API
            else:
                command_result = parse_raw_result(raw_result=raw_result,
                                                  file_hash=file_hash,
                                                  reliability=reliability,
                                                  hash_type_key=hash_type_key,
                                                  )
                # TODO Check key 2098277
            command_results.append(command_result)
    return command_results


def file_references(file_hash: str, dxl_config_files: DXLConfigFiles):
    config = get_client_config(dxl_config_files)
    with DxlClient(config) as client:
        client.connect()
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)

        hash_type_key = get_hash_type_key(file_hash=file_hash)
        if not hash_type_key:
            # return create_error_entry(
            #     'file argument must be sha1(40 charecters) or sha256(64 charecters) or md5(32 charecters)')
            raise Exception('The file format must be of type SHA-1, SHA-256 or MD5')

        api_input = {}
        api_input[hash_type_key] = file_hash

        references = tie_client.get_file_first_references(api_input)

        table = references_to_human_readable(references)

        # TODO Create correct context
        context_file = {}
        # hash_type_uppercase = hash_type.upper()

        # context_file[hash_type_uppercase] = hash
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


def set_file_reputation(hashes: List[str], dxl_config_files: DXLConfigFiles, trust_level: str, filename: str, comment: str):
    config = get_client_config(dxl_config_files)

    # find trust_level key
    trust_level_key = None
    for k, v in McAfeeTieConstants.TRUST_LEVELS.items():
        if v == trust_level:
            trust_level_key = k
            break

    if not trust_level_key:
        # TODO Maybe print the acceptable trust levels?
        raise Exception(f'Illegal argument trust_level {trust_level}. Choose value from predefined values')
        # return create_error_entry(
        #     'Illigale argument trust_level %s. Choose value from predefined values' % (trust_level,))

    with DxlClient(config) as client:
        client.connect()
        tie_client = TieClient(client)
        for file_hash in hashes:
            hash_type_key = get_hash_type_key(file_hash=file_hash)
            if not hash_type_key:
                raise Exception('The file format must be of type SHA-1, SHA-256 or MD5')

            api_input = {}
            api_input[hash_type_key] = file_hash

            tie_client.set_file_reputation(trust_level=trust_level_key,
                                           hashes=api_input,
                                           filename=filename,
                                           comment=comment)
    return 'Successfully set files reputation'


def create_temp_credentials(temp_file: tempfile._TemporaryFileWrapper, parameter_name: str):
    temp_file.write(demisto.params()[parameter_name])
    temp_file.seek(0)


def write_certificate_files():
    with tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.crt') as broker_certs_file,\
         tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.crt') as client_cert_file,\
         tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.key') as private_key_file:
        create_temp_credentials(broker_certs_file, 'broker_ca_bundle')
        create_temp_credentials(client_cert_file, 'cert_file')
        create_temp_credentials(private_key_file, 'private_key')
        dxl_config_files = DXLConfigFiles(broker_ca_bundle=broker_certs_file.name,
                                          cert_file=client_cert_file.name,
                                          private_key=private_key_file.name,
                                          broker_urls=demisto.params()['broker_urls'].split(','))
        main(dxl_config_files)


def main(dxl_config_files: DXLConfigFiles):
    command = demisto.command()
    args = demisto.args()
    reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(demisto.params().get('integrationReliability',
                                                                                                'C - Fairly reliable'))
    try:

        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(dxl_config_files))

        elif command == 'file':
            return_results(file(hashes=argToList(args.get('file')),
                                dxl_config_files=dxl_config_files,
                                reliability=reliability
                                ))

        elif command == 'tie-file-references':
            return_results(file_references(file_hash=args.get('file'),
                                           dxl_config_files=dxl_config_files,
                                           ))
      
        elif command == 'tie-set-file-reputation':
            return_results(set_file_reputation(
                           hashes=argToList(args.get('file')),
                           dxl_config_files=dxl_config_files,
                           trust_level=args.get('trust_level'),
                           filename=args.get('filename'),
                           comment=args.get('comment'),
                           ))

        else:
            raise NotImplementedError(f'Command {command} is not supported.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    write_certificate_files()

import abc
import contextlib
import tempfile
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxltieclient import TieClient
from typing import NamedTuple
from dxltieclient.constants import FileReputationProp, FileGtiAttrib, FileEnterpriseAttrib, AtdAttrib, TrustLevel, \
    HashType, EnterpriseAttrib, FileProvider, FirstRefProp, AtdTrustLevel

VENDOR_NAME = 'McAfee Threat Intelligence Exchange'
OUTPUT_PREFIX = 'McAfee.TIE'
LOWEST_TRUST_LEVEL_KEY = 'lowest_trust_level_key'
LOWEST_SCORE_KEY = 'lowest_score_key'
MAX_QUERY_LIMIT = 500


class DXLConfigFiles(NamedTuple):
    broker_ca_bundle_file: str
    client_cert_file: str
    private_key_file: str
    broker_urls: list[str]


class InstanceCertificates(NamedTuple):
    broker_ca_bundle: str
    client_cert: str
    private_key: str
    broker_urls: list[str]


class ProviderInfo(NamedTuple):
    name: str
    abbreviation: str


PROVIDER_INFO = {
    FileProvider.GTI: ProviderInfo(name='Global Threat Intelligence (GTI)', abbreviation='GTI'),
    FileProvider.ENTERPRISE: ProviderInfo(name='Enterprise reputation', abbreviation='Enterprise'),
    FileProvider.ATD: ProviderInfo(name='Advanced Threat Defense (ATD)', abbreviation='ATD'),
    FileProvider.MWG: ProviderInfo(name='Web Gateway (MWG)', abbreviation='MWG'),
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


class GeneralFileReputationParser(abc.ABC):
    """
    This abstract class is in charge of parsing the reputations' data returned from the following API call:
    https://opendxl.github.io/opendxl-tie-client-python/pydoc/dxltieclient.client.html#dxltieclient.client.TieClient.get_file_reputation
    Since all reputations have two sections, one that it is unique to each vendor, and the second that it is mutual to all,
    this class provides a method to parse the mutual section, and an abstract method that each child class
    (representing a specific vendor) must implement to parse the unique section of each vendor.
    """
    GENERAL_REPUTATION_KEYS = {
        FileReputationProp.PROVIDER_ID: "Provider",
        FileReputationProp.TRUST_LEVEL: "Trust_Level",
        FileReputationProp.CREATE_DATE: "Create_Date",
    }

    @staticmethod
    def init(provider: int):
        if (provider == FileProvider.GTI):
            return GtiFileReputationParser()

        elif (provider == FileProvider.ENTERPRISE):
            return EnterpriseFileReputationParser()

        elif (provider == FileProvider.ATD):
            return AtdFileReputationParser()

        else:
            demisto.debug(f'Unexpected provider ID returned - {provider}')
            return UnknownReputationHandler()

    @abstractmethod
    def parse_attributes(self, attributes: Dict[str, Any]):
        """
        The abstract method that is in charge of parsing the vendor's unique attributes.
        Each child class implementing this abstract method holds a dictionary that maps the data returned
        from the API (which are in numeric form) to humand readable data in order for the user to understand the
        returned results.
        """

    def parse_reputation_key(self, reputation_key: str, val: Union[str, int]):
        """
        This method is in charge of parsing the mutual section of the reputations by using the dictionary
        that is defined in the parent class (GeneralFileReputationParser).
        """
        if (reputation_key == FileReputationProp.PROVIDER_ID):
            return {self.GENERAL_REPUTATION_KEYS[reputation_key]: get_provider_name(provider_id=val)}

        elif (reputation_key == FileReputationProp.CREATE_DATE):
            return {self.GENERAL_REPUTATION_KEYS[reputation_key]: epoch_to_localtime(int(val))}

        elif (reputation_key in self.GENERAL_REPUTATION_KEYS):
            return {self.GENERAL_REPUTATION_KEYS[reputation_key]: val}

        else:
            return {reputation_key: val}

    def parse_data(self, reputation_data: Dict[str, Any]):
        """
        This method is in charge of parsing the full reputation, it does so by parsing the vendror's unique
        attributes, and the mutual attributes of all vendors.
        """
        parsed_res: Dict[str, Any] = {}
        for key, val in reputation_data.items():
            if (key == FileReputationProp.ATTRIBUTES):
                parsed_res |= self.parse_attributes(attributes=val)

            else:
                parsed_res |= self.parse_reputation_key(reputation_key=key,
                                                        val=val)
        return parsed_res


class GtiFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        FileGtiAttrib.FIRST_CONTACT: "First_Contact",
        FileGtiAttrib.PREVALENCE: "Prevalence",
        FileGtiAttrib.ORIGINAL_RESPONSE: "Original_Response",
    }

    def parse_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        parsed_res: Dict[str, Any] = {}
        for key, val in attributes.items():
            if (key == FileGtiAttrib.FIRST_CONTACT):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = epoch_to_localtime(int(val))

            elif (key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

            else:
                parsed_res[key] = val

        return parsed_res


class EnterpriseFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        FileEnterpriseAttrib.SERVER_VERSION: "Server_Version",
        FileEnterpriseAttrib.FIRST_CONTACT: "First_Contact",
        FileEnterpriseAttrib.PREVALENCE: "Prevalence",
        FileEnterpriseAttrib.ENTERPRISE_SIZE: "Enterprise_Size",
        FileEnterpriseAttrib.MIN_LOCAL_REP: "Min_Local_Rep",
        FileEnterpriseAttrib.MAX_LOCAL_REP: "Max_Local_Rep",
        FileEnterpriseAttrib.AVG_LOCAL_REP: "Avg_Local_Rep",
        FileEnterpriseAttrib.PARENT_MIN_LOCAL_REP: "Parent_Min_Local_Rep",
        FileEnterpriseAttrib.PARENT_MAX_LOCAL_REP: "Parent_Max_Local_Rep",
        FileEnterpriseAttrib.PARENT_AVG_LOCAL_REP: "Parent_Avg_Local_Rep",
        FileEnterpriseAttrib.FILE_NAME_COUNT: "File_Name_Count",
        FileEnterpriseAttrib.DETECTION_COUNT: "Detection_Count",
        FileEnterpriseAttrib.LAST_DETECTION_TIME: "Last_Detection_Time",
        FileEnterpriseAttrib.IS_PREVALENT: "Is_Prevalent",
        FileEnterpriseAttrib.CHILD_FILE_REPS: "Child_File_Reps",
        FileEnterpriseAttrib.PARENT_FILE_REPS: "Parent_File_Reps",
    }

    def parse_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        parsed_res: Dict[str, Any] = {}
        for key, val in attributes.items():
            if (key == FileEnterpriseAttrib.FIRST_CONTACT or key == FileEnterpriseAttrib.LAST_DETECTION_TIME):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = epoch_to_localtime(int(val))

            elif (key == FileEnterpriseAttrib.SERVER_VERSION):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = EnterpriseAttrib.to_version_string(val)

            elif (key == FileEnterpriseAttrib.CHILD_FILE_REPS or key == FileEnterpriseAttrib.PARENT_FILE_REPS):

                parsed_res[self.ATTRIBUTES_KEYS[key]] = val
            elif (key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

            else:
                parsed_res[key] = val

        return parsed_res


class AtdFileReputationParser(GeneralFileReputationParser):
    ATTRIBUTES_KEYS = {
        AtdAttrib.GAM_SCORE: "GAM_Score",
        AtdAttrib.AV_ENGINE_SCORE: "AV_Engine_Score",
        AtdAttrib.SANDBOX_SCORE: "Sandbox_Score",
        AtdAttrib.VERDICT: "Verdict",
        AtdAttrib.BEHAVIORS: "Behaviors",
    }
    ATD_TRUST_LEVELS = {
        AtdTrustLevel.KNOWN_TRUSTED: "KNOWN_TRUSTED",
        AtdTrustLevel.MOST_LIKELY_TRUSTED: "MOST_LIKELY_TRUSTED",
        AtdTrustLevel.MIGHT_BE_TRUSTED: "MIGHT_BE_TRUSTED",
        AtdTrustLevel.UNKNOWN: "UNKNOWN",
        AtdTrustLevel.MIGHT_BE_MALICIOUS: "MIGHT_BE_MALICIOUS",
        AtdTrustLevel.MOST_LIKELY_MALICIOUS: "MOST_LIKELY_MALICIOUS",
        AtdTrustLevel.KNOWN_MALICIOUS: "KNOWN_MALICIOUS",
        AtdTrustLevel.NOT_SET: "NOT_SET",
    }

    def parse_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        parsed_res: Dict[str, Any] = {}
        for key, val in attributes.items():
            if (key in self.ATTRIBUTES_KEYS):
                parsed_res[self.ATTRIBUTES_KEYS[key]] = val

            else:
                parsed_res[key] = val

        return parsed_res


class UnknownReputationHandler(GeneralFileReputationParser):

    def parse_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        return attributes


def get_client_config(dxl_config_files: DXLConfigFiles) -> DxlClientConfig:
    config = DxlClientConfig(
        broker_ca_bundle=dxl_config_files.broker_ca_bundle_file,
        cert_file=dxl_config_files.client_cert_file,
        private_key=dxl_config_files.private_key_file,
        brokers=[Broker.parse(url) for url in dxl_config_files.broker_urls]
    )

    config.connect_retries = 1
    config.reconnect_delay = 1
    config.reconnect_delay_max = 10

    return config


def get_provider_name(provider_id: Union[int, str]) -> str:
    provider_id_int = arg_to_number(provider_id)
    provider_info = PROVIDER_INFO.get(provider_id_int, None)
    if provider_info:
        return provider_info.name
    else:
        return str(provider_id)


def get_provider_abbr(provider_id: Union[int, str]) -> str:
    provider_id_int = arg_to_number(provider_id)
    provider_info = PROVIDER_INFO.get(provider_id_int, None)
    if provider_info:
        return provider_info.abbreviation
    else:
        return str(provider_id)


def epoch_to_localtime(epoch_time: int) -> str:
    try:
        date = datetime.fromtimestamp(epoch_time, tz=timezone.utc)
    except ValueError:
        date = datetime.fromtimestamp(epoch_time / 1000, tz=timezone.utc)

    return date.strftime("%Y-%m-%d %H:%M:%S")


def parse_reputation_human_readable(reputation):
    trust_level = reputation.get(FileReputationProp.TRUST_LEVEL)
    verbose_trust_level = TRUST_LEVELS.get(trust_level, trust_level)

    provider_id = reputation.get(FileReputationProp.PROVIDER_ID)
    provider = get_provider_name(provider_id)

    create_date = reputation.get(FileReputationProp.CREATE_DATE)
    create_date_str = epoch_to_localtime(int(create_date))

    res = {
        'Trust level': trust_level,
        'Trust level (verbose)': verbose_trust_level,
        'Provider ID': provider_id,
        'Provider (verbose)': provider,
        'Created date': create_date_str
    }

    return res


def parse_reference_human_readable(reference):
    agent_guid = reference.get(FirstRefProp.SYSTEM_GUID)
    date = reference.get(FirstRefProp.DATE)

    return {
        'Date': epoch_to_localtime(date),
        'AgentGuid': agent_guid.replace('{', '').replace('}', '')  # Remove brackets if exist
    }


def reputations_to_human_readable(reputations):
    return [parse_reputation_human_readable(rep) for rep in reputations]


def references_to_human_readable(references):
    return [parse_reference_human_readable(ref) for ref in references]


def trust_level_to_score(trust_level):
    if (trust_level >= TrustLevel.MIGHT_BE_TRUSTED):
        return Common.DBotScore.GOOD

    elif (trust_level == TrustLevel.MIGHT_BE_MALICIOUS):
        return Common.DBotScore.SUSPICIOUS

    elif (trust_level == TrustLevel.NOT_SET or trust_level == TrustLevel.UNKNOWN):
        return Common.DBotScore.NONE

    elif (trust_level < TrustLevel.MIGHT_BE_MALICIOUS):
        return Common.DBotScore.BAD

    else:
        # Shouldn't reach here, as the API doesn't support 31-69 values except for 50)
        return Common.DBotScore.NONE


def test_module(dxl_client: DxlClient):
    """Tests if there is a connection with DxlClient(which is used for connection with McAfee TIE, instead of the Client class)"""
    dxl_client.connect()
    return 'ok'


def safe_get_file_reputation(tie_client: TieClient, api_input: Dict[str, str]):
    try:
        res = tie_client.get_file_reputation(api_input)
    except Exception as e:
        demisto.info(f'McAfee failed to get file reputation with error: {str(e)}')
        return None
    return res


def get_hash_type_key(file_hash: str):
    hash_type = get_hash_type(file_hash)
    hash_type_key = HASH_TYPE_KEYS.get(hash_type, None)
    if not hash_type_key:
        raise DemistoException(f'Invalid value, {file_hash} is not a valid SHA1, SHA256 or MD5 value.')
    return hash_type_key


def get_file_instance(dbot_score: Union[Common.DBotScore, None], file_hash: str, hash_type_key: str) -> Common.File:
    return Common.File(dbot_score=dbot_score,
                       md5=file_hash if hash_type_key == HashType.MD5 else None,
                       sha1=file_hash if hash_type_key == HashType.SHA1 else None,
                       sha256=file_hash if hash_type_key == HashType.SHA256 else None)


def parse_reputation(provider_id: int, reputation: Dict):
    file_reputation_parser = GeneralFileReputationParser.init(provider=provider_id)
    parsed_reputation = file_reputation_parser.parse_data(reputation_data=reputation)
    parsed_reputation['Provider_ID'] = provider_id
    return parsed_reputation


def parse_file_reputation_raw_result(raw_result: Dict, file_hash: str, reliability: str, hash_type_key: str):
    context_data = {}
    parsed_reputation_data = {}

    # Since the range of trust levels is [0,1,...,100], we want to get the minimum trust level
    # that is not 0, therefore we define a variable that is larger than the maximum in the predefined range
    # and iterate in order to retrieve the minimum, if our minimum was not changed, that means all the trust levels
    # are zero.
    max_num = TrustLevel.KNOWN_TRUSTED_INSTALLER + 1  # More than the maximum possible trust level
    lowest_trust_level = max_num
    reputations = raw_result.values()
    for reputation in reputations:
        # Parse the raw result of each reputation result
        provider_id = reputation[FileReputationProp.PROVIDER_ID]
        parsed_reputation_data[get_provider_abbr(provider_id=provider_id)] = parse_reputation(provider_id=provider_id,
                                                                                              reputation=reputation)
        # Get the vendor's data with the lowest score
        rep_trust_level = reputation.get(FileReputationProp.TRUST_LEVEL, TrustLevel.NOT_SET)
        if rep_trust_level != TrustLevel.NOT_SET and rep_trust_level < lowest_trust_level:
            lowest_trust_level = rep_trust_level

    if lowest_trust_level == max_num:
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

    file_instance = get_file_instance(dbot_score=dbot_score,
                                      file_hash=file_hash,
                                      hash_type_key=hash_type_key)
    if lowest_tl_score[LOWEST_SCORE_KEY] >= Common.DBotScore.SUSPICIOUS:
        dbot_score.malicious_description = f"Trust level is {str(lowest_tl_score[LOWEST_TRUST_LEVEL_KEY])}"

    context_data = {'Reputations': {'Hash': file_hash}}
    context_data['Reputations'] |= parsed_reputation_data
    table = reputations_to_human_readable(reputations)
    return CommandResults(readable_output=tableToMarkdown(f'McAfee TIE Hash Reputations For {file_hash}:', table),
                          raw_response=raw_result,
                          outputs_prefix=f'{OUTPUT_PREFIX}.FilesReputations',
                          outputs=context_data,
                          indicator=file_instance,
                          )


def files_reputations_command(hashes: List[str], tie_client: TieClient, reliability: str) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    for file_hash in hashes:
        hash_type_key = get_hash_type_key(file_hash=file_hash)
        api_input = {hash_type_key: file_hash}
        raw_result = safe_get_file_reputation(tie_client, api_input)

        if not raw_result:
            dbot_score = Common.DBotScore(indicator=file_hash,
                                          indicator_type=DBotScoreType.FILE,
                                          reliability=reliability,
                                          score=Common.DBotScore.NONE,
                                          )

            file_instance = get_file_instance(dbot_score=dbot_score,
                                              file_hash=file_hash,
                                              hash_type_key=hash_type_key)

            command_result = CommandResults(readable_output=f'McAfee TIE Hash Reputation For {file_hash} was not found',
                                            indicator=file_instance,
                                            )
        else:
            command_result = parse_file_reputation_raw_result(raw_result=raw_result,
                                                              file_hash=file_hash,
                                                              reliability=reliability,
                                                              hash_type_key=hash_type_key,
                                                              )

        command_results.append(command_result)
    return command_results


def files_references_command(hashes: List[str], tie_client: TieClient, query_limit: int) -> List[CommandResults]:
    if (query_limit > MAX_QUERY_LIMIT):
        raise DemistoException(f'Query limit must not exceed {MAX_QUERY_LIMIT}')
    elif (query_limit <= 0):
        raise DemistoException('Query limit must not be zero or negative')

    command_results: List[CommandResults] = []
    for file_hash in hashes:
        hash_type_key = get_hash_type_key(file_hash=file_hash)

        api_input = {hash_type_key: file_hash}
        raw_result = tie_client.get_file_first_references(api_input,
                                                          query_limit=query_limit)

        table = references_to_human_readable(raw_result)

        file_instance = get_file_instance(dbot_score=None,
                                          file_hash=file_hash,
                                          hash_type_key=hash_type_key)
        if not raw_result:
            command_result = CommandResults(readable_output=f'McAfee TIE Hash Reference For {file_hash} was not found',
                                            indicator=file_instance,)
        else:
            context_data = {'Hash': file_hash}
            context_data['References'] = table
            command_result = CommandResults(readable_output=tableToMarkdown(f'References For Hash {file_hash}:', table),
                                            raw_response=raw_result,
                                            outputs_prefix=f'{OUTPUT_PREFIX}.FilesReferences',
                                            indicator=file_instance,
                                            outputs=context_data,
                                            )

        command_results.append(command_result)
    return command_results


def get_trust_level_key(trust_level: str):
    trust_level_key = [key for (key, val) in TRUST_LEVELS.items() if val == trust_level]
    if not trust_level_key:
        raise DemistoException(f'Illegal argument trust_level {trust_level}. Choose value from predefined values')
    else:
        return trust_level_key[0]


def set_files_reputation_command(hashes: List[str], tie_client: TieClient, trust_level: str, filename: str, comment: str):
    # Find trust_level key
    trust_level_key = get_trust_level_key(trust_level=trust_level)

    for file_hash in hashes:
        hash_type_key = get_hash_type_key(file_hash=file_hash)
        api_input = {hash_type_key: file_hash}

        tie_client.set_file_reputation(trust_level=trust_level_key,
                                       hashes=api_input,
                                       filename=filename,
                                       comment=comment)
    return CommandResults(readable_output='Successfully set files reputation')


def create_temp_credentials(temp_file: tempfile._TemporaryFileWrapper, data_to_write: str):
    temp_file.write(data_to_write)
    temp_file.seek(0)


@contextlib.contextmanager
def create_dxl_config(instance_cert: InstanceCertificates) -> DxlClientConfig:
    with tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.crt') as broker_certs_file, \
            tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.crt') as client_cert_file, \
            tempfile.NamedTemporaryFile(mode='w+', dir='./', suffix='.key') as private_key_file:
        broker_certs_file.delete
        create_temp_credentials(broker_certs_file, instance_cert.broker_ca_bundle)
        create_temp_credentials(client_cert_file, instance_cert.client_cert)
        create_temp_credentials(private_key_file, instance_cert.private_key)
        dxl_config_files = DXLConfigFiles(broker_ca_bundle_file=broker_certs_file.name,
                                          client_cert_file=client_cert_file.name,
                                          private_key_file=private_key_file.name,
                                          broker_urls=instance_cert.broker_urls)
        yield get_client_config(dxl_config_files=dxl_config_files)


@contextlib.contextmanager
def create_dxl_client(instance_cert: InstanceCertificates):
    with create_dxl_config(instance_cert=instance_cert) as dxl_client_config:
        dxl_client_cm = DxlClient(dxl_client_config)

    with dxl_client_cm as dxl_client:
        yield dxl_client


def get_tie_client(dxl_client: DxlClient):
    dxl_client.connect()  # We need to connect to the DXL fabric in order to create a TIE Client instance
    return TieClient(dxl_client)


def get_instance_certificates(params: Dict[str, str]) -> InstanceCertificates:
    return InstanceCertificates(broker_ca_bundle=params['broker_ca_bundle'],
                                client_cert=params['cert_file'],
                                private_key=params['private_key'],
                                broker_urls=params['broker_urls'].split(','))


def files_reputations(dxl_client: DxlClient, hashes: List[str], reliability: str) -> List[CommandResults]:
    tie_client = get_tie_client(dxl_client)
    return files_reputations_command(hashes=hashes,
                                     tie_client=tie_client,
                                     reliability=reliability
                                     )


def files_references(dxl_client: DxlClient, hashes: List[str], args_query_limit: Union[int, None]) -> List[CommandResults]:
    tie_client = get_tie_client(dxl_client)
    query_limit = args_query_limit if args_query_limit else MAX_QUERY_LIMIT
    return files_references_command(hashes=hashes,
                                    tie_client=tie_client,
                                    query_limit=query_limit,
                                    )


def set_files_reputation(dxl_client: DxlClient, hashes: List[str], trust_level: str,
                         filename: str, comment: str) -> CommandResults:
    tie_client = get_tie_client(dxl_client)
    return set_files_reputation_command(hashes=hashes,
                                        tie_client=tie_client,
                                        trust_level=trust_level,
                                        filename=filename,
                                        comment=comment,
                                        )


def main():  # pragma: no cover
    try:
        command = demisto.command()
        args = demisto.args()
        params = demisto.params()
        instance_cert = get_instance_certificates(params=params)
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            demisto.params().get('integrationReliability', 'C - Fairly reliable'))
        hashes = argToList(args.get('file'))
        demisto.debug(f'Command being called is {command}')
        with create_dxl_client(instance_cert=instance_cert) as dxl_client:
            # We must configure the DxlClient before trying to connect, which is why
            # we wrapped the following code with a "with" statement according to the DxlClient Docs.
            # Only after successfully configuring, can we try to connect using dxl_client.connect
            # If a configuration error is returned from the configuration phase, it will be caught before trying to connect.
            if command == 'test-module':
                # This is the call made when clicking the integration Test button.
                return_results(test_module(dxl_client=dxl_client))

            elif command == 'file':
                return_results(files_reputations(dxl_client=dxl_client,
                                                 hashes=hashes,
                                                 reliability=reliability))

            elif command == 'tie-file-references':
                return_results(files_references(dxl_client=dxl_client,
                                                hashes=hashes,
                                                args_query_limit=arg_to_number(args.get('query_limit', None))))

            elif command == 'tie-set-file-reputation':
                return_results(set_files_reputation(dxl_client=dxl_client,
                                                    hashes=hashes,
                                                    trust_level=args.get('trust_level'),
                                                    filename=args.get('filename', ''),
                                                    comment=args.get('comment', ''),
                                                    ))
            else:
                raise NotImplementedError(f'Command {command} is not supported.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        exception_des = str(e)
        if ('4044' in exception_des):
            return_error('Invalid value - Client certificates')
        elif ('4293' in exception_des):
            return_error('Invalid value - Broker CA certificates')
        elif ('4065' in exception_des):
            return_error('Invalid value - Client private key')
        else:
            return_error(f'Failed to execute {command} command.'
                         f'\nError:\n{str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

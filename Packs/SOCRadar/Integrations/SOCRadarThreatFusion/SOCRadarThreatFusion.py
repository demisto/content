import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from json.decoder import JSONDecodeError

from CommonServerUserPython import *  # noqa

import urllib3
import traceback
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'
MESSAGES: Dict[str, str] = {
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'AUTHORIZATION_ERROR': 'Authorization Error: make sure API Key is correctly set.',
    'RATE_LIMIT_EXCEED_ERROR': 'Rate limit has been exceeded. Please make sure your your API key\'s rate limit is adequate.',
}
INTEGRATION_NAME = 'SOCRadar ThreatFusion'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
        Client class to interact with the SOCRadar API
    """

    def __init__(self, base_url, api_key, verify, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def get_entity_score(self, entity):
        suffix = '/threat/analysis'
        api_params = {'key': self.api_key, 'entity': entity}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params, timeout=60,
                                      error_handler=self.handle_error_response)
        return response

    def check_auth(self):
        suffix = '/threat/analysis/check/auth'
        api_params = {'key': self.api_key}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params,
                                      error_handler=self.handle_error_response)

        return response

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response to display descriptive error messages based on status code

        :param response: SOCRadar API response.
        :return: DemistoException for particular error code.
        """

        error_reason = ''
        try:
            json_resp = response.json()
            error_reason = json_resp.get('error') or json_resp.get('message')
        except JSONDecodeError:
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            401: MESSAGES['AUTHORIZATION_ERROR'],
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            429: MESSAGES['RATE_LIMIT_EXCEED_ERROR']
        }

        if response.status_code in status_code_messages.keys():
            demisto.debug(f'Response Code: {response.status_code}, Reason: {status_code_messages[response.status_code]}')
            raise DemistoException(status_code_messages[response.status_code])
        else:
            raise DemistoException(response.raise_for_status())


''' HELPER FUNCTIONS '''


def calculate_dbot_score(score: int) -> int:
    """Transforms cyber risk score (reputation) from SOCRadar API to DBot Score and using threshold.

    Args:
        score: Cyber risk score (reputation) from SOCRadar API

    Returns:
        Score representation in DBot
    """
    return_score = 0
    # Malicious
    if score > 800:
        return_score = 3
    # Suspicious
    elif score > 400:
        return_score = 2
    # Good
    elif score > 0:
        return_score = 1
    # Unknown
    return return_score


class Validator:
    @staticmethod
    def validate_domain(domain_to_validate):
        if not isinstance(domain_to_validate, str) or len(domain_to_validate) > 255:
            return False
        if domain_to_validate.endswith("."):
            domain_to_validate = domain_to_validate[:-1]
        domain_regex = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(domain_regex.match(x) for x in domain_to_validate.split("."))

    @staticmethod
    def validate_ipv4(ip_to_validate):
        return is_ip_valid(ip_to_validate)

    @staticmethod
    def validate_ipv6(ip_to_validate):
        return is_ipv6_valid(ip_to_validate)

    @staticmethod
    def validate_hash(hash_to_validate):
        return get_hash_type(hash_to_validate) != 'Unknown'

    @staticmethod
    def raise_if_ip_not_valid(ip: str):
        """Raises an error if ip is not valid

        Args:
            ip: ip

        Raises:
            ValueError: if ip is not type of ipv4 or ipv6

        Examples:
            >>> Validator.raise_if_ip_not_valid('not an ip')
            Traceback (most recent call last):
             ...
            ValueError: IP "not an ip" is not a type of IPv4 or IPv6
            >>> Validator.raise_if_ip_not_valid('1.1.1.1')
        """
        if not Validator.validate_ipv4(ip) and not Validator.validate_ipv6(ip):
            raise ValueError(f'IP "{ip}" is not a type of IPv4 or IPv6')

    @staticmethod
    def raise_if_domain_not_valid(domain: str):
        """Raises an error if domain is not valid

        Args:
            domain: domain

        Raises:
            ValueError: if domain is not a valid domain address

        Examples:
            >>> Validator.raise_if_domain_not_valid('not a domain')
            Traceback (most recent call last):
             ...
            ValueError: Domain "not a domain" is not a valid domain address
            >>> Validator.raise_if_hash_not_valid('not a domain')
        """
        if not Validator.validate_domain(domain):
            raise ValueError(f'Domain "{domain}" is not a valid domain address')

    @staticmethod
    def raise_if_hash_not_valid(file_hash: str):
        """Raises an error if file_hash is not valid

        Args:
            file_hash: file hash

        Raises:
            ValueError: if hash is not of type SHA-1 or MD5

        Examples:
            >>> Validator.raise_if_hash_not_valid('not a hash')
            Traceback (most recent call last):
             ...
            ValueError: Hash "not a hash" is not of type SHA-1 or MD5
            >>> Validator.raise_if_hash_not_valid('7e641f6b9706d860baf09fe418b6cc87')
        """
        if not Validator.validate_hash(file_hash):
            raise ValueError(f'Hash "{file_hash}" is not of type SHA-1 or MD5')


def verify_entity_type(entity_to_control_list: list, entity_type: str):
    """Verify intended entity type. Raise exception if the provided entity type is not expected.

    :type entity_to_control_list: ``list``
    :param entity_to_control_list: Intended entity list to be verified.

    :type entity_type: ``str``
    :param entity_type: Intended entity type to be verified.
    """
    control_dict = {
        'ip': Validator.raise_if_ip_not_valid,
        'domain': Validator.raise_if_domain_not_valid,
        'hash': Validator.raise_if_hash_not_valid,
    }
    for entity_to_control in entity_to_control_list:
        control_dict[entity_type](entity_to_control)


def map_indicator_type(socradar_indicator_type: str) -> Optional[str]:
    """Map SOCRadar indicator type to XSOAR indicator type

    :type socradar_indicator_type: ``str``
    :param socradar_indicator_type: The SOCRadar indicator type

    :return: XSOAR indicator type
    :rtype: ``Optional[str]``
    """
    indicator_map = {
        'ipv4': FeedIndicatorType.IP,
        'ipv6': FeedIndicatorType.IPv6,
        'hash': FeedIndicatorType.File,
        'hostname': FeedIndicatorType.Domain,
    }

    return indicator_map.get(socradar_indicator_type)


def build_entry_context(results: Union[Dict, List], indicator_type: str):
    """Formatting results from SOCRadar API to Demisto Context

    :type results: ``Union[Dict, List]``
    :param results: Raw results obtained from SOCRadar API.

    :type indicator_type: ``str``
    :param results: Type of indicator to be used in context creation.
    """

    if isinstance(results, list):
        return [build_entry_context(entry, indicator_type) for entry in results]  # pragma: no cover

    result_data = results.get('data', {})
    return_context = {
        'Risk Score (Out of 1000)': result_data.get('score'),
        'Score Details': result_data.get('score_details'),
        'Total Encounters': len(result_data.get('findings', [])),
        map_indicator_type(result_data.get('classification')): result_data.get('value'),
    }

    if indicator_type == 'domain':
        return_context['Subdomains'] = result_data.get('subdomains', [])

    if indicator_type != 'hash':
        return_context['Whois Details'] = {}
        for key, value in result_data.get('whois', {}).items():
            # Exclude raw whois
            if key == 'raw':
                continue
            if value and type(value) is list and key in ('creation_date', 'expiration_date', 'updated_date', 'registrar'):
                value = value[0]
            return_context['Whois Details'][key] = value
        return_context['DNS Details'] = result_data.get('dns_info', {})

    if indicator_type == 'ip':
        geo_location_dict = {}
        if result_data.get('geo_location', []):
            geo_location = result_data['geo_location'][0]
            geo_location_dict = {key: value for key, value in geo_location.items() if key.lower() != 'ip'}

        asn_code = result_data.get('whois', {}).get('asn', '')
        if not asn_code:
            asn_code = geo_location_dict.get('AsnCode', '')
        asn_description = result_data.get('whois', {}).get('asn_description', '')
        if not asn_description:
            asn_description = geo_location_dict.get('AsnName', '')
        asn = f"[{asn_code}] {asn_description}"
        geo_location_dict['ASN'] = asn
        return_context['Geo Location'] = geo_location_dict

    return return_context


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.check_auth()
    return "ok"


def ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Returns SOCRadar reputation details for the given IP entities.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for ip_command

    :return:
        List of ``CommandResults`` objects that is then passed to ``return_results``
    :rtype: ``List[CommandResults]``
    """

    ip_addresses = args.get('ip', '')
    ip_list: list = argToList(ip_addresses)
    verify_entity_type(ip_list, 'ip')

    command_results_list: List[CommandResults] = []

    for ip_to_score in ip_list:
        raw_response = client.get_entity_score(ip_to_score)

        if raw_response.get('is_success'):
            if raw_response.get('data', {}).get('is_whitelisted'):
                score = 1
            elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
                score = calculate_dbot_score(score)
            title = f'SOCRadar - Analysis results for IP: {ip_to_score}'

            context_entry = build_entry_context(raw_response, 'ip')
            human_readable = tableToMarkdown(title, context_entry)

            dbot_score = Common.DBotScore(indicator=ip_to_score,
                                          indicator_type=DBotScoreType.IP,
                                          integration_name=INTEGRATION_NAME,
                                          score=score,
                                          reliability=demisto.params().get('integrationReliability'))

            ip_object = Common.IP(ip=ip_to_score,
                                  dbot_score=dbot_score,
                                  asn=context_entry['Geo Location'].get('ASN'),
                                  geo_country=context_entry['Geo Location'].get('CountryCode'),
                                  geo_latitude=context_entry['Geo Location'].get('Latitude'),
                                  geo_longitude=context_entry['Geo Location'].get('Longitude'),
                                  region=context_entry['Geo Location'].get('RegionName'))

            command_results_list.append(CommandResults(
                outputs_prefix="SOCRadarThreatFusion.Reputation.IP",
                outputs_key_field="IP",
                readable_output=human_readable,
                raw_response=raw_response,
                outputs=context_entry,
                indicator=ip_object
            ))
        else:
            message = f"Error at scoring IP {ip_to_score} while getting API response. " \
                      f"SOCRadar ThreatFusion API Response: {raw_response.get('message', '')}"
            command_results_list.append(CommandResults(readable_output=message))
    if not command_results_list:
        command_results_list = [
            CommandResults('SOCRadar ThreatFusion could not find any results for the given IP address(es).')
        ]
    return command_results_list


def domain_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Returns SOCRadar reputation details for the given domain entities.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for domain_command

    :return:
        List of ``CommandResults`` objects that is then passed to ``return_results``
    :rtype: ``List[CommandResults]``
    """
    domains = args.get('domain', '')
    domains_list: list = argToList(domains)
    verify_entity_type(domains_list, 'domain')

    command_results_list: List[CommandResults] = []

    for domain_to_score in domains_list:
        raw_response = client.get_entity_score(domain_to_score)

        if raw_response.get('is_success'):
            if raw_response.get('data', {}).get('is_whitelisted'):
                score = 1
            elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
                score = calculate_dbot_score(score)
            title = f'SOCRadar - Analysis results for domain: {domain_to_score}'

            context_entry = build_entry_context(raw_response, 'domain')
            human_readable = tableToMarkdown(title, context_entry)

            dbot_score = Common.DBotScore(indicator=domain_to_score,
                                          indicator_type=DBotScoreType.DOMAIN,
                                          integration_name=INTEGRATION_NAME,
                                          score=score,
                                          reliability=demisto.params().get('integrationReliability'))

            domain_object = Common.Domain(domain=domain_to_score,
                                          dbot_score=dbot_score,
                                          dns=', '.join(context_entry['DNS Details'].get('A', [])),
                                          creation_date=context_entry['Whois Details'].get('creation_date'),
                                          expiration_date=context_entry['Whois Details'].get('expiration_date'),
                                          updated_date=context_entry['Whois Details'].get('updated_date'),
                                          registrant_country=context_entry['Whois Details'].get('registrant_country'),
                                          registrant_name=context_entry['Whois Details'].get('registrant_name')
                                          or context_entry['Whois Details'].get('name'),
                                          registrar_name=context_entry['Whois Details'].get('registrar'),
                                          organization=context_entry['Whois Details'].get('org'),
                                          geo_country=context_entry['Whois Details'].get('country'),
                                          sub_domains=context_entry['Subdomains'],
                                          name_servers=context_entry['DNS Details'].get('NS')
                                          or context_entry['Whois Details'].get('name_servers'))

            command_results_list.append(CommandResults(
                outputs_prefix="SOCRadarThreatFusion.Reputation.Domain",
                outputs_key_field="Domain",
                readable_output=human_readable,
                raw_response=raw_response,
                outputs=context_entry,
                indicator=domain_object
            ))
        else:
            message = f"Error at scoring domain {domain_to_score} while getting API response. " \
                      f"SOCRadar ThreatFusion API Response: {raw_response.get('message', '')}"
            command_results_list.append(CommandResults(readable_output=message))
    if not command_results_list:
        command_results_list = [
            CommandResults('SOCRadar ThreatFusion could not find any results for the given domain(s).')
        ]

    return command_results_list


def file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Returns SOCRadar reputation details for the given hash entities.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for hash_command

    :return:
        List of ``CommandResults`` objects that is then passed to ``return_results``
    :rtype: ``List[CommandResults]``
    """
    file_hashes = args.get('file', '')
    file_hash_list: list = argToList(file_hashes)
    verify_entity_type(file_hash_list, 'hash')

    command_results_list: List[CommandResults] = []

    for hash_to_score in file_hash_list:
        hash_type = get_hash_type(hash_to_score)

        raw_response = client.get_entity_score(hash_to_score)

        if raw_response.get('is_success'):
            if raw_response.get('data', {}).get('is_whitelisted'):
                score = 1
            elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
                score = calculate_dbot_score(score)
            title = f'SOCRadar - Analysis results for hash: {hash_to_score}'

            context_entry = build_entry_context(raw_response, 'hash')
            human_readable = tableToMarkdown(title, context_entry)

            dbot_score = Common.DBotScore(indicator=hash_to_score,
                                          indicator_type=DBotScoreType.FILE,
                                          integration_name=INTEGRATION_NAME,
                                          score=score,
                                          reliability=demisto.params().get('integrationReliability'))

            file_object = Common.File(dbot_score=dbot_score)
            # hash_type can either be 'sha-1' or 'md5' at this point.
            if hash_type == 'sha-1':
                file_object.sha1 = hash_to_score
            else:
                file_object.md5 = hash_to_score

            command_results_list.append(CommandResults(
                outputs_prefix="SOCRadarThreatFusion.Reputation.Hash",
                outputs_key_field="File",
                readable_output=human_readable,
                raw_response=raw_response,
                outputs=context_entry,
                indicator=file_object
            ))
        else:
            message = f"Error at scoring file hash {hash_to_score} while getting API response. " \
                      f"SOCRadar ThreatFusion API Response: {raw_response.get('message', '')}"
            command_results_list.append(CommandResults(readable_output=message))
    if not command_results_list:
        command_results_list = [
            CommandResults('SOCRadar ThreatFusion could not find any results for the given file hash(es).')
        ]

    return command_results_list


def score_ip_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Returns SOCRadar reputation details for the given IP entity.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    ip_to_score = args.get('ip', '')
    verify_entity_type([ip_to_score], 'ip')

    raw_response = client.get_entity_score(ip_to_score)
    if raw_response.get('is_success'):
        if raw_response.get('data', {}).get('is_whitelisted'):
            score = 1
        elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
            score = calculate_dbot_score(score)
        title = f'SOCRadar - Analysis results for IP: {ip_to_score}'
        context_entry = build_entry_context(raw_response, 'ip')
        dbot_entry = build_dbot_entry(ip_to_score, DBotScoreType.IP, 'SOCRadar ThreatFusion', score)
        human_readable = tableToMarkdown(title, context_entry)
        context_entry.update(dbot_entry)
    else:
        message = f"Error while getting API response. SOCRadar API Response: {raw_response.get('message', '')}"
        raise DemistoException(message=message)

    return CommandResults(
        outputs_prefix="SOCRadarThreatFusion.Reputation.IP",
        outputs_key_field="IP",
        readable_output=human_readable,
        raw_response=raw_response,
        outputs=context_entry
    )


def score_domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Returns SOCRadar reputation details for the given domain entity.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    domain_to_score = args.get('domain', '')
    verify_entity_type([domain_to_score], 'domain')

    raw_response = client.get_entity_score(domain_to_score)
    if raw_response.get('is_success'):
        if raw_response.get('data', {}).get('is_whitelisted'):
            score = 1
        elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
            score = calculate_dbot_score(score)
        title = f'SOCRadar - Analysis results for domain: {domain_to_score}'
        context_entry = build_entry_context(raw_response, 'domain')
        dbot_entry = build_dbot_entry(domain_to_score, DBotScoreType.DOMAIN, 'SOCRadar ThreatFusion', score)
        human_readable = tableToMarkdown(title, context_entry)
        context_entry.update(dbot_entry)
    else:
        message = f"Error while getting API response. SOCRadar API Response: {raw_response.get('message', '')}"
        raise DemistoException(message=message)

    return CommandResults(
        outputs_prefix="SOCRadarThreatFusion.Reputation.Domain",
        outputs_key_field="Domain",
        readable_output=human_readable,
        raw_response=raw_response,
        outputs=context_entry
    )


def score_hash_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Returns SOCRadar reputation details for the given hash entity.

    :type client: ``Client``
    :param client: client to use

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    hash_to_score = args.get('hash', '')
    verify_entity_type([hash_to_score], 'hash')
    hash_type = get_hash_type(hash_to_score)

    raw_response = client.get_entity_score(hash_to_score)
    if raw_response.get('is_success'):
        if raw_response.get('data', {}).get('is_whitelisted'):
            score = 1
        elif (score := raw_response.get('data', {}).get('score', 0)) is not None:
            score = calculate_dbot_score(score)
        title = f'SOCRadar - Analysis results for hash: {hash_to_score}'
        context_entry = build_entry_context(raw_response, 'hash')
        dbot_entry = build_dbot_entry(hash_to_score, hash_type, 'SOCRadar ThreatFusion', score)
        human_readable = tableToMarkdown(title, context_entry)
        context_entry.update(dbot_entry)
    else:
        message = f"Error while getting API response. SOCRadar API Response: {raw_response.get('message', '')}"
        raise DemistoException(message=message)

    return CommandResults(
        outputs_prefix="SOCRadarThreatFusion.Reputation.Hash",
        outputs_key_field="File",
        readable_output=human_readable,
        raw_response=raw_response,
        outputs=context_entry
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')
    base_url = SOCRADAR_API_ENDPOINT
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy)
        command = demisto.command()

        commands = {
            'ip': ip_command,
            'domain': domain_command,
            'file': file_command,
            'socradar-score-ip': score_ip_command,
            'socradar-score-domain': score_domain_command,
            'socradar-score-hash': score_hash_command,
        }
        if command == 'test-module':
            return_results(test_module(client))
        else:
            command_function = commands.get(command)
            if command_function:
                return_results(command_function(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

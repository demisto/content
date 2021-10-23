"""
An integration module for the ThreatExchange V2 API.
API Documentation:
    https://developers.facebook.com/docs/threat-exchange/reference/apis
"""

import collections
from typing import Tuple
import urllib3
from CommonServerUserPython import *  # noqa
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings #
urllib3.disable_warnings()

DEFAULT_LIMIT = 20
COMMAND_PREFIX = 'threatexchange'
VENDOR_NAME = 'ThreatExchange v2'
CONTEXT_PREFIX = 'ThreatExchange'
THREAT_DESCRIPTORS_SUFFIX = 'threat_descriptors'
MALWARE_ANALYSES_SUFFIX = 'malware_analyses'
THREAT_TAGS_SUFFIX = 'threat_tags'
TAGGED_OBJECTS_SUFFIX = 'tagged_objects'
THREAT_EXCHANGE_MEMBERS_SUFFIX = 'threat_exchange_members'
TIMEOUT_FOR_LIST_CALLS = 30
DEFAULT_DESCRIPTION_FOR_MALICIOUS_INDICATOR = 'Indicator was classified as malicious by more than {}%' \
                                              ' of detection engines.'


class ThreatExchangeV2Status:
    UNKNOWN = 'UNKNOWN'
    NON_MALICIOUS = 'NON_MALICIOUS'
    SUSPICIOUS = 'SUSPICIOUS'
    MALICIOUS = 'MALICIOUS'


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(self, base_url, access_token, verify=True, proxy=False):
        super().__init__(base_url, verify, proxy)
        self.access_token = access_token

    def ip(self, ip: str, since: Optional[int], until: Optional[int], limit: Optional[int] = DEFAULT_LIMIT) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptors
        Args:
            ip: ip address
            since: Returns malware collected after a timestamp
            until: Returns malware collected before a timestamp
            limit: Defines the maximum size of a page of results. The maximum is 1,000

        Returns: The API call response
        """
        response = self._http_request(
            'GET',
            THREAT_DESCRIPTORS_SUFFIX,
            params={
                'access_token': self.access_token,
                'type': 'IP_ADDRESS',
                'text': ip,
                'strict_text': True,
                'since': since,
                'until': until,
                'limit': limit
            }
        )
        return response

    def file(self, file: str, since: Optional[int], until: Optional[int], limit: Optional[int] = DEFAULT_LIMIT) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/malware-analyses/v10.0
        Args:
            file: Hash of a file
            since: Returns malware collected after a timestamp
            until: Returns malware collected before a timestamp
            limit: Defines the maximum size of a page of results. The maximum is 1,000

        Returns: The API call response
        """

        response = self._http_request(
            'GET',
            MALWARE_ANALYSES_SUFFIX,
            params=assign_params(**{
                'access_token': self.access_token,
                'text': file,
                'strict_text': True,
                'since': since,
                'until': until,
                'limit': limit
            })
        )
        return response

    def domain(self, domain: str, since: Optional[int], until: Optional[int],
               limit: Optional[int] = DEFAULT_LIMIT) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptors
        Args:
            domain: Domain
            since: Returns malware collected after a timestamp
            until: Returns malware collected before a timestamp
            limit: Defines the maximum size of a page of results. The maximum is 1,000

        Returns: The API call response
        """

        response = self._http_request(
            'GET',
            THREAT_DESCRIPTORS_SUFFIX,
            params=assign_params(**{
                'access_token': self.access_token,
                'type': 'DOMAIN',
                'text': domain,
                'strict_text': True,
                'since': since,
                'until': until,
                'limit': limit
            })
        )
        return response

    def url(self, url: str, since: Optional[int], until: Optional[int], limit: Optional[int] = DEFAULT_LIMIT) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptors
        Args:
            url: URL
            since: Returns malware collected after a timestamp
            until: Returns malware collected before a timestamp
            limit: Defines the maximum size of a page of results. The maximum is 1,000

        Returns: The API call response
        """

        response = self._http_request(
            'GET',
            THREAT_DESCRIPTORS_SUFFIX,
            params=assign_params(**{
                'access_token': self.access_token,
                'type': 'URI',
                'text': url,
                'strict_text': True,
                'since': since,
                'until': until,
                'limit': limit
            })
        )
        return response

    def members(self) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-exchange-members/v10.0

        Returns: The API call response
        """

        response = self._http_request(
            'GET',
            THREAT_EXCHANGE_MEMBERS_SUFFIX,
            params={'access_token': self.access_token},
            timeout=TIMEOUT_FOR_LIST_CALLS
        )
        return response

    def query(self, text: str, descriptor_type: str, since: Optional[int], until: Optional[int],
              limit: Optional[int] = DEFAULT_LIMIT, strict_text: Optional[bool] = False,
              before: Optional[str] = None, after: Optional[str] = None) -> Dict:
        """
        See Also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptors
        Args:
            text: Freeform text field with a value to search for
            descriptor_type: The type of descriptor to search for
            since: Returns malware collected after a timestamp
            until: Returns malware collected before a timestamp
            limit: Defines the maximum size of a page of results. The maximum is 1,000
            strict_text: When set to 'true', the API will not do approximate matching on the value in text
            before: Returns results collected before this cursor
            after: Returns results collected after this cursor

        Returns: The API call response
        """

        response = self._http_request(
            'GET',
            THREAT_DESCRIPTORS_SUFFIX,
            params=assign_params(**{
                'access_token': self.access_token,
                'type': descriptor_type,
                'text': text,
                'strict_text': strict_text,
                'since': since,
                'until': until,
                'limit': limit,
                'before': before,
                'after': after
            }),
            timeout=TIMEOUT_FOR_LIST_CALLS
        )
        return response

    def tags_search(self, text: str, before: Optional[str] = None, after: Optional[str] = None) -> Dict:
        """
        See also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-tags/v10.0
        Args:
            text: Freeform text field with a value to search for.
                  This value should describe a broader type or class of attack you are interested in.
            before: Returns results collected before this cursor
            after:  Returns results collected after this cursor

        Returns: The API call response
        """
        response = self._http_request(
            'GET',
            THREAT_TAGS_SUFFIX,
            params=assign_params(**{
                'access_token': self.access_token,
                'text': text,
                'before': before,
                'after': after
            }),
            timeout=TIMEOUT_FOR_LIST_CALLS
        )
        return response

    def tagged_objects_list(self, tag_id: str, tagged_since: Optional[int], tagged_until: Optional[int],
                            before: Optional[str] = None, after: Optional[str] = None) -> Dict:
        """
        See also:
            https://developers.facebook.com/docs/threat-exchange/reference/apis/threattags/v10.0
        Args:
            tag_id: ThreatTag ID to get it's related tagged objects
            tagged_since:  Fetches all objects that have been tagged since this time (inclusive)
            tagged_until: Fetches all objects that have been tagged until this time (inclusive)
            before: Returns results collected before this cursor
            after:  Returns results collected after this cursor

        Returns: The API call response
        """
        url_suffix = f'{tag_id}/{TAGGED_OBJECTS_SUFFIX}'
        response = self._http_request(
            'GET',
            url_suffix,
            params=assign_params(**{
                'access_token': self.access_token,
                'tagged_since': tagged_since,
                'tagged_until': tagged_until,
                'before': before,
                'after': after
            }),
            timeout=TIMEOUT_FOR_LIST_CALLS
        )
        return response

    def object_get_by_id(self, object_id: str) -> Dict:
        """
        Gets ThreatExchange object by ID
        Args:
            object_id: ID of a ThreatExchange object

        Returns: The API call response
        """
        response = self._http_request(
            'GET',
            object_id,
            params={
                'access_token': self.access_token
            }
        )
        return response


def get_reputation_data_statuses(reputation_data: List) -> List[str]:
    """
    collects reported statuses of reputation data
    Args:
        reputation_data: returned data list of a certain reputation command

    Returns: a list of reported statuses
    """
    reputation_statuses = [status for data_entry in reputation_data if (status := data_entry.get('status'))]
    return reputation_statuses


def calculate_dbot_score(reputation_data: List, params: Dict[str, Any]) -> int:
    """
    Calculates the Dbot score of the given reputation command data, by the following logic:
    MALICIOUS > malicious threshold (50%) = Malicious
    MALICIOUS <= malicious threshold (50%) = Suspicious
    SUSPICIOUS > suspicious threshold (1) = Suspicious
    NON_MALICIOUS > non malicious threshold (50%) = Good
    else Unknown
    Args:
        reputation_data: returned data list of a certain reputation command
        params: parameters of the integration
    Returns: the calculated Dbot score
    """
    # get user's thresholds:
    malicious_threshold = arg_to_number(params.get('malicious_threshold', 50), arg_name='malicious_threshold')
    if malicious_threshold is None:
        malicious_threshold = 50
    suspicious_threshold = arg_to_number(params.get('suspicious_threshold', 1), arg_name='suspicious_threshold')
    if suspicious_threshold is None:
        suspicious_threshold = 1
    non_malicious_threshold = arg_to_number(params.get('non_malicious_threshold', 50),
                                            arg_name='non_malicious_threshold')
    if non_malicious_threshold is None:
        non_malicious_threshold = 50

    # collect and count reported statuses:
    reputation_statuses = get_reputation_data_statuses(reputation_data)
    num_of_statuses = len(reputation_statuses)
    occurrences = collections.Counter(reputation_statuses)

    # calculate Dbot score:
    num_of_malicious = occurrences.get(ThreatExchangeV2Status.MALICIOUS, 0)
    num_of_suspicious = occurrences.get(ThreatExchangeV2Status.SUSPICIOUS, 0)
    num_of_non_malicious = occurrences.get(ThreatExchangeV2Status.NON_MALICIOUS, 0)
    if num_of_statuses == 0:  # no reported statuses
        score = Common.DBotScore.NONE
    elif num_of_malicious >= 1:  # at least one malicious status was reported
        if ((num_of_malicious / num_of_statuses) * 100) > malicious_threshold:
            score = Common.DBotScore.BAD
        else:  # num_of_malicious <= malicious_threshold
            score = Common.DBotScore.SUSPICIOUS
    elif num_of_suspicious > suspicious_threshold:  # number of suspicious statuses is above threshold
        score = Common.DBotScore.SUSPICIOUS
    elif ((num_of_non_malicious / num_of_statuses) * 100) > non_malicious_threshold:
        # number of non malicious statuses is above threshold
        score = Common.DBotScore.GOOD
    else:  # there isn't enough information - Dbot score is defined as unknown
        score = Common.DBotScore.NONE

    return score


def calculate_engines(reputation_data: List) -> Tuple[int, int]:
    """
    Calculates the number of engines that scanned the indicator, and how many of them are positive
     - i.e returned malicious status.
    Args:
        reputation_data: returned data list of a certain reputation command

    Returns: number of engines, number of positive engines
    """
    num_of_engines = len(reputation_data)
    reputation_statuses = get_reputation_data_statuses(reputation_data)
    occurrences = collections.Counter(reputation_statuses)
    num_of_positive_engines = occurrences.get(ThreatExchangeV2Status.MALICIOUS, 0)

    return num_of_engines, num_of_positive_engines


def flatten_outputs_paging(raw_response: Dict) -> Dict:
    """
    flatten the paging section of the raw_response - i.e removes 'cursors' key.
    Args:
        raw_response: response of an API call

    Returns: outputs dict

    """
    paging: Dict
    paging = raw_response.get('paging', {})
    outputs = raw_response.copy()
    cursor_before = paging.get('cursors', {}).get('before')
    cursor_after = paging.get('cursors', {}).get('after')
    outputs.pop('paging', None)
    outputs['paging'] = {
        'before': cursor_before,
        'after': cursor_after,
    }
    return outputs


def get_malicious_description(score: int, reputation_data: List[Dict], params: Dict[str, Any]) -> Optional[str]:
    """
    Gets the malicious description of certain indicator.
    If the indicator was classified as malicious, description is defined as default malicious description.
    If the indicator wasn't classified as malicious, description will be None (and won't be added to context).
    Args:
        score: calculated dbot score of the indicator
        reputation_data: returned data of a certain reputation command
        params: integration's parameters

    Returns: malicious description

    """
    malicious_description: Union[str, None]
    if score == Common.DBotScore.BAD:
        malicious_threshold = arg_to_number(params.get('malicious_threshold', 50))
        default_description = DEFAULT_DESCRIPTION_FOR_MALICIOUS_INDICATOR.format(malicious_threshold)
        malicious_description = default_description

    else:  # dbot-score isn't malicious
        malicious_description = None

    return malicious_description


def convert_string_to_epoch_time(date: Optional[str], arg_name: Optional[str] = None) -> Optional[int]:
    """
    Converts a string representing a date into epoch time format
    Args:
        date: date string
        arg_name: name of the date argument

    Returns: date in epoch time format (if an error occurred, or date in None returns None)
    """
    if date:
        if date.isdigit():  # date is an epoch time format string
            return int(date)

        date_obj = dateparser.parse(date)  # date is a string in a time format such as: iso 8601, free text, etc
        if isinstance(date_obj, datetime):
            epoch_time = date_obj.timestamp()
            return int(epoch_time)
        else:  # date was given in a wrong format
            if arg_name:
                raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, date))

    return None


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client: client to use

    Returns: 'ok' if test passed, anything else will fail the test
    """

    client.ip(ip='8.8.8.8', since=None, until=None)
    return 'ok'


def ip_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns IP's reputation
    """
    ips = argToList(args.get('ip'))
    since = convert_string_to_epoch_time(args.get('since'), arg_name='since')
    until = convert_string_to_epoch_time(args.get('until'), arg_name='until')
    limit = arg_to_number(args.get('limit'), arg_name='limit')
    headers = argToList(args.get('headers'))
    reliability = params.get('feedReliability')
    results: List[CommandResults] = list()

    for ip in ips:
        if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{ip}" is not valid')
        try:
            raw_response = client.ip(ip, since, until, limit)
        except Exception as exception:
            # If anything happens, handle like there are no results
            err_msg = f'Could not process IP: "{ip}"\n {str(exception)}'
            demisto.debug(err_msg)
            raw_response = {}
        if data := raw_response.get('data'):
            score = calculate_dbot_score(reputation_data=data, params=params)
            num_of_engines, num_of_positive_engines = calculate_engines(reputation_data=data)
            malicious_description = get_malicious_description(score, data, params)
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=score,
                reliability=reliability,
                malicious_description=malicious_description
            )
            if not headers:
                headers = ['description', 'owner', 'status', 'type', 'raw_indicator', 'share_level', 'confidence',
                           'severity', 'added_on', 'last_updated', 'review_status', 'id']
            readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Result for IP {ip}', data, headers=headers)
            ip_indicator = Common.IP(
                ip=ip,
                dbot_score=dbot_score,
                detection_engines=num_of_engines,
                positive_engines=num_of_positive_engines
            )

        else:  # no data
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=Common.DBotScore.NONE,
                reliability=reliability
            )
            readable_output = f'{CONTEXT_PREFIX} does not have details about IP: {ip} \n'
            ip_indicator = Common.IP(
                ip=ip,
                dbot_score=dbot_score,
            )

        result = CommandResults(
            outputs_prefix=f'{CONTEXT_PREFIX}.IP',
            outputs_key_field='id',
            outputs=data,
            indicator=ip_indicator,
            readable_output=readable_output,
            raw_response=raw_response
        )
        results.append(result)

    return results


def file_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns file's reputation
    """
    files = argToList(args.get('file'))
    since = convert_string_to_epoch_time(args.get('since'), arg_name='since')
    until = convert_string_to_epoch_time(args.get('until'), arg_name='until')
    limit = arg_to_number(args.get('limit'), arg_name='limit')
    headers = argToList(args.get('headers'))
    reliability = params.get('feedReliability')
    results: List[CommandResults] = list()

    for file in files:
        if get_hash_type(file) not in ('sha256', 'sha1', 'md5'):  # check file's validity
            raise ValueError(f'Hash "{file}" is not of type SHA-256, SHA-1 or MD5')
        try:
            raw_response = client.file(file, since, until, limit)
        except Exception as exception:
            # If anything happens, handle like there are no results
            err_msg = f'Could not process file: "{file}"\n {str(exception)}'
            demisto.debug(err_msg)
            raw_response = {}
        if data := raw_response.get('data'):
            score = calculate_dbot_score(reputation_data=data, params=params)
            malicious_description = get_malicious_description(score, data, params)
            dbot_score = Common.DBotScore(
                indicator=file,
                indicator_type=DBotScoreType.FILE,
                integration_name=VENDOR_NAME,
                score=score,
                reliability=reliability,
                malicious_description=malicious_description
            )
            if not headers:
                headers = ['description', 'status', 'share_level', 'added_on', 'review_status', 'id', 'password',
                           'sample_size', 'sample_size_compressed', 'sample_type', 'victim_count', 'md5', 'sha1',
                           'sha256', 'sha3_384', 'ssdeep']
            readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Result for file hash {file}', data, headers=headers)
            data_entry = data[0]
            file_indicator = Common.File(
                dbot_score=dbot_score,
                file_type=data_entry.get('sample_type'),
                size=data_entry.get('sample_size'),
                md5=data_entry.get('md5'),
                sha1=data_entry.get('sha1'),
                sha256=data_entry.get('sha256'),
                ssdeep=data_entry.get('ssdeep'),
                tags=data_entry.get('tags')
            )

        else:  # no data
            dbot_score = Common.DBotScore(
                indicator=file,
                indicator_type=DBotScoreType.FILE,
                integration_name=VENDOR_NAME,
                score=Common.DBotScore.NONE,
                reliability=reliability
            )
            readable_output = f'{CONTEXT_PREFIX} does not have details about file: {file} \n'
            file_indicator = Common.File(
                dbot_score=dbot_score
            )

        result = CommandResults(
            outputs_prefix=f'{CONTEXT_PREFIX}.File',
            outputs_key_field='id',
            outputs=data,
            indicator=file_indicator,
            readable_output=readable_output,
            raw_response=raw_response
        )
        results.append(result)

    return results


def domain_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns domain's reputation
    """
    domains = argToList(args.get('domain'))
    since = convert_string_to_epoch_time(args.get('since'), arg_name='since')
    until = convert_string_to_epoch_time(args.get('until'), arg_name='until')
    limit = arg_to_number(args.get('limit'), arg_name='limit')
    headers = argToList(args.get('headers'))
    reliability = params.get('feedReliability')
    results: List[CommandResults] = list()

    for domain in domains:
        try:
            raw_response = client.domain(domain, since, until, limit)
        except Exception as exception:
            # If anything happens, handle like there are no results
            err_msg = f'Could not process domain: "{domain}"\n {str(exception)}'
            demisto.debug(err_msg)
            raw_response = {}
        if data := raw_response.get('data'):
            score = calculate_dbot_score(reputation_data=data, params=params)
            num_of_engines, num_of_positive_engines = calculate_engines(reputation_data=data)
            malicious_description = get_malicious_description(score, data, params)
            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=VENDOR_NAME,
                score=score,
                reliability=reliability,
                malicious_description=malicious_description
            )
            if not headers:
                headers = ['description', 'owner', 'status', 'type', 'raw_indicator', 'share_level', 'confidence',
                           'severity', 'added_on', 'last_updated', 'review_status', 'id']
            readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Result for domain {domain}', data, headers=headers)
            domain_indicator = Common.Domain(
                domain=domain,
                dbot_score=dbot_score,
                detection_engines=num_of_engines,
                positive_detections=num_of_positive_engines
            )
        else:  # no data
            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=VENDOR_NAME,
                score=Common.DBotScore.NONE,
                reliability=reliability
            )
            readable_output = f'{CONTEXT_PREFIX} does not have details about domain: {domain} \n'
            domain_indicator = Common.Domain(
                domain=domain,
                dbot_score=dbot_score
            )

        result = CommandResults(
            outputs_prefix=f'{CONTEXT_PREFIX}.Domain',
            outputs_key_field='id',
            outputs=data,
            indicator=domain_indicator,
            readable_output=readable_output,
            raw_response=raw_response
        )
        results.append(result)

    return results


def url_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns URL's reputation
    """
    urls = argToList(args.get('url'))
    since = convert_string_to_epoch_time(args.get('since'), arg_name='since')
    until = convert_string_to_epoch_time(args.get('until'), arg_name='until')
    limit = arg_to_number(args.get('limit'), arg_name='limit')
    headers = argToList(args.get('headers'))
    reliability = params.get('feedReliability')
    results: List[CommandResults] = list()
    for url in urls:
        try:
            raw_response = client.url(url, since, until, limit)
        except Exception as exception:
            # If anything happens, handle like there are no results
            err_msg = f'Could not process URL: "{url}"\n {str(exception)}'
            demisto.debug(err_msg)
            raw_response = {}
        if data := raw_response.get('data'):
            score = calculate_dbot_score(reputation_data=data, params=params)
            num_of_engines, num_of_positive_engines = calculate_engines(reputation_data=data)
            malicious_description = get_malicious_description(score, data, params)
            dbot_score = Common.DBotScore(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                integration_name=VENDOR_NAME,
                score=score,
                reliability=reliability,
                malicious_description=malicious_description
            )
            if not headers:
                headers = ['description', 'owner', 'status', 'type', 'raw_indicator', 'share_level', 'confidence',
                           'severity', 'added_on', 'last_updated', 'review_status', 'id']
            readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Result for URL {url}', data, headers=headers)
            url_indicator = Common.URL(
                url=url,
                dbot_score=dbot_score,
                detection_engines=num_of_engines,
                positive_detections=num_of_positive_engines
            )
        else:  # no data
            dbot_score = Common.DBotScore(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                integration_name=VENDOR_NAME,
                score=Common.DBotScore.NONE,
                reliability=reliability
            )
            readable_output = f'{CONTEXT_PREFIX} does not have details about URL: {url} \n'
            url_indicator = Common.URL(
                url=url,
                dbot_score=dbot_score
            )

        result = CommandResults(
            outputs_prefix=f'{CONTEXT_PREFIX}.URL',
            outputs_key_field='id',
            outputs=data,
            indicator=url_indicator,
            readable_output=readable_output,
            raw_response=raw_response
        )
        results.append(result)

    return results


def members_command(client: Client) -> CommandResults:
    """
    Returns a list of current members of the ThreatExchange, alphabetized by application name.
    Each application may also include an optional contact email address.
    See Also:
          https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-exchange-members/v10.0

    """
    raw_response = client.members()
    if data := raw_response.get('data'):
        headers = ['id', 'name', 'email']
        readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Members: ', data, headers=headers, removeNull=True)
    else:  # no data
        readable_output = f'{CONTEXT_PREFIX} does not have any members \n'

    result = CommandResults(
        outputs_prefix=f'{CONTEXT_PREFIX}.Member',
        outputs_key_field='id',
        outputs=data,
        readable_output=readable_output,
        raw_response=raw_response
    )
    return result


def query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Searches for subjective opinions on indicators of compromise stored in ThreatExchange.
    """
    text = str(args.get('text'))
    descriptor_type = str(args.get('type'))
    since = convert_string_to_epoch_time(args.get('since'), arg_name='since')
    until = convert_string_to_epoch_time(args.get('until'), arg_name='until')
    limit = arg_to_number(args.get('limit'), arg_name='limit')
    strict_text = argToBoolean(args.get('strict_text', False))
    headers = argToList(args.get('headers'))
    before = args.get('before')
    after = args.get('after')

    raw_response = client.query(text, descriptor_type, since, until, limit, strict_text, before, after)
    try:  # removes 'next' field to prevent access token uncovering
        del raw_response['paging']['next']
    except KeyError:  # for no paging cases
        pass

    if data := raw_response.get('data'):
        readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Query Result:', data, headers=headers)
        if raw_response.get('paging'):  # if paging exist - flatten the output
            outputs = flatten_outputs_paging(raw_response)
            readable_output += tableToMarkdown('Pagination:', outputs.get('paging'))
        else:  # no paging
            outputs = raw_response

    else:  # no data
        readable_output = f'{CONTEXT_PREFIX} does not have details about {descriptor_type}: {text} \n'
        outputs = raw_response

    outputs['text'] = text
    outputs['type'] = descriptor_type

    result = CommandResults(
        outputs_prefix=f'{CONTEXT_PREFIX}.Query',
        outputs_key_field=['text', 'type'],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response
    )

    return result


def tags_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Enables searching for tags in ThreatExchange.
    With this call you can search for ThreatTag objects by text.
    See Also:
        https://developers.facebook.com/docs/threat-exchange/reference/apis/threattags/v10.0
    """
    text = str(args.get('text'))
    before = args.get('before')
    after = args.get('after')

    raw_response = client.tags_search(text, before, after)
    try:  # removes 'next' field to prevent access token uncovering
        del raw_response['paging']['next']
    except KeyError:  # for no paging cases
        pass

    if data := raw_response.get('data'):
        readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Tags: ', data, removeNull=True)
        if raw_response.get('paging'):  # if paging exist - flatten the output
            outputs = flatten_outputs_paging(raw_response)
            readable_output += tableToMarkdown('Pagination:', outputs.get('paging'))
        else:  # no paging
            outputs = raw_response

    else:  # no data
        readable_output = f'{CONTEXT_PREFIX} does not have any tags for text: {text} \n'
        outputs = raw_response

    outputs['text'] = text

    result = CommandResults(
        outputs_prefix=f'{CONTEXT_PREFIX}.Tag',
        outputs_key_field='text',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response
    )
    return result


def tagged_objects_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of tagged objects for a specific ThreatTag.
    See Also:
        https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-tags/v10.0
    """
    tag_id = str(args.get('tag_id'))
    tagged_since = arg_to_number(args.get('tagged_since'), arg_name='tagged_since')
    tagged_until = arg_to_number(args.get('tagged_until'), arg_name='tagged_until')
    before = args.get('before')
    after = args.get('after')

    raw_response = client.tagged_objects_list(tag_id, tagged_since, tagged_until, before, after)
    try:  # removes 'next' field to prevent access token uncovering
        del raw_response['paging']['next']
    except KeyError:  # for no paging cases
        pass

    if data := raw_response.get('data'):
        readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Tagged Objects for ThreatTag: {tag_id}', data,
                                          removeNull=True)
        if raw_response.get('paging'):  # if paging exist - flatten the output
            outputs = flatten_outputs_paging(raw_response)
            readable_output += tableToMarkdown('Pagination:', outputs.get('paging'))
        else:  # no paging
            outputs = raw_response

    else:  # no data
        readable_output = f'{CONTEXT_PREFIX} does not have any tagged objects for ThreatTag: {tag_id} \n'
        outputs = raw_response

    outputs['tag_id'] = tag_id

    result = CommandResults(
        outputs_prefix=f'{CONTEXT_PREFIX}.TaggedObject',
        outputs_key_field='tag_id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response
    )
    return result


def object_get_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets ThreatExchange object by ID.
    """
    object_id = str(args.get('object_id'))

    raw_response = client.object_get_by_id(object_id)
    if raw_response:
        readable_output = tableToMarkdown(f'{CONTEXT_PREFIX} Object {object_id}:', raw_response, removeNull=True)
    else:  # no data
        readable_output = f'{CONTEXT_PREFIX} does not have any object with ID: {object_id} \n'

    result = CommandResults(
        outputs_prefix=f'{CONTEXT_PREFIX}.Object',
        outputs_key_field='id',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )
    return result


def main():
    """
    main function, parses params and runs command functions
    """
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    app_id_obj = params.get('app_id')
    app_id = app_id_obj['identifier']
    app_secret = app_id_obj['password']
    access_token = f'{app_id}|{app_secret}'
    base_url = 'https://graph.facebook.com/v3.2'
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = argToBoolean(params.get('proxy', False))
    handle_proxy()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            access_token=access_token,
            verify=verify_certificate,
            proxy=proxy
        )
        result: Union[str, CommandResults, List[CommandResults]]
        if command == 'test-module':
            result = test_module(client)
        elif command == 'ip':
            result = ip_command(client, args, params)
        elif command == 'file':
            result = file_command(client, args, params)
        elif command == 'domain':
            result = domain_command(client, args, params)
        elif command == 'url':
            result = url_command(client, args, params)
        elif command == f'{COMMAND_PREFIX}-members':
            result = members_command(client)
        elif command == f'{COMMAND_PREFIX}-query':
            result = query_command(client, args)
        elif command == f'{COMMAND_PREFIX}-tags-search':
            result = tags_search_command(client, args)
        elif command == f'{COMMAND_PREFIX}-tagged-objects-list':
            result = tagged_objects_list_command(client, args)
        elif command == f'{COMMAND_PREFIX}-object-get-by-id':
            result = object_get_by_id_command(client, args)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
        return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

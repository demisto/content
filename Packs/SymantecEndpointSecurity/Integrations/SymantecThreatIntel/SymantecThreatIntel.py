import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Symantec Threat Intel

This is an integration that allows to query the Symantec Threat Intel information
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
import re
from ipaddress import ip_address

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
INTEGRATION_NAME = 'SymantecThreatIntel'
INSIGHT_CONTEXT_PREFIX = 'Symantec.Insight'
PROTECTION_CONTEXT_PREFIX = 'Symantec.Protection'
OUTPUT_KEY = 'indicator'
DEFAULT_RELIABILITY = DBotScoreReliability.B
MALICIOUS_CATEGORIES = ['Malicious Outbound Data/Botnets', 'Malicious Sources/Malnets', 'Phishing', 'Proxy Avoidance']
SUSPICIOUS_CATEGORIES = ['Compromised Sites', 'Dynamic DNS Host', 'Hacking', 'Placeholders', 'Potentially Unwanted Software',
                         'Remote Access', 'Spam', 'Suspicious'
                         'Violence/Intolerance', 'Child Pornography', 'Gore/Extreme', 'Nudity', 'Pornography'
                         ]

insight_context_prefix = {
    'url': 'Symantec.Insight.URL',
    'ip': 'Symantec.Insight.IP',
    'domain': 'Symantec.Insight.Domain'
}


threat_level = {
    0: 'Customer Override',
    1: 'Very Safe',
    2: 'Safe',
    3: 'Probably Safe',
    4: 'Leans Safe',
    5: 'May Not Be Safe',
    6: 'Exercise Caution',
    7: 'Suspicious/Risky',
    8: 'Possibly Malicious',
    9: 'Probably Malicious',
    10: 'Malicious'
}


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self,
                 oauth_token: str,
                 base_url,
                 ignored_domains: list[str] = [],
                 ignore_private_ips: bool = True,
                 reliability: str = DEFAULT_RELIABILITY,
                 verify=True,
                 proxy=False,
                 ok_codes=(),
                 headers=None,
                 auth=None,
                 timeout=BaseClient.REQUESTS_TIMEOUT,
                 ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=ok_codes,
                         headers=headers, auth=auth, timeout=timeout)
        self._oauth_token = oauth_token
        self._session_token = None
        self.ignored_domains: list[str] = ignored_domains
        self.ignore_private_ips: bool = ignore_private_ips
        self.reliability = reliability

    def authenticate(self) -> bool:
        headers = {
            "accept": "application/json",
            "authorization": self._oauth_token,
            "content-type": "application/x-www-form-urlencoded"
        }
        resp = self._http_request('POST', '/oauth2/tokens', headers=headers)
        self._session_token = resp.get('access_token')
        return self._session_token is not None

    def broadcom_file_insight(self, file_hash: str):
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }

        resp = self._http_request('GET', url_suffix=f'/threat-intel/insight/file/{file_hash}', headers=headers)
        return resp

    def broadcom_network_insight(self, network: str):
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }
        resp = self._http_request('GET', url_suffix=f'/threat-intel/insight/network/{network}', headers=headers)
        return resp

    def broadcom_file_protection(self, file_hash: str):
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }

        resp = self._http_request('GET', url_suffix=f'/threat-intel/protection/file/{file_hash}', headers=headers)
        return resp

    def broadcom_network_protection(self, network: str):
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }

        resp = self._http_request('GET', url_suffix=f'/threat-intel/protection/network/{network}', headers=headers)
        return resp

    def broadcom_cve_protection(self, cve: str):
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }

        resp = self._http_request('GET', url_suffix=f'/threat-intel/protection/cve/{cve}', headers=headers)
        return resp


''' HELPER FUNCTIONS '''


def is_filtered(value: str, filters: list[str]) -> bool:
    if not filters:
        return False

    filter_pattern = re.escape('|'.join(filters)).replace('\\|', '|')

    match = re.match(pattern=f'(http(s)?:\\/\\/)?([a-z0-9-]*\\.)*({filter_pattern})($|\\/.*)',
                     string=value,
                     flags=re.I)
    return match is not None


def ensure_argument(args: dict[str, Any], arg_name: str) -> list[str]:
    value = args.get(arg_name)
    if not value:
        raise ValueError(f'the value of {arg_name} must not be empty')

    return argToList(value)


def intersect(a: list, b: list) -> list:
    return [x for x in a if x in b]


def has_intersection(a: list, b: list) -> bool:
    return len(intersect(a, b)) > 0


def get_indicator_by_type(type: str, indicator: str, dbot_score: Common.DBotScore) -> Common.Indicator | None:
    if type == DBotScoreType.IP:
        return Common.IP(ip=indicator, dbot_score=dbot_score)
    elif type == DBotScoreType.URL:
        return Common.URL(url=indicator, dbot_score=dbot_score)
    elif type == DBotScoreType.DOMAIN:
        return Common.Domain(domain=indicator, dbot_score=dbot_score)
    else:
        return None


def calculate_file_severity(result: dict) -> tuple[int, str | None]:
    reputation = result.get('reputation', 'UNKNOWN')
    if reputation == 'BAD':
        return (Common.DBotScore.BAD, "File has Bad Reputation")
    elif reputation == 'GOOD':
        return (Common.DBotScore.GOOD, None)
    else:
        return (Common.DBotScore.NONE, None)


def calculate_network_severity(result: dict) -> tuple[int, str | None]:
    risk_level = result.get('risk_level')
    reputation = result.get('reputation', 'UNKNOWN')
    malicious_description = None
    categories = result.get('categories', [])

    if not risk_level:
        score = Common.DBotScore.NONE
    elif risk_level <= 5:
        score = Common.DBotScore.GOOD
    elif risk_level >= 8:
        score = Common.DBotScore.BAD
        malicious_description = f'{threat_level[risk_level]}'
    else:
        score = Common.DBotScore.SUSPICIOUS

    reputation_score = Common.DBotScore.NONE
    if reputation == 'BAD' or has_intersection(MALICIOUS_CATEGORIES, categories):
        reputation_score = Common.DBotScore.BAD
        malicious_description = f'Categorized as {",".join(categories)} with {reputation} reputation'
    elif has_intersection(SUSPICIOUS_CATEGORIES, categories):
        reputation_score = Common.DBotScore.SUSPICIOUS
    elif len(categories) > 1 or (len(categories) == 1 and categories[0] != 'Uncategorized'):
        reputation_score = Common.DBotScore.GOOD

    final_score = reputation_score if reputation_score > score else score
    return (final_score, malicious_description)


def parse_insight_response(response: dict) -> dict | None:
    if 'network' in response:
        return parse_network_insight_response(response)
    elif 'file' in response:
        return parse_file_insight_response(response)
    else:
        return None


def parse_network_insight_response(response: dict) -> dict:
    network = response.get('network')
    reputation = response.get('reputation', 'UNKNOWN')
    risk_level = response.get('threatRiskLevel', {}).get('level', 0)
    first_seen = response.get('firstSeen')
    last_seen = response.get('lastSeen')
    categories = []
    for category in response.get('categorization', {}).get('categories', []):
        categories.append(category.get('name'))

    response = {'indicator': network, 'reputation': reputation, 'risk_level': risk_level, 'categories': categories,
                'first_seen': first_seen, 'last_seen': last_seen}

    return response


def parse_file_insight_response(response: dict) -> dict:
    file = response.get('file')
    reputation = response.get('reputation', 'UNKNOWN')
    actors = response.get('actors', [])

    response = {'indicator': file, 'reputation': reputation, 'actors': actors}

    return response


def build_network_insight_result(severity: tuple[int, str | None], arg_type: str,
                                 raw_result: dict, reliability: str) -> CommandResults:
    dbot_score = Common.DBotScore(indicator=raw_result['indicator'],
                                  indicator_type=arg_type,
                                  integration_name=INTEGRATION_NAME,
                                  score=severity[0],
                                  reliability=reliability,
                                  malicious_description=severity[1])

    indicator = get_indicator_by_type(type=arg_type, indicator=raw_result['indicator'], dbot_score=dbot_score)
    command_result = CommandResults(outputs_prefix=insight_context_prefix[arg_type],
                                    outputs_key_field=OUTPUT_KEY,
                                    outputs=raw_result,
                                    indicator=indicator  # type: ignore
                                    )
    return command_result


def execute_network_command(client: Client, args: list[str], arg_type: str) -> list[CommandResults]:
    results = []
    for arg in args:
        response = {'network': arg}
        if arg_type == DBotScoreType.IP:
            ip = ip_address(arg)
            if not (ip.is_private or ip.is_loopback) or not client.ignore_private_ips:
                response = client.broadcom_network_insight(arg)

        elif not is_filtered(arg, client.ignored_domains):
            response = client.broadcom_network_insight(arg)

        result = parse_insight_response(response)
        if not result:
            continue

        severity = calculate_network_severity(result)
        command_result = build_network_insight_result(severity=severity, arg_type=arg_type,
                                                      raw_result=result, reliability=client.reliability)

        results.append(command_result)

    return results


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        if client.authenticate():
            message = 'ok'
        else:
            message = 'Authentication Error: make sure API Key is correctly set'
    except Exception as e:
        raise e

    return message


def ip_reputation_command(client: Client, args: Dict[str, Any], reliability: str) -> list[CommandResults]:
    values = ensure_argument(args, 'ip')

    results = execute_network_command(client, values, DBotScoreType.IP)
    return results


def url_reputation_command(client: Client, args: Dict[str, Any], reliability: str) -> list[CommandResults]:
    values = ensure_argument(args, 'url')
    results = execute_network_command(client, values, DBotScoreType.URL)

    return results


def domain_reputation_command(client: Client, args: Dict[str, Any], reliability: str) -> list[CommandResults]:
    values = ensure_argument(args, 'domain')
    results = execute_network_command(client, values, DBotScoreType.DOMAIN)

    return results


def file_reputation_command(client: Client, args: Dict[str, Any], reliability: str) -> list[CommandResults]:
    values = ensure_argument(args, 'file')
    results = []
    for file in values:
        # The API only supports SHA256, so return a "Unknown" Reputation otherwise
        resp = {'file': file} if not re.match('^[A-Fa-f0-9]{64}$', file) else client.broadcom_file_insight(file)
        file_result = parse_insight_response(resp)
        if file_result:
            results.append(file_result)

    command_results = []
    for result in results:
        severity = calculate_file_severity(result)
        dbot_score = Common.DBotScore(indicator=result['indicator'],
                                      indicator_type=DBotScoreType.FILE,
                                      integration_name=INTEGRATION_NAME,
                                      score=severity[0],
                                      malicious_description=severity[1],
                                      reliability=reliability
                                      )

        file_indicator = Common.File(sha256=result['indicator'], dbot_score=dbot_score)
        command_result = CommandResults(outputs_prefix=f'{INSIGHT_CONTEXT_PREFIX}.File',
                                        outputs_key_field=OUTPUT_KEY,
                                        outputs=result,
                                        indicator=file_indicator)
        command_results.append(command_result)

    return command_results


def symantec_protection_file_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = ensure_argument(args, 'file')
    results = []
    for file in values:
        # The API only supports SHA256, so return a "Unknown" Reputation otherwise
        resp = {'file': file} if not re.match('^[A-Fa-f0-9]{64}$', file) else client.broadcom_file_protection(file)
        results.append(resp)

    command_results = []
    for result in results:
        command_result = CommandResults(outputs_prefix=f'{PROTECTION_CONTEXT_PREFIX}.File',
                                        outputs_key_field='file',
                                        outputs=result,
                                        raw_response=result)
        command_results.append(command_result)

    return command_results


def symantec_protection_network_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = ensure_argument(args, 'network')
    results = []
    for network in values:
        result = client.broadcom_network_protection(network)
        if result:
            results.append(result)

    command_results = []
    for result in results:

        command_result = CommandResults(outputs_prefix=f'{PROTECTION_CONTEXT_PREFIX}.Network',
                                        outputs_key_field='network',
                                        outputs=result)
        command_results.append(command_result)

    return command_results


def symantec_protection_cve_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = ensure_argument(args, 'cve')
    results = []
    for cve in values:
        result = client.broadcom_cve_protection(cve)
        if result:
            results.append(result)

    command_results = []
    for result in results:
        command_result = CommandResults(outputs_prefix=f'{PROTECTION_CONTEXT_PREFIX}.Network',
                                        outputs_key_field='file',  # Based on the documentation, the CVE is in the 'file' field
                                        outputs=result)
        command_results.append(command_result)

    return command_results


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    """

    base_url = urljoin(demisto.params()['url'], '/v1')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    oauth = demisto.params().get('credentials', {}).get('password')
    reliability = demisto.params().get('integration_reliability', DEFAULT_RELIABILITY)
    ignored_domains = argToList(demisto.params().get('ignored_domains'))
    ignore_private_ips = argToBoolean(demisto.params().get('ignore_private_ip', True))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            oauth_token=oauth,
            base_url=base_url,
            ignored_domains=ignored_domains,
            ignore_private_ips=ignore_private_ips,
            reliability=reliability,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'url':
            client.authenticate()
            return_results(url_reputation_command(client, demisto.args(), reliability))

        elif demisto.command() == 'ip':
            client.authenticate()
            return_results(ip_reputation_command(client, demisto.args(), reliability))

        elif demisto.command() == 'domain':
            client.authenticate()
            return_results(domain_reputation_command(client, demisto.args(), reliability))

        elif demisto.command() == 'file':
            client.authenticate()
            return_results(file_reputation_command(client, demisto.args(), reliability))
        elif demisto.command() == 'symantec-protection-file':
            client.authenticate()
            return_results(symantec_protection_file_command(client, demisto.args()))
            pass
        elif demisto.command() == 'symantec-protection-network':
            client.authenticate()
            return_results(symantec_protection_network_command(client, demisto.args()))
            pass
        elif demisto.command() == 'symantec-protection-cve':
            client.authenticate()
            return_results(symantec_protection_cve_command(client, demisto.args()))
            pass
        else:
            raise NotImplementedError(demisto.command())

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

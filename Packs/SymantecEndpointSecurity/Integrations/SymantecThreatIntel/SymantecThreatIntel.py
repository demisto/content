import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Symantec Threat Intel

This is an integration that allows to query the Symantec Threat Intel information
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
INTEGRATION_NAME = 'SymantecThreatIntel'
INSIGHT_CONTEXT_PREFIX = 'Symantec.Insight'
PROTECTION_CONTEXT_PREFIX = 'Symantec.Protection'
OUTPUT_KEY = 'indicator'
MALICIOUS_CATEGORIES = ['Malicious Outbound Data/Botnets', 'Malicious Sources/Malnets', 'Phishing', 'Proxy Avoidance']
SUSPICIOUS_CATEGORIES = ['Compromised Sites', 'Dynamic DNS Host', 'Hacking', 'Placeholders', 'Potentially Unwanted Software',
                         'Remote Access', 'Spam', 'Suspicious'
                         'Violence/Intolerance', 'Child Pornography', 'Gore/Extreme', 'Nudity', 'Pornography'
                         ]

ThreatLevel = {
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
    _session_token = None

    def authenticate(self, oauth_token: str) -> bool:
        headers = {
            "accept": "application/json",
            "authorization": oauth_token,
            "content-type": "application/x-www-form-urlencoded"
        }
        resp = self._http_request('POST', '/oauth2/tokens', headers=headers)
        self._session_token = resp.get('access_token', None)
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
        pass

    def broadcom_network_protection(self, network: str):
        pass

    def broadcom_cve_protection(self, cve: str):
        pass


''' HELPER FUNCTIONS '''


def intersect(a: list, b: list) -> list:
    return [x for x in a if x in b]


def has_intersection(a: list, b: list) -> bool:
    return len(intersect(a, b)) > 0


def calculate_file_severity(result: dict) -> tuple[int, str | None]:
    reputation = result.get('reputation', 'UNKNOWN')
    if reputation == 'BAD':
        return (Common.DBotScore.BAD, "File has Bad Reputation")
    elif reputation == 'GOOD':
        return (Common.DBotScore.GOOD, None)
    else:
        return (Common.DBotScore.NONE, None)


def calculate_network_severity(result: dict) -> tuple[int, str | None]:
    risk_level = result.get('risk_level', 0)
    reputation = result.get('reputation', 'UNKNOWN')
    malicious_description = None
    categories = result.get('categories', [])

    score = Common.DBotScore.GOOD if risk_level <= 5 else Common.DBotScore.BAD if risk_level >= 8 else Common.DBotScore.SUSPICIOUS
    if score == Common.DBotScore.BAD:
        malicious_description = f'{ThreatLevel[risk_level]}'

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
    categories = []
    for category in response.get('categorization', {}).get('categories', []):
        categories.append(category.get('name'))

    response = {'indicator': network, 'reputation': reputation, 'risk_level': risk_level, 'categories': categories}

    return response


def parse_file_insight_response(response: dict) -> dict:
    file = response.get('file')
    reputation = response.get('reputation', 'UNKNOWN')
    actors = response.get('actors', [])

    response = {'indicator': file, 'reputation': reputation, 'actors': actors}

    return response


def execute_network_command(client: Client, args: list[str]) -> list[dict]:
    results = []
    for arg in args:
        response = client.broadcom_network_insight(arg)
        result = parse_insight_response(response)
        if result:
            results.append(result)

    return results


''' COMMAND FUNCTIONS '''


def test_module(client: Client, oauth: str) -> str:
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
        if client.authenticate(oauth_token=oauth):
            message = 'ok'
        else:
            message = 'Authentication Error: make sure API Key is correctly set'
    except Exception as e:
        raise e

    return message

    # https://xsoar.pan.dev/docs/integrations/context-and-outputs#return-info-file
    # https://xsoar.pan.dev/docs/integrations/generic-commands-reputation#background-and-motivation
    # https://xsoar.pan.dev/docs/integrations/dbot
    # https://xsoar.pan.dev/docs/integrations/code-conventions#commandresults

    # https://xsoar.pan.dev/docs/integrations/code-conventions#credentials


def ip_reputation_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('ip', ''))
    results = execute_network_command(client, values)
    command_results = []
    for result in results:
        severity = calculate_network_severity(result)
        dbot_score = Common.DBotScore(indicator=result['indicator'],
                                      indicator_type=DBotScoreType.IP,
                                      integration_name=INTEGRATION_NAME,
                                      score=severity[0],
                                      malicious_description=severity[1]
                                      )

        ip = Common.IP(ip=result['indicator'], dbot_score=dbot_score)
        command_result = CommandResults(outputs_prefix=f'{INSIGHT_CONTEXT_PREFIX}.IP',
                                        outputs_key_field=OUTPUT_KEY,
                                        outputs=result,
                                        indicator=ip)
        command_results.append(command_result)

    return command_results


def url_reputation_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('url', ''))
    results = execute_network_command(client, values)
    command_results = []
    for result in results:
        severity = calculate_network_severity(result)
        dbot_score = Common.DBotScore(indicator=result['indicator'],
                                      indicator_type=DBotScoreType.URL,
                                      integration_name=INTEGRATION_NAME,
                                      score=severity[0],
                                      malicious_description=severity[1]
                                      )

        url = Common.URL(url=result['indicator'], dbot_score=dbot_score)
        command_result = CommandResults(outputs_prefix=f'{INSIGHT_CONTEXT_PREFIX}.URL',
                                        outputs_key_field=OUTPUT_KEY,
                                        outputs=result,
                                        indicator=url)
        command_results.append(command_result)

    return command_results


def domain_reputation_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('domain', ''))
    results = execute_network_command(client, values)
    command_results = []
    for result in results:
        severity = calculate_network_severity(result)
        dbot_score = Common.DBotScore(indicator=result['indicator'],
                                      indicator_type=DBotScoreType.DOMAIN,
                                      integration_name=INTEGRATION_NAME,
                                      score=severity[0],
                                      malicious_description=severity[1]
                                      )

        domain = Common.Domain(domain=result['indicator'], dbot_score=dbot_score)
        command_result = CommandResults(outputs_prefix=f'{INSIGHT_CONTEXT_PREFIX}.Domain',
                                        outputs_key_field=OUTPUT_KEY,
                                        outputs=result,
                                        indicator=domain)
        command_results.append(command_result)

    return command_results


def file_reputation_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('file', ''))
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
                                      malicious_description=severity[1]
                                      )

        file = Common.File(sha256=result['indicator'], dbot_score=dbot_score)
        command_result = CommandResults(outputs_prefix=f'{INSIGHT_CONTEXT_PREFIX}.File',
                                        outputs_key_field=OUTPUT_KEY,
                                        outputs=result,
                                        indicator=file)
        command_results.append(command_result)

    return command_results


def symantec_protection_file_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('file', ''))
    results = []
    for file in values:
        # The API only supports SHA256, so return a "Unknown" Reputation otherwise
        resp = {'file': file} if not re.match('^[A-Fa-f0-9]{64}$', file) else client.broadcom_file_protection(file)
        results.append(resp)

    command_results = []
    for result in results:
        command_result = CommandResults(outputs_prefix=f'{PROTECTION_CONTEXT_PREFIX}.File',
                                        outputs_key_field='file',
                                        outputs=result)
        command_results.append(command_result)

    return command_results


def symantec_protection_network_command(client: Client, args: Dict[str, Any]) -> list[CommandResults]:
    values = argToList(arg=args.get('network', ''))
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
    values = argToList(arg=args.get('cve', ''))
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


def main() -> None:
    """main function, parses params and runs command functions
    """

    base_url = urljoin(demisto.params()['url'], '/v1')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    oauth = demisto.params().get('credentials', {}).get('password')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, oauth)
            return_results(result)

        elif demisto.command() == 'url':
            client.authenticate(oauth)
            return_results(url_reputation_command(client, demisto.args()))

        elif demisto.command() == 'ip':
            client.authenticate(oauth)
            return_results(ip_reputation_command(client, demisto.args()))

        elif demisto.command() == 'domain':
            client.authenticate(oauth)
            return_results(domain_reputation_command(client, demisto.args()))

        elif demisto.command() == 'file':
            client.authenticate(oauth)
            return_results(file_reputation_command(client, demisto.args()))
        elif demisto.command() == 'symantec-protection-file':
            client.authenticate(oauth)
            return_results(symantec_protection_file_command(client, demisto.args()))
            pass
        elif demisto.command() == 'symantec-protection-network':
            client.authenticate(oauth)
            return_results(symantec_protection_network_command(client, demisto.args()))
            pass
        elif demisto.command() == 'symantec-protection-cve':
            client.authenticate(oauth)
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

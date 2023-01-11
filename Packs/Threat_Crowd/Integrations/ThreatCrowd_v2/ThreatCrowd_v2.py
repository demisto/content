import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict, Any, List, Optional, Tuple

''' CONSTANTS '''

VENDOR = 'Threat Crowd'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, reliability: DBotScoreReliability,
                 entry_limit: int):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.reliability = reliability
        self.entry_limit = entry_limit

    def _get_limit_for_command(self, command_limit: int = None):
        if command_limit:
            return None if command_limit == -1 else command_limit
        else:
            return self.entry_limit


''' HELPER FUNCTIONS '''


def _get_list_without_empty(list_to_change: list) -> list:
    if list_to_change:
        return [entry for entry in list_to_change if entry]
    return list_to_change


def handle_resolutions(resolutions: List[dict], limit: Optional[int]) -> List[dict]:
    """ Gets a resolution section from response with following struct: [{"last_resolved": "2014-12-14", "domain": "example.com"}]
        return a sorted list truncated to limit, desc by time."""

    resolutions = resolutions[:limit]
    resolutions.sort(key=lambda x: x['last_resolved'], reverse=True)
    return resolutions


def _get_dbot_score(json_res: dict) -> Tuple[int, str]:
    """
    Calculates DBot score according to https://github.com/AlienVault-OTX/ApiV2/blob/master/README.md#votes
    """
    # checks that response is valid
    if json_res.get('response_code') == '1':
        votes = json_res.get('votes')
        if votes == -1:
            return Common.DBotScore.BAD, 'BAD'
        elif votes == 0:
            return Common.DBotScore.SUSPICIOUS, 'SUSPICIOUS'
        elif votes == 1:
            return Common.DBotScore.GOOD, 'GOOD'

    return Common.DBotScore.NONE, 'None'


''' COMMAND FUNCTIONS '''


def ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'ip/report/'
    entries_limit = client._get_limit_for_command(arg_to_number(args.get('limit'), 'limit', False))
    ips = argToList(args.get('ip'))
    for ip in ips:
        res = client._http_request(method='GET', url_suffix=api_url, params={'ip': ip})

        # adding value to both outputs and raw results as it is not provided in the API response
        res['value'] = ip
        score, score_str = _get_dbot_score(res)

        dbot = Common.DBotScore(
            ip, DBotScoreType.IP, VENDOR, score, reliability=client.reliability)
        ip_object = Common.IP(ip, dbot)

        hashes = res.get('hashes', [])[:entries_limit]
        resolutions = handle_resolutions(res.get('resolutions', []), entries_limit)

        markdown = f"### Threat crowd report for ip {ip}: \n  ### DBotScore: {score_str} \n" \
                   f"{tableToMarkdown('Resolutions', resolutions, removeNull=True)} \n " \
                   f"{tableToMarkdown('Hashes', hashes, headers='Hashes', removeNull=True)}" \
                   f"{tableToMarkdown('References', res.get('references'), removeNull=True, headers='References')}"

        outputs = {
            'hashes': hashes,
            'permalink': res.get('permalink'),
            'resolutions': resolutions,
            'references': res.get('references'),
            'response_code': res.get('response_code'),
            'votes': res.get('votes'),
            'value': res.get('value')
        }

        # using res.copy() to avoid changing all previous entries's values.
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.IP',
            outputs=outputs,
            outputs_key_field='value',
            indicator=ip_object,
            readable_output=markdown,
            raw_response=res.copy()

        ))

    return command_results


def email_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'email/report/'
    emails = argToList(args.get('email'))
    for email in emails:
        res = client._http_request(method='GET', url_suffix=api_url, params={'email': email})

        # adding value to both outputs and raw results as it is not provided in the API response
        res['value'] = email
        score, score_str = _get_dbot_score(res)
        dbot = Common.DBotScore(
            email, DBotScoreType.EMAIL, VENDOR, score, reliability=client.reliability)
        email_object = Common.EMAIL(email, dbot)

        markdown = f"### Threat crowd report for Email {email} \n " \
                   f"DBotScore: {score_str} \n {tableToMarkdown('Results', res, removeNull=True)}"

        # using res.copy() to avoid changing all previous entries's values.
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.Account',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=email_object,
            readable_output=markdown,
            raw_response=res.copy()

        ))

    return command_results


def domain_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'domain/report/'
    entries_limit = client._get_limit_for_command(arg_to_number(args.get('limit'), 'limit', False))
    domains = argToList(args.get('domain'))
    for domain in domains:
        res = client._http_request(method='GET', url_suffix=api_url, params={'domain': domain})

        # adding value to both outputs and raw results as it is not provided in the API response
        res['value'] = domain
        score, score_str = _get_dbot_score(res)
        dbot = Common.DBotScore(
            domain, DBotScoreType.DOMAIN, VENDOR, score, reliability=client.reliability)
        domain_object = Common.Domain(domain, dbot)

        markdown = f"### Threat crowd report for domain {domain} \n ### DBotScore: {score_str} \n"

        subdomains = res.get('subdomains')[:entries_limit]
        resolutions = handle_resolutions(res.get('resolutions', []), entries_limit)

        markdown += f'{tableToMarkdown("Resolutions", resolutions, removeNull=True)} \n ' \
                    f'{tableToMarkdown("Subdomains", subdomains, headers=["subdomains"])} \n'
        res_to_show = res.copy()
        res_to_show.pop("resolutions")
        res_to_show.pop("subdomains")
        markdown += f'{tableToMarkdown(" ", res_to_show, removeNull=True)}'

        outputs = {
            'hashes': res.get('hashes'),
            'permalink': res.get('permalink'),
            'resolutions': resolutions,
            'references': res.get('references'),
            'response_code': res.get('response_code'),
            'votes': res.get('votes'),
            'subdomains': subdomains,
            'value': res.get('value')
        }

        # using res.copy() to avoid changing all previous entries's values.
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.Domain',
            outputs=outputs,
            outputs_key_field='value',
            indicator=domain_object,
            readable_output=markdown,
            raw_response=res.copy()

        ))

    return command_results


def antivirus_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'antivirus/report/'
    antivirus_list = argToList(args.get('antivirus'))
    entries_limit = client._get_limit_for_command(arg_to_number(args.get('limit'), 'limit', False))

    for antivirus in antivirus_list:
        res = client._http_request(method='GET', url_suffix=api_url, params={'antivirus': antivirus})

        # adding value to both outputs and raw results as it is not provided in the API response
        res['value'] = antivirus
        res['hashes'] = res['hashes'][:entries_limit]

        markdown = tableToMarkdown(f"Threat crowd report for antivirus {antivirus}", res, removeNull=True)

        # using res.copy() to avoid changing all previous entries's values.
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.AntiVirus',
            outputs=res.copy(),
            outputs_key_field='value',
            readable_output=markdown,
            raw_response=res.copy()
        ))

    return command_results


def file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'file/report/'
    files = argToList(args.get('file'))
    entries_limit = client._get_limit_for_command(arg_to_number(args.get('limit'), 'limit', False))

    for file_hash in files:
        res = client._http_request(method='GET', url_suffix=api_url, params={'resource': file_hash})

        # adding value to both outputs and raw results as it is not provided in the API response
        res['value'] = file_hash

        score, score_str = _get_dbot_score(res)
        dbot = Common.DBotScore(
            file_hash, DBotScoreType.FILE, VENDOR, score, reliability=client.reliability)
        file_object = Common.File(dbot, md5=res.get('md5'), sha1=res.get('sha1'))

        # removes empty entries returned by API
        res['scans'] = _get_list_without_empty(res.get('scans'))[:entries_limit]

        markdown = f"### Threat crowd report for File {file_hash}: \n ### DBotScore: {score_str} \n " \
                   f"{tableToMarkdown('Results', res)}".replace('<br>', '')

        # using res.copy() to avoid changing all previous entries's values.
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.File',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=file_object,
            readable_output=markdown,
            raw_response=res.copy()
        ))

    return command_results


def test_module(client: Client) -> str:
    try:
        api_url = 'ip/report/'
        client._http_request(method='GET', url_suffix=api_url, params={'ip': '1.1.1.1'})
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set.'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    command_functions = {'email': email_command,
                         'domain': domain_command,
                         'ip': ip_command,
                         'threat-crowd-antivirus': antivirus_command,
                         'file': file_command}
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')
    try:
        params = demisto.params()
        base_url = params.get('server_url')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        entry_limit = arg_to_number(params.get('entry_limit'), 'entry_limit', True)
        if not entry_limit:
            raise Exception("Please Provide a limit for number of entries. To receive all entries use -1")
        reliability = params.get('integrationReliability')
        reliability = reliability if reliability else DBotScoreReliability.C

        if DBotScoreReliability.is_valid_type(reliability):
            reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise Exception("Please provide a valid value for the Source Reliability parameter.")

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            reliability=reliability,
            entry_limit=entry_limit
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        else:
            if command in command_functions:
                return_results(command_functions[command](client, demisto.args()))
            else:
                raise NotImplementedError(f'command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

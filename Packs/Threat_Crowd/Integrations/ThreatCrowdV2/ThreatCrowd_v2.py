import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''
VENDOR = 'Threat Crowd'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API.
    """

    def __init__(self, base_url, verify, proxy, reliability):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.reliability = reliability

    def http_request(self, url_postfix: str, **kwargs) -> dict:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            requests.Response: The http response
        """

        return super()._http_request('GET', url_postfix, params=kwargs)


''' HELPER FUNCTIONS '''


def _get_dbot_score(json_res: dict):
    """Gets a json response and calculate the dbot score by the response"""

    if json_res.get('response_code') == '1':
        votes = json_res.get('votes')
        if votes == -1:
            return Common.DBotScore.BAD
        elif votes == 0:
            return Common.DBotScore.SUSPICIOUS
        elif votes == 1:
            return Common.DBotScore.GOOD

    return Common.DBotScore.NONE


''' COMMAND FUNCTIONS '''


def ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'ip/report/'
    resolution_limit = args.get('resolution_limit')
    resolution_limit = int(resolution_limit) if resolution_limit else resolution_limit
    ips = argToList(args.get('ip'))
    for ip in ips:
        res = client.http_request(url_postfix=api_url, **{'ip': ip})
        res['value'] = ip
        score = _get_dbot_score(res)
        dbot = Common.DBotScore(
            ip, DBotScoreType.IP, VENDOR, score, reliability=client.reliability)
        ip_object = Common.IP(ip, dbot)

        markdown = f"Threat crowd report for ip {ip}: \n"
        markdown += tableToMarkdown('Resolutions', res.get('resolutions', [])[:resolution_limit])
        markdown += f"Hashes: \n {res.get('hashes')} \n"
        markdown += tableToMarkdown('References', res.get('references'))

        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.IP',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=ip_object,
            readable_output=markdown,
            raw_response=res

        ))

    return command_results


def email_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'email/report/'
    emails = argToList(args.get('email'))
    for email in emails:
        res = client.http_request(url_postfix=api_url, **{'email': email})
        res['value'] = email
        score = _get_dbot_score(res)
        dbot = Common.DBotScore(
            email, DBotScoreType.EMAIL, VENDOR, score, reliability=client.reliability)
        email_object = Common.EMAIL(email, dbot)

        markdown = tableToMarkdown(f"Threat crowd report for Email {email}", res)

        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.Account',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=email_object,
            readable_output=markdown,
            raw_response=res

        ))

    return command_results


def domain_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'domain/report/'
    resolution_limit = args.get('resolution_limit')
    resolution_limit = int(resolution_limit) if resolution_limit else resolution_limit
    domains = argToList(args.get('domain'))
    for domain in domains:
        res = client.http_request(url_postfix=api_url, **{'domain': domain})
        res['value'] = domain
        score = _get_dbot_score(res)
        dbot = Common.DBotScore(
            domain, DBotScoreType.DOMAIN, VENDOR, score, reliability=client.reliability)
        domain_object = Common.Domain(domain, dbot)

        markdown = f"Threat crowd report for domain {domain} \n"
        markdown += tableToMarkdown('Resolutions', res.get('resolutions', [])[:resolution_limit])
        res_without_resolutions = res.copy()
        res_without_resolutions.pop('resolutions')
        markdown += tableToMarkdown("\n", res_without_resolutions)
        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.Domain',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=domain_object,
            readable_output=markdown,
            raw_response=res

        ))

    return command_results


def antivirus_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'antivirus/report/'
    antivirus_list = argToList(args.get('antivirus'))
    for antivirus in antivirus_list:
        res = client.http_request(url_postfix=api_url, **{'antivirus': antivirus})
        res['value'] = antivirus

        markdown = tableToMarkdown(f"Threat crowd report for antivirus {antivirus}", res)

        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.AntiVirus',
            outputs=res.copy(),
            outputs_key_field='value',
            readable_output=markdown,
            raw_response=res
        ))

    return command_results


def file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    api_url = 'file/report/'
    files = argToList(args.get('file'))
    for file_hash in files:
        res = client.http_request(url_postfix=api_url, **{'resource': file_hash})
        res['value'] = file_hash

        score = _get_dbot_score(res)
        dbot = Common.DBotScore(
            file_hash, DBotScoreType.FILE, VENDOR, score, reliability=client.reliability)
        file_object = Common.File(dbot, md5=res.get('md5'), sha1=res.get('sha1'))

        markdown = tableToMarkdown(f"Threat crowd report for File {file_hash}", res)

        command_results.append(CommandResults(
            outputs_prefix='ThreatCrowd.File',
            outputs=res.copy(),
            outputs_key_field='value',
            indicator=file_object,
            readable_output=markdown,
            raw_response=res
        ))

    return command_results


def test_module(client: Client) -> str:
    try:
        api_url = 'ip/report/'
        client.http_request(url_postfix=api_url, **{'ip': '1.1.1.1'})
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    command_functions = {'email': email_command,
                         'domain': domain_command,
                         'ip': ip_command,
                         'threat-crowd-antivirus': antivirus_command,
                         'file': file_command}

    params = demisto.params()
    base_url = params.get('server_url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.C

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            reliability=reliability
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        else:
            if demisto.command() in command_functions:
                return_results(command_functions[demisto.command()](client, demisto.args()))
            else:
                raise NotImplementedError(f'command {demisto.command()} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

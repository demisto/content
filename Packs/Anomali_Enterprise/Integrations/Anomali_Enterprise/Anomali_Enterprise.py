from typing import Dict

import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR_NAME = 'Anomali Enterprise'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client to use in the Anomali Enterprise integration. Overrides BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool):
        headers = {
            'Content-Type': 'application/json',
            'ae-authorization': f'{username}:{password}'
        }
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)
        self._username = username
        self._password = password

    def start_search_job_request(self, from_: str, to_: str, indicators: List[str]) -> dict:
        """Initiate a search job.
        Args:
            from_: from which time to initiate the search
            to_: to which time to initiate the search
            indicators: indicators to search
        Returns:
            Response from API.
        """
        data = {'username': self._username, 'password': self._password, 'from': from_, 'to': to_,
                'indicators': indicators}
        return self._http_request(method='POST', url_suffix='/api/v1/mars/forensic', headers=self._headers,
                                  json_data=data)

    def get_search_job_result_request(self, job_id: str) -> dict:
        """Retrieve a search job results.
        Args:
            job_id: the search job uuid
        Returns:
            Response from API.
        """
        params = {'jobid': job_id}
        return self._http_request(method='GET', url_suffix='/api/v1/mars/forensic', headers=self._headers,
                                  params=params)

    def domain_request(self, domain: List[str]) -> dict:
        """Retrieve information regarding a domain.
        Args:
            domain: the domain name to search
        Returns:
            Response from API.
        """
        data = {'username': self._username, 'password': self._password, 'domains': domain}
        return self._http_request(method='POST', url_suffix='/api/v1/mars/dga_score', headers=self._headers,
                                  json_data=data)


''' COMMAND FUNCTIONS '''


def module(client: Client) -> str:
    """
    Performs basic get request
    """
    response = client.domain_request(argToList('google.com'))
    if response.get('result') != 'success':
        raise Exception('To Use Anomali Enterprise, make sure you are using the current username and password '
                        'and have the needed permissions.')
    return 'ok'


def start_search_job(client: Client, args: dict) -> CommandResults:
    """Start a search job for IOCs.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    from_ = str(args.get('from', '1 day'))
    to_ = str(args.get('to', ''))
    indicators = argToList(args.get('indicators'))

    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f'
    from_iso = parse_date_range(from_, date_format=timestamp_format)[0]
    if to_:
        to_iso = parse_date_range(to_, date_format=timestamp_format)[0]
    else:
        to_iso = datetime.now().strftime(timestamp_format)

    response = client.start_search_job_request(from_iso, to_iso, indicators)

    start_search_outputs = {
        'status': 'in progress',
        'job_id': response.get('jobid', '')
    }

    return CommandResults(
        outputs_prefix='AnomaliEnterprise.ForensicSearch',
        outputs_key_field='job_id',
        outputs=start_search_outputs,
        readable_output=tableToMarkdown(name="Forensic search started:", t=start_search_outputs, removeNull=True),
        raw_response=response
    )


def get_search_job_result(client: Client, args: Dict) -> CommandResults:
    """Get the search job result.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    job_id = str(args.get('job_id'))
    limit = int(args.get('limit', '20'))
    verbose = args.get('verbose', 'true') == 'true'
    response = client.get_search_job_result_request(job_id)
    if 'error' in response:
        raise Exception(f"{str(response.get('error'))}. Job ID might have expired.")

    outputs = response
    outputs.update({'job_id': job_id})
    if not response.get('complete'):
        human_readable = f'job ID: {job_id} is still in progress.'
        outputs.update({'status': 'in progress'})
    else:
        if response.get('totalMatches'):
            headers = ['status', 'job_id', 'category', 'totalFiles', 'scannedEvents']
            human_readable = tableToMarkdown(name="Forensic search metadata:", t=response, headers=headers,
                                             removeNull=True)
            if verbose:
                human_readable += tableToMarkdown(name="Forensic search results:",
                                                  t=response.get('streamResults', [])[:limit], removeNull=True)
            if 'streamResults' in outputs:
                outputs['streamResults'] = outputs.get('streamResults', [])[:limit]  # limit the outputs to the context
        else:
            human_readable = f'No matches found for the given job ID: {job_id}.'
            response.update({'status': 'completed'})

    return CommandResults(
        outputs_prefix='AnomaliEnterprise.ForensicSearch',
        outputs_key_field='job_id',
        outputs=response,
        readable_output=human_readable,
        raw_response=response
    )


def dga_domain_status(client: Client, args: dict) -> CommandResults:
    """Search domain DGA status.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults.
    """
    domains = argToList(str(args.get('domains')))

    response = client.domain_request(domains)

    domains_data = response.get('data', {})
    outputs = []
    for domain in domains:
        output = {
            'domain': domain,
            'malware_family': domains_data.get(domain, {}).get('malware_family'),
            'probability': domains_data.get(domain, {}).get('probability')
        }
        outputs.append(output)
    return CommandResults(
        outputs_prefix='AnomaliEnterprise.DGA',
        outputs_key_field='domain',
        outputs=outputs,
        readable_output=tableToMarkdown(name="Domains DGA:", t=outputs, removeNull=True),
        raw_response=response
    )


def domain_command(client: Client, args: dict) -> List[CommandResults]:
    """Search domain DGA status.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults and DBotScore.
    """
    domain_list = argToList(args.get('domain'))

    response = client.domain_request(domain_list)
    domains_data = response.get('data', {})
    command_results_list = []
    for domain in domain_list:
        output = {
            'domain': domain,
            'malware_family': domains_data.get(domain, {}).get('malware_family'),
            'probability': domains_data.get(domain, {}).get('probability')
        }
        score = calculate_dbot_score(domains_data.get(domain, {}))

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=score,
            malicious_description=str(output.get('malware_family', ''))
        )

        domain = Common.Domain(
            domain=domain,
            dbot_score=dbot_score,
            tags='DGA' if score in [Common.DBotScore.SUSPICIOUS, Common.DBotScore.BAD] else None
        )

        command_results = CommandResults(
            outputs_prefix='AnomaliEnterprise.DGA',
            outputs_key_field='domain',
            outputs=output,
            readable_output=tableToMarkdown(name="Domains DGA:", t=output, removeNull=True),
            indicator=domain,
            raw_response=response
        )
        command_results_list.append(command_results)

    return command_results_list


def calculate_dbot_score(domain_data: dict) -> int:
    """There is no distinction between benign to unknown domains in Anomali Enterprise
    malware family exists and prob > 0.6 -> 3
    malware family exists and prob < 0.6 -> 2
    else -> 0

    Args:
        domain_data: the domain data

    Returns:
        DBot Score.
    """
    score = Common.DBotScore.NONE
    if domain_data.get('malware_family', {}):
        if float(domain_data.get('probability', 0)) > 0.6:
            score = Common.DBotScore.BAD
        else:
            score = Common.DBotScore.SUSPICIOUS
    return score


''' MAIN FUNCTION '''


def main() -> None:
    """
    Parse and validates integration params, runs integration commands.
    """
    params = demisto.params()
    server_url = params.get('url')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy') is True

    command = demisto.command()
    LOG(f'Command being called in {VENDOR_NAME} is: {command}')

    try:
        client = Client(server_url=server_url, username=username, password=password, verify=verify, proxy=proxy)
        commands = {
            'anomali-enterprise-retro-forensic-search': start_search_job,
            'anomali-enterprise-retro-forensic-search-results': get_search_job_result,
            'anomali-enterprise-dga-domain-status': dga_domain_status,
            'domain': domain_command,
        }
        if command == 'test-module':
            return_results(module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)} \n '
                     f'tracback: {traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

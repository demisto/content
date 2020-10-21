from typing import Dict, Tuple, Callable, List

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR_NAME = 'Anomali Enterprise'


class Client(BaseClient):
    """
    Client to use in the Anomali Enterprise integration. Overrides BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
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
        data = json.dumps({'username': self._username, 'password': self._password, 'from': from_, 'to': to_,
                'indicators': indicators})
        response = self._http_request(method='POST', url_suffix='/api/v1/mars/forensic', data=data)
        return response

    def get_search_job_result_request(self, job_id: str) -> dict:
        """Retrieve a search job results.
        Args:
            job_id: the search job uuid
        Returns:
            Response from API.
        """
        data = json.dumps({'username': self._username, 'password': self._password})
        params = {'jobid': job_id}
        response = self._http_request(method='GET', url_suffix='/api/v1/mars/forensic', data=data, params=params)
        return response

    def domain_request(self, domain: str) -> dict:
        """Retrieve information regarding a domain.
        Args:
            domain: the domain name to search
        Returns:
            Response from API.
        """
        data = json.dumps({'username': self._username, 'password': self._password, 'domains': domain})
        response = self._http_request(method='POST', url_suffix='/api/v1/mars/dga_score', headers=self._headers,
                                      data=data)
        return response


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
    from_ = str(args.get('from'))
    to_ = str(args.get('to'))
    indicators = str(args.get('indicators'))
    response = client.start_search_job_request(from_, to_, indicators)
    search_data = response.get('data', {})
    search_data.update({'Status': 'In Progress'})
    return CommandResults(
        outputs_prefix='AnomaliEnterprise.ForensicSearch',
        outputs_key_field='jobid',
        outputs=response,
        readable_output=tableToMarkdown(name=f"Forensic Search:", t=search_data, removeNull=True),
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
    response = client.get_search_job_result_request(job_id)
    result_data = response.get('data', {})
    status = 'In Progress' if False else 'Completed'  # TODO
    result_data.update({'Status': status})
    return CommandResults(
        outputs_prefix='AnomaliEnterprise.ForensicSearch',
        outputs_key_field='jobid',
        outputs=response,
        readable_output=tableToMarkdown(name=f"Forensic Results:", t=result_data, removeNull=True),
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
    domains = argToList(args.get('domains'))
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
        readable_output=tableToMarkdown(name=f"Domains DGA:", t=outputs, removeNull=True),
        raw_response=response
    )


def domain_command(client: Client, args: dict) -> CommandResults:
    """Search domain DGA status.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        CommandResults and DBotScore.
    """
    domain = args.get('domain')
    response = client.domain_request([domain])
    domain_data = response.get('data', {})
    output = {
        'domain': domain,
        'malware_family': domain_data.get(domain, {}).get('malware_family'),
        'probability': domain_data.get(domain, {}).get('probability')
    }
    score = calculate_dbot_score(domain_data)

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name=VENDOR_NAME,
        score=score
    )

    domain = Common.Domain(
        domain=domain,
        dbot_score=dbot_score,
    )

    return CommandResults(
        outputs_prefix='AnomaliEnterprise.DGA',
        outputs_key_field='domain',
        outputs=output,
        readable_output=tableToMarkdown(name=f"Domains DGA:", t=output, removeNull=True),
        indicators=[domain],
        raw_response=response
    )


def calculate_dbot_score(domain_data: dict) -> int:
    """There is no distinction between benign to unknown domain in Anomali Enterprise
        malware family exists and prob > 0.6 -> 3
       malware family exists and prob < 0.6 -> 2
        else -> 0

    Args:
        domain_data: the domain data

    Returns:
        DBot Score.
    """
    score = 0
    if domain_data.get('malware_family'):
        if domain_data.get('prob') > 0.6:
            score = 3
        else:
            score = 2
    return score


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    server_url = params.get('url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy') is True

    command = demisto.command()
    LOG(f'Command being called in Anomali Enterprise is: {command}')

    try:
        client = Client(server_url=server_url,username=username, password=password, verify=verify, proxy=proxy)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
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


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

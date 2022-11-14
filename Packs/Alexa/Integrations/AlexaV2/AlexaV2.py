import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, api_key: str,
                 base_url: str,
                 proxy: bool,
                 verify: bool,
                 reliability: str,
                 top_domain_threshold: int,
                 suspicious_domain_threshold: Optional[int]):
        super().__init__(base_url=base_url,
                         verify=verify,
                         proxy=proxy)
        if DBotScoreReliability.is_valid_type(reliability):
            self.reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise DemistoException("AlexaV2 error: Please provide a valid"
                                   " value for the Source Reliability parameter.")
        self.top_domain_threshold = top_domain_threshold
        self.suspicious_domain_threshold = suspicious_domain_threshold
        self.api_key = api_key

    def http_request(self, params: Dict):
        return self._http_request(method='GET',
                                  headers={'x-api-key': self.api_key},
                                  params=params)

    def alexa_rank(self, domain: str) -> Dict:
        params = {'Action': 'UrlInfo',
                  'ResponseGroup': 'Rank',
                  'Url': domain,
                  'Output': 'json'}
        return self.http_request(params=params)


''' HELPER FUNCTIONS '''


def rank_to_context(domain: str,
                    rank: Optional[int],
                    top_domain_threshold: int,
                    suspicious_domain_threshold: Optional[int],
                    reliability: DBotScoreReliability):
    if rank is None:
        score = Common.DBotScore.NONE
    elif rank < 0:
        raise DemistoException(f'AlexaV2 error: {rank} is invalid. Rank should be positive')
    elif 0 < rank <= top_domain_threshold:
        score = Common.DBotScore.GOOD
    elif suspicious_domain_threshold and rank > suspicious_domain_threshold:
        score = Common.DBotScore.SUSPICIOUS
    else:  # alexa_rank < client.threshold:
        score = Common.DBotScore.NONE
    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        reliability=reliability,
        score=score
    )
    domain_standard_context = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )
    return domain_standard_context


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args (Client): a client to use

    Return: 'ok' if test passed, anything else will fail the test.
    """

    try:
        client.alexa_rank('google.com')
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e


def alexa_domain(client: Client, domains: List[str]) -> List[CommandResults]:
    if not domains:
        raise ValueError('AlexaV2 error: domain doesn\'t exists')
    command_results: List[CommandResults] = []
    for domain in domains:
        result = client.alexa_rank(domain)
        domain_res = demisto.get(result,
                                 'Awis.Results.Result.Alexa.TrafficData.DataUrl')
        if not domain_res or domain_res == '404':  # Not found on alexa
            raise DemistoException('AlexaV2 error: Domain cannot be found')
        domain_res = domain_res[:-1] if domain_res[-1] == '/' else domain_res
        rank = demisto.get(result,
                           'Awis.Results.Result.Alexa.TrafficData.Rank')
        domain_standard_context: Common.Domain = rank_to_context(domain=domain_res,
                                                                 rank=arg_to_number(rank),
                                                                 suspicious_domain_threshold=client.suspicious_domain_threshold,
                                                                 top_domain_threshold=client.top_domain_threshold,
                                                                 reliability=client.reliability)

        rank: str = rank if rank else 'Unknown'
        result = {'Name': domain_res,
                  'Indicator': domain_res,
                  'Rank': rank}
        table = {'Domain': domain_res,
                 'Alexa Rank': rank,
                 'Reputation': domain_standard_context.dbot_score.to_readable()}
        readable = tableToMarkdown(f'Alexa Rank for {domain_res}', table, headers=list(table.keys()))
        command_results.append(CommandResults(
            outputs_prefix='Alexa.Domain',
            outputs_key_field='Name',
            outputs=result,
            readable_output=readable,
            indicator=domain_standard_context
        ))
    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    api_key = demisto.get(params, 'credentials.password')
    base_api = params.get('base_url')
    reliability = params.get('integrationReliability')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        suspicious_domain_threshold = arg_to_number(params.get('suspicious_domain_threshold', None),
                                                    required=False,
                                                    arg_name='suspicious_domain_threshold')
        top_domain_threshold = arg_to_number(params.get('top_domain_threshold'),
                                             required=True,
                                             arg_name='top_domain_threshold')
        if (suspicious_domain_threshold and suspicious_domain_threshold < 0)\
                or top_domain_threshold < 0:  # type: ignore
            raise DemistoException(f'AlexaV2 error: All threshold values should be greater than 0.'
                                   f'Suspicious domain threshold is {suspicious_domain_threshold}. '
                                   f'Top domain threshold is {top_domain_threshold}.')
        client = Client(
            base_url=base_api,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            suspicious_domain_threshold=suspicious_domain_threshold,  # type: ignore
            top_domain_threshold=top_domain_threshold,  # type: ignore
            reliability=reliability)
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'domain':
            domains = demisto.args().get('domain')
            return_results(alexa_domain(client, argToList(domains)))
        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

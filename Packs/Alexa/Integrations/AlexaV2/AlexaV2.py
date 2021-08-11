"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, api_key: str,
                 base_url: str,
                 proxy: bool,
                 verify: bool,
                 reliability: str,
                 benign: int,
                 threshold: int):
        super().__init__(base_url=base_url,
                         verify=verify,
                         proxy=proxy)
        if DBotScoreReliability.is_valid_type(reliability):
            self.reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise DemistoException("AlexaV2 error: Please provide a valid"
                                   " value for the Source Reliability parameter.")
        self.benign = benign
        self.threshold = threshold
        self.api_key = api_key

    def http_request(self, params: Dict):
        return self._http_request(method='GET',
                                  url_suffix='',
                                  headers={'x-api-key': self.api_key},
                                  params=params)

    def alexa_rank(self, domain: str) -> Dict:
        params = {'Action': 'UrlInfo',
                  'ResponseGroup': 'Rank',
                  'Url': domain,
                  'Output': 'json'}
        return self.http_request(params=params)


''' HELPER FUNCTIONS '''


def rank_to_score(domain: str, rank: Optional[int], threshold: int, benign: int, reliability: DBotScoreReliability):
    if rank is None:
        score = Common.DBotScore.SUSPICIOUS
        # score_text = 'suspicious'
    elif rank < 0:
        raise DemistoException('Rank should be positive')
    elif 0 < rank <= benign:
        score = Common.DBotScore.GOOD
        # score_text = 'good'
    elif rank > threshold:
        score = Common.DBotScore.SUSPICIOUS  # todo maybe it should be bad?
        # score_text = 'suspicious'
    else:  # alexa_rank < client.threshold:
        score = Common.DBotScore.NONE
        # score_text = 'Unkown'
    # else: # Should never be here
    #     score = 2
    #     score_text = 'suspicious'
    # todo check with Meital / Dean if we use score_text
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


def alexa_domain(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    domains = argToList(args.get('domain'))
    if not domains:
        raise ValueError('AlexaV2: domain doesn\'t exists')
    command_results: List[CommandResults] = []
    for domain in domains:
        if not re.match(urlRegex, domain):
            raise DemistoException('Entered invalid url')
        result = client.alexa_rank(domain)
        rank = demisto.get(result,
                           'Awis.Results.Result.Alexa.TrafficData.Rank')
        domain_standard_context: Common.Domain = rank_to_score(domain=domain,
                                                               rank=arg_to_number(rank),
                                                               threshold=client.threshold,
                                                               benign=client.benign,
                                                               reliability=client.reliability)

        alexa_rank: str = rank if rank else 'Unknown'
        result = {'Name': domain,
                  'Indicator': domain,
                  'Rank': alexa_rank}
        readable = f'The Alexa rank of {domain} is {alexa_rank} and has been marked as ' \
                   f'{domain_standard_context.dbot_score.score}.' \
                   f' The benign threshold is {client.benign} ' \
                   f'while the suspicious threshold is {client.threshold}.'
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
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('api_key')
    base_api = params.get('base_url')
    reliability = demisto.params().get('integrationReliability')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        threshold = arg_to_number(params.get('threshold'), required=True, arg_name='threshold')
        benign = arg_to_number(params.get('benign'), required=True, arg_name='benign')
        if threshold < 0 or benign < 0:  # type: ignore
            raise DemistoException('threshold and benign should be above 0')
        client = Client(
            base_url=base_api,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            threshold=threshold,  # type: ignore
            benign=benign,  # type: ignore
            reliability=reliability)
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'domain':
            return_results(alexa_domain(client, demisto.args()))
        else:
            raise NotImplementedError('not implemented...')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

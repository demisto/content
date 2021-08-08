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
        score = 2
        score_text = 'suspicious'
    elif rank < 0:
        raise DemistoException('Rank should be positive')
    elif 0 < rank <= benign:
        score = 1
        score_text = 'good'
    elif rank > threshold:
        score = 2
        score_text = 'suspicious'
    else:  # alexa_rank < client.threshold:
        score = 0
        score_text = 'unknown'
    # else: # Should never be here
    #     score = 2
    #     score_text = 'suspicious'

    dbot_score = Common.DBotScore(
        indicator=domain,
        integration_name='AlexaV2',
        indicator_type=DBotScoreType.DOMAIN,
        reliability=reliability,
        score=score,
        malicious_description=score_text
    )
    domain_standard_context = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )
    return domain_standard_context, score_text


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
        client.alexa_rank('google.com')
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def alexa_domain(client: Client, args: Dict[str, Any]) -> CommandResults:
    domain = args.get('domain', None)
    if not domain:
        raise ValueError('url doesn\'t exists')

    result = client.alexa_rank(domain)
    rank = demisto.get(result, 'Awis.Results.Result.Alexa.TrafficData.Rank')
    domain_standard_context, score_text = rank_to_score(domain=domain,
                                                        rank=None if rank is None else int(rank),
                                                        threshold=client.threshold,
                                                        benign=client.benign,
                                                        reliability=client.reliability)

    alexa_rank: str = rank if rank else 'Unknown'
    result = {'Name': domain,
              'Indicator': domain,
              'Rank': alexa_rank}
    readable = f'The Alexa rank of {domain} is {alexa_rank} and has been marked as {score_text}.' \
               f' The benign threshold is {client.benign} while the suspicious threshold is {client.threshold}.'
    return CommandResults(
        outputs_prefix='AlexaV2.Domain',
        outputs_key_field='Name',
        outputs=result,
        readable_output=readable,
        indicator=domain_standard_context
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('api_key')
    # get the service API url
    base_api = params.get('base_url')
    reliability = demisto.params().get('integrationReliability')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        threshold = int(params.get('threshold'))
        benign = int(params.get('benign'))
        if threshold < 0 or benign < 0:
            raise DemistoException('threshold and benign should be above 0')
        client = Client(
            base_url=base_api,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            threshold=threshold,
            benign=benign,
            reliability=reliability)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'domain':
            return_results(alexa_domain(client, demisto.args()))
        else:
            raise NotImplementedError('not implemented...')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

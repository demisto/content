###########
# IMPORTS #
###########
# STD packages
from typing import Dict, Tuple, Any, Optional, List, Union, Iterator
from itertools import islice
from math import ceil
from contextlib import contextmanager

# Local packages
import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

#########
# Notes #
#########
"""
Development info:
*** Error in demisto docker loop, when importing tcex module a print occurred therefor it's handled with context manager to suppress prints. 
    - ThreatConnect SDK - https://docs.threatconnect.com/en/latest/python/python_sdk.html  (Don't use deprecated one).
    - More filters details - https://docs.threatconnect.com/en/latest/tcex/module_threat_intelligence.html#get-indicators-by-filter
    - REST API - https://docs.threatconnect.com/en/latest/rest_api/rest_api.html
"""  # noqa W291

####################
# GLOBAL CONSTUNTS #
####################
INTEGRATION_NAME = 'ThreatConnect Feed'
INTEGRATION_CONTEXT_NAME = 'ThreatConnect'
COMMAND_OUTPUT = Tuple[str, Union[Dict[str, Any], List[Any]], Union[Dict[str, Any], List[Any]]]
INDICATOR_MAPPING_NAMES = {
    'Address': FeedIndicatorType.IP,
    'Host': FeedIndicatorType.Host,
    'EmailAddress': FeedIndicatorType.Email,
    'File': FeedIndicatorType.File,
    'URL': FeedIndicatorType.URL,
    'CIDR': FeedIndicatorType.CIDR,
}


#########
# Utils #
#########

@contextmanager
def suppress_stdout():
    """Disable stdout in beginning and enable it in exit"""
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    yield
    sys.stdout.close()
    sys.stdout = original_stdout


def calculate_dbot_score(threat_assess_score: Optional[Union[int, str]] = None) -> int:
    """ Calculate dbot score by ThreatConnect assess score (0-500) to range of 0-3:
        1. feed dev docs:https://xsoar.pan.dev/docs/integrations/feeds
        2. For more info - https://threatconnect.com/blog/quickly-assess-maliciousness-suspicious-activity-analyze/

    Args:
        threat_assess_score: score between 0-500.

    Returns:
        int: Calculated DbotScore (range 0-3).
    """
    score = 0
    if isinstance(threat_assess_score, int):
        score = ceil(threat_assess_score / (500 / 3))

    return score


def parse_indicator(indicator: Dict[str, str]) -> Dict[str, Any]:
    """ Parsing indicator by indicators demisto convension.

    Args:
        indicator: Indicator as raw response.

    Returns:
        dict: Parsed indicator.
    """
    indicator_obj = {
        "value": indicator.get('summary'),
        "type": INDICATOR_MAPPING_NAMES.get(indicator.get('type', '')),
        "rawJSON": indicator,
        "score": calculate_dbot_score(indicator.get("threatAssessScore")),
        "fields": {
            "tags": argToList(demisto.getParam("feedTags")),
        },
    }

    tlp_color = demisto.getParam('tlp_color')
    if tlp_color:
        indicator_obj['fields']['trafficlightprotocol'] = tlp_color  # type: ignore

    return indicator_obj


##########
# Client #
##########


class Client:
    """Object represnt a client for ThreatConnect actions"""

    def __init__(self, access_key: str, secret_key: str, api_path: str):
        """ Initialize client configuration:

        Args:
            access_key: Generated access key.
            secret_key: Generated secret key.
            api_path: https://api.threatconnect.com

        References:
            1. HMAC: https://docs.threatconnect.com/en/latest/tcex/authorization.html
            2. Creating user: https://training.threatconnect.com/learn/article/creating-user-accounts-kb-article#2

        Notes:
            1. When importing TcEx, Print occurred therefor an error raised in the server due to not valid stdout.
        """
        with suppress_stdout():
            from tcex import TcEx
        self._client = TcEx(config={
            "api_access_id": access_key,
            "api_secret_key": secret_key,
            "tc_api_path": api_path,
        })

    def get_owners(self) -> Iterator[Any]:
        """Get indicators owners - helping configuring the feed integration.

        Yields:
            Iterable: Owner information
        """
        return self._client.ti.owner().many()

    def get_indicators(self, offset: int = 0, limit: Optional[int] = None, owners: Optional[str] = None) \
            -> Iterator[Any]:
        """ Get indicators from threatconnect.

        Args:
            offset: Index offset from begining.
            limit: Indicator amout limit.
            owners: Filter indicators belongs to specific owner.

        Returns:
            Iterator: indicator objects.
        """
        indicators = self._client.ti.indicator().many(params={"includes": ['additional', 'attributes'],
                                                              'owner': owners})
        offset = int(offset)
        if limit:
            limit = int(limit) + offset

        return islice(indicators, offset, limit)


######################
# COMMANDS FUNCTIONS #
######################


def module_test_command(client: Client) -> COMMAND_OUTPUT:
    """ Test module - Get 4 indicators from ThreatConnect.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable - 'ok' if succeed.
        dict: Operation entry context - Empty.
        dict: Operation raw response - Empty.
    """
    try:
        client.get_indicators(limit=4)
    except RuntimeError:
        raise DemistoException("Unable to communicate with ThreatConnect API!")

    return "ok", {}, {}


def fetch_indicators_command(client: Client) -> List[Dict[str, Any]]:
    """ Fetch indicators from ThreatConnect

    Args:
        client: ThreatConnect client.

    Returns:
        list: indicator to populate in demisto server.
    """
    raw_response = client.get_indicators(owners=argToList(demisto.getParam('owners')))

    return [parse_indicator(indicator) for indicator in raw_response]


def get_indicators_command(client: Client) -> COMMAND_OUTPUT:
    """ Get indicator from ThreatConnect, Able to change limit and offset by command arguments.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    raw_response: Iterator[Any] = client.get_indicators(
        owners=argToList(demisto.getArg('owners') or demisto.getParam('owners')),
        limit=demisto.getArg('limit'),
        offset=demisto.getArg('offset'))
    readable_output: str = tableToMarkdown(name=f"{INTEGRATION_NAME} - Indicators",
                                           t=[parse_indicator(indicator) for indicator in raw_response])

    return readable_output, {}, list(raw_response)


def get_owners_command(client: Client) -> COMMAND_OUTPUT:
    """ Get availble indicators owners from ThreatConnect - Help configure ThreatConnect Feed integraiton.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    raw_response: Iterator[Any] = client.get_owners()
    readable_output: str = tableToMarkdown(name=f"{INTEGRATION_NAME} - Owners",
                                           t=list(raw_response))

    return readable_output, {}, list(raw_response)


def main():
    client = Client(demisto.getParam("api_access_id"),
                    demisto.getParam("api_secret_key"),
                    demisto.getParam("tc_api_path"),
                    )
    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands = {
        'test-module': module_test_command,
        'tc-get-indicators': get_indicators_command,
        'tc-get-owners': get_owners_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        return_error(f'Integration {INTEGRATION_NAME} Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

###########
# IMPORTS #
###########
# STD packages
from enum import Enum
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
# GLOBAL CONSTANTS #
####################
INTEGRATION_NAME = 'ThreatConnect Feed'
INTEGRATION_COMMAND_NAME = 'tc'
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

class Method(str, Enum):
    """
    A list that represent the types of http request available
    """
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Client:
    def __init__(self, api_id: str, api_secret: str, base_url: str, verify: bool = False):
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = base_url
        self.verify = verify

    def make_request(self, method: Method, url_suffix: str, payload: dict = {}, params: dict = {},
                     parse_json=True):  # pragma: no cover  # noqa
        headers = self.create_header(url_suffix, method)

        url = urljoin(self.base_url, url_suffix)
        response = requests.request(method=method, url=url, headers=headers, data=payload, params=params,
                                    verify=self.verify)
        if parse_json:
            return json.loads(response.text), response.status_code
        return response

    def create_header(self, url_suffix: str, method: Method) -> dict:
        timestamp = round(time.time())
        to_sign = f'{url_suffix}:{method}:{timestamp}'
        hash = base64.b64encode(
            hmac.new(self.api_secret.encode('utf8'), to_sign.encode('utf8'), hashlib.sha256).digest()).decode()
        return {'Authorization': f'TC {self.api_id}:{hash}', 'Timestamp': str(timestamp),
                'Content-Type': 'application/json'}


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
        url = '/api/v3/indicators?resultLimit=4'

        response, status_code = client.make_request(Method.GET, url)
        if status_code == 200:
            demisto.results('ok')
        else:
            return_error('Error from the API: ' + response.get('message',
                                                               'An error has occurred if it persist please contact your local help desk'))
    except RuntimeError:
        raise DemistoException("Unable to communicate with ThreatConnect API!")


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
    insecure = not demisto.getParam('insecure')
    client = Client(demisto.getParam('api_access_id'), demisto.getParam('api_secret_key'),
                    demisto.getParam('tc_api_path'), insecure)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands = {
        'test-module': module_test_command,
        f'{INTEGRATION_COMMAND_NAME}-get-indicators': get_indicators_command,
        f'{INTEGRATION_COMMAND_NAME}-get-owners': get_owners_command
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

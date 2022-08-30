###########
# IMPORTS #
###########
# STD packages
import hashlib
import hmac
from contextlib import contextmanager
from enum import Enum
from math import ceil
from typing import Tuple

# Local packages
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

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


def set_fields_query(fields: list) -> str:
    fields_str = ''
    for field in fields:
        fields_str += f'&fields={field}'
    return fields_str


def calculate_dbot_score(threat_assess_score: Optional[Union[int, str]] = None) -> int:
    """ Calculate dbot score by ThreatConnect assess score (0-1000) to range of 0-3:
        1. feed dev docs:https://xsoar.pan.dev/docs/integrations/feeds
        2. For more info - https://training.threatconnect.com/learn/article/threatassess-and-cal-kb-article

    Args:
        threat_assess_score: score between 0-1000.

    Returns:
        int: Calculated DbotScore (range 0-3).
    """
    score = 0
    if isinstance(threat_assess_score, int):
        score = ceil(threat_assess_score / (1000 / 3))

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


class Client(BaseClient):
    def __init__(self, api_id: str, api_secret: str, base_url: str, verify: bool = False, proxy: bool = False):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_id = api_id
        self.api_secret = api_secret

    def make_request(self, method: Method, url_suffix: str, payload: dict = {}, params: dict = {},
                     parse_json=True, get_next=False):  # pragma: no cover  # noqa
        headers = self.create_header(url_suffix, method)

        response = self._http_request(method=method, url_suffix=url_suffix, data=payload, resp_type='json',
                                      params=params,
                                      headers=headers)

        if get_next:
            return response.get('data'), response.get('status'), response.get('next')
        if parse_json:
            return response.get('data'), response.get('status')
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


def create_or_query(param_name: str, delimiter_str: str) -> str:
    if not delimiter_str:
        return ''
    arr = delimiter_str.split(',')
    query = ''
    for item in arr:
        query += f'{param_name}="{item}" OR '
    return query[:len(query) - 3]


def module_test_command(client: Client):  # pragma: no cover
    """ Test module - Get 4 indicators from ThreatConnect.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable - 'ok' if succeed.
        dict: Operation entry context - Empty.
        dict: Operation raw response - Empty.
    """
    url = '/api/v3/groups?resultLimit=2'
    response, status = client.make_request(Method.GET, url)
    if status == 'Success':
        return "ok", {}, {}
    else:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))


def fetch_indicators_command(client: Client) -> List[Dict[str, Any]]:  # pragma: no cover
    """ Fetch indicators from ThreatConnect

    Args:
        client: ThreatConnect client.

    Returns:
        list: indicator to populate in demisto server.
    """
    owners = f'AND ({create_or_query("ownerName", demisto.getParam("owners"))}) '
    tags = f'AND ({create_or_query("tags", demisto.getParam("tags"))}) '
    status = f'AND ({create_or_query("status", demisto.getParam("status"))}) '
    fields = set_fields_query(argToList(demisto.getParam("fields")))
    last_run = demisto.getLastRun()
    last_run = last_run.get('from_date')
    demisto.debug('last run get: ' + str(last_run))
    from_date = ''
    if last_run:
        from_date = f'AND (dateAdded > "{last_run}") '
    tql = f'{owners if owners != "AND () " else ""}' \
          f'{tags if tags != "AND () " else ""}' \
          f'{from_date if from_date != "AND () " else ""}' \
          f'{status if status != "AND () " else ""}'.replace('AND', '', 1)
    if tql:
        tql = urllib.parse.quote(tql.encode('utf8'))  # type: ignore
        tql = f'?tql={tql}'
    else:
        tql = ''
    url = f'/api/v3/indicators{tql}{fields}&resultStart=0&resultLimit=200&sorting=dateAdded%20ASC'
    if '?' not in url:
        url = url.replace('&', '?', 1)  # type: ignore
    indicators = []
    while True:
        demisto.debug('URL: ' + url)
        response, status, next = client.make_request(Method.GET, url, get_next=True)
        if status == 'Success':
            indicators.extend(response)
            # Limit the number of results to not get an error from the API
            if len(indicators) < 15000 and next:
                url = next.replace(demisto.getParam('tc_api_path'), '')
            else:
                break

    return indicators


def get_indicators_command(client: Client):  # pragma: no cover
    """ Get indicator from ThreatConnect, Able to change limit and offset by command arguments.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    limit = demisto.args().get('limit', '50')
    offset = demisto.args().get('offset', '0')
    owners = demisto.getArg('owners') or demisto.getParam('owners')
    owners = create_or_query(owners, "ownerName")
    owners = urllib.parse.quote(owners.encode('utf8'))  # type: ignore
    url = f'/api/v3/indicators?tql={owners}&resultStart={offset}&resultLimit={limit}'

    response, status = client.make_request(Method.GET, url)
    if status == 'Success':
        readable_output: str = tableToMarkdown(name=f"{INTEGRATION_NAME} - Indicators",
                                               t=[parse_indicator(indicator) for indicator in
                                                  response])  # type: ignore # noqa

        return readable_output, {}, list(response)


def get_owners_command(client: Client) -> COMMAND_OUTPUT:  # pragma: no cover
    """ Get availble indicators owners from ThreatConnect - Help configure ThreatConnect Feed integraiton.

    Args:
        client: ThreatConnect client.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    url = '/api/v3/security/owners?resultLimit=500'
    response, status = client.make_request(Method.GET, url)

    readable_output: str = tableToMarkdown(name=f"{INTEGRATION_NAME} - Owners",
                                           t=list(response))

    return readable_output, {}, list(response)


def main():  # pragma: no cover
    insecure = not demisto.getParam('insecure')
    proxy = not demisto.getParam('proxy')
    credentials = demisto.params().get('api_credentials', {})
    access_id = credentials.get('identifier') or demisto.params().get('api_access_id')
    secret_key = credentials.get('password') or demisto.params().get('api_secret_key')
    client = Client(access_id, secret_key,
                    demisto.getParam('tc_api_path'), verify=insecure, proxy=proxy)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': module_test_command,
        f'{INTEGRATION_COMMAND_NAME}-get-indicators': get_indicators_command,
        f'{INTEGRATION_COMMAND_NAME}-get-owners': get_owners_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            if indicators:
                demisto.info('Last run set:' + str(indicators[-1].get('dateAdded')))
                demisto.setLastRun({'from_date': indicators[-1].get('dateAdded')})
            indicators = [parse_indicator(indicator) for indicator in indicators]
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        else:
            readable_output, outputs, raw_response = commands[command](client)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        return_error(f'Integration {INTEGRATION_NAME} Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

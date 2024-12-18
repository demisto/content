###########
# IMPORTS #
###########
# STD packages
import hashlib
import hmac
from contextlib import contextmanager
from enum import Enum
from math import ceil

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
COMMAND_OUTPUT = tuple[str, Union[Dict[str, Any], List[Any]], Union[Dict[str, Any], List[Any]]]
INDICATOR_MAPPING_NAMES = {
    'Address': FeedIndicatorType.IP,
    'CIDR': FeedIndicatorType.CIDR,
    'EmailAddress': FeedIndicatorType.Email,
    'File': FeedIndicatorType.File,
    'Host': FeedIndicatorType.Domain,
    'Mutex': FeedIndicatorType.MUTEX,
    'Registry Key': FeedIndicatorType.Registry,
    'URL': FeedIndicatorType.URL,
    'Attack Pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'Campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'Course of Action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'Intrusion Set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'Malware': ThreatIntel.ObjectsNames.MALWARE,
    'Report': ThreatIntel.ObjectsNames.REPORT,
    'Tool': ThreatIntel.ObjectsNames.TOOL,
    'Vulnerability': FeedIndicatorType.CVE,
    'ASN': FeedIndicatorType.AS,
}

TC_INDICATOR_TO_XSOAR_INDICATOR = {
    # indicator_type: {Raw Field: XSOAR Indicator Field}
    'IP': {'dateAdded': 'firstseenbysource',
           'lastModified': 'updateddate',
           'threatAssessRating': 'verdict',
           'threatAssessConfidence': 'confidence',
           'description': 'description',
           'summary': 'shortdescription',
           'ip': 'address'},
    'CIDR': {'dateAdded': 'firstseenbysource',
             'lastModified': 'updateddate',
             'threatAssessRating': 'verdict',
             'threatAssessConfidence': 'confidence',
             'summary': 'name',
             'threatAssessScore': 'sourceoriginalseverity'},
    'Email': {'dateAdded': 'firstseenbysource',
              'lastModified': 'updateddate',
              'threatAssessRating': 'verdict',
              'threatAssessConfidence': 'confidence',
              'description': 'description',
              'summary': 'name',
              'address': 'emailaddress'},
    'File': {'dateAdded': 'firstseenbysource',
             'lastModified': 'updateddate',
             'threatAssessConfidence': 'confidence',
             'threatAssessRating': 'verdict',
             'description': 'description',
             'summary': 'name',
             'md5': 'md5',
             'sha1': 'sha1',
             'sha256': 'sha256'},
    'Domain': {'dateAdded': 'firstseenbysource',
               'lastModified': 'updateddate',
               'threatAssessRating': 'verdict',
               'threatAssessConfidence': 'confidence',
               'description': 'description',
               'summary': 'name',
               'hostName': 'domainname'},
    'Mutex': {'dateAdded': 'firstseenbysource',
              'threatAssessRating': 'verdict',
              'description': 'description',
              'threatAssessConfidence': 'confidence',
              'summary': 'name'},
    'Registry Key': {'dateAdded': 'firstseenbysource',
                     'lastModified': 'updateddate',
                     'threatAssessRating': 'verdict',
                     'threatAssessConfidence': 'confidence',
                     'description': 'description',
                     'summary': 'name'},
    'URL': {'dateAdded': 'firstseenbysource',
            'lastModified': 'updateddate',
            'threatAssessRating': 'verdict',
            'threatAssessConfidence': 'confidence',
            'description': 'description',
            'summary': 'name',
            'text': 'address'},
    'ASN': {'dateAdded': 'firstseenbysource',
            'lastModified': 'updateddate',
            'threatAssessRating': 'verdict',
            'description': 'description',
            'threatAssessConfidence': 'confidence',
            'AS Number': 'value',
            'summary': 'name'},
    'Attack Pattern': {'dateAdded': 'firstseenbysource',
                       'lastModified': 'updateddate',
                       'description': 'description',
                       'name': 'name'},
    'Campaign': {'dateAdded': 'firstseenbysource',
                 'lastModified': 'updateddate',
                 'name': 'name'},
    'Course of Action': {'dateAdded': 'firstseenbysource',
                         'lastModified': 'updateddate',
                         'name': 'name'},
    'Intrusion Set': {'dateAdded': 'firstseenbysource',
                      'lastModified': 'updateddate',
                      'name': 'name'},
    'Malware': {'dateAdded': 'firstseenbysource',
                'lastModified': 'updateddate',
                'name': 'name'},
    'Report': {'dateAdded': 'firstseenbysource',
               'lastModified': 'updateddate',
               'name': 'name',
               'publishDate': 'published'},
    'Tool': {'dateAdded': 'firstseenbysource',
             'lastModified': 'updateddate',
             'name': 'name'},
    'CVE': {'dateAdded': 'firstseenbysource',
            'lastModified': 'updateddate',
            'name': 'name',
            'publishDate': 'published'}
}

INDICATOR_TYPES = ['EmailAddress',
                   'File',
                   'Host',
                   'URL',
                   'ASN',
                   'CIDR',
                   'Hashtag',
                   'Mutex',
                   'Registry Key',
                   'User Agent',
                   'Address'
                   ]
INDICATOR_GROUPS = ['Attack Pattern',
                    'Campaign',
                    'Course of Action',
                    'Intrusion Set',
                    'Malware',
                    'Report',
                    'Tool',
                    'Vulnerability'
                    ]


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


def set_fields_query(params: dict, endpoint: str) -> str:
    """Creating fields query to add information to the API response"""
    fields_str = '&fields=tags'
    if endpoint == 'indicators':
        fields_str += '&fields=threatAssess'
    if argToBoolean(params.get('createRelationships')):
        fields_str += '&fields=associatedGroups&fields=associatedIndicators'

    return fields_str


def create_types_query(params: dict, endpoint: str) -> str:
    """Creating TypeName query to fetch different types of indicators"""
    group_types = argToList(params.get('group_type'))
    indicator_types = argToList(params.get('indicator_type'))
    types = []

    if not group_types and not indicator_types:
        raise DemistoException('No indicator type or group type were chosen, please choose at least one.')
    if endpoint == 'indicators':
        if 'All' in indicator_types:
            types.extend(INDICATOR_TYPES)
        else:
            types.extend(indicator_types)
    else:
        if 'All' in group_types:
            types.extend(INDICATOR_GROUPS)
        else:
            types.extend(group_types)

    query = 'typeName IN ("' + '","'.join(types) + '")'

    return query


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


def create_rk_grid_field(indicator: dict):
    """Creating the Key Value field for the registry key indicator type

    Args:
        indicator (dict): The data of the indicator
    """
    key_value = [{'name': indicator.get('Key Name'),
                 'type': indicator.get('Value Name'),
                  'data': indicator.get('Key Type')
                  }]

    return key_value


def get_indicator_value(indicator: dict, indicator_type: str) -> str:
    """Getting the indicator value according to the indicator type
    Args:
        indicator (dict): The data of the indicator
        indicator_type (str): The type of the indicator
    Returns:
        str: The indicator value
    """
    if indicator_type == 'File':
        indicator_value = indicator.get('sha256') or indicator.get('sha1') or indicator.get('md5') or ''
    else:
        indicator_value = indicator.get('summary') or indicator.get('name', '')
    return indicator_value


def parse_indicator(indicator: Dict[str, str]) -> Dict[str, Any]:
    """ Parsing indicator by indicators demisto convention.
    Args:
        indicator: Indicator as raw response.
    Returns:
        dict: Parsed indicator.
    """
    indicator_type = INDICATOR_MAPPING_NAMES.get(indicator.get('type', ''), '')
    indicator_value = get_indicator_value(indicator, indicator_type)
    fields = create_indicator_fields(indicator, indicator_type)
    relationships = create_indicator_relationships(fields, indicator_type, indicator_value)  # type: ignore
    indicator_obj = {
        "value": indicator_value,
        "type": indicator_type,
        "rawJSON": indicator,
        "score": calculate_dbot_score(indicator.get("threatAssessScore", '')),
        "fields": fields,
        "relationships": relationships
    }

    return indicator_obj


def create_indicator_fields(indicator, indicator_type):
    """Creating an indicator fields from a raw indicator"""
    params = demisto.params()
    indicator_fields_mapping = TC_INDICATOR_TO_XSOAR_INDICATOR.get(indicator_type, {})

    fields: dict = {}

    for indicator_key, xsoar_indicator_key in indicator_fields_mapping.items():
        fields[xsoar_indicator_key] = indicator.get(indicator_key, '')

    raw_tags = indicator.get('tags', {}).get('data', [])
    tags = [tag.get('name', '') for tag in raw_tags]
    fields['tags'] = tags

    fields['reportedby'] = [name for name in [indicator.get('ownerName', ''), indicator.get('source', '')] if name]

    fields['feedrelatedindicators'] = indicator.get("associatedIndicators", {}).get('data') or []
    fields['feedrelatedindicators'].extend(indicator.get("associatedGroups", {}).get('data') or [])

    if 'description' not in fields:
        fields['description'] = indicator.get('attributes', {}).get('description', '')
    if indicator_type == 'Course of Action':
        fields['action'] = indicator.get('attributes', {}).get('action', '')
    if indicator_type == 'Registry Key':
        fields['Key Value'] = create_rk_grid_field(indicator)
        fields['namefield'] = indicator.get('Key Name', '')

    tlp_color = params.get('tlp_color', '')
    if tlp_color:
        fields['trafficlightprotocol'] = tlp_color  # type: ignore

    remove_nulls_from_dictionary(fields)

    return fields


def create_indicator_relationships(indicator: dict, indicator_type: str, indicator_value: str):
    relationships_list = []
    if argToBoolean(demisto.getParam('createRelationships')):
        demisto.debug('Creating relationships')
        b_entities = indicator.get('feedrelatedindicators', [])
        for entity_b in b_entities:
            entity_b_value = entity_b.get('summary') or entity_b.get('name')
            entity_b_type = entity_b.get('type')
            relationships_list.extend(
                create_relationships(indicator_value, indicator_type, entity_b_value, entity_b_type))

    return relationships_list


def create_relationships(entity_a: str, entity_a_type: str, entity_b: str, entity_b_type: str):
    """
    Create a list of entityRelationship object from the api result
    """
    relationships_list = []

    if entity_b and entity_b_type:
        relationship_entity = EntityRelationship(entity_a=entity_a, entity_a_type=entity_a_type,
                                                 name=EntityRelationship.Relationships.RELATED_TO,
                                                 entity_b=entity_b, entity_b_type=entity_b_type,
                                                 source_reliability=demisto.getParam('feedReliability'),
                                                 brand=INTEGRATION_NAME)
        relationships_list.append(relationship_entity.to_indicator())
        demisto.debug(f'Created relationsip between {entity_a} and {entity_b}')
    else:
        demisto.debug(
            f"WARNING: Relationships will not be created to entity A {entity_a}"
            f" with relationship name {EntityRelationship.Relationships.RELATED_TO}")
    return relationships_list


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
                     parse_json=True, get_next=False, full_url=None):  # pragma: no cover  # noqa
        if not full_url and not url_suffix:
            # if no url is stated, there is no need to make a request
            return [], None, ''
        headers = self.create_header(url_suffix, full_url, method)
        response = self._http_request(method=method, url_suffix=url_suffix, data=payload, resp_type='json',
                                      params=params, headers=headers, full_url=full_url)

        if get_next:
            return response.get('data'), response.get('status'), response.get('next')
        if parse_json:
            return response.get('data'), response.get('status')
        return response

    def create_header(self, url_suffix: str, full_url: str, method: Method) -> dict:
        timestamp = round(time.time())
        if full_url:
            url_suffix = full_url.replace(demisto.getParam('tc_api_path').rstrip('/'), '')
        to_sign = f'{url_suffix}:{method.value}:{timestamp}'
        api_hash = base64.b64encode(
            hmac.new(self.api_secret.encode('utf8'), to_sign.encode('utf8'), hashlib.sha256).digest()).decode()
        return {'Authorization': f'TC {self.api_id}:{api_hash}', 'Timestamp': str(timestamp),
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


def module_test_command(client: Client, args):  # pragma: no cover # noqa
    """ Test module - Get 4 indicators from ThreatConnect.
    Args:
        client: ThreatConnect client.
    Returns:
        str: Human readable - 'ok' if succeed.
        dict: Operation entry context - Empty.
        dict: Operation raw response - Empty.
    """
    url = '/api/v3/groups?resultLimit=2'
    try:
        response, status = client.make_request(Method.GET, url)
        if status == 'Success':
            return "ok", {}, {}
        else:
            return_error('Error from the API: ' + response.get('message',
                                                               'An error has occurred, if it persist, please contact your '
                                                               'local help desk'))
    except Exception as e:
        exception_text = str(e).lower()
        if 'resource not found' in exception_text:
            return "ok", {}, {}
        else:
            return_error(str(e))


def fetch_indicators_command(client: Client, params: dict, last_run: dict) -> tuple[
    List[Dict[str, Any]], List[Dict[str, Any]]]:  # noqa  # pragma: no cover
    """ Fetch indicators from ThreatConnect

    Args:
        client: ThreatConnect client.

    Returns:
        list: indicator to populate in demisto server.
    """
    indicators_url = build_url_with_query_params(params, 'indicators', last_run)
    groups_url = build_url_with_query_params(params, 'groups', last_run)

    indicators = []
    groups = []
    indicators_next_link = ''
    groups_next_link = ''
    try:
        while True:
            if indicators_next_link or groups_next_link:
                if indicators_next_link:
                    demisto.debug('Indicators Next Link: ' + indicators_next_link)
                    response, _, indicators_next_link = client.make_request(Method.GET,
                                                                            url_suffix='',
                                                                            get_next=True,
                                                                            full_url=indicators_next_link)
                    indicators.extend(response)
                if groups_next_link:
                    demisto.debug('Groups Next Link: ' + groups_next_link)
                    response, _, groups_next_link = client.make_request(Method.GET,
                                                                        url_suffix='',
                                                                        get_next=True,
                                                                        full_url=groups_next_link)
                    groups.extend(response)
            elif indicators_url or groups_url:
                demisto.debug('Indicators URL: ' + indicators_url)
                indicators_response, _, indicators_next_link = client.make_request(Method.GET, indicators_url,
                                                                                   get_next=True)
                indicators.extend(indicators_response)
                indicators_url = ''

                demisto.debug('Groups URL: ' + groups_url)
                groups_response, _, groups_next_link = client.make_request(Method.GET, groups_url, get_next=True)
                groups.extend(groups_response)
                groups_url = ''

            # Limit the number of results to not get an error from the API
            if ((len(indicators) + len(groups)) > int(demisto.params().get('fetch_limit', '2000'))) or (
                    not indicators_next_link and not groups_next_link):
                break
    except Exception as e:
        demisto.error(
            f'Got an error in the fetch loop. Returning {len(groups)} groups + {len(indicators)} indicators. error: {str(e)}')

    return indicators, groups


def build_url_with_query_params(params: dict, endpoint: str, last_run: dict):
    """Setting the url for the request for each endpoint"""
    if not should_send_request(params, endpoint):
        return ''

    last_run_date = last_run.get(endpoint, {}).get('from_date', '')
    demisto.debug('last run get: ' + str(last_run_date))
    from_date = ''
    if last_run_date:
        from_date = f'AND (dateAdded > "{last_run_date}") '

    fields = set_fields_query(params, endpoint)
    tql = params.get('indicator_query')
    if not tql:
        tql = set_tql_query(from_date, params, endpoint)

    if tql:
        tql = urllib.parse.quote(tql.encode('utf8'))  # type: ignore
        tql = f'?tql={tql}'
    else:
        tql = ''
    url = f'/api/v3/{endpoint}{tql}{fields}&resultStart=0&resultLimit=100&sorting=dateAdded%20ASC'
    if '?' not in url:
        # replacing only the first occurrence of & if ? is not present in url
        url = url.replace('&', '?', 1)  # type: ignore

    return url


def should_send_request(params: dict, endpoint: str):
    """Checking if the user has indicated any indicator/group types to fetch from the API"""
    if endpoint == 'indicators':
        if not argToList(params.get('indicator_type')):
            return False
    else:
        if not argToList(params.get('group_type')):
            return False

    return True


def set_tql_query(from_date: str, params: dict, endpoint: str) -> str:
    """Creating tql query to add information to the API response"""
    owners = f'AND ({create_or_query("ownerName", params.get("owners"))}) '  # type: ignore
    tags = f'AND ({create_or_query("tag", params.get("tags"))}) '  # type: ignore
    status = f'AND ({create_or_query("status", params.get("status"))}) '  # type: ignore

    confidence = ''
    active_only = ''
    threat_score = ''
    if endpoint == 'indicators':
        active_only = 'AND indicatorActive EQ True ' if argToBoolean(params.get("indicator_active")) else ''
        confidence = f'AND confidence GT {params.get("confidence")} ' if int(params.get("confidence")) != 0 else ''  # type: ignore # noqa
        threat_score = f'AND threatAssessScore GT {params.get("threat_assess_score")} ' \
            if int(params.get("threat_assess_score")) != 0 else ''  # type: ignore

    type_name_query = create_types_query(params, endpoint)
    type_names = f'AND {type_name_query}' if type_name_query else ''

    tql = f'{owners if owners != "AND () " else ""}' \
          f'{tags if tags != "AND () " else ""}' \
          f'{from_date if from_date != "AND () " else ""}' \
          f'{status if status != "AND () " else ""}' + active_only + confidence + threat_score + type_names

    tql = tql.replace('AND ', '', 1)
    return tql


def get_updated_last_run(indicators: list, groups: list, previous_run: dict) -> dict:
    """Setting the Last Run structure"""

    next_run = {}
    if indicators:
        next_run['indicators'] = {'from_date': indicators[-1].get('dateAdded')}
    else:
        next_run['indicators'] = previous_run.get('indicators', {})
    if groups:
        next_run['groups'] = {'from_date': groups[-1].get('dateAdded')}
    else:
        next_run['groups'] = previous_run.get('groups', {})

    demisto.debug('The new last_run is: ' + str(next_run))
    return next_run


def get_indicators_command(client: Client, args: dict) -> dict:  # type: ignore # pragma: no cover
    """ Get indicator from ThreatConnect, Able to change limit and offset by command arguments.
    Args:
        client: ThreatConnect client.
        args: The arguments from XSOAR.
    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')

    tql = args.get('tql_query', '')
    if not tql:
        owners = f'AND ({create_or_query("ownerName", args.get("owners"))}) ' if args.get("owners") else ''  # type: ignore # noqa
        active_only = f'AND indicatorActive EQ {args.get("active_indicators")} ' \
            if argToBoolean(args.get("active_indicators")) else ''
        confidence = f'AND confidence GT {args.get("confidence")} ' if args.get("confidence") else ''
        threat_score = f'AND threatAssessScore GT {args.get("threat_assess_score")} ' if args.get(
            "threat_assess_score") else ''

        types = argToList(args.get("indicator_type"))
        query = ''

        if types:
            if 'All' in types:
                query = 'AND typeName IN ("' + '","'.join(INDICATOR_TYPES) + '")'
            else:
                query = 'AND typeName IN ("' + '","'.join(types) + '")'

        tql = active_only + confidence + threat_score + confidence + owners + query
        tql = tql.replace('AND ', '', 1)

    if tql:
        tql = urllib.parse.quote(tql.encode('utf8'))  # type: ignore
        tql = f'?tql={tql}'

    url = f'/api/v3/indicators{tql}&resultStart={offset}&resultLimit={limit}&fields=threatAssess'
    if '?' not in url:
        # replacing only the first occurrence of & if ? is not present in url
        url = url.replace('&', '?', 1)  # type: ignore

    demisto.debug("URL: " + url)
    response, status = client.make_request(Method.GET, url)
    if status == 'Success':
        t = [parse_indicator(indicator) for indicator in response]
        readable_output: str = tableToMarkdown(name=f"{INTEGRATION_NAME} - Indicators",
                                               t=t, removeNull=True)  # type: ignore # noqa

        return readable_output, {}, list(response)  # type: ignore
    return {}


def get_owners_command(client: Client, args: dict) -> COMMAND_OUTPUT:  # pragma: no cover
    """ Get availble indicators owners from ThreatConnect - Help configure ThreatConnect Feed integraiton.
    Args:
        client: ThreatConnect client.
        args: The arguments from XSOAR.
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


def main():  # pragma: no cover # noqa
    insecure = not demisto.getParam('insecure')
    proxy = not demisto.getParam('proxy')
    credentials = demisto.params().get('api_credentials', {})
    access_id = credentials.get('identifier') or demisto.params().get('api_access_id')
    secret_key = credentials.get('password') or demisto.params().get('api_secret_key')
    params = demisto.params()
    args = demisto.args()
    last_run = demisto.getLastRun()
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
            indicators, groups = fetch_indicators_command(client, params, last_run)
            next_run = get_updated_last_run(indicators, groups, last_run)
            demisto.setLastRun(next_run)

            indicators = [parse_indicator(indicator) for indicator in indicators]
            demisto.debug(f'The number of new indicators: {len(indicators)}')
            groups = [parse_indicator(group) for group in groups]
            demisto.debug(f'The number of new groups: {len(groups)}')

            merged_list = groups + indicators
            for b in batch(merged_list, batch_size=2000):
                demisto.createIndicators(b)

        else:
            readable_output, outputs, raw_response = commands[command](client, args)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        return_error(f'Integration {INTEGRATION_NAME} Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

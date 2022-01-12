import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import requests
import traceback
from typing import Dict

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

INDICATORS_TYPE_RESPONSE = {'malware': 'malware',
                            'actor': 'threat-actors',
                            }
MAP_TYPE_TO_URL = {
    'Malware': 'malware',
    'Actors': 'actor',
    'Indicators': 'indicator'
}
MAP_TYPE_TO_RESPONSE = {
    'Malware': 'malware',
    'Actors': 'threat-actors',
    'Indicators': 'indicators'
}
MAP_NAME_TO_TYPE = {
    'Malware': ThreatIntel.ObjectsNames.MALWARE,
    'Actors': ThreatIntel.ObjectsNames.THREAT_ACTOR
}
MAP_INDICATORS_TYPE = {'fqdn': FeedIndicatorType.Domain,
                       'ipv4': FeedIndicatorType.IP,
                       'md5': FeedIndicatorType.File,
                       'sha1': FeedIndicatorType.File,
                       'sha256': FeedIndicatorType.File,
                       'url': FeedIndicatorType.URL}

''' CLIENT CLASS '''


class MandiantClient(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool, timeout: int,
                 first_fetch: str, limit: int, types: List,
                 metadata: bool = False, enrichment: bool = False, tags: List = [], tlp_color: Optional[str] = None):
        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy, ok_codes=[200])
        self._headers = {
            'X-App-Name': "content.xsoar.cortex.paloaltonetworks.v1.0",
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._get_token()}'
        }
        self.timeout = timeout
        self.first_fetch = first_fetch
        self.limit = limit
        self.types = types
        self.metadata = metadata
        self.tlp_color = tlp_color
        self.tags = tags
        self.enrichment = enrichment

        LOG.add_replace_strs(self._get_token())

    def _get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid.
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        valid_until = integration_context.get('valid_until')

        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until:
            if now_timestamp < valid_until:
                return token

        # else generate a token and update the integration context accordingly
        token = self._generate_token()

        return token

    def _generate_token(self) -> str:
        """
        Generates new token.
        """
        data = {
            'grant_type': 'client_credentials'
        }
        resp = self._http_request(method='POST', url_suffix='token', resp_type='json', data=data)
        self._token = resp.get('access_token')

        integration_context = get_integration_context()
        integration_context.update({'token': self._token})
        # Add 10 minutes buffer for the token
        integration_context.update({'valid_until': datetime.timestamp(datetime.now(timezone.utc)) - 600})
        set_integration_context(integration_context)

        return self._token

    def get_indicator_additional_info(self, identifier: str, indicator_type: str, info_type: str = "") \
            -> Union[Dict, List]:
        """
        Get additional information for given indicator.

        Args:
            identifier (Dict): Indicator's identifier.
            indicator_type (str): The indicator type.
            info_type (str): Type of additional info
        Returns:
            Dict: Additional metadata of the indicator.
        """
        url = f"v4/{MAP_TYPE_TO_URL[indicator_type]}"
        url = urljoin(url, identifier)
        url = urljoin(url, info_type)
        if url[-1] == '/':
            url = url[:-1]

        call_result = {}
        try:
            call_result = self._http_request(method="GET", url_suffix=url, timeout=self.timeout)
        except DemistoException as e:
            # If there is an internal issue inside the server, don't fail the entire fetch session
            if e.res.status_code != 500:
                raise e

        res = call_result
        if info_type:
            # for additional info the api call result structure is different
            if info_type == 'attack-pattern':
                res = call_result.get('attack-patterns', {})
                if isinstance(res, str) and res == 'redacted':
                    res = []  # type: ignore
                elif res and isinstance(res, dict):
                    res = list(res.values())  # type:ignore
            else:
                res = call_result.get(info_type, [])
        return res

    def get_indicators(self, indicator_type: str, params: Dict = {}) -> List:
        """
        Get additional information for given indicator.

        Args:
            indicator_type (str): The indicator type.
            params (Dict): HTTP call params
        Returns:
            List: list indicators.
        """
        try:
            url = f'/v4/{MAP_TYPE_TO_URL[indicator_type]}'

            res = self._http_request(method="GET", url_suffix=url, timeout=self.timeout, params=params)

            res = res.get(MAP_TYPE_TO_RESPONSE[indicator_type], [])

        except DemistoException:
            res = []

        return res


''' HELPER FUNCTIONS '''


def get_new_indicators(client: MandiantClient, last_run: str, indicator_type: str, limit: int) -> List:
    """
    Get new indicators list.
    Args:
        client (MandiantClient): client
        last_run (str): last run as free text or date format
        indicator_type (str): the desired type to fetch
        limit (int): number of indicator to fetch
    Returns:
        List: new indicators

    """
    start_date = arg_to_datetime(last_run)

    params = {}
    if indicator_type == 'Indicators':
        # for indicator type the earliest time to fetch is 90 days ago
        earliest_fetch = arg_to_datetime('90 days ago')
        start_date = max(earliest_fetch, start_date)
        params = {'start_epoch': int(start_date.timestamp()), 'limit': limit}  # type:ignore

    new_indicators_list = client.get_indicators(indicator_type, params=params)

    if indicator_type != 'Indicators':
        new_indicators_list.sort(key=lambda x: arg_to_datetime(x.get('last_updated')), reverse=True)  # new to old
        new_indicators_list = list(
            filter(lambda x: arg_to_datetime(x['last_updated']).timestamp() > start_date.timestamp(),  # type: ignore
                   new_indicators_list))

    return new_indicators_list


def get_indicator_list(client: MandiantClient, limit: int, first_fetch: str, indicator_type: str,
                       update_context: bool = True) -> List[Dict]:
    """
    Get list of indicators from given type.
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to return.
        first_fetch (str): Get indicators newer than first_fetch.
        indicator_type (str): indicator type
        update_context (bool): Whether or not save to context the last run
    Returns:
        List[Dict]: list of indicators
    """
    last_run_dict = demisto.getLastRun()
    indicators_list = last_run_dict.get(f'{indicator_type}List', [])
    if len(indicators_list) < limit:
        last_run = last_run_dict.get(indicator_type + 'Last', first_fetch)
        new_indicators_list = get_new_indicators(client, last_run, indicator_type, limit)
        indicators_list += new_indicators_list

    if indicators_list:
        new_indicators_list = indicators_list[:limit]
        last_run_dict[indicator_type + 'List'] = indicators_list[limit:]
        date_key = 'last_seen' if indicator_type == 'Indicators' else 'last_updated'
        last_run_dict[indicator_type + 'LastFetch'] = new_indicators_list[-1][date_key]

        if update_context:
            demisto.setLastRun(last_run_dict)

        indicators_list = new_indicators_list

    return indicators_list


def get_verdict(mscore: Optional[str]) -> int:
    """
    Convert mscore to dbot score
    Args:
        mscore (str): mscore, value from 0 to 100

    Returns:
        int: DBotScore
    """
    if not mscore:
        return Common.DBotScore.NONE
    mscore = int(mscore)
    if 0 <= mscore <= 20:
        return Common.DBotScore.GOOD
    elif 21 <= mscore <= 50:
        return Common.DBotScore.NONE
    elif 51 <= mscore <= 80:
        return Common.DBotScore.SUSPICIOUS
    elif 81 <= mscore <= 100:
        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.NONE


def get_indicator_relationships(raw_indicator: Dict, indicator_field: str, entity_a_field: str, entity_a_type: str,
                                entity_b_field: str, entity_b_type: str, name: str, reverse_name: str):
    """
    Creates relationships for the given indicator

    Args:
        raw_indicator (Dict): indicator
        indicator_field (str): indicator field that contains the entities list
        entity_a_field (str): indicator field that contains the entity name
        entity_a_type (str): indicator field that contains the entity type
        entity_b_field (str): entity field that contains the entity name
        entity_b_type (str): entity field that contains the entity type
        name (str): the relationship name
        reverse_name (str): the relationship reverse name

    Returns:

    """
    entities_list = raw_indicator.get(indicator_field, [])
    relationships = []
    if entities_list != 'redacted':
        relationships = [EntityRelationship(entity_a=raw_indicator.get(entity_a_field, ''),
                                            entity_a_type=entity_a_type,
                                            name=name,
                                            entity_b=entity.get(entity_b_field, ''),
                                            entity_b_type=entity_b_type,
                                            reverse_name=reverse_name
                                            )
                         for entity in entities_list]
    return relationships


def create_malware_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
      Creates a malware indicator
      Args:
          client (MandiantClient): client
          raw_indicator (Dict): indicator
      Returns:
          Dict: malware indicator
    """
    fields = {'operatingsystemrefs': raw_indicator.get('operating_systems'),
              'aliases': raw_indicator.get('aliases'),
              'capabilities': raw_indicator.get('capabilities'),
              'tags': [i.get('name', '') for i in  # type:ignore
                       argToList(raw_indicator.get('industries'))] + client.tags,  # type:ignore
              'mandiantdetections': raw_indicator.get('detections'),
              'yara': [(yara.get('name'), yara.get('id')) for yara in  # type: ignore
                       raw_indicator.get('yara', [])] if raw_indicator.get('yara', []) != 'redacted' else [],
              'roles': raw_indicator.get('roles'),
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              'lastseenbysource': raw_indicator.get('last_activity_time'),
              'trafficlightprotocol': client.tlp_color
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values

    relationships = get_indicator_relationships(raw_indicator, 'actors', 'name', ThreatIntel.ObjectsNames.MALWARE,
                                                'name',
                                                ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                EntityRelationship.Relationships.RELATED_TO,
                                                EntityRelationship.Relationships.RELATED_TO)

    relationships += get_indicator_relationships(raw_indicator, 'cve', 'name', ThreatIntel.ObjectsNames.MALWARE,
                                                 'name',
                                                 FeedIndicatorType.CVE,
                                                 EntityRelationship.Relationships.RELATED_TO,
                                                 EntityRelationship.Relationships.RELATED_TO)
    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.MALWARE,
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields,
        'relationships': relationships
    }
    return indicator_obj


def create_actor_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator

    Returns: Parsed indicator
    """
    raw_indicator = {k: v for k, v in raw_indicator.items() if v and v != 'redacted'}  # filter none and redacted values
    fields = {'primarymotivation': raw_indicator.get('motivations'),
              'tags': [industry.get('name') for industry in  # type: ignore
                       raw_indicator.get('industries', [])] + client.tags,
              'aliases': [alias.get('name') for alias in raw_indicator.get('aliases', [])],  # type:ignore
              'firstseenbysource': [item.get('earliest') for item in raw_indicator.get('observed', [])],  # type:ignore
              'lastseenbysource': [item.get('recent') for item in raw_indicator.get('observed', [])],  # type:ignore
              'targets': [target.get('name') for target in  # type:ignore
                          raw_indicator.get('locations', {}).get('target', [])],  # type:ignore
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              'trafficlightprotocol': client.tlp_color
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values

    relationships = get_indicator_relationships(raw_indicator, 'malware', 'name', ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                'name',
                                                ThreatIntel.ObjectsNames.MALWARE,
                                                EntityRelationship.Relationships.RELATED_TO,
                                                EntityRelationship.Relationships.RELATED_TO)

    relationships += get_indicator_relationships(raw_indicator, 'cve', 'name', ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                 'cve_id',
                                                 FeedIndicatorType.CVE,
                                                 EntityRelationship.Relationships.TARGETS,
                                                 EntityRelationship.Relationships.TARGETED_BY)

    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.THREAT_ACTOR,
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields,
        'relationships': relationships
    }
    return indicator_obj


def create_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator

    Returns: Parsed indicator
    """
    fields = {'primarymotivation': raw_indicator.get('motivations'),
              'firstseenbysource': raw_indicator.get('first_seen'),
              'lastseenbysource': raw_indicator.get('last_seen'),
              'stixid': raw_indicator.get('id'),
              'trafficlightprotocol': client.tlp_color
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values
    indicator_obj = {
        'value': raw_indicator.get('value'),
        'type': MAP_INDICATORS_TYPE[raw_indicator.get('type', '')],
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields
    }
    return indicator_obj


MAP_INDICATORS_FUNCTIONS = {
    'Malware': create_malware_indicator,
    'Actors': create_actor_indicator,
    'Indicators': create_indicator
}
''' COMMAND FUNCTIONS '''


def test_module(client: MandiantClient, args: Dict) -> str:
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
        get_indicators_command(client, args=args, update_context=False)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e) or 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def enrich_indicators(client: MandiantClient, indicators_list: List, indicator_type: str) -> None:
    """
    For each indicator in indicators_list create relationships and adding the relevant indicators
    Args:
        client (MandiantClient): client
        indicators_list (List): list of raw indicators
        indicator_type (str): the current indicator type

    Returns:
        List of relevant indicators
    """
    for indicator in indicators_list:
        indicator_id = indicator.get('fields', {}).get('stixid', '')
        indicator_name = indicator.get('fields', {}).get('name', '')

        reports_list = client.get_indicator_additional_info(indicator_type=indicator_type,
                                                            identifier=indicator_id,
                                                            info_type='reports')

        reports_relationships = [EntityRelationship(entity_a=indicator_name,
                                                    entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                    name=EntityRelationship.Relationships.RELATED_TO,
                                                    entity_b=report.get('title'),
                                                    entity_b_type=ThreatIntel.ObjectsNames.REPORT,
                                                    reverse_name=EntityRelationship.Relationships.RELATED_TO
                                                    )
                                 for report in reports_list if report]

        general_list = client.get_indicator_additional_info(indicator_type=indicator_type,
                                                            identifier=indicator_id,
                                                            info_type='indicators')

        general_relationships = [EntityRelationship(entity_a=indicator_name,
                                                    entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                    name=EntityRelationship.Relationships.INDICATED_BY,
                                                    entity_b=general_indicator.get('value'),
                                                    entity_b_type=MAP_INDICATORS_TYPE[
                                                        general_indicator.get('type', '')],
                                                    reverse_name=EntityRelationship.Relationships.INDICATOR_OF)
                                 for general_indicator in general_list if general_indicator]

        attack_pattern_list = client.get_indicator_additional_info(indicator_type=indicator_type,
                                                                   identifier=indicator_id,
                                                                   info_type='attack-pattern')

        attack_pattern_relationships = [EntityRelationship(entity_a=indicator_name,
                                                           entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                           name=EntityRelationship.Relationships.USES,
                                                           entity_b=attack_pattern.get('title'),
                                                           entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                                                           reverse_name=EntityRelationship.Relationships.USED_BY
                                                           )
                                        for attack_pattern in attack_pattern_list if attack_pattern]

        indicator['relationships'] += reports_relationships + general_relationships + attack_pattern_relationships


def fetch_indicators(client: MandiantClient, args: Dict = {}, update_context: bool = True):
    """
    For each type the fetch indicator command will:
        1. Fetch a list of indicators, this is done in a single API call and retrieve minimal data for each indicator.
        2. Fetch additional metadata, in order to fetch additional metadata an API call is required for each indicator.
           Note: the additional data is added to the original indicator.
        3. Create relationships (enrichment), each indicator requires an additional 3 API calls in order to create
           relationships.

        The result is the a single list of all the indicators and the new indicators created during the enrichment.
    Args:
        client (MandiantClient): client
        args (Dict): This if given arguments, their values are used instead the one in the client
        update_context (bool): Whether or not to update the context.
    Returns:
        List of all indicators
    """

    limit = int(args.get('limit', client.limit))
    metadata = argToBoolean(args.get('indicatorMetadata', client.metadata))
    enrichment = argToBoolean(args.get('indicatorRelationships', client.enrichment))
    types = argToList(args.get('type', client.types))

    first_fetch = client.first_fetch

    result = []
    for indicator_type in types:

        indicators_list = get_indicator_list(client, limit, first_fetch, indicator_type, update_context)

        if metadata and indicator_type != 'Indicators':
            indicators_list = [client.get_indicator_additional_info(identifier=indicator.get('id'),  # type:ignore
                                                                    indicator_type=indicator_type)
                               for indicator in indicators_list]

        indicators = [MAP_INDICATORS_FUNCTIONS[indicator_type](client, indicator) for indicator in indicators_list]

        if enrichment and indicator_type != 'Indicators':
            enrich_indicators(client, indicators, indicator_type)

        result += indicators

    return result


def get_indicators_command(client: MandiantClient, args: Dict, update_context: bool = True):
    """
    Get indicators command
    Args:
        client (MandiantClient): client
        args:
            limit (int): number of indicators to fetch
            metadata (bool): whether or not to get extra information for each indicator
            enrichment (bool): whether or not to get relationships for each indicator
            types (List): indicators types
        update_context (bool): If set, doesn't update the context output

    Returns:

    """
    indicators = fetch_indicators(client, args, update_context)
    human_readable = tableToMarkdown('Indicators from AutoFocus Tags Feed:', indicators,
                                     headers=['value', 'type', 'fields'], headerTransform=string_to_table_header,
                                     removeNull=True)
    if update_context:
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='',
            outputs_key_field='',
            raw_response=indicators,
            outputs={},
        )
    else:
        return human_readable


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    auth = params.get('auth', {})
    username = auth.get('identifier', '')
    password = auth.get('password', '')
    base_url = params.get('url', '')
    timeout = int(params.get('timeout', 60))
    tlp_color = demisto.params().get('tlp_color')
    feedTags = argToList(demisto.params().get('feedTags'))
    first_fetch = params.get('first_fetch', '3 days ago')
    limit = int(params.get('max_fetch', 50))
    metadata = argToBoolean(params.get('indicatorMetadata', False))
    enrichment = argToBoolean(params.get('indicatorRelationships', False))
    types = argToList(params.get('type'))

    demisto.debug(f'Command being called is {command}')
    try:
        client = MandiantClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            username=username,
            password=password,
            timeout=timeout,
            tags=feedTags,
            tlp_color=tlp_color,
            first_fetch=first_fetch,
            limit=limit,
            metadata=metadata,
            enrichment=enrichment,
            types=types
        )

        if command == 'test-module':
            result = test_module(client, args)
            return_results(result)

        elif command == 'feed-mandiant-get-indicators':
            return_results(fetch_indicators(client, args))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

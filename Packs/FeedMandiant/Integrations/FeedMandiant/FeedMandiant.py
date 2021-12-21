import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import requests
import traceback
from typing import Dict

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
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
                 x_app_name: str):
        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy)
        self._headers = {
            'X-App-Name': x_app_name,
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._get_token()}'
        }
        self._timeout = timeout

    @logger
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

        now = datetime.now(timezone.utc)
        now_timestamp = datetime.timestamp(now)
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until:
            if now_timestamp < valid_until:
                return token

        # else generate a token and update the integration context accordingly
        token = self._generate_token()

        return token

    @logger
    def _generate_token(self) -> str:
        """
        Generates new token.
        """
        data = {
            'grant_type': 'client_credentials'
        }
        resp = self._http_request(method='POST', url_suffix='token', resp_type='json', data=data, ok_codes=[200])
        self._token = resp.get('access_token')

        integration_context = get_integration_context()
        integration_context.update({'token': self._token})
        # Add 10 minutes buffer for the token
        integration_context.update({'valid_until': datetime.timestamp(datetime.now(timezone.utc)) - 600})
        set_integration_context(integration_context)

        return self._token

    def get_metadata(self, indicator: Dict, indicator_type: str) -> Dict:
        """
        Get additional information for given indicator.

        Args:
            indicator (Dict): Basic indicator.
            indicator_type (str): The indicator type.
        Returns:
            Dict: Additional metadata of the indicator.
        """
        try:
            identifier = indicator.get('id')
            res = self._http_request(
                method="GET", url_suffix=f'/v4/{MAP_TYPE_TO_URL[indicator_type]}/{identifier}', timeout=self._timeout,
                ok_codes=[200])
        except DemistoException:
            res = indicator
        return res

    def get_indicator_info(self, identifier: str, info_type: str) -> List:
        """
        Get additional information for given indicator.

        Args:
            identifier (str): Indicator's id.
            info_type (str): The indicator type.
        Returns:
            Dict: Additional metadata of the indicator.
        """
        try:
            res = self._http_request(method="GET", url_suffix=f'/v4/malware/{identifier}/{info_type}',
                                     timeout=self._timeout, ok_codes=[200])
            if info_type == 'attack-pattern':
                res = res.get('attack-patterns')

                if res.get('malware', {}).get('attack-patterns') == 'redacted':
                    res = []
            else:
                res = res.get(info_type, [])

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
    start_date = dateparser.parse(last_run, settings={'TIMEZONE': 'UTC'})

    if indicator_type == 'Indicators':
        # for indicator type the earliest time to fetch is 90 days ago
        earliest_fetch = dateparser.parse('90 days ago', settings={'TIMEZONE': 'UTC'})
        start_date = max(earliest_fetch, start_date)

    params = {'start_epoch': int(start_date.timestamp()), 'limit': limit} if indicator_type == 'Indicators' else {}

    res = client._http_request(method="GET", url_suffix=f'/v4/{MAP_TYPE_TO_URL[indicator_type]}',
                               timeout=client._timeout, params=params, ok_codes=[200])

    new_indicators_list = res.get(MAP_TYPE_TO_RESPONSE[indicator_type], [])

    date_key = 'last_seen' if indicator_type == 'Indicators' else 'last_updated'

    new_indicators_list.sort(key=lambda x: dateparser.parse(x.get(date_key)), reverse=True)  # new to old
    new_indicators_list = list(filter(lambda x: dateparser.parse(x[date_key]).timestamp() > start_date.timestamp(),
                                      new_indicators_list))

    return new_indicators_list


def get_indicator_list(client: MandiantClient, limit: int, first_fetch: str, indicator_type: str) -> List[Dict]:
    """
    Get list of indicators from given type.
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to return.
        first_fetch (str): Get indicators newer than first_fetch.
        indicator_type (str): indicator type

    Returns:
        List[Dict]: list of indicators
    """
    last_run_dict = demisto.getLastRun()
    indicators_list = last_run_dict.get(indicator_type + 'List', [])
    if len(indicators_list) < limit:
        last_run = last_run_dict.get(indicator_type + 'Last', first_fetch)
        new_indicators_list = get_new_indicators(client, last_run, indicator_type, limit)
        indicators_list += new_indicators_list

    if indicators_list:
        new_indicators_list = indicators_list[:limit]
        last_run_dict[indicator_type + 'List'] = indicators_list[limit:]

        date_key = 'last_seen' if indicator_type == 'Indicators' else 'last_updated'

        last_run_dict[indicator_type + 'Last'] = new_indicators_list[-1][date_key]

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


def get_relationships_malware(raw_indicator: Dict) -> List:
    """
    Creates relationships for the given indicator (Malware type)
    Args:
        raw_indicator (Dict): indicator

    Returns:
        List: list of relationships
    """
    relationships = []
    actors_list = raw_indicator.get('actors', [])
    if actors_list != 'redacted':
        for actor in actors_list:
            relationships.append(
                EntityRelationship(entity_a=raw_indicator.get('name', ''),
                                   entity_a_type=ThreatIntel.ObjectsNames.MALWARE,
                                   name=EntityRelationship.Relationships.RELATED_TO,
                                   entity_b=actor.get('name'),
                                   entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                   reverse_name=EntityRelationship.Relationships.RELATED_TO
                                   ).to_indicator())
    cve_list = raw_indicator.get('cve', [])
    if cve_list != 'redacted':
        for cve in cve_list:
            relationships.append(
                EntityRelationship(entity_a=raw_indicator.get('name', ''),
                                   entity_a_type=ThreatIntel.ObjectsNames.MALWARE,
                                   name=EntityRelationship.Relationships.RELATED_TO,
                                   entity_b=cve.get('name'),
                                   entity_b_type=FeedIndicatorType.CVE,
                                   reverse_name=EntityRelationship.Relationships.RELATED_TO
                                   ).to_indicator())
    return relationships


def get_relationships_actor(raw_indicator: Dict) -> List:
    """
    Creates relationships for the given indicator (actor type)
    Args:
        raw_indicator (Dict): indicator

    Returns:
        List: list of relationships
    """
    relationships = []
    malware_list = raw_indicator.get('malware', [])
    if malware_list != 'reducted':
        for malware in malware_list:
            relationships.append(
                EntityRelationship(entity_a=raw_indicator.get('name', ''),
                                   entity_a_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                   name=EntityRelationship.Relationships.RELATED_TO,
                                   entity_b=malware.get('name'),
                                   entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                                   reverse_name=EntityRelationship.Relationships.RELATED_TO
                                   ).to_indicator())
    cve_list = raw_indicator.get('cve', [])
    if cve_list != 'redacted':
        for cve in cve_list:
            relationships.append(
                EntityRelationship(entity_a=raw_indicator.get('name', ''),
                                   entity_a_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                   name=EntityRelationship.Relationships.TARGETS,
                                   entity_b=cve.get('cve_id'),
                                   entity_b_type=FeedIndicatorType.CVE,
                                   reverse_name=EntityRelationship.Relationships.TARGETED_BY
                                   ).to_indicator())
    return relationships


def create_malware_indicator(raw_indicator: Dict) -> Dict:
    """
      Creates a malware indicator
      Args:
          raw_indicator (Dict): indicator

      Returns:
          Dict: malware indicator
    """
    fields = {'operatingsystemrefs': raw_indicator.get('operating_systems'),
              'aliases': raw_indicator.get('aliases'),
              'capabilities': raw_indicator.get('capabilities'),
              'tags': raw_indicator.get('industries'),
              'mandiantdetections': raw_indicator.get('detections'),
              'yara': [(yara.get('name'), yara.get('id')) for yara in
                       raw_indicator.get('yara', [])] if raw_indicator.get('yara', []) != 'redacted' else [],
              'roles': raw_indicator.get('roles'),
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              'lastseenbysource': raw_indicator.get('last_activity_time'),
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values
    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.MALWARE,
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields,
        'relationships': get_relationships_malware(raw_indicator)
    }
    return indicator_obj


def create_report_indicator(raw_indicator: Dict, entity_a: str, entity_a_type: str) -> Dict:
    """
      Creates a malware indicator
      Args:
        raw_indicator (Dict): indicator
        entity_a (str): entity_a name (for relationship)
        entity_a_type (str): entity_a type (for relationship)
      Returns:
          Dict: report indicator
    """
    fields = {'mandiantreportid': raw_indicator.get('report_id'),
              'tags': raw_indicator.get('intelligence_type'),
              'stixid': raw_indicator.get('id'),
              'title': raw_indicator.get('title'),
              'published': raw_indicator.get('published_date'),
              'mandiantversion': raw_indicator.get('version'),
              'reporttype': raw_indicator.get('report_type'),
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}
    indicator_obj = {
        'value': raw_indicator.get('title'),
        'type': ThreatIntel.ObjectsNames.REPORT,
        'rawJSON': raw_indicator,
        'fields': fields,
        'score': get_verdict(raw_indicator.get('mscore')),
        'relationships': [EntityRelationship(entity_a=entity_a,
                                             entity_a_type=entity_a_type,
                                             name=EntityRelationship.Relationships.RELATED_TO,
                                             entity_b=raw_indicator.get('title'),
                                             entity_b_type=ThreatIntel.ObjectsNames.REPORT,
                                             reverse_name=EntityRelationship.Relationships.RELATED_TO
                                             ).to_indicator()]
    }
    return indicator_obj


def create_general_indicator(raw_indicator: Dict, entity_a: str, entity_a_type: str) -> Dict:
    """
      Creates a malware indicator
      Args:
        raw_indicator (Dict): indicator
        entity_a (str): entity_a name (for relationship)
        entity_a_type (str): entity_a type (for relationship)
      Returns:
          Dict: report indicator
    """
    indicator_obj = {
        'value': raw_indicator.get('value'),
        'type': MAP_INDICATORS_TYPE[raw_indicator.get('type', '')],
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'relationships': [EntityRelationship(entity_a=entity_a,
                                             entity_a_type=entity_a_type,
                                             name=EntityRelationship.Relationships.INDICATED_BY,
                                             entity_b=raw_indicator.get('value'),
                                             entity_b_type=MAP_INDICATORS_TYPE[raw_indicator.get('type', '')],
                                             reverse_name=EntityRelationship.Relationships.INDICATOR_OF
                                             ).to_indicator()]
    }
    return indicator_obj


def create_attack_pattern_indicator(raw_indicator: Dict, entity_a: str, entity_a_type: str) -> Dict:
    """
        Creates a attack_pattern indicator
        Args:
          raw_indicator (Dict): indicator
          entity_a (str): entity_a name (for relationship)
          entity_a_type (str): entity_a type (for relationship)
        Returns:
            Dict: attack_pattern indicator
      """
    fields = {'creationdate': raw_indicator.get('created'),
              'name': raw_indicator.get('name'),
              'aliases': raw_indicator.get('attack_pattern_identifier'),
              'updateddate': raw_indicator.get('modified'),
              'description': raw_indicator.get('description'),
              'stixid': raw_indicator.get('id'),
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}
    indicator_obj = {
        'value': raw_indicator.get('title'),
        'type': ThreatIntel.ObjectsNames.REPORT,
        'rawJSON': raw_indicator,
        'fields': fields,
        'score': get_verdict(raw_indicator.get('mscore')),
        'relationships': [EntityRelationship(entity_a=entity_a,
                                             entity_a_type=entity_a_type,
                                             name=EntityRelationship.Relationships.USES,
                                             entity_b=raw_indicator.get('title'),
                                             entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                                             reverse_name=EntityRelationship.Relationships.USED_BY
                                             ).to_indicator()]
    }
    return indicator_obj


def create_actor_indicator(raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        raw_indicator (Dict): raw indicator

    Returns: Parsed indicator
    """
    raw_indicator = {k: v for k, v in raw_indicator.items() if v and v != 'redacted'}  # filter none and redacted values
    fields = {'primarymotivation': raw_indicator.get('motivations'),
              'tags': [industry.get('name') for industry in raw_indicator.get('industries', [])],
              'aliases': [alias.get('name') for alias in raw_indicator.get('aliases', [])],
              'firstseenbysource': [item.get('earliest') for item in raw_indicator.get('observed', [])],
              'lastseenbysource': [item.get('recent') for item in raw_indicator.get('observed', [])],
              'targets': [target.get('name') for target in raw_indicator.get('locations', {}).get('target', [])],
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values
    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.THREAT_ACTOR,
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields,
        'relationships': get_relationships_actor(raw_indicator)
    }
    return indicator_obj


def create_indicator(raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        raw_indicator (Dict): raw indicator

    Returns: Parsed indicator
    """
    fields = {'primarymotivation': raw_indicator.get('motivations'),
              'firstseenbysource': raw_indicator.get('first_seen'),
              'lastseenbysource': raw_indicator.get('last_seen'),
              'stixid': raw_indicator.get('id'),
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


def test_module(client: MandiantClient) -> str:
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
        client._generate_token()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e) or 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def enrich_indicators(client: MandiantClient, indicators_list: List, indicator_type: str) -> List:
    """
    For each indicator in indicators_list create relationships and adding the relevant indicators
    Args:
        client (MandiantClient): client
        indicators_list (List): list of raw indicators
        indicator_type (str): the current indicator type

    Returns:
        List of relevant indicators
    """
    indicators: List[Dict] = []
    for indicator in indicators_list:
        reports = [create_report_indicator(report, indicator.get('name', ''), MAP_NAME_TO_TYPE[indicator_type])
                   for report in client.get_indicator_info(indicator.get('id', ''), 'reports')]

        general_indicators = [create_general_indicator(general_indicator, indicator.get('name', ''),
                                                       MAP_NAME_TO_TYPE[indicator_type])
                              for general_indicator in client.get_indicator_info(indicator.get('id', ''), 'indicators')]

        attack_pattern = [create_attack_pattern_indicator(attack_pattern, indicator.get('name', ''),
                                                          MAP_NAME_TO_TYPE[indicator_type])
                          for attack_pattern in client.get_indicator_info(indicator.get('id', ''), 'attack-pattern')]

        indicators = indicators + reports + general_indicators + attack_pattern

    return indicators


def fetch_indicators(client: MandiantClient, limit: int, first_fetch: str, metadata: bool, enrichment: bool,
                     types: List[str]):
    """
    fetch indicator
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to fetch
        first_fetch (str): first fetch
        metadata (bool): whether or not to get extra information for each indicator
        enrichment (bool): whether or not to get relationships for each indicator
        types (List): indicators types

    Returns:
        List of indictors
    """
    result = []
    for indicator_type in types:

        indicators_list = get_indicator_list(client, limit, first_fetch, indicator_type)

        if metadata and indicator_type != 'Indicators':
            indicators_list = [client.get_metadata(i, indicator_type) for i in indicators_list]

        indicators = [MAP_INDICATORS_FUNCTIONS[indicator_type](indicator) for indicator in indicators_list]

        if enrichment and indicator_type != 'Indicators':
            indicators = enrich_indicators(client, indicators, indicator_type)
        result += indicators
    return result


def get_indicators_command(client: MandiantClient, limit: int, first_fetch: str, metadata: bool, enrichment: bool,
                           types: List[str]):
    """
    Get indicators command
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to fetch
        first_fetch (str): first fetch
        metadata (bool): whether or not to get extra information for each indicator
        enrichment (bool): whether or not to get relationships for each indicator
        types (List): indicators types

    Returns: List

    """
    indicators = fetch_indicators(client, limit, first_fetch, metadata, enrichment, types)
    human_readable = tableToMarkdown('Indicators from AutoFocus Tags Feed:', indicators,
                                     headers=['value', 'type', 'fields'], headerTransform=string_to_table_header,
                                     removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


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
    x_app_name = params.get('xappname')

    demisto.debug(f'Command being called is {command}')
    try:
        client = MandiantClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            username=username,
            password=password,
            timeout=timeout,
            x_app_name=x_app_name
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'feed-mandiant-get-indicators':
            limit = int(args.get('limit', 50))
            metadata = argToBoolean(args.get('indicatorMetadata', False))
            enrichment = argToBoolean(args.get('indicatorRelationships', False))
            types = argToList(args.get('type'))
            first_fetch = params.get('first_fetch', '3 days ago')

            return_results(get_indicators_command(client, limit, first_fetch, metadata, enrichment, types))

        elif command == 'fetch-indicators':
            limit = int(params.get('max_fetch', 50))
            first_fetch = params.get('first_fetch', '3 days ago')
            metadata = argToBoolean(params.get('indicatorMetadata', False))
            enrichment = argToBoolean(params.get('indicatorRelationships', False))
            types = argToList(params.get('type'))

            indicators = fetch_indicators(client, limit, first_fetch, metadata, enrichment, types)
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

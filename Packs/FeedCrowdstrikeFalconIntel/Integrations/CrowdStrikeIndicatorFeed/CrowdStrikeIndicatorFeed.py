import copy

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from CrowdStrikeApiModule import *  # noqa: E402

# IMPORTS
from datetime import datetime
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

XSOAR_TYPES_TO_CROWDSTRIKE = {
    'account': "username",
    'domain': "domain",
    'email': "email_address",
    'file md5': "hash_md5",
    'file sha-256': "hash_sha256",
    'ip': "ip_address",
    'registry key': "registry",
    'url': "url"
}
CROWDSTRIKE_TO_XSOAR_TYPES = {
    'username': FeedIndicatorType.Account,
    'domain': FeedIndicatorType.Domain,
    'email_address': FeedIndicatorType.Email,
    'hash_md5': FeedIndicatorType.File,
    'hash_sha1': FeedIndicatorType.File,
    'hash_sha256': FeedIndicatorType.File,
    'registry': FeedIndicatorType.Registry,
    'url': FeedIndicatorType.URL,
    'ip_address': FeedIndicatorType.IP,
    'reports': ThreatIntel.ObjectsNames.REPORT,
    'actors': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'malware_families': ThreatIntel.ObjectsNames.MALWARE,
    'vulnerabilities': FeedIndicatorType.CVE
}
INDICATOR_TO_CROWDSTRIKE_RELATION_DICT: Dict[str, Any] = {
    ThreatIntel.ObjectsNames.REPORT: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO
    },
    ThreatIntel.ObjectsNames.THREAT_ACTOR: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO
    },
    ThreatIntel.ObjectsNames.MALWARE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO
    },
    FeedIndicatorType.CVE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Account: EntityRelationship.Relationships.RELATED_TO
    }
}
CROWDSTRIKE_INDICATOR_RELATION_FIELDS = ['reports', 'actors', 'malware_families', 'vulnerabilities', 'relations']


class Client(CrowdStrikeClient):

    def __init__(self, credentials, base_url, include_deleted, type, limit, tlp_color=None, feed_tags=None,
                 malicious_confidence=None, filter=None, generic_phrase=None, insecure=True, proxy=False,
                 first_fetch=None, create_relationships=True):
        params = assign_params(credentials=credentials,
                               server_url=base_url,
                               insecure=insecure,
                               ok_codes=tuple(),
                               proxy=proxy)
        super().__init__(params)
        self.type = type
        self.malicious_confidence = malicious_confidence
        self.filter = filter
        self.generic_phrase = generic_phrase
        self.include_deleted = include_deleted
        self.tlp_color = tlp_color
        self.feed_tags = feed_tags
        self.limit = limit
        self.first_fetch = first_fetch
        self.create_relationships = create_relationships

    def get_indicators(self, params):
        response = super().http_request(
            method='GET',
            params=params,
            url_suffix='intel/combined/indicators/v1',
            timeout=30
        )
        return response

    def fetch_indicators(self, limit: Optional[int], offset: Optional[int] = 0, fetch_command=False) -> list:
        """ Get indicators from CrowdStrike API

        Args:
            limit(int): number of indicators to return
            offset: indicators offset
            fetch_command: In order not to update last_run time if it is not fetch command

        Returns:
            (list): parsed indicators
        """
        filter = f'({self.filter})' if self.filter else ''
        if self.type:
            type_fql = self.build_type_fql(self.type)
            filter = f'({type_fql})+{filter}' if filter else f'({type_fql})'

        if self.malicious_confidence:
            malicious_confidence_fql = ','.join([f"malicious_confidence:'{item}'"
                                                 for item in self.malicious_confidence])
            filter = f"{filter}+({malicious_confidence_fql})" if filter else f'({malicious_confidence_fql})'

        if fetch_command:
            if last_run := self.get_last_run():
                filter = f'{filter}+({last_run})' if filter else f'({last_run})'
            elif self.first_fetch:
                last_run = f'last_updated:>={int(self.first_fetch)}'
                filter = f'{filter}+({last_run})' if filter else f'({last_run})'

        demisto.info(f' filter {filter}')
        params = assign_params(include_deleted=self.include_deleted,
                               limit=limit,
                               offset=offset, q=self.generic_phrase,
                               filter=filter,
                               sort='last_updated|asc')

        response = self.get_indicators(params=params)
        timestamp = self.set_last_run()

        # need to fetch all indicators after the limit
        if pagination := response.get('meta', {}).get('pagination'):
            pagination_offset = pagination.get('offset', 0)
            pagination_limit = pagination.get('limit')
            total = pagination.get('total', 0)
            if pagination_offset + pagination_limit < total:
                timestamp = response.get('resources', [])[-1].get('last_updated')

        if response.get('meta', {}).get('pagination', {}).get('total', 0) and fetch_command:
            demisto.setIntegrationContext({'last_modified_time': timestamp})
            demisto.info(f'set last_run: {timestamp}')

        indicators = self.create_indicators_from_response(response, self.tlp_color, self.feed_tags, self.create_relationships)
        return indicators

    @staticmethod
    def set_last_run():
        """
        Returns: Current timestamp
        """
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        return timestamp

    @staticmethod
    def get_last_run() -> str:
        """ Gets last run time in timestamp

        Returns:
            last run in timestamp, or '' if no last run
        """
        if last_run := demisto.getIntegrationContext().get('last_modified_time'):
            demisto.info(f'get last_run: {last_run}')
            params = f'last_updated:>={last_run}'
        else:
            params = ''
        return params

    @staticmethod
    def create_indicators_from_response(raw_response, tlp_color=None, feed_tags=None, create_relationships=True) -> list:
        """ Builds indicators from API raw response

            Args:
                raw_response: response from crowdstrike API
                tlp_color: tlp color chosen by customer
                feed_tags: Feed tags to filter by
                create_relationships: Whether to create relationships.

            Returns:
                (list): list of indicators
            """

        parsed_indicators: list = []
        indicator: dict = {}

        for resource in raw_response['resources']:
            indicator = {
                'type': CROWDSTRIKE_TO_XSOAR_TYPES.get(resource.get('type'), resource.get('type')),
                'value': resource.get('indicator'),
                'rawJSON': resource,
                'fields': {'actor': resource.get('actors'),
                           'reports': resource.get('reports'),
                           'malwarefamily': resource.get('malware_families'),
                           'stixkillchainphases': resource.get('kill_chains'),
                           'ipaddress': resource.get('ip_address_types'),
                           'domainname': resource.get('domain_types'),
                           'targets': resource.get('targets'),
                           'threattypes': [{'threatcategory': threat} for threat in resource.get('threat_types', [])],
                           'vulnerabilities': resource.get('vulnerabilities'),
                           'confidence': resource.get('malicious_confidence'),
                           'updateddate': resource.get('last_updated'),
                           'creationdate': resource.get('published_date'),
                           'tags': [label.get('name') for label in resource.get('labels')]  # type: ignore
                           }
            }
            if tlp_color:
                indicator['fields']['trafficlightprotocol'] = tlp_color
            if feed_tags:
                indicator['fields']['tags'].extend(feed_tags)
            if create_relationships:
                relationships = create_and_add_relationships(indicator, resource)
                indicator['relationships'] = relationships
            parsed_indicators.append(indicator)

        return parsed_indicators

    @staticmethod
    def build_type_fql(types_list: list) -> str:
        """ Builds an indicator type query for the filter parameter

        Args:
            types_list(list): indicator types that was chosen by user

        Returns:
            (str): FQL query containing the relevant indicator types we want to fetch from Crowdstrike
        """

        if 'ALL' in types_list:
            # Replaces "ALL" for all types supported on XSOAR.
            crowdstrike_types = [f"type:'{type}'" for type in CROWDSTRIKE_TO_XSOAR_TYPES.keys()]
        else:
            crowdstrike_types = [f"type:'{XSOAR_TYPES_TO_CROWDSTRIKE.get(type.lower())}'" for type in types_list if
                                 type.lower() in XSOAR_TYPES_TO_CROWDSTRIKE]

        result = ','.join(crowdstrike_types)
        return result


def create_and_add_relationships(indicator: dict, resource: dict) -> list:
    """
    Creates and adds relationships to indicators for each CrowdStrike relationships type.

    Args:
        indicator(dict): The indicator in XSOAR format.
        resource(dict): The indicator from the response.

    Returns:
        List of relationships objects.
    """

    relationships = []

    for field in CROWDSTRIKE_INDICATOR_RELATION_FIELDS:
        if field in resource and resource[field]:
            relationships.extend(create_relationships(field, indicator, resource))

    return relationships


def create_relationships(field: str, indicator: dict, resource: dict) -> list:
    """
    Creates indicator relationships.

    Args:
        field(str): A CrowdStrike indicator field which contains relationships.
        indicator(dict): The indicator in XSOAR format.
        resource(dict): The indicator from the response.

    Returns:
        List of relationships objects.
    """
    relationships = []

    for relation in resource[field]:
        related_indicator_type = CROWDSTRIKE_TO_XSOAR_TYPES[field] if field != 'relations' else \
            CROWDSTRIKE_TO_XSOAR_TYPES[relation['type']]
        relation_name = INDICATOR_TO_CROWDSTRIKE_RELATION_DICT[related_indicator_type].get(indicator['type'], indicator['type']) \
            if field != 'relations' else EntityRelationship.Relationships.RELATED_TO

        indicator_relation = EntityRelationship(
            name=relation_name,
            entity_a=indicator['value'],
            entity_a_type=indicator['type'],
            entity_b=relation['indicator'] if field == 'relations' else relation,
            entity_b_type=related_indicator_type,
            reverse_name=EntityRelationship.Relationships.RELATIONSHIPS_NAMES[relation_name]
        ).to_indicator()

        relationships.append(indicator_relation)

    return relationships


def fetch_indicators_command(client: Client):
    """ fetch indicators from the Crowdstrike Intel

    Args:
        client: Client object

    Returns:
        list of indicators(list)
    """
    parsed_indicators = client.fetch_indicators(
        fetch_command=True,
        limit=client.limit
    )
    # we submit the indicators in batches
    for b in batch(parsed_indicators, batch_size=2000):
        demisto.createIndicators(b)
    return parsed_indicators


def crowdstrike_indicators_list_command(client: Client, args: dict) -> CommandResults:
    """ Gets indicator from Crowdstrike Intel to readable output

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """

    offset = arg_to_number(args.get('offset', 0))
    limit = arg_to_number(args.get('limit', 50))
    parsed_indicators = client.fetch_indicators(
        limit=limit,
        offset=offset,
        fetch_command=False
    )
    if outputs := copy.deepcopy(parsed_indicators):
        for indicator in outputs:
            indicator['id'] = indicator.get('rawJSON', {}).get('id')

        readable_output = tableToMarkdown(name='Indicators from CrowdStrike Falcon Intel', t=outputs,
                                          headers=["type", "value", "id"], headerTransform=pascalToSpace)

        return CommandResults(
            outputs=outputs,
            outputs_prefix='CrowdStrikeFalconIntel.Indicators',
            outputs_key_field='id',
            readable_output=readable_output,
            raw_response=parsed_indicators
        )
    else:
        return CommandResults(
            readable_output='No Indicators.'
        )


def test_module(client: Client, args: dict) -> str:
    try:
        client.fetch_indicators(limit=client.limit, fetch_command=False)
    except Exception:
        raise Exception("Could not fetch CrowdStrike Indicator Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok'


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()

    credentials = params.get('credentials')
    proxy = params.get('proxy', False)
    insecure = params.get('insecure', False)
    first_fetch_param = params.get('first_fetch')
    first_fetch_datetime = arg_to_datetime(first_fetch_param) if first_fetch_param else None
    first_fetch = first_fetch_datetime.timestamp() if first_fetch_datetime else None

    base_url = params.get('base_url')
    tlp_color = params.get('tlp_color')
    include_deleted = params.get('include_deleted', False)
    type = argToList(params.get('type'), 'ALL')
    malicious_confidence = argToList(params.get('malicious_confidence'))
    filter = params.get('filter')
    generic_phrase = params.get('generic_phrase')
    max_fetch = arg_to_number(params.get('max_indicator_to_fetch')) if params.get('max_indicator_to_fetch') else 10000
    max_fetch = min(max_fetch, 10000)
    feed_tags = argToList(params.get('feedTags'))
    create_relationships = params.get('create_relationships', True)

    args = demisto.args()

    try:
        command = demisto.command()
        demisto.info(f'Command being called is {demisto.command()}')

        client = Client(
            credentials=credentials,
            base_url=base_url,
            insecure=insecure,
            proxy=proxy,
            tlp_color=tlp_color,
            feed_tags=feed_tags,
            include_deleted=include_deleted,
            type=type,
            malicious_confidence=malicious_confidence,
            filter=filter,
            generic_phrase=generic_phrase,
            limit=max_fetch,
            first_fetch=first_fetch,
            create_relationships=create_relationships
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, args)
            return_results(result)

        elif command == 'fetch-indicators':
            fetch_indicators_command(client=client)

        elif command == 'crowdstrike-indicators-list':
            return_results(crowdstrike_indicators_list_command(client, args))

        elif command == "crowdstrike-reset-fetch-indicators":
            return_results(reset_last_run())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

from typing import List, Dict

from taxii2client.common import TokenAuth
from taxii2client.v20 import Server, as_pages

from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

UNIT42_TYPES_TO_DEMISTO_TYPES = {
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain': FeedIndicatorType.Domain,
    'domain-name': FeedIndicatorType.Domain,
    'url': FeedIndicatorType.URL,
    'md5': FeedIndicatorType.File,
    'sha-1': FeedIndicatorType.File,
    'sha-256': FeedIndicatorType.File,
    'file:hashes': FeedIndicatorType.File,
}

RELATIONS_TYPE_TO_DEMISTO_TYPES = {
    'campaign': 'Campaign',
    'attack-pattern': 'Attack Pattern',
    'report': 'Report',
    'indicator': 'Indicator',
    'malware': 'Malware',
    'course-of-action': 'Course of Action'

}


class Client(BaseClient):

    def __init__(self, api_key, verify):
        """Implements class for Unit 42 feed.

        Args:
            api_key: unit42 API Key.
            verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        """
        super().__init__(base_url='https://stix2.unit42.org/taxii', verify=verify)
        self._api_key = api_key
        self._proxies = handle_proxy()
        self.objects_data = {}

    def get_stix_objects(self, test: bool = False, items_types: list = []):
        for type_ in items_types:
            self.fetch_stix_objects_from_api(test, type=type_)

    def fetch_stix_objects_from_api(self, test: bool = False, **kwargs):
        """Retrieves all entries from the feed.

        Args:
            test: Whether it was called during clicking the test button or not - designed to save time.

        """
        data = []

        server = Server(url=self._base_url, auth=TokenAuth(key=self._api_key), verify=self._verify,
                        proxies=self._proxies)

        for api_root in server.api_roots:
            for collection in api_root.collections:
                for bundle in as_pages(collection.get_objects, per_request=100, **kwargs):
                    data.extend(bundle.get('objects'))
                    if test:
                        return data

        self.objects_data[kwargs.get('type')] = data


def parse_indicators(indicator_objects: list, feed_tags: list = [], tlp_color: Optional[str] = None) -> list:
    """Parse the objects retrieved from the feed.
    Args:
      indicator_objects: a list of objects containing the indicators.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
    Returns:
        A list of processed indicators.
    """
    indicators = []
    if indicator_objects:
        for indicator_object in indicator_objects:
            pattern = indicator_object.get('pattern')
            for key in UNIT42_TYPES_TO_DEMISTO_TYPES.keys():
                if pattern.startswith(f'[{key}'):  # retrieve only Demisto indicator types
                    indicator_obj = {
                        "value": indicator_object.get('name'),
                        "type": UNIT42_TYPES_TO_DEMISTO_TYPES[key],
                        "rawJSON": indicator_object,
                        "fields": {
                            "firstseenbysource": indicator_object.get('created'),
                            "indicatoridentification": indicator_object.get('id'),
                            "tags": list((set(indicator_object.get('labels'))).union(set(feed_tags))),
                            "modified": indicator_object.get('modified'),
                            "reportedby": 'Unit42',
                        }
                    }

                    if tlp_color:
                        indicator_obj['fields']['trafficlightprotocol'] = tlp_color

                    indicators.append(indicator_obj)

    return indicators


def parse_reports(report_objects: list, feed_tags: list = [], tlp_color: Optional[str] = None) -> list:
    """Parse the objects retrieved from the feed.

    Args:
      report_objects: a list of objects containing the reports.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.

    Returns:
        A list of processed reports.
    """
    reports = []

    for report_object in report_objects:
        report = dict()  # type: Dict[str, Any]

        report['type'] = 'STIX Report'
        report['value'] = f"[Unit42 ATOM] {report_object.get('name')}"
        report['fields'] = {
            'stixid': report_object.get('id'),
            'published': report_object.get('published'),
            'description': report_object.get('description', ''),
            "reportedby": 'Unit42',
            "tags": list((set(report_object.get('labels'))).union(set(feed_tags))),
        }
        if tlp_color:
            report['fields']['trafficlightprotocol'] = tlp_color

        report['rawJSON'] = {
            'unit42_id': report_object.get('id'),
            'unit42_labels': report_object.get('labels'),
            'unit42_published': report_object.get('published'),
            'unit42_created_date': report_object.get('created'),
            'unit42_modified_date': report_object.get('modified'),
            'unit42_description': report_object.get('description'),
            'unit42_object_refs': report_object.get('object_refs')
        }

        reports.append(report)

    return reports


def parse_campaigns(campaigns_obj, feed_tags, tlp_color):
    campaigns_indicators = []
    for campaign in campaigns_obj:
        indicator_obj = {
            "value": campaign.get('name'),
            "type": 'Campaign',
            "rawJSON": campaign,
            "score": 3,
            "fields": {
                'stixid': campaign.get('id'),
                "firstseenbysource": campaign.get('created'),
                "modified": campaign.get('modified'),
                'description': campaign.get('description'),
                "reportedby": 'Unit42',
                "tags": feed_tags,
            }
        }

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        campaigns_indicators.append(indicator_obj)

    return campaigns_indicators


def handle_multiple_dates_in_one_field(field_name: str, field_value: str):
    """Parses datetime fields to handle one value or more

    Args:
        field_name (str): The field name that holds the data (created/modified).
        field_value (str): Raw value returned from feed.

    Returns:
        str. One datetime value (min/max) according to the field name.
    """
    dates_as_string = field_value.splitlines()
    dates_as_datetime = [datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ') for date in dates_as_string]

    if field_name == 'created':
        return f"{min(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
    else:
        return f"{max(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"


def get_indicator_publication(indicator):
    publications = []
    for external_reference in indicator.get('external_references', []):
        if external_reference.get('external_id'):
            continue
        url = external_reference.get('url')
        description = external_reference.get('description')
        publications.append({'Link': url, 'Title': description})
    return publications


def get_attack_id_and_value_from_name(attack_indicator):
    """
    Split indicator name into MITRE ID and indicator value: 'T1108: Redundant Access' -> MITRE ID = T1108,
    indicator value = 'Redundant Access'.
    """
    ind_name = attack_indicator.get('name')
    idx = ind_name.index(':')
    ind_id = ind_name[:idx]
    value = ind_name[idx + 2:]
    return ind_id, value


def create_attack_pattern_indicator(client, feed_tags, tlp_color) -> List:
    """Creates Attack Pattern indicators with the related mitre course of action.

    Returns:
        Attack Pattern indicators list.
    """

    attack_pattern_indicators = []
    attack_indicator_objects = client.objects_data['attack-pattern']

    for attack_indicator in attack_indicator_objects:

        publications = get_indicator_publication(attack_indicator)
        mitre_id, value = get_attack_id_and_value_from_name(attack_indicator)

        indicator = {
            "value": value,
            "type": 'Attack Pattern',
            "fields": {
                'stixid': attack_indicator.get('id'),
                "firstseenbysource": handle_multiple_dates_in_one_field('created', attack_indicator.get('created')),
                "modified": handle_multiple_dates_in_one_field('modified', attack_indicator.get('modified')),
                'description': attack_indicator.get('description'),
                'operatingsystemrefs': attack_indicator.get('x_mitre_platforms'),
                "publications": publications,
                "mitreid": mitre_id,
                "reportedby": 'Unit42',
                "tags": feed_tags,
            }
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        attack_pattern_indicators.append(indicator)
    return attack_pattern_indicators


def create_course_of_action_indicators(client, feed_tags, tlp_color):
    course_of_action_indicators = []
    course_of_action_objects = client.objects_data['course-of-action']

    for coa_indicator in course_of_action_objects:

        publications = get_indicator_publication(coa_indicator)

        indicator = {
            "value": coa_indicator.get('name'),
            "type": 'Attack Pattern',
            "score": 0,
            "fields": {
                'stixid': coa_indicator.get('id'),
                "firstseenbysource": handle_multiple_dates_in_one_field('created', coa_indicator.get('created')),
                "modified": handle_multiple_dates_in_one_field('modified', coa_indicator.get('modified')),
                'description': coa_indicator.get('description', ''),
                "publications": publications,
                "reportedby": 'Unit42',
                "tags": feed_tags,
            }
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        course_of_action_indicators.append(indicator)
    return course_of_action_indicators


def get_ioc_type(indicator, id_to_object):
    ioc_type = ''
    indicator_obj = id_to_object.get(indicator, {})
    pattern = indicator_obj.get('pattern', '')
    for unit42_type in UNIT42_TYPES_TO_DEMISTO_TYPES:
        if unit42_type in pattern:
            ioc_type = UNIT42_TYPES_TO_DEMISTO_TYPES.get(unit42_type)  # type: ignore
            break
    return ioc_type


def get_ioc_value(ioc, id_to_obj):
    ioc_obj = id_to_obj.get(ioc)
    if ioc_obj:
        return f"[Unit42 ATOM] {ioc_obj.get('name')}" if ioc_obj.get('type') == 'report' else ioc_obj.get('name')


def create_list_relationships(client, id_to_object):
    relationships_list = []
    relationships_objects = client.objects_data['relationship']
    for relationships_object in relationships_objects:
        a_type = relationships_object.get('source_ref').split('--')[0]
        a_type = RELATIONS_TYPE_TO_DEMISTO_TYPES.get(a_type)
        if a_type == 'Indicator':
            a_type = get_ioc_type(relationships_object.get('source_ref'), id_to_object)

        b_type = relationships_object.get('target_ref').split('--')[0]
        b_type = RELATIONS_TYPE_TO_DEMISTO_TYPES.get(b_type)
        if b_type == 'Indicator':
            b_type = get_ioc_type(relationships_object.get('target_ref'), id_to_object)

        mapping_fields = {
            'lastseenbysource': relationships_object.get('modified'),
            'firstseenbysource': relationships_object.get('created')
        }

        entity_a = get_ioc_value(relationships_object.get('source_ref'), id_to_object)
        entity_b = get_ioc_value(relationships_object.get('target_ref'), id_to_object)

        relationship_type = relationships_object.get('relationship_type')
        if relationship_type == 'indicates':
            relationship_type = 'indicated-by'

        entity_relation = EntityRelation(name=relationship_type,
                                         entity_a=entity_a,
                                         entity_a_type=a_type,
                                         entity_b=entity_b,
                                         entity_b_type=b_type,
                                         fields=mapping_fields)
        relationships_list.append(entity_relation.to_indicator())
    return relationships_list


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.get_stix_objects(test=True, items_types=['indicator', 'report'])
    return 'ok'


def fetch_indicators(client: Client, feed_tags: list = [], tlp_color: Optional[str] = None,
                     create_relationships=False) -> List[Dict]:
    """Retrieves indicators and reports from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
        create_relationships: Create indicators relationships
    Returns:
        List. Processed indicators and reports from feed.
    """
    item_types_to_fetch_from_api = ['report', 'indicator', 'malware', 'campaign', 'attack-pattern', 'relationship',
                                    'course-of-action']
    client.get_stix_objects(items_types=item_types_to_fetch_from_api)

    for type_, objects in client.objects_data.items():
        demisto.info(f'Fetched {len(objects)} Unit42 {type_} objects.')

    ioc_indicators = parse_indicators(client.objects_data['indicator'], feed_tags, tlp_color)
    reports = parse_reports(client.objects_data['report'], feed_tags, tlp_color)
    campaigns = parse_campaigns(client.objects_data['campaign'], feed_tags, tlp_color)
    attack_patterns = create_attack_pattern_indicator(client, feed_tags, tlp_color)
    course_of_actions = create_course_of_action_indicators(client, feed_tags, tlp_color)

    id_to_object = {
        obj.get('id'): obj for obj in
        client.objects_data['report'] + client.objects_data['indicator'] + client.objects_data['malware']
        + client.objects_data['campaign'] + client.objects_data['attack-pattern']
        + client.objects_data['course-of-action']
    }

    dummy_indicator = {}
    if create_relationships:
        list_relationships = create_list_relationships(client, id_to_object)

        dummy_indicator = {
            "value": "$$DummyIndicator$$",
            "relationships": list_relationships
        }

    if dummy_indicator:
        ioc_indicators.append(dummy_indicator)

    demisto.debug(f'{len(ioc_indicators)} XSOAR Indicators were created.')
    demisto.debug(f'{len(reports)} XSOAR STIX Reports Indicators were created.')
    demisto.debug(f'{len(campaigns)} XSOAR campaigns Indicators were created.')
    demisto.debug(f'{len(attack_patterns)} Attack Patterns Indicators were created.')
    demisto.debug(f'{len(course_of_actions)} Course of Actions Indicators were created.')

    return ioc_indicators + reports + campaigns + attack_patterns + course_of_actions


def get_indicators_command(client: Client, args: Dict[str, str], feed_tags: list = [],
                           tlp_color: Optional[str] = None) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Demisto Outputs.
    """
    limit = int(args.get('limit', '10'))

    indicators = client.fetch_stix_objects_from_api(test=True, type='indicator')

    indicators = parse_indicators(indicators, feed_tags, tlp_color)
    limited_indicators = indicators[:limit]

    readable_output = tableToMarkdown('Unit42 Indicators:', t=limited_indicators, headers=['type', 'value', 'fields'])

    command_results = CommandResults(
        outputs_prefix='',
        outputs_key_field='',
        outputs={},
        readable_output=readable_output,
        raw_response=limited_indicators
    )

    return command_results


def main():
    """
    PARSE AND VALIDATE FEED PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    api_key = str(params.get('api_key', ''))
    verify = not params.get('insecure', False)
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    create_relationships = params.get('create_relationships')

    command = demisto.command()
    demisto.debug(f'Command being called in Unit42 feed is: {command}')

    try:
        client = Client(api_key, verify)

        if command == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client, feed_tags, tlp_color, create_relationships)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        elif command == 'unit42-get-indicators':
            return_results(get_indicators_command(client, args, feed_tags, tlp_color))

    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

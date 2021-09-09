from typing import List, Dict, Tuple

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

COURSE_OF_ACTION_U42 = ['Cortex XDR Prevent', 'DNS Security', 'XSOAR']
COURSE_OF_ACTION_BP = ['URL Filtering', 'NGFW', 'Wildfire', 'Threat Prevention']
COURSE_OF_ACTION_HEADERS = ['name', 'title', 'description', 'impact statement', 'recommendation number',
                            'remediation procedure']


class Client(BaseClient):

    def __init__(self, api_key, verify=False, proxy=False):
        """Implements class for Unit 42 feed.

        Args:
            api_key: unit42 API Key.
            verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
            proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url='https://stix2.unit42.org/taxii', verify=verify,
                         proxy=proxy)
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


def parse_indicators_relationships(indicators: List, matched_relationships: Dict, id_to_object: Dict):
    """Parse the relationships between indicators to attack-patterns, malware and campaigns.

    Args:
      indicators (List): a list of indicators.
      matched_relationships (Dict): a dict of relationships in the form of `id: list(related_ids)`.
      id_to_object: a dict in the form of `id: stix_object`.

    Returns:
        A list of indicators, containing the indicators and the relationships between them.
    """
    for indicator in indicators:
        indicator_id = indicator.get('fields', {}).get('indicatoridentification', '')
        for relation in matched_relationships.get(indicator_id, []):
            relation_object = id_to_object.get(relation)
            if not relation_object:
                # in case a relationship object mentioned a connection to another object
                # that were not fetched from the feed.
                continue

            if relation.startswith('attack-pattern'):
                relation_value_field = relation_object.get('external_references')
                field_type = 'feedrelatedindicators'
                indicator['fields']['feedrelatedindicators'] = []
            elif relation.startswith('campaign'):
                relation_value_field = relation_object.get('name')
                field_type = 'campaign'
            elif relation.startswith('malware'):
                relation_value_field = relation_object.get('name')
                field_type = 'malwarefamily'
            else:
                continue

            if isinstance(relation_value_field, str):
                # multiple malware or campaign names can be associated to an indicator
                if field_type in indicator.get('fields'):
                    indicator['fields'][field_type].extend([relation_value_field])
                else:
                    indicator['fields'][field_type] = [relation_value_field]

            else:  # a feedrelatedindicators is a list of dict
                all_urls = []
                external_id = ''

                for item in relation_value_field:
                    if 'url' in item:
                        all_urls.append(item.get('url'))

                        if 'external_id' in item:
                            external_id = item.get('external_id')

                feedrelatedindicators_obj = {
                    'type': 'MITRE ATT&CK',
                    'value': external_id,
                    'description': ','.join(all_urls)
                }
                indicator['fields'][field_type].extend([feedrelatedindicators_obj])

    return indicators


def sort_report_objects_by_type(objects):
    """Get lists of objects by their type.

    Args:
      objects: a list of objects.

    Returns:
        List. Objects of type report.
    """
    main_report_objects = []
    sub_report_objects = []

    for obj in objects:
        is_main_report = False

        for object_id in obj.get('object_refs'):
            if object_id.startswith('report'):
                is_main_report = True
                break

        if is_main_report:
            main_report_objects.append(obj)
        else:
            sub_report_objects.append(obj)

    return main_report_objects, sub_report_objects


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
        report['value'] = report_object.get('name')
        report['fields'] = {
            'stixid': report_object.get('id'),
            'published': report_object.get('published'),
            'stixdescription': report_object.get('description', ''),
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


def parse_reports_relationships(reports: List, sub_reports: List, matched_relationships: Dict,
                                id_to_object: Dict, courses_of_action_products: Dict) -> Tuple[list, list]:
    """Parse the relationships between reports' malware to attack-patterns and indicators.

    Args:
      reports: a list of reports.
      sub_reports: a list of sub-reports.
      matched_relationships (Dict): a dict of relationships in the form of `id: list(related_ids)`.
      id_to_object: a dict in the form of `id: stix_object`.
      courses_of_action_products (Dict): Connects courses of action id with the relationship product.

    Returns:
        A list of processed reports.
        a list of MITRE ATT&CK indicators.
    """
    indicators = []
    for report in reports:
        related_ids = []  # Since main reports dont hold their own relationships theres a need to collect them.

        related_sub_reports = [object_id for object_id in report.get('rawJSON', {}).get('unit42_object_refs', [])
                               if object_id.startswith('report')]

        report_malware_set = set()

        for sub_report in sub_reports:
            if sub_report.get('id') in related_sub_reports:
                # Indicators relationship only comes from being related to the malware objects of the report.
                related_ids += [id_ for id_ in matched_relationships.get(sub_report.get('id'), [])
                                if not id_.startswith('indicator')]

                for object_id in sub_report.get('object_refs', []):
                    if object_id.startswith('malware'):
                        report_malware_set.add(object_id)
                    elif object_id.startswith('attack-pattern'):
                        related_ids.append(object_id)

        report['fields']['feedrelatedindicators'] = []

        for malware_id in report_malware_set:
            related_ids += matched_relationships.get(malware_id, [])

            malware_object = id_to_object.get(malware_id)

            if malware_object:
                report['fields']['feedrelatedindicators'].extend([{
                    'type': 'Malware',
                    'value': malware_object.get('name'),
                    'description': malware_object.get(
                        'description', ', '.join(malware_object.get('labels', ['No description provided.'])))
                }])

        indicators.extend(parse_related_indicators(report, related_ids, id_to_object,
                                                   matched_relationships, courses_of_action_products))

    return reports, indicators


def parse_related_indicators(report: Dict, related_ids: List, id_to_object: Dict, matched_relationships: Dict,
                             courses_of_action_products: Dict) -> List[Dict]:
    """ Creates feed related indicators to Stix report object.

    Args:
        report (dict): Stix report object.
        related_ids (List): Malware objects ids related to the report.
        id_to_object (Dict): a dict in the form of `id: stix_object`.
        matched_relationships (Dict): a dict of relationships in the form of `id: list(related_ids)`.
        courses_of_action_products (Dict): Connects courses of action id with the relationship product.

    Returns:
        List of MITRE ATT&CK indicators.
    """
    indicators = []
    for relation in related_ids:
        relation_object = id_to_object.get(relation)
        if not relation_object:
            continue

        if relation.startswith('attack-pattern'):
            type_name = 'MITRE ATT&CK'
            relation_value_field = relation_object.get('external_references')
        elif relation.startswith('indicator'):
            # Need to create the connection only to file hashes
            if not relation_object.get('pattern', '').startswith('[file:'):
                continue

            type_name = 'Indicator'
            relation_value_field = relation_object.get('name')
        elif relation.startswith('malware'):
            type_name = 'Malware'
            relation_value_field = relation_object.get('name')
        else:
            continue

        if isinstance(relation_value_field, str):
            report['fields']['feedrelatedindicators'].extend([{
                'type': type_name,
                'value': relation_value_field,
                'description': ', '.join(relation_object.get('labels', ['No description provided.']))
            }])
            indicator_val = relation_value_field

        else:
            all_urls = []
            external_id = ''

            for item in relation_value_field:
                if 'url' in item:
                    all_urls.append(item.get('url'))

                    if 'external_id' in item:
                        external_id = item.get('external_id')

            report['fields']['feedrelatedindicators'].extend([{
                'type': type_name,
                'value': external_id,
                'description': ','.join(all_urls)
            }])
            indicator_val = external_id

        if indicator_val and type_name == 'MITRE ATT&CK':
            # create MITRE ATT&CK indicator
            indicators.append(create_mitre_indicator(indicator_val, relation_object, matched_relationships,
                                                     id_to_object, courses_of_action_products))

    return indicators


def create_mitre_indicator(indicator_val: str, relation_object: Dict, matched_relationships: Dict, id_to_object: Dict,
                           courses_of_action_products: Dict) -> Dict:
    """Creates MITRE ATT&CK indicator with the related mitre course of action.

    Args:
        indicator_val (String): The indicator value.
        relation_object (Dict): Stix relationship object.
        matched_relationships (Dict): a dict of relationships in the form of `id: list(related_ids)`.
        id_to_object (Dict): a dict in the form of `id: stix_object`.
        courses_of_action_products (Dict): Connects courses of action id with the relationship product.

    Returns:
        MITRE ATT&CK indicator.
    """

    relationship = relation_object.get('id')
    courses_of_action: Dict[str, List] = {}

    if relationship in matched_relationships:
        for source in matched_relationships[relationship]:
            if source.startswith('course-of-action') and id_to_object.get(source):
                relationship_product = courses_of_action_products[source]
                if relationship_product not in courses_of_action:
                    courses_of_action[relationship_product] = []
                courses_of_action[relationship_product].append(id_to_object[source])

    name = relation_object.get('name')
    name = name.partition(':')[2] if name else ''
    return {
        "value": indicator_val,
        "type": 'MITRE ATT&CK',
        "fields": {
            "mitrename": name.strip(),
            "mitredescription": relation_object.get('description'),
            "firstseenbysource": relation_object.get('created'),
            "indicatoridentification": relation_object.get('id'),
            "tags": [],
            "modified": relation_object.get('modified'),
            "reportedby": 'Unit42',
            "mitrecourseofaction": create_course_of_action_field(courses_of_action),
            "mitrekillchainphases": relation_object.get('kill_chain_phases')
        }
    }


def create_course_of_action_field(courses_of_action: dict) -> str:
    """creates a markdown tables from the courses of action data according to the product type.

    Args:
        courses_of_action: dictionary containing the courses of action data.

    Returns:
        markdown string with courses of action tables.
    """
    if not courses_of_action:
        return 'No courses of action found.'
    markdown = ''
    for relationship_product, courses_list in courses_of_action.items():
        tmp_table = []
        for course_of_action in courses_list:
            row = {}
            if relationship_product in COURSE_OF_ACTION_U42:
                row['title'] = course_of_action.get('x_panw_coa_u42_title')
                row['description'] = course_of_action.get('description')

            if relationship_product in COURSE_OF_ACTION_BP:
                row['title'] = course_of_action.get('x_panw_coa_bp_title')
                row['impact statement'] = course_of_action.get('x_panw_coa_bp_impact_statement')
                row['recommendation number'] = course_of_action.get('x_panw_coa_bp_recommendation_number')
                row['description'] = course_of_action.get('x_panw_coa_bp_description')
                row['remediation procedure'] = course_of_action.get('x_panw_coa_bp_remediation_procedure')

            row['name'] = course_of_action.get('name')

            tmp_table.append(row)

        md_table = tableToMarkdown(relationship_product, tmp_table, removeNull=True,
                                   headerTransform=string_to_table_header, headers=COURSE_OF_ACTION_HEADERS)
        markdown = f'{markdown}\n{md_table}'
    return markdown


def match_relationships(relationships: List):
    """Creates a dict that connects object_id to all objects_ids it has a relationship with.

    Args:
        relationships (List): A list of relationship objects.

    Returns:
        Dict. Connects object_id to all objects_ids it has a relationship with. In the form of `id: [related_ids]`
        Dict. Connects courses of action id with the relationship product.
    """
    matches: Dict[str, set] = {}
    courses_of_action_products = {}

    for relationship in relationships:
        source = relationship.get('source_ref')
        target = relationship.get('target_ref')

        if not source or not target:
            continue

        if source in matches:
            matches[source].add(target)
        else:
            matches[source] = {target}

        if target in matches:
            matches[target].add(source)
        else:
            matches[target] = {source}

        if source.startswith('course-of-action'):
            product = relationship.get('x_panw_coa_u42_panw_product', [])
            if product:
                courses_of_action_products[source] = product[0]
            else:
                courses_of_action_products[source] = 'No product'
    return matches, courses_of_action_products


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.get_stix_objects(test=True, items_types=['indicator', 'report'])
    return 'ok'


def fetch_indicators(client: Client, feed_tags: list = [], tlp_color: Optional[str] = None) -> List[Dict]:
    """Retrieves indicators and reports from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        List. Processed indicators and reports from feed.
    """
    item_types_to_fetch_from_api = ['report', 'indicator', 'malware', 'campaign',
                                    'attack-pattern', 'relationship', 'course-of-action']
    client.get_stix_objects(items_types=item_types_to_fetch_from_api)

    for type_, objects in client.objects_data.items():
        demisto.info(f'Fetched {len(objects)} Unit42 {type_} objects.')

    id_to_object = {
        obj.get('id'): obj for obj in
        client.objects_data['report'] + client.objects_data['indicator'] + client.objects_data['malware']
        + client.objects_data['campaign'] + client.objects_data['attack-pattern'] + client.objects_data['course-of-action']
    }

    matched_relationships, courses_of_action_products = match_relationships(client.objects_data['relationship'])

    indicators = parse_indicators(client.objects_data['indicator'], feed_tags, tlp_color)
    indicators = parse_indicators_relationships(indicators, matched_relationships, id_to_object)

    main_report_objects, sub_report_objects = sort_report_objects_by_type(client.objects_data['report'])
    reports = parse_reports(main_report_objects, feed_tags, tlp_color)
    reports, mitre_indicators = parse_reports_relationships(reports, sub_report_objects, matched_relationships,
                                                            id_to_object, courses_of_action_products)

    demisto.debug(f'{len(indicators)} XSOAR Indicators were created.')
    demisto.debug(f'{len(reports)} XSOAR STIX Report Indicators were created.')
    demisto.debug(f'{len(mitre_indicators)} MITRE ATT&CK Indicators were created.')

    return indicators + reports + mitre_indicators


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
    proxy = argToBoolean(params.get('proxy') or 'false')

    command = demisto.command()
    demisto.debug(f'Command being called in Unit42 feed is: {command}')

    try:
        client = Client(api_key, verify, proxy)

        if command == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client, feed_tags, tlp_color)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        elif command == 'unit42-get-indicators':
            return_results(get_indicators_command(client, args, feed_tags, tlp_color))

    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

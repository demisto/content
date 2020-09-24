from typing import List, Dict, Optional, Set

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

    def get_stix_objects(self, test: bool = False) -> list:
        """Retrieves all entries from the feed.

        Args:
            test: Whether it was called during clicking the test button or not - designed to save time.
        Returns:
            A list of stix objects, containing the indicators.
        """
        data = []
        server = Server(url=self._base_url, auth=TokenAuth(key=self._api_key), verify=self._verify,
                        proxies=self._proxies)

        for api_root in server.api_roots:
            for collection in api_root.collections:
                for bundle in as_pages(collection.get_objects, per_request=100):
                    data.extend(bundle.get('objects'))
                    if test:
                        break
        return data


def get_object_type(objects: list, types: list) -> list:
    """Get the object specified.
    Args:
      objects: a list of objects.
      types: a list of the types.
    Returns:
        A list of a certain type.
    """
    return [item for item in objects if item.get('type') in types]


def parse_indicators(objects: list, feed_tags: list = [], tlp_color: Optional[str] = None) -> list:
    """Parse the objects retrieved from the feed.
    Args:
      objects: a list of objects containing the indicators.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
    Returns:
        A list of indicators, containing the indicators.
    """
    indicators_objects = [item for item in objects if item.get('type') == 'indicator']  # retrieve only indicators

    indicators = []
    if indicators_objects:
        for indicator_object in indicators_objects:
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


def parse_relationships(indicators: list, relationships: list = [], pivots: list = []) -> list:
    """Parse the relationships between indicators to attack-patterns, malware and campaigns.
    Args:
      indicators: a list of indicators.
      relationships: a list of relationships.
      pivots: a list of attack-patterns, malware and campaigns.
    Returns:
        A list of indicators, containing the indicators and the relationships between them.
    """
    for indicator in indicators:
        indicator_id = indicator.get('fields', {}).get('indicatoridentification', '')
        for relationship in relationships:
            reference = ''
            if indicator_id == relationship.get('source_ref'):
                reference = relationship.get('target_ref', '')

            elif indicator_id == relationship.get('target_ref'):
                reference = relationship.get('source_ref', '')

            field = ''
            if reference:  # if there is a reference, get the relevant pivot
                if reference.startswith('attack-pattern'):
                    field = 'external_references'
                    field_type = 'feedrelatedindicators'
                elif reference.startswith('campaign'):
                    field = 'name'
                    field_type = 'campaign'
                elif reference.startswith('malware'):
                    field = 'name'
                    field_type = 'malwarefamily'

            if field:  # if there is a pivot, map the relevant data accordingly
                for pivot in pivots:
                    if pivot.get('id') == reference:
                        pivot_field = pivot.get(field)
                        if isinstance(pivot_field, str):
                            # multiple malware or campaign names can be associated to an indicator
                            if field_type in indicator.get('fields'):
                                indicator['fields'][field_type].extend([pivot_field])
                            else:
                                indicator['fields'][field_type] = [pivot_field]
                        else:  # a feedrelatedindicators is a list of dict
                            indicator['fields'][field_type] = []
                            for item in pivot_field:
                                if 'url' in item or 'external_id' in item:
                                    feedrelatedindicators_obj = {
                                        'type': 'MITRE ATT&CK',
                                        'value': item.get('external_id'),
                                        'description': item.get('url')
                                    }
                                    indicator['fields'][field_type].extend([feedrelatedindicators_obj])

    return indicators


class PlaybookProcessor:
    base_url = 'https://pan-unit42.github.io/playbook_viewer/playbook_json/'

    def __init__(self, feed_tags: List, tlp_color: Optional[str]):
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        self.playbook_suffixes = self.get_playbooks_urls()

    @staticmethod
    def get_playbooks_urls():
        return [
            'chafer.json',
            'cozyduke.json',
            'darkhydrus.json',
            'dragonok.json',
            'hangover.json',
            'inception.json',
            'konni.json',
            'menupass.json',
            'oilrig.json',
            'patchwork.json',
            'pickaxe.json',
            'pkplug.json',
            'rancor.json',
            'reaper.json',
            'sofacy.json',
            'th3bug.json',
            'tick.json',
            'windshift.json',
        ]

    def get_playbook_data(self, url):
        json_url = PlaybookProcessor.base_url + url
        raw_json = requests.get(json_url)

        try:
            bundle = raw_json.json()

            if bundle.get('type', '') == 'bundle' and bundle.get('spec_version', '') == '2.0':
                return bundle
            else:
                return_error('{} - no valid stix 2.0 bundle found'.format(url))
        except Exception as e:
            return_error('{} - could not parse json from file\n{}'.format(url, e))

        return {}

    def sort_objects(self, all_objects):
        report_object = {}
        malware_objects = []
        indicator_objects = []
        relationship_objects = []
        attack_pattern_objects = []

        for obj in all_objects:
            if obj['type'] == 'report':
                report_object = objz

            elif obj['type'] == 'indicator':
                indicator_objects.append(obj)

            elif obj['type'] == 'malware':
                malware_objects.append(obj)

            elif obj['type'] == 'relationship':
                relationship_objects.append(obj)

            elif obj['type'] == 'attack-pattern':
                attack_pattern_objects.append(obj)

        return report_object, malware_objects, indicator_objects, relationship_objects, attack_pattern_objects

    def process_report(self, report_object: Dict):
        report = dict()  # type: Dict[str, Any]

        report['type'] = 'STIX Report'
        report['value'] = report_object.get('name')
        report['fields'] = {
            'stixid': report_object.get('id'),
            'published': report_object.get('published'),
            'stixdescription': report_object.get('description', ''),
            "reportedby": 'Unit42',
            "tags": list((set(report_object.get('labels'))).union(set(self.feed_tags))),
        }
        if self.tlp_color:
            report['fields']['trafficlightprotocol'] = self.tlp_color

        report['rawJSON'] = {
            'unit42_id': report_object.get('id'),
            'unit42_labels': report_object.get('labels'),
            'unit42_published': report_object.get('published'),
            'unit42_created_date': report_object.get('created'),
            'unit42_modified_date': report_object.get('modified'),
            'unit42_description': report_object.get('description'),
            'unit42_object_refs': report_object.get('object_refs')
        }

        connected_objects_ids = [obj_id for obj_id in report_object.get('object_refs') if obj_id.startswith('indicator')]

        return report, connected_objects_ids

    def process_connected_objects(self, indicator_objects: List, connected_objects_ids: List):
        raw_indicators = []

        for indicator in indicator_objects:
            if indicator.get('id') in connected_objects_ids:
                raw_indicators.append(indicator)

        return parse_indicators(raw_indicators)

    def process_playbook(self, bundle: Dict):
        objects = bundle.get('objects', [])

        report_object, malware_objects, indicator_objects, relationship_objects, attack_pattern_objects = \
            PlaybookProcessor.sort_objects(objects)

        report, connected_objects_ids = self.process_report(report_object)
        related_indicators = self.process_connected_objects(indicator_objects, connected_objects_ids)

        if report:
            report = parse_relationships([report], relationship_objects, malware_objects + attack_pattern_objects)
            return report

        return {}

    def process_playbooks(self):
        reports = []

        suffixes = self.get_playbooks_urls()
        for suffix in suffixes:
            bundle = self.get_playbook_data(suffix)
            report = self.process_playbook(bundle)

            if report:
                reports.append(report)

        return reports


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.get_stix_objects(test=True)
    return 'ok'


def fetch_indicators(client: Client, feed_tags: list = [], tlp_color: Optional[str] = None) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Indicators.
    """
    objects: list = client.get_stix_objects()
    demisto.info(str(f'Fetched Unit42 Indicators. {str(len(objects))} Objects were received.'))
    indicators = parse_indicators(objects, feed_tags, tlp_color)
    relationships = get_object_type(objects, types=['relationship'])
    pivots = get_object_type(objects, types=['attack-pattern', 'malware', 'campaign'])
    indicators = parse_relationships(indicators, relationships, pivots)
    demisto.debug(str(f'{str(len(indicators))} Demisto Indicators were created.'))
    return indicators


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
    objects: list = client.get_stix_objects(test=True)
    indicators = parse_indicators(objects, feed_tags, tlp_color)
    limited_indicators = indicators[:limit]

    readable_output = tableToMarkdown('Unit42 Indicators:', t=limited_indicators, headers=['type', 'value'])

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

    command = demisto.command()
    demisto.debug(f'Command being called in Unit42 feed is: {command}')

    try:
        client = Client(api_key, verify)

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

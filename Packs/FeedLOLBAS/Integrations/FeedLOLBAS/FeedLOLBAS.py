import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
MITRE_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

DEFAULT_FEED_TAGS = {'LOLBAS'}
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool,
                 create_relationships: bool, feed_tags: List[str], tlp_color: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.create_relationships = create_relationships
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        self.verify = verify
        self.proxy = proxy

    def get_indicators(self):  # pragma: no cover
        """
        Get indicators from LOLBAS API.
        """
        demisto.debug('Getting indicators from lolbas api.')
        return self._http_request('GET', '/lolbas.json', resp_type='json')

    def get_mitre_data(self) -> List[Dict[str, Any]]:
        """
        Get MITRE data from GitHub.
        """
        headers = {
            'Content-Type': 'application/taxii+json',
            'Accept': 'application/vnd.oasis.taxii+json; version=2.0'
        }
        return self._http_request(full_url=MITRE_URL, method='GET', headers=headers, resp_type='json').get('objects', [])


''' COMMAND FUNCTIONS '''


def test_module(client: Client):  # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.get_indicators()
    return_results('ok')


def create_relationship_list(indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Create relationships between indicators.
    For example, if an indicator has a MITRE ID, create a relationship between the indicator and the MITRE ID.
    """
    relationships = []
    entity_a = indicator.get('value')
    for command in indicator.get('fields', {}).get('Commands', []):
        if mitre_id := command.get('mitrename'):
            relation_obj = EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=entity_a,
                entity_a_type=ThreatIntel.ObjectsNames.TOOL,
                entity_b=mitre_id,
                entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN, )
            relationships.append(relation_obj.to_indicator())
    return relationships


def map_indicator_fields(raw_indicator: Dict[str, Any]) -> Dict[str, Any]:
    command_keys = ['Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID', 'OperatingSystem', 'MitreName']

    mapped_commands = []
    mapped_detections = []
    mapped_paths = []
    commands = raw_indicator.get('Commands', [])
    detections = raw_indicator.get('Detection', [])
    paths = raw_indicator.get('Full_Path', [])
    if commands:
        for command in commands:
            mapped_commands.append({lolbas_field.lower(): command.get(lolbas_field) for lolbas_field in command_keys})
    if detections:
        for detection in detections:
            if detection_keys := list(detection.keys()):
                mapped_detections.append({'type': detection_keys[0], 'content': detection.get(detection_keys[0])})
    if paths:
        for path in paths:
            mapped_paths.append({'path': path.get('Path')})

    return {
        'Commands': mapped_commands,
        'Detections': mapped_detections,
        'Paths': mapped_paths,
        'description': raw_indicator.get('Description'),
        'url': raw_indicator.get('url')
    }


def build_indicator_custom_fields(client: Client) -> Dict[str, Any]:
    """
    Map MITRE ID to MITRE name.
    """
    result_map = {}

    mitre_data = client.get_mitre_data()
    # filter only the attack-pattern objects.
    mitre_data = [obj for obj in mitre_data if obj.get('type') == 'attack-pattern']
    # build a dictionary list of mitre_id: mitre_name.
    for obj in mitre_data:
        external_refs = list(obj.get('external_references', []))
        for external_ref in external_refs:
            mitre_name = obj.get('name')
            if mitre_id := external_ref.get('external_id'):
                result_map[mitre_id] = mitre_name
    for mitre_id in result_map.keys():
        if len(mitre_id.split('.')) == 2:
            main_mitre_id = mitre_id.split('.')[0]
            result_map[mitre_id] = f"{result_map[main_mitre_id]}: {result_map[mitre_id]}"
    return result_map


def build_mitre_tags(raw_indicator: Dict[str, Any], mitre_id_to_name: Dict[str, str]) -> List[str]:
    """
    Returns an extended MITRE tags list of a single indicator.
    """
    mitre_tags = []
    for command in raw_indicator.get('Commands', []):
        if mitre_id := command.get('MitreID', ''):
            mitre_name = mitre_id_to_name.get(mitre_id, '')
            command['MitreName'] = mitre_name
            mitre_tags.extend([mitre_name, mitre_id, command.get('Category')])
    return mitre_tags


def build_indicators(client: Client, raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Builds indicators JSON data in XSOAR expected format from the raw response.
    """
    demisto.debug(f'Creating {len(raw_indicators)} indicators.')
    indicators: List[Dict[str, Any]] = []
    mitre_id_to_name = build_indicator_custom_fields(client)

    for raw_indicator in raw_indicators:
        additional_tags = build_mitre_tags(raw_indicator, mitre_id_to_name)

        indicator: Dict[str, Any] = {
            'type': ThreatIntel.ObjectsNames.TOOL,
            'value': raw_indicator.get('Name'),
            'fields': map_indicator_fields(raw_indicator),
            'rawJSON': raw_indicator,
        }
        if tlp_color := client.tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        if feed_tags := client.feed_tags:
            indicator['fields']['tags'] = feed_tags + additional_tags
        if client.create_relationships:
            indicator['relationships'] = create_relationship_list(indicator)
        indicators.append(indicator)
    return indicators


def create_relationships(indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Create relationships between indicators.
    """
    demisto.debug('Creating relationships.')
    return create_relationship_list(indicator)


def fetch_indicators(client: Client, limit: int = None) -> \
        List[Dict[str, Any]] | Tuple[List[Dict[str, Any]], str]:
    """
        Fetch indicators from LOLBAS API and create indicators in XSOAR.
    """
    response = client.get_indicators()
    indicators = build_indicators(client, response)
    if limit:
        return indicators[:limit], response
    return indicators, response


''' MAIN FUNCTION '''


def get_indicators(client, limit):
    """
    Get indicators from LOLBAS API, mainly for debug.
    """
    hr_list = []
    output_list = []

    if limit and limit <= 0:
        raise ValueError('Limit must be a positive number.')
    indicators, raw_res = fetch_indicators(client, limit)
    indicators = indicators[:limit] if isinstance(indicators, List) \
        else [indicators] if indicators else []
    for record in indicators:
        hr = {'Name': record.get('value'), 'Description': record.get('fields', {}).get('description')}
        hr_list.append(hr)
        output_list.append({'Type': record.get('type'),
                            'Commands': record.get('fields', {}).get('Commands'),
                            'Detections': record.get('fields', {}).get('Detections'),
                            'Paths': record.get('fields', {}).get('Paths'),
                            'URL': record.get('fields', {}).get('url')} | hr)
    return CommandResults(outputs=output_list, outputs_prefix='LOLBAS.Indicators', raw_response=raw_res,
                          readable_output=tableToMarkdown("LOLBAS indicators", hr_list, headers=['Name', 'Description']),
                          outputs_key_field='Name')


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params.get('base_url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    create_relationships = params.get('create_relationships', True)
    # Append default tags.
    feed_tags = list(set(argToList(params.get('feedTags', []))) | DEFAULT_FEED_TAGS)
    tlp_color = params.get('tlp_color', '')
    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            create_relationships=create_relationships,
            feed_tags=feed_tags,
            tlp_color=tlp_color,
        )

        if command == 'test-module':
            test_module(client)
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                try:
                    demisto.createIndicators(iter_)
                except Exception:
                    # find problematic indicator
                    for indicator in iter_:
                        try:
                            demisto.createIndicators([indicator])
                        except Exception as err:
                            demisto.debug(f'createIndicators Error: failed to create the following indicator:'
                                          f' {indicator}\n {err}')
                    raise
        elif command == 'lolbas-get-indicators':
            limit = arg_to_number(demisto.args().get('limit', None))
            return_results(get_indicators(client, limit))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

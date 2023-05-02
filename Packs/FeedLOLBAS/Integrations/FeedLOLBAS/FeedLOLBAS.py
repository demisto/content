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

    def get_indicators(self) -> str:  # pragma: no cover
        """
        Get indicators from LOLBAS API.
        """
        demisto.debug('Getting indicators from lolbas api.')
        return self._http_request('GET', '/lolbas.json', resp_type='json')


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


def create_relationship_list(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create relationships between indicators.
    For example, if an indicator has a MITRE ID, create a relationship between the indicator and the MITRE ID.
    """
    relationships = []
    for indicator in indicators:
        entity_a = indicator.get('value')
        for command in indicator.get('fields', {}).get('Commands', []):
            if mitre_id := command.get('mitreid'):
                relation_obj = EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=entity_a,
                    entity_a_type=ThreatIntel.ObjectsNames.TOOL,
                    entity_b=mitre_id,
                    entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN, )
                relationships.append(relation_obj.to_indicator())
    return relationships


def get_mitre_data(client: Client) -> List[Dict[str, Any]]:
    """
    Get MITRE data from GitHub.
    """
    headers = {
        'Content-Type': 'application/taxii+json',
        'Accept': 'application/vnd.oasis.taxii+json; version=2.0'
    }
    if client.proxy:
        proxies = handle_proxy()
    else:
        proxies = {
            "http": None,
            "https": None,
        }
    return requests.get(MITRE_URL, headers=headers, verify=client.verify, proxies=proxies).json().get('objects', [])


def map_indicator_fields(pre_indicator: Dict[str, Any]) -> Dict[str, Any]:
    command_keys = ['Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID', 'OperatingSystem']

    mapped_commands = []
    mapped_detections = []
    mapped_paths = []
    commands = pre_indicator.get('Commands', [])
    detections = pre_indicator.get('Detection', [])
    paths = pre_indicator.get('Full_Path', [])
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
        'description': pre_indicator.get('Description')
    }


def map_mitre_id_to_name(client: Client) -> Dict[str, str]:
    """
    Map MITRE ID to MITRE name.
    """
    result_map = {}

    mitre_data = get_mitre_data(client)
    # filter only the attack-pattern objects.
    mitre_data = [obj for obj in mitre_data if obj.get('type') == 'attack-pattern']
    # build a dictionary list of mitre_id: mitre_name.
    for obj in mitre_data:
        for external_ref in obj.get('external_references'):
            mitre_name = obj.get('name')
            if mitre_id := external_ref.get('external_id'):
                result_map[mitre_id] = mitre_name
    for mitre_id in result_map.keys():
        if len(mitre_id.split('.')) == 2:
            main_mitre_id = mitre_id.split('.')[0]
            result_map[mitre_id] = f"{result_map[main_mitre_id]}: {result_map[mitre_id]}"
    return result_map


def pre_process_indicator(pre_indicator: Dict[str, Any], mitre_id_to_name) -> List[str]:
    """
    Pre-process the indicator, map the MitreID with MitreName and build the relevant tag list.
    """
    mitre_tags = []
    for command in pre_indicator.get('Commands', []):
        if mitre_id := command.get('MitreID', ''):
            mitre_name = mitre_id_to_name.get(mitre_id, '')
            command['MitreID'] = mitre_name
            mitre_tags.extend([mitre_name, mitre_id, command.get('Category')])
    return mitre_tags


def create_indicators(client: Client, pre_indicators) -> List[Dict[str, Any]]:
    """
    Create indicators from the response.
    """
    demisto.debug(f'Creating {len(pre_indicators)} indicators.')
    indicators: List[Dict[str, Any]] = []
    mitre_id_to_name = map_mitre_id_to_name(client)

    for pre_indicator in pre_indicators:
        additional_tags = pre_process_indicator(pre_indicator, mitre_id_to_name)

        indicator: Dict[str, Any] = {
            'type': ThreatIntel.ObjectsNames.TOOL,
            'value': pre_indicator.get('Name'),
            'fields': map_indicator_fields(pre_indicator),
            'rawJSON': pre_indicator,
        }
        if tlp_color := client.tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        if feed_tags := client.feed_tags:
            indicator['fields']['tags'] = feed_tags + additional_tags

        indicators.append(indicator)
    return indicators


def create_relationships(client: Client, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create relationships between indicators.
    """
    if client.create_relationships:
        demisto.debug('Creating relationships.')
        relationships = create_relationship_list(indicators)
        if relationships:
            dummy_indicator_for_relations = {
                'value': '$$DummyIndicator$$',
                'relationships': relationships
            }
            indicators.append(dummy_indicator_for_relations)
    return indicators


def fetch_indicators(client: Client, limit: int = None) -> \
        List[Dict[str, Any]] | Tuple[List[Dict[str, Any]], str]:
    """
        Fetch indicators from LOLBAS API and create indicators in XSOAR.
    """
    response = client.get_indicators()
    indicators = create_indicators(client, response)
    indicators = create_relationships(client, indicators)
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
        if record.get('value', '') == '$$DummyIndicator$$':
            continue
        hr = {'Name': record.get('value'), 'Description': record.get('fields', {}).get('description')}
        hr_list.append(hr)
        output_list.append({'Type': record.get('type'),
                            'Commands': record.get('fields', {}).get('Commands'),
                            'Detections': record.get('fields', {}).get('Detections'),
                            'Paths': record.get('fields', {}).get('Paths')} | hr)
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

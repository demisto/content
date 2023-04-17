import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

BASE_URL = 'https://lolbas-project.github.io/api'
DEFAULT_FEED_TAGS = {'LOLBAS', 'MitreID'}
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, verify: bool, proxy: bool,
                 create_relationships: bool, feed_tags: List[str], tlp_color: str):
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy)
        self.create_relationships = create_relationships
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color

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
            if mitre_id := command.get('MitreID'):
                relation_obj = EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=entity_a,
                    entity_a_type=ThreatIntel.ObjectsNames.TOOL,
                    entity_b=mitre_id,
                    entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN, )
                relationships.append(relation_obj.to_indicator())
    return relationships


def create_indicators(client: Client, pre_indicators) -> List[Dict[str, Any]]:
    """
    Create indicators from the response.
    """
    demisto.debug(f'Creating {len(pre_indicators)} indicators.')
    indicators: List[Dict[str, Any]] = []
    for pre_indicator in pre_indicators:
        indicator: Dict[str, Any] = {
            'type': ThreatIntel.ObjectsNames.TOOL,
            'value': pre_indicator.get('Name'),
            'description': pre_indicator.get('Description'),
            'fields': {
                'Commands': pre_indicator.get('Commands', []),
                'Detections': pre_indicator.get('Detections', []),
                'Paths': pre_indicator.get('Full_Paths', []),
            },
            'rawJSON': pre_indicator,
        }
        if tlp_color := client.tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        if feed_tags := client.feed_tags:
            indicator['fields']['tags'] = feed_tags
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


def fetch_indicators(client: Client) -> List[Dict[str, Any]]:
    """
        Fetch indicators from LOLBAS API and create indicators in XSOAR.
    """
    response = client.get_indicators()
    indicators = create_indicators(client, response)
    indicators = create_relationships(client, indicators)
    return indicators


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    create_relationships = argToBoolean(params.get('create_relationships', True))
    # Append default tags.
    feed_tags = list(set(argToList(params.get('feedTags', []))) | DEFAULT_FEED_TAGS)
    tlp_color = params.get('tlp_color', '')
    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            create_relationships=create_relationships,
            feed_tags=feed_tags,
            tlp_color=tlp_color,
        )

        if command == 'test-module':
            test_module(client)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client)

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

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

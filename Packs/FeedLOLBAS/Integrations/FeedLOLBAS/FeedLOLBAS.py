import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

CSV_REGEX = r'"([^"]*)"'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool,
                 create_relationships: bool, feed_tags: List[str], tlp_color: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.create_relationships = create_relationships
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color

    def get_indicators(self) -> str:  # pragma: no cover
        """
        Get indicators from LOLBAS API.
        """
        return self._http_request('GET', '/lolbas.csv', resp_type='csv').text


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
    try:
        client.get_indicators()
        return_results('ok')

    except DemistoException:
        return_error('Could not connect to server')


def parse_response(response) -> List[Dict[str, str]]:
    """
    Parse the response from LOLBAS API.
    """
    pre_indicators: List[Dict[str, str]] = []
    rows_resp = response.split('\n')
    if rows_resp:
        headers = rows_resp[0].split(',')
        for row in rows_resp[1:]:
            row = re.findall(CSV_REGEX, row)
            if len(row) == len(headers):
                pre_indicators.append(dict(zip(headers, row)))
    return pre_indicators


def create_relationship_list(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create relationships between indicators.
    For example, if an indicator has a MITRE ID, create a relationship between the indicator and the MITRE ID.
    """
    relationships = []
    for indicator in indicators:
        entity_a = indicator.get('value')
        entity_b = indicator.get('fields', {}).get('Commands', {}).get('MitreID', "")
        if entity_a and entity_b:
            relation_obj = EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=entity_a,
                entity_a_type=ThreatIntel.ObjectsNames.TOOL,
                entity_b=entity_b,
                entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN, )
            relationships.append(relation_obj.to_indicator())
    return relationships


def parse_detections(pre_parsed_detections: str) -> List[Dict[str, str]]:
    """
        Parse detections from the response.
    """
    parsed_detections = []

    if detections := pre_parsed_detections:
        for detection in detections.split(','):
            if detection.count(':') > 0:
                if splitted_detection := detection.split(':', 1):
                    if detection_type := splitted_detection[0]:
                        if detection_content := splitted_detection[1]:
                            parsed_detections.append({"Type": detection_type, "Content": detection_content})
    return parsed_detections


def create_indicators(client: Client, pre_indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Create indicators from the response.
    """
    indicators: List[Dict[str, Any]] = []
    for pre_indicator in pre_indicators:
        indicator: Dict[str, Any] = {
            "type": ThreatIntel.ObjectsNames.TOOL,
            "value": pre_indicator.get('Filename'),
            "description": pre_indicator.get('Description'),
            "fields": {
                "Commands": {
                    "Command": pre_indicator.get('Command'),
                    "Description": pre_indicator.get('Command Description'),
                    "Usecase": pre_indicator.get('Command Usecase'),
                    "Category": pre_indicator.get('Command Category'),
                    "Privileges": pre_indicator.get('Command Privileges'),
                    "MitreID": pre_indicator.get('MITRE ATT&CK technique'),
                    "OperatingSystem": pre_indicator.get('Operating System')
                },
                "Detections": parse_detections(pre_indicator.get("Detection", "")),
                "Paths": {"Paths": pre_indicator.get('Paths'), }
            },
            "rawJSON": pre_indicator,
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
        relationships = create_relationship_list(indicators)
        if relationships:
            dummy_indicator_for_relations = {
                "value": "$$DummyIndicator$$",
                "relationships": relationships
            }
            indicators.append(dummy_indicator_for_relations)
    return indicators


def fetch_indicators(client: Client) -> List[Dict[str, Any]]:
    """
        Fetch indicators from LOLBAS API and create indicators in XSOAR.
    """
    response = client.get_indicators()
    pre_indicators = parse_response(response)
    indicators = create_indicators(client, pre_indicators)
    indicators = create_relationships(client, indicators)
    return indicators


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = 'https://lolbas-project.github.io/api'
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    create_relationships = argToBoolean(params.get('create_relationships', True))
    feed_tags = argToList(params.get('feedTags', []))
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

from CommonServerPython import *

import json

import FeedMISPThreatActors
from FeedMISPThreatActors import build_relationships, parse_refs, fetch_indicators_command, main, Client, get_indicators_command


CLIENT = Client(
    base_url='example.com',
    verify=False,
    proxy=False,
    reliability='B - Usually reliable')


def _open_json_file(path):
    with open(path) as f:
        return json.loads(f.read())


def test_parse_refs():
    """Tests the parse_refs function.

    Scenario: Parsing reference links for an IOC

    Given:
        A list of reference links.

    When:
        Calling the parse_refs function with an original IOC and the list of references.

    Then:
        Ensure the function returns a list of parsed references with the correct structure.
    """
    refs = ['link1', 'link2']
    parsed_refs = parse_refs('original_ioc', refs)

    assert len(parsed_refs) == 2
    assert parsed_refs[0]['link'] == 'link1'
    assert parsed_refs[1]['link'] == 'link2'


def test_build_relationship():
    """Tests the build_relationships function.

    Scenario: Building relationships between IOCs

    Given:
        An original IOC, a list of related IOCs, their type, and a relationship name.

    When:
        Calling the build_relationships function with these parameters.

    Then:
        Ensure the function returns a list of correctly structured relationships.
    """
    original_ioc = "original_ioc"
    related_iocs = ["related_ioc1", "related_ioc2"]
    related_iocs_type = "domain"
    relationship_name = "related-to"

    relationships = build_relationships(
        original_ioc=original_ioc,
        related_iocs=related_iocs,
        related_iocs_type=related_iocs_type,
        relationship_name=relationship_name
    )

    assert len(relationships) == 2

    for index, relationship in enumerate(relationships, start=0):
        assert relationship['entityA'] == original_ioc
        assert relationship['name'] == relationship_name
        assert relationship['entityB'] == related_iocs[index]


def test_fetch_indicators_command(mocker):
    """Tests the fetch_indicators_command function.

    Scenario: Fetching indicators from MISP Threat Actors feed

    Given:
        A mocked CLIENT object with a predefined response for get_threat_actors_galaxy_file.

    When:
        Calling the fetch_indicators_command function with the mocked CLIENT.

    Then:
        Ensure the function returns indicators matching the expected output in structure and content.
    """
    data = _open_json_file("test_data/misp_threat_actor_galaxy_example.json")
    expected = _open_json_file("test_data/fetch_indicator_results.json")

    mocker.patch.object(CLIENT, "get_threat_actors_galaxy_file", return_value=data)
    version, results = fetch_indicators_command(CLIENT, "", "WHITE")

    assert results[0]['value'] == expected[0]['value']
    assert results[0]['type'] == expected[0]['type']
    assert results[0]['fields']['description'] == expected[0]['fields']['description']


def test_get_indicators_command(mocker):
    """Tests the get_indicators_command function.

    Scenario: Retrieving indicators from MISP Threat Actors feed

    Given:
        A mocked CLIENT object with a predefined response for get_threat_actors_galaxy_file.

    When:
        Calling the get_indicators_command function with the mocked CLIENT and empty parameters.

    Then:
        Ensure the function returns a human-readable output matching the expected format and content.
    """
    expected = "### Threat Actors\n|Name|Aliases|Country|Description|\n|---|---|---|---|\n| TEST | AKA | country | test |\n"
    data = _open_json_file("test_data/misp_threat_actor_galaxy_example.json")
    mocker.patch.object(CLIENT, "get_threat_actors_galaxy_file", return_value=data)
    results = get_indicators_command(CLIENT, {})

    assert results.to_context()['HumanReadable'] == expected


def test_feedmispthreatactors_main_command_success(mocker):
    """Tests the main function of FeedMISPThreatActors for successful execution.

    Scenario: Running the main function of FeedMISPThreatActors

    Given:
        Mocked objects for demisto.params, CLIENT.get_threat_actors_galaxy_file,
        demisto.command, and FeedMISPThreatActors.fetch_indicators_command.

    When:
        Calling the main function.

    Then:
        Ensure that the createIndicators method is called, indicating successful
        processing and creation of indicators.
    """
    raw_response = _open_json_file("test_data/misp_threat_actor_galaxy_example.json")

    mocker.patch.object(demisto, "params", return_value={
        "url": "https://example.com",
        "proxy": False,
        "verify_certificate": False,
        "reliability": "B - Usually reliable"
    })
    mocker.patch.object(CLIENT, "get_threat_actors_galaxy_file", return_value=raw_response)
    mocker.patch.object(demisto, "command", return_value="fetch-indicators")
    mocker.patch.object(FeedMISPThreatActors,
                        "fetch_indicators_command",
                        return_value=(1, _open_json_file('test_data/fetch_indicator_results.json')))
    mock_createIndicators = mocker.patch.object(demisto, "createIndicators")

    main()

    assert mock_createIndicators.called

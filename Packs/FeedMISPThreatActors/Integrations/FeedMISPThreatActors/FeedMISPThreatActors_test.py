from CommonServerPython import *

import json

import FeedMISPThreatActors
from FeedMISPThreatActors import build_relationships, parse_refs, fetch_indicators_command, main, Client


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

    Checks the output of the parse_refs function with
    the expected output.
    """
    refs = ['link1', 'link2']
    parsed_refs = parse_refs('original_ioc', refs)

    assert len(parsed_refs) == 2
    assert parsed_refs[0]['link'] == 'link1'
    assert parsed_refs[1]['link'] == 'link2'


def test_build_relationship():
    """Tests the build_relationships function.

    Checks the output of the build_relationships function with
    the expected output.
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
    """
    Test the fetch_indicators_command function.

    This test mocks the get_threat_actors_galaxy_file method of the CLIENT object
    to return predefined test data. It then calls fetch_indicators_command and
    compares the results with expected output.

    Args:
        mocker: pytest mocker fixture for mocking objects

    The test checks if:
    1. The value of the first indicator matches the expected value
    2. The type of the first indicator matches the expected type
    3. The description field of the first indicator matches the expected description
    """

    data = _open_json_file("test_data/misp_threat_actor_galaxy_example.json")
    expected = _open_json_file("test_data/fetch_indicator_results.json")

    mocker.patch.object(CLIENT, "get_threat_actors_galaxy_file", return_value=data)
    version, results = fetch_indicators_command(CLIENT, "", "WHITE")

    assert results[0]['value'] == expected[0]['value']
    assert results[0]['type'] == expected[0]['type']
    assert results[0]['fields']['description'] == expected[0]['fields']['description']


def test_feedmispthreatactors_main_command_success(mocker):
    """
    Test the main function of FeedMISPThreatActors for successful execution.

    This test mocks various objects and methods to simulate a successful run of the main function.
    It checks if the createIndicators method is called, which indicates that the function
    has successfully processed and attempted to create indicators.

    Args:
        mocker: pytest mocker fixture for mocking objects

    The test performs the following steps:
    1. Mocks the demisto.params to return a dictionary with configuration parameters.
    2. Mocks the CLIENT.get_threat_actors_galaxy_file to return a predefined raw response.
    3. Mocks the demisto.command to return "fetch-indicators".
    4. Mocks the FeedMISPThreatActors.fetch_indicators_command to return a tuple of version and indicators.
    5. Mocks the demisto.createIndicators method.
    6. Calls the main function.
    7. Asserts that the createIndicators method was called.
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

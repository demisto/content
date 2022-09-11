import json


def test_poll_collection():
    """
    Given:
        - A collection of indicators in STIX format.

    When:
        - fetch_indicators_command is running.

    Then:
        - Validate the indicator extract as expected.
    """
    from StixParserV2 import parse_stix

    # with open('TestData/stix1_from_feed/collection_example.xml', 'r') as xml_f:
    #     stix_content = xml_f.read()

    res = parse_stix('TestData/stix1_from_feed/collection_example.xml')

    with open('TestData/stix1_from_feed/indicators_example.json') as json_f:
        expected_result = json.load(json_f)

    assert res == expected_result

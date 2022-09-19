import json

import pytest


def create_json_output_file(result, file_name):
    json_object = json.dumps(result, indent=4)
    # Writing to sample.json
    with open(f'test_data/stix1_dror/{file_name}', "w") as outfile:
        outfile.write(json_object)


@pytest.mark.parametrize('indicators_file, expected_result', [
    ('file-stix-ioc.xml', 'file-stix-ioc-results.json'),
    ('ip-stix-ioc.xml', 'ip-stix-ioc-results.json'),
    ('url-stix-ioc.xml', 'url-stix-ioc-results.json'),
    ('collection_example.xml', 'indicators_example.json'),
    ('STIX_Domain_Watchlist.xml', 'STIX_Domain_Watchlist_result.json'),
    ('STIX_FileHash_Watchlist.xml', 'STIX_FileHash_Watchlist_result.json'),
    ('STIX_URL_Watchlist.xml', 'STIX_URL_Watchlist_result.json'),
    ('STIX_Phishing_Indicator.xml', 'STIX_Phishing_Indicator_result.json'),
])
def test_parse_stix1(indicators_file, expected_result):
    """
    Given:
        - A collection of indicators in STIX format.

    When:
        - Parsing stix1 indicators.

    Then:
        - Validate the indicators extract as expected.
    """
    from StixParserV2 import parse_stix

    res = parse_stix(f'test_data/stix1_tests/{indicators_file}')

    with open(f'test_data/stix1_tests/{expected_result}') as json_f:
        expected_result = json.load(json_f)

    assert res == expected_result


@pytest.mark.parametrize('indicators_file, expected_result', [
    ('stix2_example1.json', 'expected_result_example1.json'),
    ('stix2_example2.json', 'expected_result_example2.json'),
    ('stix2_example3.json', 'expected_result_example3.json'),
    ('stix2_example4.json', 'expected_result_example4.json'),
    ('stix2_example5.json', 'expected_result_example5.json'),
    ('stix2_example6.json', 'expected_result_example6.json'),
    ('stix2.json', 'stix2_results.json'),
])
def test_parse_stix2(indicators_file, expected_result):
    """
    Given:
        - A collection of indicators in STIX2 format.

    When:
        - Parsing stix2 indicators.

    Then:
        - Validate the indicators extract as expected.
    """
    from StixParserV2 import STIX2Parser

    with open(f'test_data/stix2_tests/{indicators_file}') as json_f:
        stix2 = json.load(json_f)
    with open(f'test_data/stix2_tests/{expected_result}') as json_f:
        expected_result = json.load(json_f)

    taxii2_parser = STIX2Parser()
    observables = taxii2_parser.parse_stix2(stix2)

    assert observables == expected_result


# @pytest.mark.parametrize('indicators_file, expected_result', [
#     ('STIX_Domain_Watchlist.xml', 'STIX_Domain_Watchlist_result.json'),
# ])
# def test_parse_stix1(indicators_file, expected_result):
#     """
#     Given:
#         - A collection of indicators in STIX format.
#
#     When:
#         - Parsing stix1 indicators.
#
#     Then:
#         - Validate the indicators extract as expected.
#     """
#     from StixParserV2 import parse_stix
#
#     res = parse_stix(f'test_data/stix1_dror/{indicators_file}')
#
#     # create_json_output_file(res, expected_result)
#     with open(f'test_data/stix1_dror/{expected_result}') as json_f:
#         expected_result = json.load(json_f)
#
#     assert res == expected_result


# def test_parse_stix2_not_parsed():
#     """
#     Given:
#         - A collection of indicators in STIX2 format.
#
#     When:
#         - fetch_indicators_command is running.
#
#     Then:
#         - Validate the indicator extract as expected.
#     """
#     from StixParserV2 import STIX2Parser
#
#     with open('test_data/stix2_tests/stix2.json') as json_f:
#         stix2 = json.load(json_f)
#
#     taxii2_parser = STIX2Parser()
#     observables = taxii2_parser.parse_stix2(stix2)
#
#     with open('test_data/stix2_tests/stix2_results.json') as json_f:
#         expected_result = json.load(json_f)
#
#     assert observables == expected_result

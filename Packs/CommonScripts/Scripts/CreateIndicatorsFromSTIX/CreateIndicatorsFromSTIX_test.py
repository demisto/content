from CreateIndicatorsFromSTIX import *


def test_create_indicators_loop_wo_args(mocker):
    """
    Given:
        - A collection of indicators in XSOAR Format

    When:
        - Parsing stix indicators.

    Then:
        - Validate the indicators extract without errors.
    """
    args = {}
    with open('test_data/expected_result_example3.json') as json_f:
        indicators = json.load(json_f)
    mocker.patch.object(demisto, 'executeCommand', return_value=[None])
    results, errors = create_indicators_loop(args, indicators)

    assert errors == []
    assert results.readable_output == 'Create Indicators From STIX: 2 indicators were created.'


def test_create_indicators_loop_w_args(mocker):
    """
    Given:
        - A collection of indicators in XSOAR Format

    When:
        - Parsing stix indicators.

    Then:
        - Validate the indicators extract without errors.
    """
    args = {
        'add_context': 'true',
        'tags': 'tag1,tag2'
    }

    with open('test_data/expected_result_example3.json') as json_f:
        indicators = json.load(json_f)
    mocker.patch.object(demisto, 'executeCommand', return_value=[None])
    results, errors = create_indicators_loop(args, indicators)

    assert errors == []
    assert results.readable_output == 'Create Indicators From STIX: 2 indicators were created.'
    assert results.outputs[0]['tags'] == ['tag1', 'tag2']


def test_parse_indicators_using_stix_parser(mocker):
    """
    Given:
        - A collection of indicators in STIX Format

    When:
        - Parsing stix indicators using STIXParserV2.

    Then:
        - Validate the indicators extract without errors.
    """
    with open('test_data/expected_result_example3.json') as json_f:
        expected_res = json_f.read()
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': expected_res, 'Type': 1}])
    mocker.patch('CommonServerPython.is_error', False)
    indicators = parse_indicators_using_stix_parser('entry_id')
    assert json.loads(expected_res) == indicators

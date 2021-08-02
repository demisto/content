import pytest
import demistomock as demisto  # noqa: F401

CASE_ANCHOR_EMPTY = {'ssdeep_hash': '',
                     'ssdeep_hashes_to_compare': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C'}
CASE_HASH_LIST_EMPTY = {'ssdeep_hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                        'ssdeep_hashes_to_compare': ''}
CASE_VALID_INPUT = {'ssdeep_hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                    'ssdeep_hashes_to_compare':
                        '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C, 3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                    'output_key': 'test'}

INPUT_INVALID_CASES = [
    (CASE_ANCHOR_EMPTY, 'Please provide an hash to compare to.'),
    (CASE_HASH_LIST_EMPTY, 'Please provide at least one hash to compare with.'),

]


@pytest.mark.parametrize('case_inputs, expected_error_msg', INPUT_INVALID_CASES)
def test_handle_inputs_fails_on_invalid_input(case_inputs, expected_error_msg):
    """
    Given:
        invalid input
    When:
        running handle_inputs
    Then:
        validates the relevant error is shown.
    """

    from SSDeepSimilarity import _handle_inputs
    try:
        _handle_inputs(case_inputs)
        raise Exception("Inputs are valid")
    except ValueError as e:
        assert expected_error_msg == str(e)


VALID_INPUT_CASES = [
    (CASE_VALID_INPUT, '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
     ['3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C'], 'test')
]


@pytest.mark.parametrize('case_inputs, expected_hash, expected_list, expected_output', VALID_INPUT_CASES)
def test_handle_inputs(case_inputs, expected_hash, expected_list, expected_output):
    """
    Given:
        valid input
    When:
        running handle_inputs
    Then:
        validates the inputs are handled correctly.
    """

    from SSDeepSimilarity import _handle_inputs
    anchor_hash, hashes_to_compare, output_key = _handle_inputs(case_inputs)
    assert anchor_hash == expected_hash
    assert hashes_to_compare == expected_list
    assert output_key == expected_output


ONE_HASH_TO_COMPARE = {'anchor_hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                       'hashes_to_compare': ['3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C'], 'output_key': 'test'}
TWO_TO_COMPARE_INCLUDE_ITSELF = {'anchor_hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                                 'hashes_to_compare': ['3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                                                       '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C'], 'output_key': 'test'}
INPUT_CASES = [
    (TWO_TO_COMPARE_INCLUDE_ITSELF, (
        'ssdeep,1.1--blocksize:hash:hash,filename\n'
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n',
        'ssdeep,1.1--blocksize:hash:hash,filename\n'
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n'
        '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C,"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C"\n'),
     {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
         {'hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'similarityValue': 100},
         {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22}]}
     ),
]
SSDEEP_RESULT_EXAMPLE = ['"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",100',
                         '"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",22']


@pytest.mark.parametrize('case_inputs, called_with, expected_output', INPUT_CASES)
def test_compare_ssdeep(mocker, case_inputs, called_with, expected_output):
    """
    Given:
        valid hash, hash list and output key
    When:
        running compare_ssdeep
    Then:
        validates the outputs are as expected.
    """
    import SSDeepSimilarity
    command_mock = mocker.patch.object(SSDeepSimilarity, 'run_ssdeep_command', return_value=SSDEEP_RESULT_EXAMPLE)
    res = SSDeepSimilarity.compare_ssdeep(**case_inputs)
    assert command_mock.call_args[0] == called_with
    assert res.outputs == expected_output


def test_format_results():
    """
    Given:
        A result list from the ssdeep command
    When:
        Converting results to outputs format
    Then:
        Validating the outputs created matches expected.
    """

    from SSDeepSimilarity import _format_results
    res = _format_results(SSDEEP_RESULT_EXAMPLE)
    assert res == [{'hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                    'similarityValue': 100},
                   {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C',
                    'similarityValue': 22}]


FILE1 = 'ssdeep,1.1--blocksize:hash:hash,filename\n' \
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n'
FILE2 = 'ssdeep,1.1--blocksize:hash:hash,filename\n' \
        '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C,"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C"\n'


def test_linux_command():
    """
    NOTE: CANNOT RUN LOCALLY WHEN NOT LINUX!
    Given:
        2 file's content containing ssdeep hashes
    When:
        Running ssdeep linux's command
    Then:
        Validating the command returns the expected result
    """

    from SSDeepSimilarity import run_ssdeep_command
    res = run_ssdeep_command(FILE1, FILE2)
    assert res == ['"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",22', '']

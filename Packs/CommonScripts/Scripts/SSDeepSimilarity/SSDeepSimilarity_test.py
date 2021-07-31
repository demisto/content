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
    (ONE_HASH_TO_COMPARE, {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
        {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22}]}),
    (TWO_TO_COMPARE_INCLUDE_ITSELF, {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
        {'hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'similarityValue': 100},
        {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22}]}
     ),
]


@pytest.mark.parametrize('case_inputs, expected_output', INPUT_CASES)
def test_compare_ssdeep(case_inputs, expected_output):
    """
    Given:
        valid hash, hash list and output key
    When:
        running compare_ssdeep
    Then:
        validates the outputs are as expected.
    """
    from SSDeepSimilarity import compare_ssdeep
    res = compare_ssdeep(**case_inputs)
    assert res.outputs == expected_output


INPUT_CASES = [
    (TWO_TO_COMPARE_INCLUDE_ITSELF,
     {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
         {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22}]}, 'internal_error',
     'Could not compare hashes due to internal error:'
     ),
    (TWO_TO_COMPARE_INCLUDE_ITSELF,
     {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
         {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22}]}, 'type_error',
     'Hashes must be of type String, Unicode or Bytes:'
     ),
]


@pytest.mark.parametrize('case_inputs, expected_output, error, error_msg', INPUT_CASES)
def test_compare_ssdeep_fails(mocker, case_inputs, expected_output, error, error_msg):
    """
    Given:
        either valid or invalid hash, hash list and output key
    When:
        running compare_ssdeep with error from ssdeep module
    Then:
        validates the relevant error is shown correctly.
    """
    from SSDeepSimilarity import compare_ssdeep, ssdeep
    error = ssdeep.InternalError() if error == 'internal_error' else TypeError()
    mocker.patch.object(ssdeep, 'compare', side_effect=[error, 22])
    demisto_mock = mocker.patch.object(demisto, 'error')
    res = compare_ssdeep(**case_inputs)
    assert res.outputs == expected_output
    assert demisto_mock.call_count == 1
    assert demisto_mock.call_args[0][0].args[0].startswith(error_msg)

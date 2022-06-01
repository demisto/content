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


HASHES_TO_COMPARE_INCLUDE_ITSELF = {'anchor_hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',
                                    'hashes_to_compare': ['3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C',  # same as anchor
                                                          '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C',  # changed hash
                                                          '12#$4!2',  # invalid char in hash with valid format
                                                          'A12#$4!2'],  # invalid hash, will be ignored.
                                    'output_key': 'test'}
INPUT_CASES = [
    (HASHES_TO_COMPARE_INCLUDE_ITSELF, (
        'ssdeep,1.1--blocksize:hash:hash,filename\n'
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n',
        'ssdeep,1.1--blocksize:hash:hash,filename\n'
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n'
        '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C,"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C"\n'
        '12#$4!2,"12#$4!2"\nA12#$4!2,"A12#$4!2"\n'),
     {'SourceHash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'compared_hashes': [
         {'hash': '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C', 'similarityValue': 100},
         {'hash': '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C', 'similarityValue': 22},
         {'hash': '12#$4!2', 'similarityValue': 0}]}
     ),
]
SSDEEP_RESULT_EXAMPLE = ['"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",100',
                         '"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",22',
                         '"12#$4!2","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",0']


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
                    'similarityValue': 22},
                   {'hash': '12#$4!2',
                    'similarityValue': 0}]


FILE1 = 'ssdeep,1.1--blocksize:hash:hash,filename\n' \
        '3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C,"3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"\n'
FILE2 = 'ssdeep,1.1--blocksize:hash:hash,filename\n' \
        '3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C,"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C"\n' \
        '12#$4!2,"12#$4!2"\nA12#$4!2,"A12#$4!2"\n'


def test_linux_command(capfd):
    """
    NOTE: CANNOT RUN LOCALLY WHEN NOT LINUX!
    Given:
        2 file's content containing ssdeep hashes, the second one have valid hash,
        invalid hash with valid format and invalid hash with invalid format.
    When:
        Running ssdeep linux's command
    Then:
        Validating the command returns the expected result-
        the first hash with relevant score and the second hash with 0 score (ignoring the third hash)
    """

    from SSDeepSimilarity import run_ssdeep_command
    with capfd.disabled():
        res = run_ssdeep_command(FILE1, FILE2)
        assert res == ['"3:AXGBicFlIHBGcL6wCrFQEv:AXGH6xLsr2C","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",22',
                       '"12#$4!2","3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",0',
                       '']


CASE_FIRST_RUN = ('1test',
                  'output',
                  [{'hash': '2test', 'similarityValue': 2}],
                  {},
                  [{'hash': '2test', 'similarityValue': 2}])
CASE_ONE_EXIST = ('1test', 'output',
                  [{'hash': '2test', 'similarityValue': 2}],
                  {'SourceHash': '1test', 'compared_hashes':
                      [{'hash': '3test', 'similarityValue': 2}]},
                  [{'hash': '3test', 'similarityValue': 2}, {'hash': '2test', 'similarityValue': 2}])

CASE_ONE_RELEVANT_AND_ONE_NOT = ('1test', 'output', [{'hash': '2test', 'similarityValue': 2}],
                                 [{'SourceHash': '1test', 'compared_hashes': [{'hash': '3test', 'similarityValue': 2}]},
                                  {'SourceHash': '4test',
                                   'compared_hashes': [{'hash': '6test', 'similarityValue': 2}]}],
                                 [{'hash': '3test', 'similarityValue': 2}, {'hash': '2test', 'similarityValue': 2}]
                                 )

CASE_NO_NEW_ITEMS = ('1test', 'output', [{'hash': '3test', 'similarityValue': 2}],
                     [{'SourceHash': '1test', 'compared_hashes': [{'hash': '3test', 'similarityValue': 2}]},
                      {'SourceHash': '4test', 'compared_hashes': [{'hash': '6test', 'similarityValue': 2}]}],
                     [{'hash': '3test', 'similarityValue': 2}]
                     )

OUTPUTS_CASES = [
    CASE_FIRST_RUN,
    CASE_ONE_EXIST,
    CASE_ONE_RELEVANT_AND_ONE_NOT,
    CASE_NO_NEW_ITEMS
]


@pytest.mark.parametrize('anchor, output_key, new_compared_hash, existing_context, expected_new_outputs', OUTPUTS_CASES)
def test_handle_existing_outputs(mocker, anchor, output_key, new_compared_hash, existing_context, expected_new_outputs):
    """
    Given:
        anchor, output_key, new_compared_hash and existing_context
    When:
        Running the script more then once
    Then:
        Validating the context gets the updated data without deleting the previous one or creating duplicates

    """
    from SSDeepSimilarity import _handle_existing_outputs
    mocker.patch.object(demisto, 'get', return_value=existing_context)
    res = _handle_existing_outputs(anchor, output_key, new_compared_hash)
    assert res == expected_new_outputs

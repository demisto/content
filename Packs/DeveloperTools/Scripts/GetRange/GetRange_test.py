import pytest


get_range_command_by_index_list = [
    ('0', [0]),
    ('0,1,2', [0, 1, 2]),
    ('0,2', [0, 2]),
    ('0,2-3', [0, 2, 3]),
    ('0,2-2', [0, 2]),
    ('2-3', [2, 3]),
]


@pytest.mark.parametrize('indexes,expected_results', get_range_command_by_index_list)
def test_get_range_command_by_index_list(mocker, indexes, expected_results):
    """
        Given
        - List of indexes.
        When
        - Calling main method.
        Then
        - Return filtered list.
    """
    from GetRange import main
    import demistomock as demisto

    mocker.patch.object(demisto, 'args', return_value={'range': indexes, 'value': [i for i in range(10)]})
    m = mocker.patch.object(demisto, 'results')
    main()
    assert m.call_args.args[0].get('Contents').get('Value') == expected_results

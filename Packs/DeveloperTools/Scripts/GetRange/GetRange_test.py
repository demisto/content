import pytest

get_range_command_by_index_list = [
    ([], []),
    ([0, 1, 2], [0, 1, 2]),
    ([3], [3]),
    ([3, 5], [3, 5]),
    ((3, 5), [3, 5]),
    ((), [])
]


@pytest.mark.parametrize('indexes,expected_results', get_range_command_by_index_list)
def test_get_range_command_by_index_list(indexes, expected_results):
    """
        Given
        - Index list or tuple.
        When
        - Filtering value using index list.
        Then
        - Return filtered list.
    """
    from GetRange import get_range_command

    results = get_range_command({'value': [i for i in range(0, 10)], 'range': indexes})
    assert results.outputs['value'] == expected_results


get_range_command_by_range_str = [
    ('', []),
    ('0-3', [0, 1, 2, 3]),
    ('9-', [9]),
    ('-1', [0, 1]),
    ('0-9', [i for i in range(10)]),
    ('4-5', [4, 5]),
]


@pytest.mark.parametrize('indexes,expected_results', get_range_command_by_range_str)
def test_get_range_command_by_range_str(indexes, expected_results):
    """
        Given
        - Index range str.
        When
        - Filtering value using index list.
        Then
        - Return filtered list.
    """
    from GetRange import get_range_command

    results = get_range_command({'value': [i for i in range(10)], 'range': indexes})
    assert results.outputs['value'] == expected_results

from unittest.mock import patch

import pytest


@pytest.mark.parametrize('indexes, expected_results', [
    ('0', [0]),
    ('0,1,2', [0, 1, 2]),
    ('0,2', [0, 2]),
    ('0,2-3', [0, 2, 3]),
    ('0,2-2', [0, 2]),
    ('2-3', [2, 3]),
])
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
    with patch('GetRange.return_results') as return_results:
        mocker.patch.object(demisto, 'args', return_value={'range': indexes, 'value': [i for i in range(10)]})
        main()
        assert return_results.call_args.kwargs.get('results') == expected_results

import pytest

import demistomock as demisto
from InRange import main


@pytest.mark.parametrize('left,right,expected', [
    ('4', '1,8', True),
    ('7', '-1,3', False),
])
def test_in_range(mocker, left, right, expected):
    """
    Given:
        - Case A: Range of 1-8 and value 4
        - Case A: Range of -1-3 and value 7

    When:
        - Running InRange

    Then:
        - Case A: True is returned
        - Case B: False is returned
    """
    mocker.patch.object(demisto, 'args', return_value={
        'left': left,
        'right': right,
    })
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with(expected)

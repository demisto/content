import pytest
import demistomock as demisto
from Any import main



@pytest.mark.parametrize('left,right,result', [(1, 2, False), (1, "1,2,3", True),
                                               (1, 2, False), (1, 1, True),
                                               (1, 2, False), (1, 1, True)])
def test_main(mocker, left, right, result):
    mocker.patch.object(demisto, 'args', return_value={'left': left, 'right': right})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_args_list[0][0][0] == result

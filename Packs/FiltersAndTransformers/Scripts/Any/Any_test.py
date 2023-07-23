import pytest
import demistomock as demisto


@pytest.mark.parametrize('left,right,result', [(1, 2, 1, False), (1, 1, 1, True),
                                                (1, 2, 2, False), (1, 1, 2, True),
                                                (1, 2, 3, False), (1, 1, 3, True)])
test_main(mocker, left, right, result):
    from Any import main

    mocker.patch.object(demisto, 'args', return_value={
        'left': left,
        'right': right
    })
    main()
    assert demisto.results == result

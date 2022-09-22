import pytest

import demistomock as demisto

CIDR_RANGES = [
    ('192.168.0.0/24', '18', 1, [False]),
    ('192.168.0.0/24', '32', 1, [True]),
    ('2002::1234:abcd:ffff:c0a8:101/127', '64', 1, [False]),
    ('2002::1234:abcd:ffff:c0a8:101/127', '168', 1, [True]),
    ('192.168.0.0/24,2002::1234:abcd:ffff:c0a8:101/127', '64', 2, [True, False]),
    ('300.168.0.0/24', '64', 1, [False]),  # invalid CIDR range
]


@pytest.mark.parametrize('left,right,call_count,result', CIDR_RANGES)
def test_main(mocker, left, right, call_count, result):
    from CIDRBiggerThanPrefix import main

    mocker.patch.object(demisto, 'args', return_value={
        'left': left,
        'right': right
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == call_count
    for i in range(len(result)):
        results = demisto.results.call_args_list[i][0][0]
        assert results == result[i]

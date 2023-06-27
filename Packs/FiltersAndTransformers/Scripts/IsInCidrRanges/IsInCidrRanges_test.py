import pytest

import demistomock as demisto

CIDR_RANGES = [
    ('172.16.0.1', '10.0.0.0/8,192.168.0.0/16', 1, [False]),
    ('172.40.5.10', '172.16.0.0/12', 1, [False]),
    ('10.5.5.5', '10.0.0.0/8,192.168.0.0/16', 1, [True]),
    ('172.16.0.1,10.5.5.5', '10.0.0.0/8,192.168.0.0/16', 2, [False, True]),
    ('172.16.0.1,10.5.5.5', '10.0.0.0/8', 2, [False, True]),
    ('192.168.1.1,192.168.1.2,10.10.1.1', '192.168.0.0/16,192.168.1.3/32', 3, [True, True, False]),
    ('172.16.0', '10.0.0.0/8', 1, [False]),  # invalid IP address
    ('172.16.0.1', '300.0.0.0/8', 1, [False]),  # invalid CIDR range
]


@pytest.mark.parametrize('left,right,call_count,result', CIDR_RANGES)
def test_main(mocker, left, right, call_count, result):
    from IsInCidrRanges import main

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

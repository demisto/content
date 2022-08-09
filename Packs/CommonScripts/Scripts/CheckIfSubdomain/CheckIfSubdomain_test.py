import pytest

import demistomock as demisto

CIDR_RANGES = [
    ('issubdomain.good.com,anothersubdomain.good.com,notasubdomain.bad.com', 'good.com', 3, [True, True, False]),
    ('"issubdomain.good.com, anothersubdomain.good.com, notasubdomain.bad.com"', 'good.com', 3, [True, True, False]),
    ('subdomain.good.com,notsubdomain.bad.com', '*.good.com', 2, [True, False]),
    ('subdomain.good.com,notsubdomain.bad.com,subdomain.stillgood.com', '*.good.com,stillgood.com', 3, [True, False, True]),
    ('subdomain', 'good.com', 1, [False]),  # invalid internal domain
    ('subdomain.good.com', 'com', 1, [False]),  # invalid domain
]


@pytest.mark.parametrize('left,right,call_count,result', CIDR_RANGES)
def test_main(mocker, left, right, call_count, result):
    from CheckIfSubdomain import main

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

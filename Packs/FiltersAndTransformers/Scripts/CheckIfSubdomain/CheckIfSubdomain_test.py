import os

import pytest

import demistomock as demisto

CIDR_RANGES = [
    (['issubdomain.good.com', 'anothersubdomain.good.com', 'notasubdomain.bad.com'], ['good.com'], 3, [True, True, False]),
    (['issubdomain.good.com', 'anothersubdomain.good.com', 'notasubdomain.bad.com'], ['good.com'], 3, [True, True, False]),
    (['subdomain.good.com', 'notsubdomain.bad.com'], ['*.good.com'], 2, [True, False]),
    (['subdomain.good.com', 'notsubdomain.bad.com', 'subdomain.stillgood.com'],
     ['*.good.com', 'stillgood.com'], 3, [True, False, True]),
    (['subdomain'], ['good.com'], 1, [False]),  # invalid internal domain
    (['subdomain.good.com'], ['com'], 1, [False]),  # invalid domain
]


@pytest.mark.parametrize('left,right,call_count,result', CIDR_RANGES)
def test_main(mocker, left, right, call_count, result):
    import CheckIfSubdomain
    current_dir = os.getcwd()
    CheckIfSubdomain.SUFFIX_LIST_URLS = [f"file://{current_dir}/test_data/public_list.dat"]  # disable-secrets-detection
    mocker.patch.object(demisto, 'results')
    CheckIfSubdomain.check_if_subdomain(internal_domains=right, domains=left, use_tldextract_default_list=False)
    assert demisto.results.call_count == call_count
    for i in range(len(result)):
        results = demisto.results.call_args_list[i][0][0]
        assert results == result[i]

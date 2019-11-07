import pytest

bad_response = {
    'base': {
        'ref': 'master'
    }
}

good_response = {
    'base': {
        'ref': 'not_master'
    }
}


def test_check_base_branch(requests_mock, mocker):
    url = 'https://api.github.com/repos/demisto/content/pulls/528'
    from Tests.scripts.verify_base_branch_for_contribution import check_base_branch
    requests_mock.get(url, json=bad_response)
    with pytest.raises(SystemExit) as se:
        check_base_branch(528)
        assert se.value.code == 1
    requests_mock.get(url, json=good_response)
    with pytest.raises(SystemExit) as se:
        check_base_branch(528)
        assert se.value.code == 0

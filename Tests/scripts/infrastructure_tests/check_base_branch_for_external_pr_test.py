from pytest import raises

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


def check_base_branch_test(requests_mock):
    from Tests.scripts.check_base_branch_for_external_pr import check_base_branch
    url = 'https://api.github.com/repos/demisto/content/pulls/528'
    requests_mock.get(url, json=bad_response)
    with raises(SystemExit) as se:
        check_base_branch(528)
        assert se.value.code == 1
    requests_mock.get(url, json=good_response)
    with raises(SystemExit) as se:
        check_base_branch(528)
        assert se.value.code == 0
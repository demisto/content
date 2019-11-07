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


def test_check_base_branch(requests_mock):
    url = 'https://api.github.com/repos/demisto/content/pulls/528'
    from Tests.scripts.check_base_branch_for_external_pr import check_base_branch
    requests_mock.get(url, json=bad_response)
    with pytest.raises(SystemExit) as se:
        check_base_branch(528)
        assert 'p' == 'k'
        assert se.value.code == 1
        # m.get(url, json=good_response)
        # with pytest.raises(SystemExit) as se:
        #     out, _ = capsys.readouterr()
        #     assert 'Verified pull request #528 base branch successfully.' in out
        #     check_base_branch(528)
        #     assert se.value.code == 0

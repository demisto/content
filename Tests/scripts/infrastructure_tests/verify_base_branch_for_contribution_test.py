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


def test_check_base_branch(requests_mock, capsys):
    url = 'https://api.github.com/repos/demisto/content/pulls/528'
    from Tests.scripts.verify_base_branch_for_contribution import check_base_branch
    requests_mock.get(url, json=bad_response)
    with pytest.raises(SystemExit) as se:
        check_base_branch('528')
        out, _ = capsys.readouterror()
        assert 'Cannot merge a contribution directly to master, the pull request reviewer will handle that soon.' in out
        assert se.value.code == 1
    requests_mock.get(url, json=good_response)
    with pytest.raises(SystemExit) as se:
        check_base_branch('528')
        out, _ = capsys.readouterror()
        assert 'Verified pull request #528 base branch successfully.' in out
        assert se.value.code == 0

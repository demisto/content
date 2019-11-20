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


def test_verify_base_branch(requests_mock):
    url = 'https://api.github.com/repos/demisto/content/pulls/528'
    from Tests.scripts.verify_base_branch_for_contribution import verify_base_branch
    requests_mock.get(url, json=bad_response)
    msg, is_valid = verify_base_branch('528')
    assert is_valid is False
    assert 'Cannot merge a contribution directly to master, the pull request reviewer will handle that soon.' == msg
    requests_mock.get(url, json=good_response)
    msg, is_valid = verify_base_branch('528')
    assert is_valid is True
    assert 'Verified pull request #528 base branch successfully.' == msg

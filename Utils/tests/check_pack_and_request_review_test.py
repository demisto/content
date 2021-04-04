import pytest

from Utils.request_contributor_review import check_reviewers


@pytest.mark.parametrize('pr_author,version,reviewers,call_count', [('xsoar-bot', '1.0.0', ['reviewer'], 0),
                                                                    ('xsoar-bot', '1.0.2', ['reviewer'], 1),
                                                                    ('xsoar-bot', '1.0.0', [], 0)])
def test_check_reviewers(mocker, pr_author, version, reviewers, call_count):
    """
       Given
        - pr_author - author of thr pr
        - version - pack version taken from pack_metadata
        - reviewers - pack reviewers

       When
       - calling check_pack_and_request_review function at the request_contributor_review

       Then
       - validating that tag_user_on_pr function called only when the pack is not new,
       or it is was not opened by 'xsoar-bot'
    """
    check_reviewers_mock = mocker.patch('Utils.request_contributor_review.tag_user_on_pr')

    check_reviewers(reviewers=reviewers, pr_author=pr_author, version=version,
                    modified_files=['Pack/TestPack/file1'], pack='TestPack', pr_number='1', github_token='github_token',
                    verify_ssl=True)
    assert check_reviewers_mock.call_count == call_count

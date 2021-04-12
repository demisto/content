import pytest
import os
from oauth2client.client import AccessTokenCredentials

from Utils.request_contributor_review import check_reviewers, get_access_token, send_email_to_reviewers


@pytest.mark.parametrize('pr_author,version,reviewers,call_count,expected',
                         [('xsoar-bot', '1.0.0', {'reviewer'}, 0, False),
                          ('xsoar-bot', '1.0.2', {'reviewer'}, 1, True),
                          ('xsoar-bot', '1.0.0', {}, 0, False)])
def test_check_reviewers(mocker, pr_author, version, reviewers, call_count, expected):
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

    notified = check_reviewers(reviewers=reviewers, pr_author=pr_author, version=version,
                               modified_files=['Pack/TestPack/file1'], pack='TestPack', pr_number='1',
                               github_token='github_token',
                               verify_ssl=True)
    assert check_reviewers_mock.call_count == call_count
    assert notified == expected


def test_get_access_token_with_refresh_token(requests_mock):
    """
       Given
        - refresh_token - in order to obtain access token, to send mails

       When
       - calling get_access_token function at the send_email_to_reviewers function

       Then
       - validating that access_token was returned as expected
        """
    requests_mock.post("https://www.googleapis.com/oauth2/v4/token",
                       json={"access_token": "access_token_test",
                             "expires_in": 3599,
                             "token_type": "Bearer"})

    access_token = get_access_token('refresh_token')
    assert access_token == 'access_token_test'


def test_get_access_token_with_saved_access_token_in_environ():
    """
       Given
        - access_token and valid until saved in the os environment

       When
       - calling get_access_token function at the send_email_to_reviewers function

       Then
       - validating that access_token was returned as expected, same as was saved in the environ
        """
    os.environ['ACCESS_TOKEN'] = 'access_token_test'
    os.environ['VALID_UNTIL'] = str(2532944120)
    access_token = get_access_token('refresh_token')
    assert access_token == 'access_token_test'


def test_send_email_to_reviewers(mocker, capsys):
    """
       Given
        - reviewers_emails - developer mails to review the changes on the pack
        - refresh_token - gmail refresh token in order to obtain access key
        - pack_name - pack that was modified
        - pr_number - github pr number

       When
       - calling send_email_to_reviewers function

       Then
       - validating that message was sent sucessfully, and information printed out
    """
    class ServiceMock:
        def users(self):
            return self

        def messages(self):
            return self

        def send(self, userId, body):
            return self

        def execute(self):
            return

    service_mock = ServiceMock()
    mocker.patch('Utils.request_contributor_review.get_access_token', return_value='access_token')
    mocker.patch.object(AccessTokenCredentials, '__init__', return_value=None)
    mocker.patch('Utils.request_contributor_review.build', return_value=service_mock)

    send_email_to_reviewers(
        reviewers_emails='reviewer1@mail.com, reviewer2@mail.com',  # disable-secrets-detection
        refresh_token='email_refresh_token',
        pack_name='TestPack',
        pr_number='1'
    )
    captured = capsys.readouterr()
    assert 'Email sent to' in captured.out
    assert 'contributors of pack TestPack' in captured.out

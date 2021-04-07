import pytest
from httplib2 import Response
import httplib2
import os
from oauth2client.client import AccessTokenCredentials

from Utils.request_contributor_review import check_reviewers, get_access_token, send_email_to_reviewers, \
    notify_contributors_by_email


@pytest.mark.parametrize('pr_author,version,reviewers,call_count', [('xsoar-bot', '1.0.0', {'reviewer'}, 0),
                                                                    ('xsoar-bot', '1.0.2', {'reviewer'}, 1),
                                                                    ('xsoar-bot', '1.0.0', {}, 0)])
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


def test_get_access_token_with_refresh_token(mocker):
    """
       Given
        - refresh_token - in order to obtain access token, to send mails

       When
       - calling get_access_token function at the send_email_to_reviewers function

       Then
       - validating that access_token was returned as expected
        """
    mock_response = (
        Response(dict(status=200)),
        b'{\n  "access_token": "access_token_test",\n  "expires_in": 3599,\n  "scope": "https://www.googleapis.com/auth/gmail.compose https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly",\n  "token_type": "Bearer"\n}'
    )
    mocker.patch.object(httplib2.Http, 'request', return_value=mock_response)

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


@pytest.mark.parametrize('dev_emails,support_emails,expected_result', [(['reviewer1@mail.com', 'reviewer2@mail.com'],
                                                                        'support@mail.com',
                                                                        'reviewer1@mail.com,reviewer2@mail.com'),
                                                                       ('',
                                                                        'support@mail.com',
                                                                        'support@mail.com'),
                                                                       ('',
                                                                        ['support1@mail.com', 'support2@mail.com'],
                                                                        'support1@mail.com,support2@mail.com')
                                                                       ])
def test_notify_contributors_by_email(mocker, dev_emails, support_emails, expected_result):
    """
       Given
        - dev_emails - mails of the pack developers
        - support_emails - mails of pack support

       When
       - calling notify_contributors_by_email function, when there are some mails at pack metadata
        and this is not new pack

       Then
       - validating that if there dev mails, mail sent only to developers,
        and if there no developer mails, send mail to the support.
    """
    send_email_mock = mocker.patch('Utils.request_contributor_review.send_email_to_reviewers',
                                   return_value='access_token')

    notify_contributors_by_email(
        dev_reviewers_emails=['reviewer1@mail.com', 'reviewer2@mail.com'],
        support_reviewers_emails='support@mail.com',
        email_refresh_token='email_refresh_token',
        pack='TestPack',
        pr_number='1',
    )
    assert send_email_mock.call_args[1]['reviewers_emails'] == 'reviewer1@mail.com,reviewer2@mail.com'


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
        reviewers_emails='reviewer1@mail.com, reviewer2@mail.com',
        refresh_token='email_refresh_token',
        pack_name='TestPack',
        pr_number='1'
    )
    captured = capsys.readouterr()
    assert 'Email sent to' in captured.out
    assert 'reviewers of pack TestPack' in captured.out

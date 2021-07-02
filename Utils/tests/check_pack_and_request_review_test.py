import pytest
from Utils.request_contributor_review import check_reviewers, send_email_to_reviewers


@pytest.mark.parametrize('pr_author,version,reviewers,call_count,tagged_packs_reviewers,expected',
                         [('xsoar-bot', '1.0.0', {'reviewer'}, 0, set(), False),
                          ('xsoar-bot', '1.0.2', {'reviewer'}, 1, set(), True),
                          ('xsoar-bot', '1.0.0', set(), 0, set(), False),
                          ('xsoar-bot', '1.0.0', {'reviewA'}, 0, {'reviewA'}, True),
                          ('xsoar-bot', '1.0.2', {'reviewA', 'reviewB'}, 1, {'reviewA'}, True)])
def test_check_reviewers(mocker, pr_author, version, reviewers, call_count, tagged_packs_reviewers, expected):
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
                               verify_ssl=True,
                               tagged_packs_reviewers=tagged_packs_reviewers)
    assert check_reviewers_mock.call_count == call_count
    assert notified == expected


def test_send_email_to_reviewers(mocker, capsys):
    """
       Given
        - reviewers_emails - developer mails to review the changes on the pack
        - api_token - sendgrid api token in order to obtain access key
        - pack_name - pack that was modified
        - pr_number - github pr number

       When
       - calling send_email_to_reviewers function

       Then
       - validating that message was sent sucessfully, and information printed out
    """

    class SgMock:
        def __init__(self):
            self.client = self.Client()

        class Client:
            def __init__(self):
                self.mail = self.Mail()

            class Mail:
                def __init__(self):
                    self.send = self.Send()

                class Send:
                    def post(self, request_body):
                        return self.Res(request_body)

                    class Res:
                        def __init__(self, _):
                            self.status_code = 202

    sg_mock = SgMock()

    mocker.patch('Utils.request_contributor_review.sendgrid.SendGridAPIClient', return_value=sg_mock)

    mail_sent = send_email_to_reviewers(
        reviewers_emails=['reviewer1@mail.com', 'reviewer2@mail.com'],  # disable-secrets-detection
        api_token='email_api_token',
        pack_name='TestPack',
        pr_number='1',
        modified_files=['TestPack/file1', 'TestPack/file2']
    )
    captured = capsys.readouterr()
    assert 'Email sent to' in captured.out
    assert 'contributors of pack TestPack' in captured.out
    assert mail_sent

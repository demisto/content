import logging
import demistomock as demisto
import pytest

import EWSMailSender
from exchangelib.errors import UnauthorizedError


class MockAccount:
    def __init__(self, primary_smtp_address="", error=401):
        self.primary_smtp_address = primary_smtp_address
        self.error = error

    @property
    def root(self):
        if self.error == 401:
            raise UnauthorizedError('Wrong username or password')
        if self.error == 404:
            raise Exception('Page not found')


def test_prepare():
    res = EWSMailSender.prepare()
    assert res.server == 'outlook.office365.com'


def test_start_logging():
    EWSMailSender.start_logging()
    logging.getLogger().debug("test this")
    assert "test this" in EWSMailSender.log_stream.getvalue()


def test_get_account_unauthorized_error(mocker):
    """
    Given:
        Incorrect credentials
    When:
        Creating an Account
    Then:
        Verify we've tried 3 times to create an account
        And we put it to the debug.log
    """
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(error=401))
    demisto_debug = mocker.patch.object(demisto, 'debug')

    EWSMailSender.get_account('test@test.com')

    assert demisto_debug.call_args.args[0] == 'Got unauthorized error, This is attempt number 3'


def test_get_account_not_found_error(mocker):
    """
    Given:
        Incorrect endpoint
    When:
        Creating an Account
    Then:
        Verify we do not try 3 times to create an Account
        And the debug.log is empty
    """
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(error=404))
    demisto_debug = mocker.patch.object(demisto, 'debug')

    with pytest.raises(Exception) as e:
        EWSMailSender.get_account('test@test.com')

    assert str(e.value) == 'Page not found'
    assert not demisto_debug.call_args


def test_send_mail(mocker):
    """
    Given -
        to, subject and replyTo arguments to send an email.

    When -
        trying to send an email

    Then -
        verify the context output is returned correctly and that the 'to' and 'replyTo' arguments were sent
        as a list of strings.
    """
    from EWSMailSender import send_email
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))
    send_email_mocker = mocker.patch.object(EWSMailSender, 'send_email_to_mailbox')
    result = send_email(to="test@gmail.com", subject="test", replyTo="test1@gmail.com,test2@gmail.com,test3@gmail.com")
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert send_email_mocker.call_args.kwargs.get('reply_to') == [
        'test1@gmail.com', 'test2@gmail.com', 'test3@gmail.com'
    ]
    assert result.get('Contents') == {
        'from': 'test@gmail.com', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }


def test_send_mail_with_trailing_comma(mocker):
    """
    Given -
        a 'subject' which is 'test' and 'to' which is 'test@gmail.com,' (ending with a comma),

    When -
        trying to send an email

    Then -
        verify that the 'to' field was extracted correctly and that the trailing comma was handled.
    """
    from EWSMailSender import send_email
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(primary_smtp_address="test@gmail.com"))
    send_email_mocker = mocker.patch.object(EWSMailSender, 'send_email_to_mailbox')
    result = send_email(to="test@gmail.com,", subject="test")
    assert send_email_mocker.call_args.kwargs.get('to') == ['test@gmail.com']
    assert result.get('Contents') == {
        'from': 'test@gmail.com', 'to': ['test@gmail.com'], 'subject': 'test', 'attachments': []
    }

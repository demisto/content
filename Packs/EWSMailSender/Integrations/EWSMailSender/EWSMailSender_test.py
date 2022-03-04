import logging
import demistomock as demisto
import pytest

import EWSMailSender
from exchangelib.errors import UnauthorizedError


class MockAccount():
    def __init__(self, error):
        self.error = error

    @property
    def root(self):
        if self.error == 401:
            raise UnauthorizedError('Wrong username or password')
        if self.error == 404:
            raise Exception('Page not found')


def test_prepare():
    res = EWSMailSender.prepare()
    assert res.protocol.server == 'outlook.office365.com'


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
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(401))
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
    mocker.patch.object(EWSMailSender, 'Account', return_value=MockAccount(404))
    demisto_debug = mocker.patch.object(demisto, 'debug')

    with pytest.raises(Exception) as e:
        EWSMailSender.get_account('test@test.com')

    assert str(e.value) == 'Page not found'
    assert not demisto_debug.call_args

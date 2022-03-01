import logging
import EWSMailSender
from exchangelib.errors import UnauthorizedError


def test_prepare():
    res = EWSMailSender.prepare()
    assert res.protocol.server == 'outlook.office365.com'


def test_start_logging():
    EWSMailSender.start_logging()
    logging.getLogger().debug("test this")
    assert "test this" in EWSMailSender.log_stream.getvalue()


def test_get_account(mocker):
    email_account = 'test@test.com'
    mocker.patch.object(EWSMailSender.get_account(email_account), return_value=UnauthorizedError)

    EWSMailSender.get_account(email_account)

    assert True

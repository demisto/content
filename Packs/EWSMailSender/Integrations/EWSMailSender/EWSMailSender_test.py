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

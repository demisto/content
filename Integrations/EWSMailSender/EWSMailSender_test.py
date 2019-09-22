import logging
import EWSMailSender


def test_prepar():
    res = EWSMailSender.prepare()
    assert res.protocol.server == 'outlook.office365.com'


def test_start_logging():
    EWSMailSender.start_logging()
    logging.getLogger().debug("test this")
    assert "test this" in EWSMailSender.log_stream.getvalue()

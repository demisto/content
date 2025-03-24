from CommonServerPython import *
import pytest
from contextlib import contextmanager
import logging


class Logger:
    def debug(self, message):
        return "debug" + message

    def info(self, message):
        return "info" + message

    def warning(self, message):
        return "warning" + message

    def error(self, message):
        return "error" + message

    def critical(self, message):
        return "critical" + message


class Manager:
    @contextmanager
    def get_logger(self):
        try:
            yield Logger()
        finally:
            pass


def test_init_manager():
    from SyslogSender import init_manager

    # Set
    params = {"address": "127.0.0.1", "port": "514", "protocol": "tcp", "priority": "LOG_DEBUG", "facility": "LOG_SYSLOG"}

    # Arrange
    manager = init_manager(params)

    # Assert
    assert manager.address == "127.0.0.1"
    assert manager.port == 514
    assert manager.protocol == "tcp"
    assert manager.logging_level == 10
    assert manager.facility == 5


@pytest.mark.parametrize("investigation_id", ["999", "909"])
def test_mirror_investigation_new_and_existing(mocker, investigation_id):
    from SyslogSender import mirror_investigation

    # Set

    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "investigation", return_value={"id": investigation_id})
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "mirrorInvestigation")

    # Arrange
    mirror_investigation()

    success_results = demisto.results.call_args_list[0][0]
    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    # Assert
    assert success_results[0] == "Investigation mirrored to Syslog successfully."
    assert mirror_id == investigation_id
    assert mirror_type == "all:FromDemisto"
    assert auto_close is False


def test_send_with_severity(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, "args", return_value={"severity": "4", "message": "!!!", "messageType": "incidentOpened"})
    link = "https://www.eizelulz.com:8443/#/WarRoom/727"
    mocker.patch.object(demisto, "investigation", return_value={"type": 1, "id": 1})
    mocker.patch.object(demisto, "demistoUrls", return_value={"warRoom": link})
    mocker.patch.object(demisto, "results")
    mocker.patch.object(Logger, "info")

    # Arrange
    syslog_send_notification(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == "1, !!! https://www.eizelulz.com:8443/#/WarRoom/727"
    assert results == "Message sent to Syslog successfully."


def test_send_with_severity_zero(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, "args", return_value={"severity": "0", "message": "!!!", "messageType": "incidentOpened"})
    link = "https://www.eizelulz.com:8443/#/WarRoom/727"
    mocker.patch.object(demisto, "investigation", return_value={"type": 1, "id": 1})
    mocker.patch.object(demisto, "demistoUrls", return_value={"warRoom": link})
    mocker.patch.object(demisto, "results")
    mocker.patch.object(Logger, "critical")

    # Arrange
    syslog_send_notification(Manager(), 1)
    send_count = Logger.critical.call_count
    results_count = demisto.results.call_count

    # Assert
    assert send_count == 0
    assert results_count == 0


def test_send(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, "args", return_value={"message": "eyy"})
    link = "https://www.eizelulz.com:8443/#/WarRoom/727"
    mocker.patch.object(demisto, "investigation", return_value={"type": 1, "id": 1})
    mocker.patch.object(demisto, "demistoUrls", return_value={"warRoom": link})
    mocker.patch.object(demisto, "results")
    mocker.patch.object(Logger, "info")

    # Arrange
    syslog_send_notification(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == "1, eyy https://www.eizelulz.com:8443/#/WarRoom/727"
    assert results == "Message sent to Syslog successfully."


def test_send_with_non_default_log_level(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, "args", return_value={"message": "eyy", "level": "DEBUG"})
    link = "https://www.eizelulz.com:8443/#/WarRoom/727"
    mocker.patch.object(demisto, "investigation", return_value={"type": 1, "id": 1})
    mocker.patch.object(demisto, "demistoUrls", return_value={"warRoom": link})
    mocker.patch.object(demisto, "results")

    mocker.patch.object(Logger, "debug")
    mocker.patch.object(Logger, "info")  # This is the default log level

    # Arrange
    syslog_send_notification(Manager(), 1)
    debug_send_args = Logger.debug.call_args[0]
    info_send_args = Logger.info.call_args  # make sure nothing was sent in the info log level
    results = demisto.results.call_args[0][0]

    # Assert
    assert debug_send_args[0] == "1, eyy https://www.eizelulz.com:8443/#/WarRoom/727"
    assert not info_send_args
    assert results == "Message sent to Syslog successfully."


def test_prepare_certificate_file():
    """
    Given:
    - certificate: Certificate.
    When:
    - Preparing global variables and creating the StreamServer.

    Then:
    - Ensure globals are set as expected and server is returned with expected attributes.
    """
    from SyslogSender import prepare_certificate_file

    result = prepare_certificate_file("example")
    assert len(result)


def test_SyslogHandlerTLS_init(mocker):
    """
    Given:
    - address
    - port
    - facility
    - log_level
    - certificate: Certificate.
    When:
    - Preparing global variables and creating the SyslogHandlerTLS handler.

    Then:
    - Ensure globals are set as expected and the handler was created.
    """
    from SyslogSender import SyslogHandlerTLS

    address = "127.0.0.1"
    port = 6514
    log_level = logging.DEBUG
    facility = 0
    cert_path = "cert.pem"
    mocker.patch("ssl.SSLContext.load_verify_locations", return_value=None)
    mocker.patch.object(ssl.SSLContext, "wrap_socket")
    mocker.patch.object(socket.socket, "connect")
    handler = SyslogHandlerTLS(address, port, log_level, facility, cert_path, False)
    assert handler.address == address
    assert handler.port == port
    assert handler.certfile == cert_path
    assert handler.facility == facility
    assert handler.level == log_level


def test_SyslogManager():
    """
    Given:
    - address
    - port
    - facility
    - log_level
    - certificate: Certificate.
    When:
    - Preparing global variables and creating the SyslogHandlerTLS handler.

    Then:
    - Ensure globals are set as expected and the handler was created.
    """
    from SyslogSender import SyslogManager

    address = "127.0.0.1"
    port = 6514
    log_level = logging.DEBUG
    facility = 0
    cert_path = "cert.pem"
    protocol = "udp"
    self_signed = True
    handler = SyslogManager(address, port, protocol, log_level, facility, cert_path, self_signed)
    assert handler.address == address
    assert handler.port == port
    assert handler.syslog_cert_path == cert_path
    assert handler.facility == facility
    assert handler.logging_level == log_level


def test_syslog_send(mocker):
    """
    Given:
    - address
    - port
    - facility
    - log_level
    - certificate: Certificate.
    When:
    - calling syslog_send.

    Then:
    - Ensure the message was sent.
    """
    import SyslogSender

    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SyslogSender, "send_log")
    demisto_results_mocker = mocker.patch.object(demisto, "results")
    SyslogSender.syslog_send(None)
    assert demisto_results_mocker.called
    assert demisto.results.call_args[0][0] == "Message sent to Syslog successfully."


def test_SyslogManager_tcp(mocker):
    """
    Given:
    - address
    - port
    - facility
    - log_level
    - certificate: Certificate.
    When:
    - calling creating a logger using tcp protocol.

    Then:
    - Ensure manger, handler and logger are being created.
    """
    from SyslogSender import SyslogManager, init_manager

    params = {
        "address": "127.0.0.1",
        "port": "514",
        "protocol": "tcp",
        "priority": "LOG_DEBUG",
        "facility": "LOG_SYSLOG",
        "cert_path": "",
    }
    handler = {
        "SysLogLogger": {
            "level": "INFO",
            "class": "rfc5424logging.handler.Rfc5424SysLogHandler",
            "address": ("127.0.0.1", 514),
            "enterprise_id": 32473,
        }
    }

    # Arrange
    manager = init_manager(params)
    mocker.patch.object(SyslogManager, "_get_handler", return_value=handler)
    handler = SyslogManager._get_handler(manager)
    # mocker.patch.object(Logger, 'setLevel')
    logger = SyslogManager._init_logger(manager, handler)
    assert logger.level == 10


def test_SyslogManager_tls(mocker):
    """
    Given:
    - address
    - port
    - facility
    - log_level
    - certificate: Certificate.
    When:
    - calling creating a logger using tls protocol.

    Then:
    - Ensure manger, handler and logger are being created.
    """
    import SyslogSender
    from SyslogSender import SyslogManager, init_manager

    params = {
        "address": "127.0.0.1",
        "port": "6514",
        "protocol": "tls",
        "priority": "LOG_DEBUG",
        "facility": "LOG_SYSLOG",
        "certificate": {"certificate": "cert.pem"},
    }
    handler = {
        "syslog": {
            "level": "INFO",
            "class": "tlssyslog.handlers.TLSSysLogHandler",
            "formatter": "simple",
            "address": ("127.0.0.1", 6514),
            "ssl_kwargs": {
                "cert_reqs": ssl.CERT_REQUIRED,
                "ssl_version": ssl.PROTOCOL_TLS_CLIENT,
                "ca_certs": "cert.pem",
            },
        }
    }

    # Arrange
    mocker.patch.object(SyslogSender, "prepare_certificate_file", return_value="cert.pem")
    manager = init_manager(params)
    mocker.patch.object(SyslogManager, "init_handler_tls", return_value=handler)
    handler = SyslogManager.init_handler_tls(manager, "cert.pem")
    logger = SyslogManager._init_logger(manager, handler)
    assert logger.level == 10


def test_main(mocker):
    import SyslogSender
    from SyslogSender import main

    params = {
        "address": "127.0.0.1",
        "port": "6514",
        "protocol": "tls",
        "priority": "LOG_DEBUG",
        "facility": "LOG_SYSLOG",
        "certificate": {"password": "-----BEGIN SSH CERTIFICATE----- MIIF7z gdwZcx IENpdH -----END SSH CERTIFICATE-----"},
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="syslog-send")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SyslogSender, "send_log")
    demisto_results_mocker = mocker.patch.object(demisto, "results")
    main()
    assert demisto_results_mocker.called
    assert demisto.results.call_args[0][0] == "Message sent to Syslog successfully."

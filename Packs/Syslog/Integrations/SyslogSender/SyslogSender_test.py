from CommonServerPython import *
import pytest
from contextlib import contextmanager
import unittest


class Logger:
    def debug(self, message):
        return 'debug' + message

    def info(self, message):
        return 'info' + message

    def warning(self, message):
        return 'warning' + message

    def error(self, message):
        return 'error' + message

    def critical(self, message):
        return 'critical' + message


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
    params = {
        'address': '127.0.0.1',
        'port': '514',
        'protocol': 'tcp',
        'priority': 'LOG_DEBUG',
        'facility': 'LOG_SYSLOG'
    }

    # Arrange
    manager = init_manager(params)

    # Assert
    assert manager.address == '127.0.0.1'
    assert manager.port == 514
    assert manager.protocol == 'tcp'
    assert manager.logging_level == 10
    assert manager.facility == 5


@pytest.mark.parametrize('investigation_id', ['999', '909'])
def test_mirror_investigation_new_and_existing(mocker, investigation_id):
    from SyslogSender import mirror_investigation

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': investigation_id})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'mirrorInvestigation')

    # Arrange
    mirror_investigation()

    success_results = demisto.results.call_args_list[0][0]
    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    # Assert
    assert success_results[0] == 'Investigation mirrored to Syslog successfully.'
    assert mirror_id == investigation_id
    assert mirror_type == 'all:FromDemisto'
    assert auto_close is False


def test_send_with_severity(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, 'args', return_value={'severity': '4', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'info')

    # Arrange
    syslog_send_notification(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == '1, !!! https://www.eizelulz.com:8443/#/WarRoom/727'
    assert results == 'Message sent to Syslog successfully.'


def test_send_with_severity_zero(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, 'args', return_value={'severity': '0', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'critical')

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
    mocker.patch.object(demisto, 'args', return_value={'message': 'eyy'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'info')

    # Arrange
    syslog_send_notification(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == '1, eyy https://www.eizelulz.com:8443/#/WarRoom/727'
    assert results == 'Message sent to Syslog successfully.'


def test_send_with_non_default_log_level(mocker):
    from SyslogSender import syslog_send_notification

    # Set
    mocker.patch.object(demisto, 'args', return_value={'message': 'eyy', 'level': 'DEBUG'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')

    mocker.patch.object(Logger, 'debug')
    mocker.patch.object(Logger, 'info')  # This is the default log level

    # Arrange
    syslog_send_notification(Manager(), 1)
    debug_send_args = Logger.debug.call_args[0]
    info_send_args = Logger.info.call_args  # make sure nothing was sent in the info log level
    results = demisto.results.call_args[0][0]

    # Assert
    assert debug_send_args[0] == '1, eyy https://www.eizelulz.com:8443/#/WarRoom/727'
    assert not info_send_args
    assert results == 'Message sent to Syslog successfully.'


def test_init_manager_address():
    """
    Given:
    - address
    - port
    - priority
    - facility
    When:
    - Preparing global variables and creating the StreamServer.

    Then:
    - Ensure globals are set as expected and server is returned with expected attributes.
    """
    from SyslogSender import init_manager
    params = {
        'address': 'https://www.example.com/tests/stillexample/testthisexapmle123456789',
        'port': '514',
        'protocol': 'tcp',
        'priority': 'LOG_DEBUG',
        'facility': 'LOG_SYSLOG'
    }
    address_after_encoding = base64.b64encode(params['address'].encode()).decode("utf-8")

    # Arrange
    manager = init_manager(params)
    assert manager.address == address_after_encoding
    assert manager.port == 514
    assert manager.protocol == 'tcp'
    assert manager.logging_level == 10
    assert manager.facility == 5


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
    result = prepare_certificate_file('example')
    assert len(result)


def test_SyslogHandlerTLS_init(mocker):
    """
    Given:
    - certificate: Certificate.
    When:
    - Preparing global variables and creating the SyslogHandlerTLS handler.

    Then:
    - Ensure globals are set as expected.
    """
    from SyslogSender import SyslogHandlerTLS
    address = '127.0.0.1'
    port = 6514
    log_level = logging.DEBUG
    facility = 0
    cert_path = 'cert.pem'
    mocker.patch('ssl.SSLContext.load_verify_locations', return_value=None)
    mocker.patch.object(ssl.SSLContext, 'wrap_socket')
    mocker.patch.object(socket.socket, 'connect')
    handler = SyslogHandlerTLS(address, port, log_level, facility, cert_path)
    assert handler.address == address
    assert handler.port == port
    assert handler.certfile == cert_path
    assert handler.facility == facility
    assert handler.level == log_level


def test_SyslogManager():
    from SyslogSender import SyslogManager
    address = '127.0.0.1'
    port = 6514
    log_level = logging.DEBUG
    facility = 0
    cert_path = 'cert.pem'
    protocol = 'udp'
    handler = SyslogManager(address, port, protocol, log_level, facility, cert_path)
    assert handler.address == address
    assert handler.port == port
    assert handler.syslog_cert_path == cert_path
    assert handler.facility == facility
    assert handler.logging_level == log_level
from CommonServerPython import *
import pytest
from contextlib import contextmanager


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

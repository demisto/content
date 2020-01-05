import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest
import json as js
from contextlib import contextmanager


MIRRORS = '''
   [{
   "investigation_id": "910",
     "mirror_type":"all",
     "mirrored":true
  },
  {
     "investigation_id": "909",
     "mirror_type":"all",
     "mirrored":true
  }]'''


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


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


RETURN_ERROR_TARGET = 'SyslogSender.return_error'


@pytest.fixture(autouse=True)
def setup():
    set_integration_context({
        'mirrors': MIRRORS
    })


def test_init_manager():
    from SyslogSender import init_manager

    # Set
    params = {
        'address': '127.0.0.1',
        'port': '514',
        'protocol': 'tcp',
        'logging_level': 'INFO',
        'facility': 'LOG_SYSLOG'
    }

    # Arrange
    manager = init_manager(params)

    # Assert
    assert manager.address == '127.0.0.1'
    assert manager.port == 514
    assert manager.protocol == 'tcp'
    assert manager.logging_level == 20
    assert manager.facility == 5


@pytest.mark.parametrize('investigation_id', ['999', '909'])
def test_mirror_investigation_new_and_existing(mocker, investigation_id):
    from SyslogSender import mirror_investigation

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': investigation_id})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')

    new_mirror = {
        'investigation_id': investigation_id,
        'mirror_type': 'all',
        'mirrored': False
    }

    # Arrange
    mirror_investigation()

    success_results = demisto.results.call_args_list[0][0]
    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: investigation_id == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert success_results[0] == 'Investigation mirrored to Syslog successfully.'
    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_send_with_severity(mocker):
    from SyslogSender import syslog_send

    # Set
    mocker.patch.object(demisto, 'args', return_value={'severity': '4', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'info')

    # Arrange
    syslog_send(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == '1, !!! https://www.eizelulz.com:8443/#/WarRoom/727'
    assert results == 'Message sent to Syslog successfully.'


def test_send_with_severity_zero(mocker):
    from SyslogSender import syslog_send

    # Set
    mocker.patch.object(demisto, 'args', return_value={'severity': '0', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'critical')

    # Arrange
    syslog_send(Manager(), 1)
    send_count = Logger.critical.call_count
    results_count = demisto.results.call_count

    # Assert
    assert send_count == 0
    assert results_count == 0


def test_send(mocker):
    from SyslogSender import syslog_send

    # Set
    mocker.patch.object(demisto, 'args', return_value={'message': 'eyy'})
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1, 'id': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(Logger, 'info')

    # Arrange
    syslog_send(Manager(), 1)
    send_args = Logger.info.call_args[0]
    results = demisto.results.call_args[0][0]

    # Assert
    assert send_args[0] == '1, eyy https://www.eizelulz.com:8443/#/WarRoom/727'
    assert results == 'Message sent to Syslog successfully.'


def test_check_for_mirrors(mocker):
    from SyslogSender import check_for_mirrors
    # Set
    mirrors = js.loads(MIRRORS)
    mirrors.append({
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirrored': False
    })

    set_integration_context({
        'mirrors': js.dumps(mirrors),
    })

    new_mirror = {
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirrored': True
    }

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation')

    # Arrange
    check_for_mirrors()

    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: '999' == m['investigation_id'], new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror

    assert mirror_id == '999'
    assert mirror_type == 'all:FromDemisto'
    assert auto_close is False

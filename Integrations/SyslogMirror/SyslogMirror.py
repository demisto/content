import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from contextlib import contextmanager
from logging.handlers import SysLogHandler
from distutils.util import strtobool
import requests
import logging
import socket

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


PLAYGROUND_INVESTIGATION_TYPE = 9
INCIDENT_OPENED = 'incidentOpened'
LOGGING_LEVEL_DICT = {
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}
SEVERITY_DICT = {
    'Unknown': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}


class SysLogManager:
    def __init__(self, address: str, port: int, protocol: str, logging_level: int):
        self.address = address
        self.port = port
        self.protocol = protocol
        self.logging_level = logging_level

    @contextmanager
    def get_logger(self) -> logging.Logger:
        handler = self._get_handler()
        syslog_logger = self._init_logger(handler)
        try:
            yield syslog_logger
        finally:
            syslog_logger.removeHandler(handler)
            handler.close()

    def _get_handler(self) -> SysLogHandler:
        if self.protocol == 'tcp':
            return SysLogHandler((self.address, self.port), socktype=socket.SOCK_STREAM)
        else:
            return SysLogHandler((self.address, self.port))

    def _init_logger(self, handler: SysLogHandler) -> logging.Logger:
        syslog_logger = logging.getLogger('SysLogLogger')
        syslog_logger.setLevel(self.logging_level)
        syslog_logger.addHandler(handler)

        return syslog_logger


def init_logger(params: dict) -> SysLogManager:
    address = params.get('address')
    port = int(params.get('port', 514))
    protocol = params.get('protocol').lower()
    logging_level = LOGGING_LEVEL_DICT.get(params.get('logging_level', 'INFO'), logging.INFO)

    return SysLogManager(address, port, protocol, logging_level)


def check_for_mirrors():
    """
    Checks for newly created mirrors and updates the server accordingly
    """
    integration_context = demisto.getIntegrationContext()
    if integration_context.get('mirrors'):
        mirrors = json.loads(integration_context['mirrors'])
        for mirror in mirrors:
            if not mirror['mirrored']:
                demisto.info('Mirroring: {}'.format(mirror['investigation_id']))
                mirror = mirrors.pop(mirrors.index(mirror))
                investigation_id = mirror['investigation_id']
                mirror_type = mirror['mirror_type']
                demisto.mirrorInvestigation(investigation_id, '{}:{}'.format(mirror_type, 'FromDemisto'), False)
                mirror['mirrored'] = True
                mirrors.append(mirror)

                demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})


def mirror_investigation():
    """
    Updates the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type', 'all')

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in playground.')

    integration_context = demisto.getIntegrationContext()
    mirror = {
        'investigation_id': investigation.get('id'),
        'mirror_type': mirror_type,
        'mirrored': False
    }

    if 'mirrors' not in integration_context:
        mirrors = []
    else:
        mirrors = json.loads(integration_context['mirrors'])

    mirrors.append(mirror)
    demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})

    demisto.results('Investigation mirrored successfully.')


def syslog_send(manager: SysLogManager, min_severity: int):
    """
    Sends a message to syslog
    """
    message = demisto.args().get('message', '')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('ignoreAddURL', False)
    severity = demisto.args().get('severity')  # From server
    message_type = demisto.args().get('messageType', '')  # From server

    if severity:
        try:
            severity = int(severity)
        except Exception:
            severity = None
            pass

    if message_type == INCIDENT_OPENED and (severity is not None and severity < min_severity):
        return

    if not message:
        message = ' '

    message = message.replace('\n', ' ').replace('\r', ' ').replace('`', '')
    investigation = demisto.investigation()
    if investigation:
        if entry:
            message = '{}, {}'.format(entry, message)
        message = '{}, {}'.format(investigation.get('id'), message)

    if ignore_add_url and isinstance(ignore_add_url, str):
        ignore_add_url = bool(strtobool(ignore_add_url))
    if not ignore_add_url:
        investigation = demisto.investigation()
        server_links = demisto.demistoUrls()
        if investigation:
            if investigation.get('type') != PLAYGROUND_INVESTIGATION_TYPE:
                link = server_links.get('warRoom')
                if link:
                    if entry:
                        link += '/' + entry
                    message += '\n{} {}'.format('View it on:', link)
            else:
                link = server_links.get('server', '')
                if link:
                    message += '\n{} {}'.format('View it on:', link + '#/home')

    with manager.get_logger() as syslog_logger:
        if severity == SEVERITY_DICT['Critical']:
            syslog_logger.critical(message)
        else:
            syslog_logger.info(message)


def long_running_main():
    while True:
        check_for_mirrors()
        time.sleep(5)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    syslog_manager = init_logger(demisto.params())
    min_severity = SEVERITY_DICT.get(demisto.params().get('severity', 'Low'), 1)

    try:
        if demisto.command() == 'test-module':
            with syslog_manager.get_logger() as syslog_logger:
                syslog_logger.info('This is a test')
            demisto.results('ok')
        elif demisto.command() == 'mirror-investigation':
            mirror_investigation()
        elif demisto.command() == 'send-notification':
            syslog_send(syslog_manager, min_severity)
        elif demisto.command() == 'long-running-execution':
            long_running_main()

    # Log exceptions
    except Exception as e:
        LOG(e)
        LOG.print_log()
        raise
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from contextlib import contextmanager
from logging.handlers import SysLogHandler
from distutils.util import strtobool
from logging import Logger, getLogger, INFO, DEBUG, WARNING, ERROR, CRITICAL
from socket import SOCK_STREAM
from typing import Union, Tuple, Dict, Any

''' CONSTANTS '''


PLAYGROUND_INVESTIGATION_TYPE = 9
INCIDENT_OPENED = 'incidentOpened'
LOGGING_LEVEL_DICT = {
    'INFO': INFO,
    'DEBUG': DEBUG,
    'WARNING': WARNING,
    'ERROR': ERROR,
    'CRITICAL': CRITICAL
}
FACILITY_DICT = {
    'LOG_AUTH': SysLogHandler.LOG_AUTH,
    'LOG_AUTHPRIV': SysLogHandler.LOG_AUTHPRIV,
    'LOG_CRON': SysLogHandler.LOG_CRON,
    'LOG_DAEMON': SysLogHandler.LOG_DAEMON,
    'LOG_FTP': SysLogHandler.LOG_FTP,
    'LOG_KERN': SysLogHandler.LOG_KERN,
    'LOG_LPR': SysLogHandler.LOG_LPR,
    'LOG_MAIL': SysLogHandler.LOG_MAIL,
    'LOG_NEWS': SysLogHandler.LOG_NEWS,
    'LOG_SYSLOG': SysLogHandler.LOG_SYSLOG,
    'LOG_USER': SysLogHandler.LOG_USER,
    'LOG_UUCP': SysLogHandler.LOG_UUCP,
    'LOG_LOCAL0': SysLogHandler.LOG_LOCAL0,
    'LOG_LOCAL1': SysLogHandler.LOG_LOCAL1,
    'LOG_LOCAL2': SysLogHandler.LOG_LOCAL2,
    'LOG_LOCAL3': SysLogHandler.LOG_LOCAL3,
    'LOG_LOCAL4': SysLogHandler.LOG_LOCAL4,
    'LOG_LOCAL5': SysLogHandler.LOG_LOCAL5,
    'LOG_LOCAL6': SysLogHandler.LOG_LOCAL6,
    'LOG_LOCAL7': SysLogHandler.LOG_LOCAL7
}
SEVERITY_DICT = {
    'Unknown': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}

''' Syslog Manager '''


class SyslogManager:
    def __init__(self, address: str, port: int, protocol: str, logging_level: int, facility: int):
        """
        Class for managing instances of a syslog logger.
        :param address: The IP address of the syslog server.
        :param port: The port of the syslog server.
        :param protocol: The messaging protocol (TCP / UDP).
        :param logging_level: The logging level.
        """
        self.address = address
        self.port = port
        self.protocol = protocol
        self.logging_level = logging_level
        self.facility = facility

    @contextmanager  # type: ignore[misc, arg-type]
    def get_logger(self) -> Logger:
        """
        Get a new instance of a syslog logger.
        :return: syslog logger
        """
        handler = self._get_handler()
        syslog_logger = self._init_logger(handler)
        try:
            yield syslog_logger
        finally:
            syslog_logger.removeHandler(handler)
            handler.close()

    def _get_handler(self) -> SysLogHandler:
        """
        Get a syslog handler for a logger according to provided parameters.
        :return: syslog handler
        """
        address: Union[str, Tuple[str, int]] = (self.address, self.port)
        kwargs: Dict[str, Any] = {
            'facility': self.facility
        }

        if self.protocol == 'tcp':
            kwargs['socktype'] = SOCK_STREAM
        elif self.protocol == 'unix':
            address = self.address

        kwargs['address'] = address

        return SysLogHandler(**kwargs)

    def _init_logger(self, handler: SysLogHandler) -> Logger:
        """
        Initialize a logger with a syslog handler.
        :param handler: A syslog handler
        :return: A syslog logger
        """
        syslog_logger = getLogger('SysLogLogger')
        syslog_logger.setLevel(self.logging_level)
        syslog_logger.addHandler(handler)

        return syslog_logger


''' HELPER FUNCTIONS '''


def init_manager(params: dict) -> SyslogManager:
    """
    Create a syslog manager instance according to provided parameters.
    :param params: Parameters for the syslog manager.
    :return: syslog manager
    """
    address = params.get('address', '')
    port = int(params.get('port', 514))
    protocol = params.get('protocol', 'udp').lower()
    facility = FACILITY_DICT.get(params.get('facility', 'LOG_SYSLOG'), SysLogHandler.LOG_SYSLOG)
    logging_level = LOGGING_LEVEL_DICT.get(params.get('logging_level', 'INFO'), INFO)

    return SyslogManager(address, port, protocol, logging_level, facility)


def send_log(manager: SyslogManager, message: str, log_level: str):
    """
    Use a syslog manager to get a logger and send a message to syslog.
    :param manager: The syslog manager
    :param message: The message to send
    :param log_level: The logging level
    """
    with manager.get_logger() as syslog_logger:   # type: Logger
        if log_level == 'DEBUG':
            syslog_logger.debug(message)
        if log_level == 'INFO':
            syslog_logger.info(message)
        if log_level == 'WARNING':
            syslog_logger.warning(message)
        if log_level == 'ERROR':
            syslog_logger.error(message)
        if log_level == 'CRITICAL':
            syslog_logger.critical(message)


def check_for_mirrors():
    """
    Check for newly created mirrors and update the server accordingly
    """
    integration_context = demisto.getIntegrationContext()
    mirrors = json.loads(integration_context.get('mirrors', '[]'))
    for mirror in mirrors:
        if not mirror['mirrored']:
            investigation_id = mirror['investigation_id']
            demisto.info(f'Mirroring: {investigation_id}')
            mirror = mirrors.pop(mirrors.index(mirror))
            mirror_type = mirror['mirror_type']
            demisto.mirrorInvestigation(investigation_id, f'{mirror_type}:FromDemisto', False)
            mirror['mirrored'] = True
            mirrors.append(mirror)

            demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})


def mirror_investigation():
    """
    Update the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type', 'all')

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in the playground.')

    investigation_id = investigation.get('id')
    integration_context = demisto.getIntegrationContext()
    mirrors = json.loads(integration_context.get('mirrors', '[]'))

    mirror_filter = list(filter(lambda m: m['investigation_id'] == investigation_id, mirrors))
    if mirror_filter:
        # Delete existing mirror
        mirrors.pop(mirrors.index(mirror_filter[0]))
    mirror = {
        'investigation_id': investigation_id,
        'mirror_type': mirror_type,
        'mirrored': False
    }

    mirrors.append(mirror)
    demisto.setIntegrationContext({'mirrors': json.dumps(mirrors)})

    demisto.results('Investigation mirrored to Syslog successfully.')


''' Syslog send command '''


def syslog_send(manager: SyslogManager, min_severity: int):
    """
    Send a message to syslog
    :param manager: Syslog manager
    :param min_severity: Minimum severity of incidents to send messages about
    """
    message = demisto.args().get('message', '')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('ignoreAddURL', False)
    log_level = demisto.args().get('log_level')
    severity = demisto.args().get('severity')  # From server
    message_type = demisto.args().get('messageType', '')  # From server

    if severity:
        try:
            severity = int(severity)
        except Exception:
            severity = None

    if message_type == INCIDENT_OPENED and (severity is not None and severity < min_severity):
        return

    if not message:
        message = ''

    message = message.replace('\n', ' ').replace('\r', ' ').replace('`', '')
    investigation = demisto.investigation()
    if investigation:
        investigation_id = investigation.get('id')
        if entry:
            message = f'{entry}, {message}'
        message = f'{investigation_id}, {message}'

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
                    message += f' {link}'
            else:
                link = server_links.get('server', '')
                if link:
                    message += f' {link}#/home'

    if not message:
        return_error('No message received')

    if not log_level:
        log_level = 'INFO'

    send_log(manager, message, log_level)

    demisto.results('Message sent to Syslog successfully.')


def long_running_main():
    """
    Loop for the long running process.
    """
    while True:
        try:
            check_for_mirrors()
        except Exception as e:
            error_message = f'Error: {str(e)}'
            demisto.error(error_message)
            demisto.updateModuleHealth(error_message)
        time.sleep(5)


''' MAIN '''


def main():
    LOG(f'Command being called is {demisto.command()}')

    syslog_manager = init_manager(demisto.params())
    min_severity = SEVERITY_DICT.get(demisto.params().get('severity', 'Low'), 1)

    try:
        if demisto.command() == 'test-module':
            with syslog_manager.get_logger() as syslog_logger:  # type: Logger
                syslog_logger.info('This is a test')
            demisto.results('ok')
        elif demisto.command() == 'mirror-investigation':
            mirror_investigation()
        elif demisto.command() == 'send-notification':
            syslog_send(syslog_manager, min_severity)
        elif demisto.command() == 'long-running-execution':
            long_running_main()
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

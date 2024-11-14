import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from contextlib import contextmanager
from logging.handlers import SysLogHandler
from distutils.util import strtobool
from logging import Logger, getLogger, INFO, DEBUG, WARNING, ERROR, CRITICAL
from socket import SOCK_STREAM
from collections.abc import Generator
from tempfile import NamedTemporaryFile
from rfc5424logging import Rfc5424SysLogHandler
import socket
import ssl

''' CONSTANTS '''

PLAYGROUND_INVESTIGATION_TYPE = 9
INCIDENT_OPENED = 'incidentOpened'
LOGGING_LEVEL_DICT = {
    'LOG_INFO': INFO,
    'LOG_DEBUG': DEBUG,
    'LOG_WARNING': WARNING,
    'LOG_ERR': ERROR,
    'LOG_CRIT': CRITICAL
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

TCP = 'tcp'
UDP = 'udp'
TLS = 'tls'
PROTOCOLS = {TCP, UDP, TLS}
MAX_PORT = 65535
DEFAULT_TCP_SYSLOG_PORT = 514
DEFAULT_TLS_SYSLOG_PORT = 6514

'''SyslogHandlerTLS'''


class SyslogHandlerTLS(logging.Handler):
    def __init__(self, address: str, port: int, log_level: int, facility: int, cert_path: str, if_self_sign_cert: bool):
        """
        Initialize a handler.
        """
        logging.Handler.__init__(self)
        self.address = address
        self.port = port
        self.certfile = cert_path
        self.facility = facility
        self.level = log_level
        # Create a TCP socket
        ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Wrap the socket with SSL
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        # In order to allow self signed certificate:
        if if_self_sign_cert:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        ssl_context.load_verify_locations(self.certfile)
        ssl_sock = ssl_context.wrap_socket(ssl_sock, server_hostname=self.address)
        self.socket = ssl_sock
        try:
            self.socket.connect((self.address, self.port))
        except OSError as exc:
            if ssl_sock:
                ssl_sock.close()
            raise DemistoException(str(exc))

    def emit(self, record):
        """
        Emit a record.

        The record is formatted, and then sent to the syslog server. If
        exception information is present, it is NOT sent to the server.
        """
        ident = ''  # prepended to all messages
        try:
            msg = self.format(record)
            if ident:
                msg = ident + msg

            # Calculate the priority value
            priority = (self.facility << 3) | self.level
            # Construct the syslog message in RFC 5424 format
            syslog_message = '<{priority}>1 {timestamp} {hostname} {appname} {procid} {msgid} - {message}\n'.format(
                priority=priority,
                timestamp=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                hostname=socket.gethostname(),
                appname=record.name,
                procid=os.getpid(),
                msgid='-',
                message=self.format(record)
            )
            # Connect to the syslog server
            self.socket.send(syslog_message.encode('utf-8'))

        except Exception as e:
            if self.socket:
                self.socket.close()
            demisto.error(str(e))


''' Syslog Manager '''


class SyslogManager:
    def __init__(self, address: str, port: int, protocol: str, logging_level: int,
                 facility: int, cert_path: str | None, self_signed_certificate: bool):
        """
        Class for managing instances of a syslog logger.
        :param address: The IP address of the syslog server.
        :param port: The port of the syslog server.
        :param protocol: The messaging protocol (TCP / UDP / TLS).
        :param logging_level: The logging level.
        """
        self.address = address
        self.port = port
        self.protocol = protocol
        self.logging_level = logging_level
        self.facility = facility
        self.syslog_cert_path = cert_path
        self.self_signed_cert = self_signed_certificate

    @contextmanager  # type: ignore[misc, arg-type]
    def get_logger(self) -> Generator:
        """
        Get a new instance of a syslog logger.
        :return: syslog logger
        """
        if self.protocol == TLS and self.syslog_cert_path:
            demisto.debug('creating tls logger handler')
            handler = self.init_handler_tls(self.syslog_cert_path)
        else:
            demisto.debug('creating tcp/udp logger handler')
            handler = self._get_handler()
        syslog_logger = self._init_logger(handler)
        demisto.debug('logger was created ')
        try:
            yield syslog_logger
        finally:
            syslog_logger.removeHandler(handler)
            handler.close()

    def _get_handler(self) -> Rfc5424SysLogHandler:
        sock_kind = SOCK_STREAM if self.protocol == TCP else socket.SOCK_DGRAM
        return Rfc5424SysLogHandler(address=(self.address, self.port),
                                    facility=self.facility,
                                    socktype=sock_kind,
                                    utc_timestamp=True)

    def init_handler_tls(self, certfile: str):
        return SyslogHandlerTLS(address=self.address,
                                port=self.port,
                                cert_path=certfile,
                                facility=self.facility,
                                log_level=self.logging_level,
                                if_self_sign_cert=self.self_signed_cert)

    def _init_logger(self, handler: Rfc5424SysLogHandler | SyslogHandlerTLS) -> Logger:
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


def prepare_certificate_file(certificate: str) -> str:
    """
    Prepares the certificate file and key for ssl connection.
    Args:
        certificate (str): Certificate. For SSL connection.
    Returns:
        (str, str): certificate_path.
    """
    certificate_file = NamedTemporaryFile(delete=False)
    certificate_path = certificate_file.name
    certificate_file.write(bytes(certificate, 'utf-8'))
    certificate_file.close()
    demisto.debug('Successfully preparing the certificate')
    return certificate_path


def init_manager(params: dict) -> SyslogManager:
    """
    Create a syslog manager instance according to provided parameters.
    :param params: Parameters for the syslog manager.
    :return: syslog manager
    """
    address = params.get('address')
    protocol = params.get('protocol', UDP).lower()
    facility = FACILITY_DICT.get(params.get('facility', 'LOG_SYSLOG'), SysLogHandler.LOG_SYSLOG)
    logging_level = LOGGING_LEVEL_DICT.get(params.get('priority', 'LOG_INFO'), INFO)
    certificate: Optional[str] = (replace_spaces_in_credential(params.get('certificate', {}).get('password'))
                                  or params.get('certificate', None))
    certificate_path: Optional[str] = None
    default_port: int = DEFAULT_TLS_SYSLOG_PORT if protocol == 'tls' else DEFAULT_TCP_SYSLOG_PORT
    port = arg_to_number(params.get('port'), required=False) or default_port
    self_signed_certificate = params.get('self_signed_certificate', False)
    if not address:
        raise DemistoException('A address must be provided.')
    if port and (port < 0 or port > MAX_PORT):
        raise DemistoException(f'Given port: {port} is not valid and must be between 0-{MAX_PORT}')
    if protocol == 'tls' and not certificate:
        raise DemistoException('A certificate must be provided in TLS protocol.')
    if certificate and protocol == 'tls':
        certificate_path = prepare_certificate_file(certificate)
    return SyslogManager(address, port, protocol, logging_level, facility, certificate_path, self_signed_certificate)


def send_log(manager: SyslogManager, message: str, log_level: str):
    """
    Use a syslog manager to get a logger and send a message to syslog.
    :param manager: The syslog manager
    :param message: The message to send
    :param log_level: The logging level
    """
    with manager.get_logger() as syslog_logger:  # type: Logger
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


def mirror_investigation():
    """
    Update the integration context with a new or existing mirror.
    """
    mirror_type = demisto.args().get('type', 'all')

    investigation = demisto.investigation()

    if investigation.get('type') == PLAYGROUND_INVESTIGATION_TYPE:
        return_error('Can not perform this action in the playground.')

    investigation_id = investigation.get('id')

    demisto.mirrorInvestigation(investigation_id, f'{mirror_type}:FromDemisto', False)

    demisto.results('Investigation mirrored to Syslog successfully.')


''' Syslog send command '''


def syslog_send_notification(manager: SyslogManager, min_severity: int):
    """
    Send a message to syslog
    :param manager: Syslog manager
    :param min_severity: Minimum severity of incidents to send messages about
    """
    message = demisto.args().get('message', '')
    entry = demisto.args().get('entry')
    ignore_add_url = demisto.args().get('ignoreAddURL', False)
    log_level = demisto.args().get('level', 'INFO')
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
        raise ValueError('No message received')

    send_log(manager, message, log_level)

    demisto.results('Message sent to Syslog successfully.')


def syslog_send(manager):
    message = demisto.args().get('message', '')
    log_level = demisto.args().get('level', 'INFO')
    send_log(manager, message, log_level)
    demisto.results('Message sent to Syslog successfully.')


''' MAIN '''


def main():
    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            syslog_manager = init_manager(demisto.params())
            with syslog_manager.get_logger() as syslog_logger:  # type: Logger
                syslog_logger.info('The connection was successfully established')
            demisto.results('ok')
        elif demisto.command() == 'mirror-investigation':
            mirror_investigation()
        elif demisto.command() == 'syslog-send':
            if 'address' in demisto.args():
                # params provided in the command args
                syslog_manager = init_manager(demisto.args())
            else:
                syslog_manager = init_manager(demisto.params())
            syslog_send(syslog_manager)
        elif demisto.command() == 'send-notification':
            min_severity = SEVERITY_DICT.get(demisto.params().get('severity', 'Low'), 1)
            syslog_manager = init_manager(demisto.params())
            syslog_send_notification(syslog_manager, min_severity)
    except Exception as e:
        exception_msg = str(e)
        error_message = f"The following error was thrown: {exception_msg} "
        if 'PEM lib (_ssl.c:4123)' in exception_msg:
            error_message += 'Potential causes could include: ' \
                             'That the certificate is not in the correct format (e.g. it\'s not in PEM format)- ' \
                             'Make sure to insert the Certificate was insert correctly. ' \
                             'or, The certificate is expired or otherwise invalid'
        elif 'CERTIFICATE_VERIFY_FAILED' in exception_msg:
            error_message += 'If the certificate is self sign, make sure to check the Self Signed Certificate button.' \
                             'Otherwise, The certificate is not trusted by the system or by the client trying to' \
                             ' establish the connection'
        elif 'UnicodeError: label too long' in exception_msg:
            error_message += '\nPotential cause could be too long URL label, which means  there is a part of the' \
                             ' URL between two dots that is longer than 64 chars.'
        raise DemistoException(error_message)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

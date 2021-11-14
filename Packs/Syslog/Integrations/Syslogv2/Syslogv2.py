from dataclasses import dataclass
from tempfile import NamedTemporaryFile
from typing import Callable

import syslogmp
from gevent.server import StreamServer
from syslog_rfc5424_parser import SyslogMessage, ParseError

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MAX_SAMPLES = 10
BUF_SIZE = 1024
LOG_FORMAT: str = ''
MESSAGE_REGEX: Optional[str] = None
INCIDENT_TYPE: Optional[str] = None
MAX_PORT: int = 65535


@dataclass
class SyslogMessageExtract:
    app_name: Optional[str]
    facility: str
    host_name: Optional[str]
    msg: str
    msg_id: Optional[str]
    process_id: Optional[str]
    sd: dict
    severity: str
    timestamp: str
    version: Optional[int]
    occurred: Optional[str]


def parse_rfc_3164_format(log_message: bytes) -> SyslogMessageExtract:
    """
    Receives a log message which is in RFC 3164 format. Parses it into SyslogMessageExtract data class object
    Args:
        log_message (bytes): Syslog message.

    Returns:
        (SyslogMessageExtract): Extraction data class
    """
    try:
        syslog_message: syslogmp.Message = syslogmp.parse(log_message)
    except syslogmp.parser.MessageFormatError as e:
        raise DemistoException(f'Could not parse the log message. Error was: {e}') from e
    return SyslogMessageExtract(
        app_name=None,
        facility=syslog_message.facility.name,
        host_name=syslog_message.hostname,
        msg=syslog_message.message.decode('utf-8'),
        msg_id=None,
        process_id=None,
        sd={},
        severity=syslog_message.severity.name,
        timestamp=syslog_message.timestamp.isoformat(),
        version=None,
        # Because RF-3164 doesn't return localized date, can't determine the localized time it occurred.
        occurred=None
    )


def parse_rfc_5424_format(log_message: bytes) -> SyslogMessageExtract:
    """
    Receives a log message which is in RFC 5424 format. Parses it into SyslogMessageExtract data class object
    Args:
        log_message (bytes): Syslog message.

    Returns:
        (SyslogMessageExtract): Extraction data class
    """
    try:
        syslog_message: SyslogMessage = SyslogMessage.parse(log_message.decode('utf-8'))
    except ParseError as e:
        raise DemistoException(f'Could not parse the log message. Error was: {e}') from e
    return SyslogMessageExtract(
        app_name=syslog_message.appname,
        facility=syslog_message.facility.name,
        host_name=syslog_message.hostname,
        msg=syslog_message.msg,
        msg_id=syslog_message.msgid,
        process_id=syslog_message.procid,
        sd=syslog_message.sd,
        severity=syslog_message.severity.name,
        timestamp=syslog_message.timestamp,
        version=syslog_message.version,
        occurred=syslog_message.timestamp
    )


RFC3164 = 'RFC3164'
RFC5424 = 'RFC5424'
FORMAT_TO_PARSER_FUNCTION: Dict[str, Callable[[bytes], SyslogMessageExtract]] = {
    RFC3164: parse_rfc_3164_format,
    RFC5424: parse_rfc_5424_format
}


def test_module() -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Returns:
        (str): 'ok' if test passed, anything else will fail the test.
    """
    return 'ok'


def fetch_samples() -> None:
    """
    Retrieves samples from context.
    """
    demisto.incidents(get_integration_context().get('samples'))


def create_incident_from_syslog_message(extracted_message: SyslogMessageExtract, incident_type: Optional[str]) -> dict:
    """
    Creates incident from the extracted Syslog message.
    Args:
        extracted_message (SyslogMessageExtract): Syslog message extraction details.
        incident_type (Optional[str]): Incident type.

    Returns:
        (dict): Incident.
    """
    return {
        'name': f'Syslog from [{extracted_message.host_name}][{extracted_message.timestamp}]',
        'rawJSON': json.dumps(vars(extracted_message)),
        'occurred': extracted_message.occurred,
        'type': incident_type
    }


def update_integration_context_samples(incident: dict, max_samples: int = MAX_SAMPLES) -> None:
    """
    Updates the integration context samples with the newly created incident.
    If the size of the samples has reached `MAX_SAMPLES`, will pop out the latest sample.
    Args:
        incident (dict): The newly created incident.
        max_samples (int): Max samples size.

    Returns:
        (None): Modifies the integration context samples field.
    """
    ctx = get_integration_context()
    updated_samples_list: List[Dict] = [incident] + ctx.get('samples', [])
    if len(updated_samples_list) > max_samples:
        updated_samples_list.pop()
    ctx['samples'] = updated_samples_list
    set_integration_context(ctx)


def log_message_passes_filter(log_message: SyslogMessageExtract, message_regex: Optional[str]) -> bool:
    """
    Given log message extraction and a possible message regex, checks if the message passes the filters:
    1) Message regex is None, therefore no filter was asked to be made.
    2) Message regex is not None: Filter the Syslog message if regex does not exist in the message,
                                  if regex exists in the Syslog message, do not filter.
    Args:
        log_message (SyslogMessageExtract): The extracted details of a Syslog message.
        message_regex (Optional[str]): Message regex to match if exists.

    Returns:
        (bool): True if the message shouldn't be filtered, false if the message should be filtered.
    """
    if not message_regex:
        return True
    regexp = re.compile(message_regex)
    return True if regexp.search(log_message.msg) else False


def perform_long_running_loop(socket_data: bytes):
    """
    Performs one loop of a long running execution.
    - Gets data from socket.
    - Parses the Syslog message data.
    - If the Syslog message data passes filter, creates a new incident.
    - Saves the incident in integration context for samples.
    Args:
        socket_data (bytes): Retrieved socket data.

    Returns:
        (None): Creates incident in Cortex XSOAR platform.
    """
    extracted_message: SyslogMessageExtract = FORMAT_TO_PARSER_FUNCTION[LOG_FORMAT](socket_data)
    if log_message_passes_filter(extracted_message, MESSAGE_REGEX):
        incident: dict = create_incident_from_syslog_message(extracted_message, INCIDENT_TYPE)
        update_integration_context_samples(incident)
        demisto.createIncidents([incident])


def perform_long_running_execution(sock: Any, _: tuple) -> None:
    """
    The long running execution loop. Gets input, and performs a while True loop and logs any error that happens.
    Stops when there is no more data to read.
    Args:
        sock: Socket.
        _: Address. Not used inside loop so marked as underscore.

    Returns:
        (None): Reads data, calls   that creates incidents from inputted data.
    """
    demisto.error('Starting long running execution')
    file_obj = sock.makefile(mode='rb')
    while True:
        demisto.error('Waiting for line')
        line = file_obj.readline()
        demisto.error(f'line read: {line}')
        if not line:
            demisto.info('Disconnect')
            break
        perform_long_running_loop(line)
    file_obj.close()


def prepare_globals_and_create_server(port: int, log_format: str, message_regex: Optional[str],
                                      incident_type: Optional[str], certificate: Optional[str],
                                      private_key: Optional[str]) -> StreamServer:
    """
    Prepares global environments of LOG_FORMAT, MESSAGE_REGEX, INCIDENT_TYPE and creates the server to listen
    to Syslog messages.
    Args:
        port (int): Port
        log_format (str): Log format of messages to be received from Syslog, either RFC-3164 or RFC-5424.
        message_regex (Optional[str]): Regex. Will create incident only if Syslog message matches this regex.
        incident_type (Optional[str]): Incident type.
        certificate (Optional[str]): Certificate. For SSL connection.
        private_key (Optional[str]): Private key. For SSL connection.

    Returns:
        (StreamServer): Server to listen to Syslog messages.
    """
    global LOG_FORMAT, MESSAGE_REGEX, INCIDENT_TYPE
    LOG_FORMAT = log_format
    MESSAGE_REGEX = message_regex
    INCIDENT_TYPE = incident_type
    if certificate and private_key:
        certificate_file = NamedTemporaryFile(delete=False)
        certificate_path = certificate_file.name
        certificate_file.write(bytes(certificate, 'utf-8'))
        certificate_file.close()
        cert_file = certificate_path

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_path = private_key_file.name
        private_key_file.write(bytes(private_key, 'utf-8'))
        private_key_file.close()
        keyfile = private_key_path

        server = StreamServer(('0.0.0.0', port), perform_long_running_execution, keyfile=keyfile,
                              certfile=cert_file)
        demisto.debug('Starting HTTPS Server')
    else:
        server = StreamServer(('0.0.0.0', port), perform_long_running_execution)
        demisto.debug('Starting HTTP Server')
    return server


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    message_regex: Optional[str] = params.get('message_regex')
    incident_type: Optional[str] = params.get('incident_type')
    certificate: Optional[str] = params.get('certificate', {}).get('password')
    private_key: Optional[str] = params.get('private_key', {}).get('password')

    log_format: str = params.get('log_format', '')
    if log_format not in FORMAT_TO_PARSER_FUNCTION:
        raise DemistoException(f'Given format: {log_format} is not in the expected format.\n'
                               f'Please choose one of the following formats: {FORMAT_TO_PARSER_FUNCTION.keys()}')

    try:
        port = int(params.get('longRunningPort'))
    except (ValueError, TypeError) as e:
        raise DemistoException(f'Invalid listen port - {e}') from e
    if port < 0 or MAX_PORT < port:
        raise DemistoException(f'Given port: {port} is not valid and must be between 0-{MAX_PORT}')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            return_results(test_module())
        elif command == 'fetch-incidents':
            fetch_samples()
        elif command == 'long-running-execution':
            server: StreamServer = prepare_globals_and_create_server(port, log_format, message_regex, incident_type,
                                                                     certificate, private_key)
            server.serve_forever()
        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

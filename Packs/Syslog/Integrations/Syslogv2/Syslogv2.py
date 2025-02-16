from dataclasses import dataclass
from tempfile import NamedTemporaryFile
from typing import Callable

import urllib3

import syslogmp
from gevent.server import StreamServer
from syslog_rfc5424_parser import SyslogMessage, ParseError

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MAX_SAMPLES = 10
BUF_SIZE = 1024
MESSAGE_REGEX: Optional[str] = None
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


def parse_no_length_limit(data: bytes) -> syslogmp.parser.Message:
    """
    Parse a syslog message with no length limit.
    """
    parser = syslogmp.parser._Parser(b'')
    parser.stream = syslogmp.parser.Stream(data)

    priority_value = parser._parse_pri_part()
    timestamp, hostname = parser._parse_header_part()
    message = parser._parse_msg_part()

    return syslogmp.parser.Message(
        facility=priority_value.facility,
        severity=priority_value.severity,
        timestamp=timestamp,
        hostname=hostname,
        message=message,
    )


def parse_rfc_3164_format(log_message: bytes) -> Optional[SyslogMessageExtract]:
    """
    Receives a log message which is in RFC 3164 format. Parses it into SyslogMessageExtract data class object
    Args:
        log_message (bytes): Syslog message.

    Returns:
        (Optional[SyslogMessageExtract]): Extraction data class
    """
    try:
        syslog_message: syslogmp.Message = parse_no_length_limit(log_message)
    except syslogmp.parser.MessageFormatError as e:
        demisto.debug(f'Could not parse the log message, got MessageFormatError. Error was: {e}. Message is: {log_message.decode("utf-8")}')
        return None
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


def parse_rfc_5424_format(log_message: bytes) -> Optional[SyslogMessageExtract]:
    """
    Receives a log message which is in RFC 5424 format. Parses it into SyslogMessageExtract data class object
    Args:
        log_message (bytes): Syslog message.

    Returns:
        (Optional[SyslogMessageExtract]): Extraction data class
    """
    try:
        syslog_message: SyslogMessage = SyslogMessage.parse(log_message.decode('utf-8'))
    except ParseError as e:
        demisto.debug(f'Could not parse the log message, got ParseError. Error was: {e}. Message is {log_message.decode("utf-8")}')
        return None
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


def parse_rfc_6587_format(log_message: bytes) -> Optional[SyslogMessageExtract]:
    """
    Receives a log message which is in RFC 6587 format. Parses it into SyslogMessageExtract data class object
    Args:
        log_message (bytes): Syslog message.

    Returns:
        (SyslogMessageExtract): Extraction data class
    """
    log_message = log_message.decode('utf-8')
    split_msg: List[str] = log_message.split(' ')
    if not log_message or not log_message[0].isdigit() or not len(split_msg) > 1:
        return None
    try:
        log_message = ' '.join(split_msg[1:])
        encoded_msg = log_message.encode()
        for format_func in format_funcs:
            # if it is RFC6587 itself, continue
            if format_func == parse_rfc_6587_format:
                continue
            extracted_message = format_func(encoded_msg)
            if extracted_message:
                return extracted_message
    except ValueError as e:
        demisto.debug(f'Could not parse the log message, got ValueError. Error was: {e}. Message is {log_message.decode("utf-8")}')
        return None
    return None


format_funcs: List[Callable[[bytes], Optional[SyslogMessageExtract]]] = [parse_rfc_3164_format, parse_rfc_5424_format,
                                                                         parse_rfc_6587_format]


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
        incident_type (Optional[str]): The incident type

    Returns:
        (dict): Incident.
    """
    return {
        'name': f'Syslog from [{extracted_message.host_name}][{extracted_message.timestamp}]',
        'rawJSON': json.dumps(vars(extracted_message)),
        'occurred': extracted_message.occurred,
        'type': incident_type,
        'details': '\n'.join([f'{k}: {v}' for k, v in vars(extracted_message).items() if v])
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
    incident_type: Optional[str] = demisto.params().get('incident_type', '')
    extracted_message: Optional[SyslogMessageExtract] = None
    for format_func in format_funcs:
        extracted_message = format_func(socket_data)
        if extracted_message:
            demisto.debug(f'Succeeded in parsing the message with {format_func}')
            break
    if not extracted_message:
        raise DemistoException(f'Could not parse the following message: {socket_data.decode("utf-8")}')

    if log_message_passes_filter(extracted_message, MESSAGE_REGEX):
        incident: dict = create_incident_from_syslog_message(extracted_message, incident_type)
        update_integration_context_samples(incident)
        demisto.createIncidents([incident])


def perform_long_running_execution(sock: Any, address: tuple) -> None:
    """
    The long running execution loop. Gets input, and performs a while True loop and logs any error that happens.
    Stops when there is no more data to read.
    Args:
        sock: Socket.
        address(tuple): Address. Not used inside loop so marked as underscore.

    Returns:
        (None): Reads data, calls   that creates incidents from inputted data.
    """
    demisto.debug('Starting long running execution')
    file_obj = sock.makefile(mode='rb')
    try:
        while True:
            try:
                line = file_obj.readline()
                if not line:
                    demisto.info(f'Disconnected from {address}')
                    break
                socket_data = line.strip()
                demisto.debug(f"####Syslog Performing long_running_loop on data {socket_data}")
                perform_long_running_loop(socket_data)
            except Exception as e:
                demisto.error(traceback.format_exc())  # print the traceback
                demisto.error(f'Error occurred during long running loop. Error was: {e}')
            finally:
                demisto.debug('Finished reading message')
    finally:
        file_obj.close()


def prepare_globals_and_create_server(port: int, message_regex: Optional[str], certificate: Optional[str],
                                      private_key: Optional[str]) -> StreamServer:
    """
    Prepares global environments of LOG_FORMAT, MESSAGE_REGEX and creates the server to listen
    to Syslog messages.
    Args:
        port (int): Port
        message_regex (Optional[str]): Regex. Will create incident only if Syslog message matches this regex.
        certificate (Optional[str]): Certificate. For SSL connection.
        private_key (Optional[str]): Private key. For SSL connection.

    Returns:
        (StreamServer): Server to listen to Syslog messages.
    """
    global MESSAGE_REGEX
    MESSAGE_REGEX = message_regex
    if certificate and private_key:
        certificate_file = NamedTemporaryFile(delete=False)
        certificate_path = certificate_file.name
        certificate_file.write(bytes(certificate, 'utf-8'))
        certificate_file.close()

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_path = private_key_file.name
        private_key_file.write(bytes(private_key, 'utf-8'))
        private_key_file.close()
        server = StreamServer(('0.0.0.0', port), perform_long_running_execution, keyfile=private_key_path,
                              certfile=certificate_path)
        demisto.debug('Starting HTTPS Server')
    else:
        server = StreamServer(('0.0.0.0', port), perform_long_running_execution)
        demisto.debug('Starting HTTP Server')
    return server


def get_mapping_fields() -> Dict[str, str]:
    return {
        'app_name': 'Application Name',
        'facility': 'Facility',
        'host_name': 'Host Name',
        'msg': 'Message',
        'msg_id': 'Message ID',
        'process_id': 'Process ID',
        'sd': 'Structured Data',
        'severity': 'Severity',
        'timestamp': 'Timestamp',
        'version': 'Syslog Version',
        'occurred': 'Occurred Time'
    }


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    message_regex: Optional[str] = params.get('message_regex')
    certificate = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('identifier'))
                   or params.get('certificate'))
    private_key = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('password', ''))
                   or params.get('private_key'))
    port: Union[Optional[str], int] = params.get('longRunningPort')
    try:
        port = int(params.get('longRunningPort'))
    except (ValueError, TypeError):
        raise DemistoException('Please select an engine and insert a valid listen port.')
    if port < 0 or port > MAX_PORT:
        raise DemistoException(f'Given port: {port} is not valid and must be between 0-{MAX_PORT}')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            try:
                prepare_globals_and_create_server(port, message_regex, certificate, private_key)
            except OSError as e:
                if 'Address already in use' in str(e):
                    raise DemistoException(f'Given port: {port} is already in use. Please either change port or '
                                           f'make sure to close the connection in the server using that port.')
                raise e
            return_results('ok')
        elif command == 'fetch-incidents':
            # The integration fetches incidents in the long-running-execution command. Fetch incidents is called
            # only when "Pull From Instance" is clicked in create new classifier section in Cortex XSOAR.
            # The fetch incidents returns samples of incidents generated by the long-running-execution.
            fetch_samples()
        elif command == 'long-running-execution':
            server: StreamServer = prepare_globals_and_create_server(port, message_regex, certificate, private_key)
            server.serve_forever()
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields())
        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

from dataclasses import dataclass
from typing import Callable

import syslogmp
from syslog_rfc5424_parser import SyslogMessage, ParseError

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MAX_SAMPLES = 10
BUF_SIZE = 1024


@dataclass
class SyslogMessageExtract:
    app_name: Optional[str]  # su
    facility: str  # SyslogFacility.auth
    host_name: Optional[str]  # client_machine
    msg: str  # su root failed for joe on /dev/pts/2
    msg_id: Optional[str]  # None
    process_id: Optional[str]  # None
    sd: dict  # sd
    severity: str  # err
    timestamp: str  # date
    version: Optional[int]  # 1


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
        version=None
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
        version=syslog_message.version
    )


RFC3164 = 'RFC3164'
RFC5424 = 'RFC5424'
FORMAT_TO_PARSER_FUNCTION: Dict[str, Callable[[bytes], SyslogMessageExtract]] = {
    RFC3164: parse_rfc_3164_format,
    RFC5424: parse_rfc_5424_format
}


def test_module(host_address: str, port: int) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        host_address (str): Host address
        port (int): Port

    Returns:
        (str): 'ok' if test passed, anything else will fail the test.
    """
    message: str = 'ok'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host_address, port))
        except OSError as e:
            if "Can't assign requested address" in str(e):
                message = 'The given IP address could not be accessed\n.Please make sure the IP address in valid' \
                          ' and can be accessed.'
            elif 'nodename nor servname provided, or not known' in str(e):
                message = 'Could not find the host address. Please verify host address is correct.'
            elif 'Permission denied' in str(e):
                message = 'Permission was denied. Make sure you have permissions to access to the given port.'
            else:
                raise e
    return message


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
        'occurred': extracted_message.timestamp,
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


def perform_long_running_loop(s: socket.socket, log_format: str, message_regex: Optional[str],
                              incident_type: Optional[str]) -> None:
    """
    Performs one loop of a long running execution.
    - Waits for data from socket
    - Parses the Syslog message data.
    - If the Syslog message data passes filter, creates a new incident.
    - Saves the incident in integration context for samples.
    Args:
        s (socket.socket): Socket to retrieve Syslog messages from.
        log_format (str): The Syslog format the messages will be sent with. one of the dictionary keys of the
                          constant `FORMAT_TO_PARSER_FUNCTION` variable.
        message_regex (Optional[str]): Message regex to match if exists.
        incident_type (Optional[str]): Incident type.

    Returns:
        (None): Creates incident in Cortex XSOAR platform.
    """
    data, address = s.recvfrom(BUF_SIZE)
    extracted_message: SyslogMessageExtract = FORMAT_TO_PARSER_FUNCTION[log_format](data)
    if log_message_passes_filter(extracted_message, message_regex):
        incident: dict = create_incident_from_syslog_message(extracted_message, incident_type)
        update_integration_context_samples(incident)
        demisto.createIncidents([incident])


def perform_long_running_execution(host_address: str, port: int, log_format: str, protocol: str,
                                   message_regex: Optional[str], incident_type: Optional[str]):
    """
    The long running execution loop. Binds a socket, and performs a while True loop and logs any error that happens.
    Args:
        host_address (str): The host address to connect to.
        port (int): Port.
        log_format (str): The Syslog format the messages will be sent with. one of the dictionary keys of the
                          constant `FORMAT_TO_PARSER_FUNCTION` variable.
        protocol (str): TODO
        message_regex (Optional[str]): Message regex. If given, will only create incidents of Syslog messages whom
                                       matches this filter.
        incident_type (Optional[str]): Incident type.

    Returns:

    """
    # Create socket and bind to address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host_address, port))
        except OSError as e:
            if "Can't assign requested address" in str(e):
                raise DemistoException('The given IP address could not be accessed\n.Please make sure the IP address '
                                       'is valid and can be accessed.')
            elif 'nodename nor servname provided, or not known' in str(e):
                raise DemistoException('Could not find the host address. Please verify host address is correct.')
            elif 'Permission denied' in str(e):
                raise DemistoException(
                    'Permission was denied. Make sure you have permissions to access to the given port.')
            else:
                raise e
        while True:
            try:
                perform_long_running_loop(s, log_format, message_regex, incident_type)
            except Exception as e:
                demisto.error(f'Error occurred during long running loop: {e}')
                demisto.error(traceback.format_exc())


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    # params = {
    #     'host_address': '127.0.0.1',
    #     'longRunningPort': 32376,
    #     'log_format': RFC3164
    # }
    # command = 'long-running-execution'

    host_address: str = params.get('host_address', '')
    protocol: str = params.get('protocol', '')
    message_regex: Optional[str] = params.get('message_regex')
    incident_type: Optional[str] = params.get('incident_type')

    log_format: str = params.get('log_format', '')
    if log_format not in FORMAT_TO_PARSER_FUNCTION:
        raise DemistoException(f'Given format: {log_format} is not in the expected format.\n'
                               f'Please choose one of the following formats: {FORMAT_TO_PARSER_FUNCTION.keys()}')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        try:
            port = int(params.get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if command == 'test-module':
            return_results(test_module(host_address, port))
        elif command == 'fetch-incidents':
            fetch_samples()
        elif command == 'long-running-execution':
            perform_long_running_execution(host_address, port, log_format, protocol, message_regex, incident_type)
        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    # z = b'<116>Nov  9 17:07:20 M-C02DKB3QMD6M softwareupdated[288]: Removing client SUUpdateServiceClient pid=90550, uid=375597002, installAuth=NO rights=(), transactions=0 (/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents/XPCServices/com.apple.preferences.softwareupdate.remoteservice.xpc/Contents/MacOS/com.apple.preferences.softwareupdate.remoteservice)\n'
    # z = """<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry"""
    # x = SyslogMessage.parse(z)
    # z = 2
    # x = syslogmp.parse(z)
    # zzz = 32
    main()

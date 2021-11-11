from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import syslogmp
from syslog_rfc5424_parser import SyslogMessage
from dataclasses import dataclass
from typing import Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MAX_SAMPLES = 10
BUF_SIZE=1024
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
    syslog_message: syslogmp.Message = syslogmp.parse(log_message)
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
    syslog_message: SyslogMessage = SyslogMessage.parse(log_message.decode('utf-8'))
    return SyslogMessageExtract(
        app_name=syslog_message.appname,
        facility=syslog_message.facility,
        host_name=syslog_message.hostname,
        msg=syslog_message.msg,
        msg_id=syslog_message.msgid,
        process_id=syslog_message.procid,
        sd=syslog_message.sd,
        severity=syslog_message.severity,
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
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host_address, port))
        except OSError as e:
            if "Can't assign requested address" in str(e):
                message = 'The given IP address could not be accessed\n.Please make sure the IP address in valid and can be accessed.'
    return message


def fetch_samples() -> None:
    """
    Retrieves samples from context.
    """
    demisto.incidents(get_integration_context().get('samples'))


def create_incident_from_log_message(log_message: str):
    return {
        'Name': f'Syslog from [hostname][date_formatab]',
        'RawJSON': json.dumps(log_message),
        'Details': 'details'
    }

def perform_long_running_loop(s: socket.socket, log_format: str, message_regex: str,
                              incident_type: Optional[str]) -> None:
    data, address = s.recvfrom(BUF_SIZE)
    extracted_message: SyslogMessageExtract = FORMAT_TO_PARSER_FUNCTION[log_format](data)
    if log_message_passes_filter(extracted_message, message_regex):
        incident: dict = {
            'name': f'Syslog from [{extracted_message.host_name}][{extracted_message.timestamp}]',
            'rawJSON': json.dumps(vars(extracted_message)),
            'occurred': extracted_message.timestamp,
            'type': incident_type
        }
        ctx = get_integration_context()
        updated_samples_list: List[Dict] = [incident] + ctx.get('samples', [])
        if len(updated_samples_list) > MAX_SAMPLES:
            updated_samples_list.pop()
        ctx['samples'] = updated_samples_list
        demisto.createIncidents([incident])
def log_message_passes_filter(log_message: SyslogMessageExtract, message_regex: str) -> bool:
    return not message_regex or (True if re.match(message_regex, log_message.msg) else False)


def perform_long_running_execution(host_address: str, port: int, log_format: str, protocol: str, message_regex: str,
                                   incident_type: Optional[str]):
    # Create socket and bind to address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host_address, port))
        except OSError as e:
            if "Can't assign requested address" in str(e):
                raise DemistoException('The given IP address could not be accessed\n.'
                                       'Please make sure the IP address in valid and can be accessed.') from e
        while True:
            try:
                perform_long_running_loop(s, log_format, message_regex, incident_type)
            except Exception as e:
                demisto.error(f'Error occurred during long running loop: {e}')
                demisto.error(traceback.format_exc())


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    params = {
        'host_address': '127.0.0.1',
        'longRunningPort': 32376,
        'log_format': RFC3164
    }
    command = 'test-module'

    host_address: str = params.get('host_address', '')
    protocol: str = params.get('protocol', '')
    message_regex: str = params.get('message_regex', '')
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
            perform_long_running_execution(
                host_address,
                port,
                log_format,
                protocol,
                message_regex,
                incident_type
            )
        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    z = b'<116>Nov  9 17:07:20 M-C02DKB3QMD6M softwareupdated[288]: Removing client SUUpdateServiceClient pid=90550, uid=375597002, installAuth=NO rights=(), transactions=0 (/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents/XPCServices/com.apple.preferences.softwareupdate.remoteservice.xpc/Contents/MacOS/com.apple.preferences.softwareupdate.remoteservice)\n'
    # z = """<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry"""
    # x = SyslogMessage.parse(z)
    # z = 2
    x = syslogmp.parse(z)
    zzz = 32
    main()

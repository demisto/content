import json
import io
import pytest
from Syslog_v2 import parse_rfc_3164_format, parse_rfc_5424_format, test_module, fetch_samples, \
    create_incident_from_syslog_message, Callable, SyslogMessageExtract, Optional, update_integration_context_samples, \
    log_message_passes_filter, perform_long_running_loop
from CommonServerPython import DemistoException, set_integration_context, get_integration_context, socket
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


rfc_test_data = util_load_json('./test_data/rfc_test_data.json')


@pytest.mark.parametrize('test_case, func', [(rfc_test_data['rfc-3164']['case_one_valid'], parse_rfc_3164_format),
                                             (rfc_test_data['rfc-3164']['case_two_valid'], parse_rfc_3164_format),
                                             (rfc_test_data['rfc-5424']['case_one_valid'], parse_rfc_5424_format),
                                             (rfc_test_data['rfc-5424']['case_two_valid'], parse_rfc_5424_format)])
def test_parse_rfc_format_valid(test_case: dict, func: Callable[[bytes], SyslogMessageExtract]):
    """
    Given:
    - log_message: Syslog message.

    When:
    - Parsing the Syslog message into SyslogMessageExtract data class.

    Then:
    - Ensure the expected data is returned.

    """
    assert vars(func(test_case['log_message'].encode())) == test_case['expected_vars']


@pytest.mark.parametrize('test_case, func, err_message', [(rfc_test_data['rfc-3164']['case_weird_message'],
                                                           parse_rfc_3164_format,
                                                           'Could not parse the log message. Error was: PRI part must '
                                                           'have 3, 4, or 5 bytes.'),
                                                          (rfc_test_data['rfc-3164']['case_rfc-5424_format'],
                                                           parse_rfc_3164_format,
                                                           "Could not parse the log message. Error was: time data "
                                                           "'2021 1 2003-10-11T22' does not match format '%Y %b %d "
                                                           "%H:%M:%S'"),
                                                          (rfc_test_data['rfc-3164']['case_garbage_timestamp'],
                                                           parse_rfc_3164_format,
                                                           'Could not parse the log message. Error was: Timestamp '
                                                           'must be followed by a space character.'),
                                                          (rfc_test_data['rfc-5424']['case_weird_message'],
                                                           parse_rfc_5424_format,
                                                           "Could not parse the log message. Error was: Unable to "
                                                           "parse message: 'Some message not in rfc 5424 format'"),
                                                          (rfc_test_data['rfc-5424']['case_rfc-3164_format'],
                                                           parse_rfc_5424_format,
                                                           "Could not parse the log message. Error was: Unable to "
                                                           "parse message: '<116>Nov  9 17:07:20 HostName "
                                                           "softwareupdated[288]: Removing client "
                                                           "SUUpdateServiceClient pid=90550, uid=375597002, "
                                                           "installAuth=NO rights=(), transactions=0 ("
                                                           "/System/Library/PreferencePanes/SoftwareUpdate.prefPane"
                                                           "/Contents/XPCServices/com.apple.preferences"
                                                           ".softwareupdate.remoteservice.xpc/Contents/MacOS/com"
                                                           ".apple.preferences.softwareupdate.remoteservice)'")
                                                          ])
def test_parse_rfc_not_valid(test_case: dict, func: Callable[[bytes], SyslogMessageExtract], err_message: str):
    """
    Given:
    - log_message: Syslog message.

    When:
    - Parsing the Syslog message and the log message is not in the expected format.

    Then:
    - Ensure expected error is returned with the expected error message.

    """
    import re
    with pytest.raises(DemistoException, match=re.escape(err_message)):
        func(test_case['log_message'].encode())


@pytest.mark.parametrize('host_address, port, expected', [('127.0.0.1', 36666, 'ok'),
                                                          ('abc', 36666, 'Could not find the host address. Please '
                                                                         'verify host address is correct.'),
                                                          ('127.0.0.1', 1, 'Permission was denied. Make sure you have '
                                                                           'permissions to access to the given '
                                                                           'port.')])
def test_module_test(host_address: str, port: int, expected: str):
    """
    Given:
    - host_address: Host to connect to.
    - port: Port.

    When:
    - Executing test module command

    Then:
    - Ensure expected message is returned.

    """
    assert test_module(host_address, port) == expected


@pytest.mark.parametrize('samples', [({}), ([{'app_name': None, 'facility': 'security4', 'host_name': 'mymachine',
                                              'msg': "su: 'su root' failed for lonvick on /dev/pts/8", 'msg_id': None,
                                              'process_id': None, 'sd': {}, 'severity': 'critical',
                                              'timestamp': '2021-10-11T22:14:15', 'version': None}]),
                                     [{'app_name': None, 'facility': 'security4', 'host_name': 'mymachine',
                                       'msg': "su: 'su root' failed for lonvick on /dev/pts/8", 'msg_id': None,
                                       'process_id': None, 'sd': {}, 'severity': 'critical',
                                       'timestamp': '2021-10-11T22:14:15', 'version': None},
                                      {'app_name': 'evntslog', 'facility': 'local4',
                                       'host_name': 'mymachine.example.com',
                                       'msg': 'BOMAn application event log entry', 'msg_id': 'ID47',
                                       'process_id': None,
                                       'sd': {'exampleSDID@32473': {'eventID': '1011', 'eventSource': 'Application',
                                                                    'iut': '3'}}, 'severity': 'notice',
                                       'timestamp': '2003-10-11T22:14:15.003Z', 'version': 1}]])
def test_fetch_samples(samples: list[dict], mocker):
    """
    Given:

    When:
    - Calling fetch samples

    Then:
    - Ensure samples in context are returned.
    """
    set_integration_context({'samples': samples})
    mock_incident = mocker.patch.object(demisto, 'incidents')
    fetch_samples()
    assert mock_incident.call_args[0][0] == samples


@pytest.mark.parametrize('extracted_msg, incident_type, expected',
                         [(SyslogMessageExtract(
                             app_name='evntslog',
                             facility='local4',
                             host_name='mymachine.example.com',
                             msg='BOMAn application event log entry',
                             msg_id='ID47',
                             process_id=123,
                             sd={
                                 'exampleSDID@32473': {
                                     'eventID': '1011',
                                     'eventSource': 'Application',
                                     'iut': '3'
                                 }
                             },
                             severity='critical',
                             timestamp='2003-10-11T22:14:15.003Z',
                             version=1,
                             occurred='2003-10-11T22:14:15.003Z'),
                           None,
                           {'name': 'Syslog from [mymachine.example.com][2003-10-11T22:14:15.003Z]',
                            'occurred': '2003-10-11T22:14:15.003Z',
                            'rawJSON': '{"app_name": "evntslog", "facility": "local4", "host_name": '
                                       '"mymachine.example.com", "msg": "BOMAn application event log '
                                       'entry", "msg_id": "ID47", "process_id": 123, "sd": '
                                       '{"exampleSDID@32473": {"eventID": "1011", "eventSource": '
                                       '"Application", "iut": "3"}}, "severity": "critical", "timestamp": '
                                       '"2003-10-11T22:14:15.003Z", "version": 1, '
                                       '"occurred": "2003-10-11T22:14:15.003Z"}',
                            'type': None}),
                             (SyslogMessageExtract(
                                 app_name='evntslog',
                                 facility='local4',
                                 host_name='mymachine.example.com',
                                 msg='BOMAn application event log entry',
                                 msg_id='ID47',
                                 process_id=123,
                                 sd={
                                     'exampleSDID@32473': {
                                         'eventID': '1011',
                                         'eventSource': 'Application',
                                         'iut': '3'
                                     }
                                 },
                                 severity='critical',
                                 timestamp='2003-10-11T22:14:15.003Z',
                                 version=1,
                                 occurred='2003-10-11T22:14:15.003Z'),
                              'Syslog Alert RFC-5424',
                              {'name': 'Syslog from [mymachine.example.com][2003-10-11T22:14:15.003Z]',
                               'occurred': '2003-10-11T22:14:15.003Z',
                               'rawJSON': '{"app_name": "evntslog", "facility": "local4", "host_name": '
                                          '"mymachine.example.com", "msg": "BOMAn application event log '
                                          'entry", "msg_id": "ID47", "process_id": 123, "sd": '
                                          '{"exampleSDID@32473": {"eventID": "1011", "eventSource": '
                                          '"Application", "iut": "3"}}, "severity": "critical", "timestamp": '
                                          '"2003-10-11T22:14:15.003Z", "version": 1, '
                                          '"occurred": "2003-10-11T22:14:15.003Z"}',
                               'type': 'Syslog Alert RFC-5424'}),
                             (SyslogMessageExtract(
                                 app_name=None,
                                 facility='log_alert',
                                 host_name='mymachine.example.com',
                                 msg="softwareupdated[288]: Removing client SUUpdateServiceClient pid=90550, "
                                     "uid=375597002, installAuth=NO rights=(), transactions=0 ("
                                     "/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents/XPCServices"
                                     "/com.apple.preferences.softwareupdate.remoteservice.xpc/Contents/MacOS/com"
                                     ".apple.preferences.softwareupdate.remoteservice)",
                                 msg_id=None,
                                 process_id=None,
                                 sd={},
                                 severity='warning',
                                 timestamp='2021-11-09T17:07:20',
                                 version=None,
                                 occurred=None),
                              None,
                              {'name': 'Syslog from [mymachine.example.com][2021-11-09T17:07:20]',
                               'occurred': None,
                               'rawJSON': '{"app_name": null, "facility": "log_alert", "host_name": '
                                          '"mymachine.example.com", "msg": "softwareupdated[288]: Removing '
                                          'client SUUpdateServiceClient pid=90550, uid=375597002, '
                                          'installAuth=NO rights=(), transactions=0 '
                                          '(/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents'
                                          '/XPCServices/com.apple.preferences.softwareupdate.remoteservice.xpc'
                                          '/Contents/MacOS/com.apple.preferences.softwareupdate.remoteservice)", '
                                          '"msg_id": null, "process_id": null, "sd": {}, "severity": '
                                          '"warning", "timestamp": "2021-11-09T17:07:20", "version": null, '
                                          '"occurred": null}',
                               'type': None}),
                             (SyslogMessageExtract(
                                 app_name=None,
                                 facility='log_alert',
                                 host_name='mymachine.example.com',
                                 msg="softwareupdated[288]: Removing client SUUpdateServiceClient pid=90550, "
                                     "uid=375597002, installAuth=NO rights=(), transactions=0 ("
                                     "/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents/XPCServices"
                                     "/com.apple.preferences.softwareupdate.remoteservice.xpc/Contents/MacOS/com"
                                     ".apple.preferences.softwareupdate.remoteservice)",
                                 msg_id=None,
                                 process_id=None,
                                 sd={},
                                 severity='warning',
                                 timestamp='2021-11-09T17:07:20',
                                 version=None,
                                 occurred=None),
                              'Syslog Alert RFC-3164',
                              {'name': 'Syslog from [mymachine.example.com][2021-11-09T17:07:20]',
                               'occurred': None,
                               'rawJSON': '{"app_name": null, "facility": "log_alert", "host_name": '
                                          '"mymachine.example.com", "msg": "softwareupdated[288]: Removing '
                                          'client SUUpdateServiceClient pid=90550, uid=375597002, '
                                          'installAuth=NO rights=(), transactions=0 '
                                          '(/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents'
                                          '/XPCServices/com.apple.preferences.softwareupdate.remoteservice.xpc'
                                          '/Contents/MacOS/com.apple.preferences.softwareupdate.remoteservice)", '
                                          '"msg_id": null, "process_id": null, "sd": {}, "severity": '
                                          '"warning", "timestamp": "2021-11-09T17:07:20", "version": null, '
                                          '"occurred": null}',
                               'type': 'Syslog Alert RFC-3164'})])
def test_create_incident_from_syslog_message(extracted_msg: SyslogMessageExtract, incident_type: Optional[str],
                                             expected: dict):
    """
    Given:
    - Extracted Syslog message
    - Incident type

    When:
    - Converting extracted message to incident
    Cases:
        Case 1: RFC 5424 message without incident type specified.
        Case 2: RFC 5424 message with incident type specified.
        Case 3: RFC 3164 message without incident type specified.
        Case 4: RFC 3164 message with incident type specified.

    Then:
    - Ensure expected incident is created
    """
    assert create_incident_from_syslog_message(extracted_msg, incident_type) == expected


INCIDENT_EXAMPLE = {'name': 'Syslog from [mymachine.example.com][2021-11-09T17:07:20]',
                    'occurred': '2021-11-09T17:07:20',
                    'rawJSON': '{"app_name": null, "facility": "log_alert", "host_name": '
                               '"mymachine.example.com", "msg": "softwareupdated[288]: Removing '
                               'client SUUpdateServiceClient pid=90550, uid=375597002, '
                               'installAuth=NO rights=(), transactions=0 '
                               '(/System/Library/PreferencePanes/SoftwareUpdate.prefPane/Contents'
                               '/XPCServices/com.apple.preferences.softwareupdate.remoteservice.xpc'
                               '/Contents/MacOS/com.apple.preferences.softwareupdate.remoteservice)", '
                               '"msg_id": null, "process_id": null, "sd": {}, "severity": '
                               '"warning", "timestamp": "2021-11-09T17:07:20", "version": null}',
                    'type': 'Syslog Alert RFC-3164'}
INCIDENT_EXAMPLE2 = {'name': 'Syslog from [mymachine.example.com][2003-10-11T22:14:15.003Z]',
                     'occurred': '2003-10-11T22:14:15.003Z',
                     'rawJSON': '{"app_name": "evntslog", "facility": "local4", "host_name": '
                                '"mymachine.example.com", "msg": "BOMAn application event log '
                                'entry", "msg_id": "ID47", "process_id": 123, "sd": '
                                '{"exampleSDID@32473": {"eventID": "1011", "eventSource": '
                                '"Application", "iut": "3"}}, "severity": "critical", "timestamp": '
                                '"2003-10-11T22:14:15.003Z", "version": 1}',
                     'type': None}
INCIDENT_EXAMPLE3 = {'name': 'Syslog from [mymachine.example.com][2003-10-11T22:14:15.003Z]',
                     'occurred': '2003-10-11T22:14:15.003Z',
                     'rawJSON': '{"app_name": "evntslog", "facility": "local4", "host_name": '
                                '"mymachine.example.com", "msg": "BOMAn application event log '
                                'entry", "msg_id": "ID47", "process_id": 123, "sd": '
                                '{"exampleSDID@32473": {"eventID": "1011", "eventSource": '
                                '"Application", "iut": "3"}}, "severity": "critical", "timestamp": '
                                '"2003-10-11T22:14:15.003Z", "version": 1}',
                     'type': None}


@pytest.mark.parametrize('init_ctx, incident,sample_size, expected_context',
                         [({}, INCIDENT_EXAMPLE, 10, [INCIDENT_EXAMPLE]),
                          ({'samples': [INCIDENT_EXAMPLE]}, INCIDENT_EXAMPLE2, 10,
                           [INCIDENT_EXAMPLE2, INCIDENT_EXAMPLE]),
                          ({'samples': [INCIDENT_EXAMPLE]}, INCIDENT_EXAMPLE2, 1,
                           [INCIDENT_EXAMPLE2]),
                          ({'samples': [INCIDENT_EXAMPLE2, INCIDENT_EXAMPLE]}, INCIDENT_EXAMPLE3, 2,
                           [INCIDENT_EXAMPLE3, INCIDENT_EXAMPLE2])])
def test_update_integration_context_samples(init_ctx, incident, sample_size, expected_context):
    """
    Given:
    - incident: Incident.

    When:
    - Updating the samples with the given incident.
    Cases:
        Case 1: Context is empty.
        Case 2: Context is not empty, samples size not reached.
        Case 2: Context is not empty, samples size reached.
        Case 2: Context is not empty, samples size reached.

    Then:
    - Ensure context is updated as expected
    """
    set_integration_context(init_ctx)
    update_integration_context_samples(incident, sample_size)
    assert get_integration_context() == {'samples': expected_context}


MESSAGE_EXTRACT_EXAMPLE = SyslogMessageExtract(
    app_name='evntslog',
    facility='local4',
    host_name='mymachine.example.com',
    msg='BOMAn application event log entry',
    msg_id='ID47',
    process_id=123,
    sd={
        'exampleSDID@32473': {
            'eventID': '1011',
            'eventSource': 'Application',
            'iut': '3'
        }
    },
    severity='critical',
    timestamp='2003-10-11T22:14:15.003Z',
    version=1,
    occurred='2003-10-11T22:14:15.003Z')


@pytest.mark.parametrize('log_message, message_regex, expected', [(MESSAGE_EXTRACT_EXAMPLE, None, True),
                                                                  (MESSAGE_EXTRACT_EXAMPLE, 'event log', True),
                                                                  (MESSAGE_EXTRACT_EXAMPLE, 'error', False)])
def test_log_message_passes_filter(log_message, message_regex, expected):
    """
    Given:
    - log_message: Extracted Syslog message data.
    - message_regex: Regex to filter Syslog messages by.
    When:
    - Filtering log messages whom message does not contain `message_regex` if it was given.
    Cases:
        Case 1: Regex was not given.
        Case 2: Regex was given and exists in the log message.
        Case 3: Regex was given and does not exist in the log message.

    Then:
    - Ensure the expected result of filter is returned (True for cases 1 and 3, False for case 2).
    """
    assert log_message_passes_filter(log_message, message_regex) == expected


loop_data = util_load_json('./test_data/long_running_loop_data.json')


@pytest.mark.parametrize('test_data, test_name', [(loop_data['rfc-3164'], 'no_regex'),
                                                  (loop_data['rfc-3164'], 'regex_pass_filter'),
                                                  (loop_data['rfc-3164'], 'regex_doesnt_pass_filter'),
                                                  (loop_data['rfc-5424'], 'no_regex'),
                                                  (loop_data['rfc-5424'], 'regex_pass_filter'),
                                                  (loop_data['rfc-5424'], 'regex_doesnt_pass_filter')])
def test_perform_long_running_loop(mocker, test_data, test_name):
    """
    Given:
    - socket: Socket to retrieve Syslog messages from.
    - log_format: The Syslog format the messages will be sent with. one of the dictionary keys of the
                  constant `FORMAT_TO_PARSER_FUNCTION` variable.
    - message_regex: Message regex to match if exists.
    - incident_type: Incident type.
    When:
    - Performing one loop in the long-running execution
    Cases:
        Case 1: Log format is RFC 3164, no message regex.
        Case 2: Log format is RFC 3164, message regex, passes filter.
        Case 3: Log format is RFC 3164, message regex, doesn't pass filter.
        Case 4: Log format is RFC 5424, no message regex.
        Case 5: Log format is RFC 5424, message regex, passes filter.
        Case 6: Log format is RFC 5424, message regex, doesn't pass filter.

    Then:
    - Ensure incident is created if needed for each case, and exists in context data.
    """
    from mock import Mock
    import Syslog_v2
    tmp_format, tmp_reg, temp_incident = Syslog_v2.LOG_FORMAT, Syslog_v2.MESSAGE_REGEX, Syslog_v2.INCIDENT_TYPE
    test_name_data = test_data[test_name]
    Syslog_v2.LOG_FORMAT, Syslog_v2.MESSAGE_REGEX, Syslog_v2.INCIDENT_TYPE = test_data['log_format'], test_name_data.get('message_regex'), test_name_data.get('incident_type')
    set_integration_context({})
    incident_mock = mocker.patch.object(demisto, 'createIncidents')
    if test_name_data.get('expected'):
        perform_long_running_loop(test_data['log_message'].encode())
        assert incident_mock.call_args[0][0] == test_name_data.get('expected')
        assert get_integration_context() == {'samples': test_name_data.get('expected')}
    else:
        perform_long_running_loop(test_data['log_message'].encode())
        assert not demisto.createIncidents.called
        assert not get_integration_context()
    Syslog_v2.LOG_FORMAT, Syslog_v2.MESSAGE_REGEX, Syslog_v2.INCIDENT_TYPE = tmp_format, tmp_reg, temp_incident

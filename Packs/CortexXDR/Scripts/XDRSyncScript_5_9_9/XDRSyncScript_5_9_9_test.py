from CommonServerPython import *
import copy
import json
import XDRSyncScript_5_9_9 as xdr_script
from XDRSyncScript_5_9_9 import ASSIGNED_USER_MAIL_XDR_FIELD, MODIFICATION_TIME_XDR_FIELD, MANUAL_SEVERITY_XDR_FIELD, \
    SEVERITY_XDR_FIELD


INCIDENT_IN_DEMISTO = {
    "sourceInstance": "Palo Alto Networks Cortext XDR IR_instance_1",
    "occurred": "2019-05-30T14:32:22.398+03:00",
    "closeReason": "",
    "modified": "2019-06-02T11:15:09.323251+03:00",
    "CustomFields": {
        "xdrincidentid": "697567",
        "xdrurl": "http://example.com/incident-view/697567",
        "xdrdescription": "WildFire Malware detected on host HostNameFFM8VIP9",
        "xdralertcount": 1,
        "xdrstatus": "new",
        "xdrassignedusermail": "",
        "xdrassigneduserprettyname": "",
        "xdrmodificationtime": "2019-06-02T11:15:09.323251+03:00",
        "xdralerts": [
            {
                "category": "WildFirePostDetection",
                "action_pretty": "Detected (Reported)",
                "description": "Suspicious executable detected",
                "severity": "high",
                "host_ip": "8.8.8.8",
                "source": "Traps",
                "alert_id": "50820",
                "host_name": "HostNameFFM8VIP9",
                "detection_timestamp": 1559215835437,
                "action": "REPORTED",
                "user_name": "N/A",
                "name": "WildFire Malware"
            }
        ],
        "xdrfileartifacts": [
            {
                "file_signature_status": "SIGNATURE_UNAVAILABLE",
                "is_process": None,
                "file_name": "LCTGSK7IML.docx",
                "file_wildfire_verdict": "UNKNOWN",
                "alert_count": 1,
                "is_malicious": None,
                "is_manual": None,
                "file_signature_vendor_name": None,
                "type": "HASH",
                "file_sha256": "384654fa409c7a500a4a843d33a005c9d670d4845d3a9e096efc8b00ad05a621"
            }
        ],
        "xdrnetworkartifacts": []
    },
    "severity": 1,
    "name": "#697567 - WildFire Malware detected on host HostNameFFM8VIP9",
    "created": "2019-06-02T11:13:54.674006+03:00",
    "sourceBrand": "Palo Alto Networks Cortext XDR IR",
}

OLD_INCIDENT_IN_DEMISTO = {
    "sourceInstance": "Palo Alto Networks Cortext XDR IR_instance_1",
    "occurred": "2019-05-30T14:32:22.398+03:00",
    "closeReason": "",
    "modified": "2019-06-02T11:15:09.323251+03:00",
    "CustomFields": {
        "xdrincidentid": "697567",
        "xdrurl": "http://example.com/incident-view/697567",
        "xdrdescription": "WildFire Malware detected on host HostNameFFM8VIP9",
        "xdralertcount": 1,
        "xdrstatus": "new",
        "xdrassignedusermail": "",
        "xdrassigneduserprettyname": "",
        "xdralerts": [
            {
                "category": "WildFirePostDetection",
                "action_pretty": "Detected (Reported)",
                "description": "Suspicious executable detected",
                "severity": "high",
                "host_ip": "8.8.8.8",
                "source": "Traps",
                "alert_id": "50820",
                "host_name": "HostNameFFM8VIP9",
                "detection_timestamp": 1559215835437,
                "action": "REPORTED",
                "user_name": "N/A",
                "name": "WildFire Malware"
            }
        ],
        "xdrfileartifacts": [
            {
                "file_signature_status": "SIGNATURE_UNAVAILABLE",
                "is_process": None,
                "file_name": "LCTGSK7IML.docx",
                "file_wildfire_verdict": "UNKNOWN",
                "alert_count": 1,
                "is_malicious": None,
                "is_manual": None,
                "file_signature_vendor_name": None,
                "type": "HASH",
                "file_sha256": "384654fa409c7a500a4a843d33a005c9d670d4845d3a9e096efc8b00ad05a621"
            }
        ],
        "xdrnetworkartifacts": []
    },
    "labels": [
        {
            "type": "modification_time",
            "value": 1559463309323,
        }
    ],
    "severity": 1,
    "name": "#697567 - WildFire Malware detected on host HostNameFFM8VIP9",
    "created": "2019-06-02T11:13:54.674006+03:00",
    "sourceBrand": "Palo Alto Networks Cortext XDR IR",
}

INCIDENT_FROM_XDR = {
    "host_count": 1,
    "manual_severity": None,
    "xdr_url": "http://example.com/incident-view/697567",
    "assigned_user_pretty_name": None,
    "alert_count": 1,
    "med_severity_alert_count": 0,
    "detection_time": None,
    "user_count": 1,
    "severity": "low",
    "alerts": [
        {
            "category": "WildFirePostDetection",
            "action_pretty": "Detected (Reported)",
            "description": "Suspicious executable detected",
            "severity": "high",
            "host_ip": "8.8.8.8",
            "source": "Traps",
            "alert_id": "50820",
            "host_name": "HostNameFFM8VIP9",
            "detection_timestamp": 1559215835437,
            "action": "REPORTED",
            "user_name": "N/A",
            "name": "WildFire Malware"
        }
    ],
    "low_severity_alert_count": 0,
    "status": "new",
    "description": "WildFire Malware detected on host HostNameFFM8VIP9",
    "resolve_comment": None,
    "creation_time": 1559215942398,
    "modification_time": 1559215942398,
    "network_artifacts": [],
    "file_artifacts": [
        {
            "file_signature_status": "SIGNATURE_UNAVAILABLE",
            "is_process": None,
            "file_name": "LCTGSK7IML.docx",
            "file_wildfire_verdict": "UNKNOWN",
            "alert_count": 1,
            "is_malicious": None,
            "is_manual": None,
            "file_signature_vendor_name": None,
            "type": "HASH",
            "file_sha256": "384654fa409c7a500a4a843d33a005c9d670d4845d3a9e096efc8b00ad05a621"
        }
    ],
    "manual_description": None,
    "incident_id": "697567",
    "notes": None,
    "assigned_user_mail": None,
    "high_severity_alert_count": 1
}

INCIDENT_FROM_XDR_RAW_RESPONSE = {
    'incident': INCIDENT_FROM_XDR
}


def test_compare_incident_in_demisto_vs_xdr_context___incident_not_modified():
    """
    Given
    - incident in xdr which already in context
    - incident in demisto

    When
    - nothing has changed

    Then
    - compare function returns
        is_modified=False
    """

    incident_id = "100"
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_in_demisto = copy.deepcopy(INCIDENT_IN_DEMISTO)
    xdr_incident_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    xdr_incident_in_context['severity'] = 1
    is_modified, update_args = xdr_script.compare_incident_in_demisto_vs_xdr_context(incident_in_demisto,
                                                                                     xdr_incident_in_context,
                                                                                     incident_id,
                                                                                     fields_mapping)
    assert not is_modified


def test_compare_incident_in_demisto_vs_xdr_context___status_was_modified():
    """
    Given
    - incident in xdr which already in context
    - incident in demisto

    When
    - xdrstatus field in demisto changed to closed

    Then
    - compare function returns
        is_modified=True
        update_args contains status
    """

    incident_id = "100"
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_in_demisto = copy.deepcopy(INCIDENT_IN_DEMISTO)
    incident_in_demisto["CustomFields"]["xdrstatus"] = "closed"

    xdr_incident_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    xdr_incident_in_context['severity'] = 1

    is_modified, update_args = xdr_script.compare_incident_in_demisto_vs_xdr_context(incident_in_demisto,
                                                                                     xdr_incident_in_context,
                                                                                     incident_id,
                                                                                     fields_mapping)

    assert is_modified
    assert {
        "incident_id": "100",
        "status": "closed"
    } == update_args


def test_compare_incident_in_demisto_vs_xdr_context___severity_was_modified():
    """
    Given
    - incident in xdr which already in context
    - incident in demisto

    When
    - severity field in demisto changed to 3 (high)

    Then
    - compare function returns
        is_modified=True
        update_args contains manual_severity
    """

    incident_id = "100"
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_in_demisto = copy.deepcopy(INCIDENT_IN_DEMISTO)
    incident_in_demisto["severity"] = 3

    xdr_incident_in_context = copy.deepcopy(INCIDENT_FROM_XDR)

    is_modified, update_args = xdr_script.compare_incident_in_demisto_vs_xdr_context(incident_in_demisto,
                                                                                     xdr_incident_in_context,
                                                                                     incident_id,
                                                                                     fields_mapping)

    assert is_modified
    assert {
        "incident_id": "100",
        "manual_severity": "high"
    } == update_args


def test_compare_incident_in_demisto_vs_xdr_context___status_and_severity_was_modified():
    """
    Given
    - incident in xdr which already in context
    - incident in demisto

    When
    - severity field in demisto changed
    - xdrstatus field in demisto changed

    Then
    - compare function returns
        is_modified=True
        update_args contains manual_severity and status
    """

    incident_id = "100"
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_in_demisto = copy.deepcopy(INCIDENT_IN_DEMISTO)
    incident_in_demisto["severity"] = 3
    incident_in_demisto["CustomFields"]["xdrstatus"] = "closed"

    xdr_incident_in_context = copy.deepcopy(INCIDENT_FROM_XDR)

    is_modified, update_args = xdr_script.compare_incident_in_demisto_vs_xdr_context(incident_in_demisto,
                                                                                     xdr_incident_in_context,
                                                                                     incident_id,
                                                                                     fields_mapping)

    assert is_modified
    assert {
        "incident_id": "100",
        "manual_severity": "high",
        "status": "closed"
    } == update_args


def test_compare_incident_latest_xdr_incident_with_older_xdr_in_context____when_nothing_changed():
    """
    Given
    - incident from xdr - latest
    - incident from xdr - older
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity

    When
    - nothing changed

    Then
    - ensure compare returns is_modified=False

    """
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_in_xdr_latest = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_from_xdr_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_from_xdr_in_context['severity'] = 1

    is_modified, update_args = xdr_script.compare_incident_in_xdr_vs_previous_xdr_in_context(
        incident_in_xdr_latest,
        incident_from_xdr_in_context,
        fields_mapping)

    assert not is_modified


def test_compare_incident_latest_xdr_incident_with_older_xdr_in_context____when_status_changed():
    """
    Given
    - incident from xdr - latest
    - incident from xdr - older
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity

    When
    - status changed from new to under_investigation

    Then
    - ensure compare returns is_modified=True
    - ensure compare returns update_args contains xdrstatus=under_investigation

    """
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity",
    }

    incident_in_xdr_latest = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_in_xdr_latest["status"] = "under_investigation"
    incident_in_xdr_latest["modification_time"] += 100

    incident_from_xdr_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_from_xdr_in_context['severity'] = 1

    is_modified, update_args = xdr_script.compare_incident_in_xdr_vs_previous_xdr_in_context(
        incident_in_xdr_latest,
        incident_from_xdr_in_context,
        fields_mapping)

    assert is_modified
    assert {
        "xdrstatus": "under_investigation",
    } == update_args


def test_compare_incident_latest_xdr_incident_with_older_xdr_in_context____when_manual_severity_changed():
    """
    Given
    - incident from xdr - latest
    - incident from xdr - older
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity

    When
    - manual_severity changed from None to medium

    Then
    - ensure compare returns is_modified=True
    - ensure compare returns update_args contains severity=medium

    """
    fields_mapping = {
        "status": "xdrstatus",
        "manual_severity": "severity"
    }

    incident_in_xdr_latest = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_in_xdr_latest["manual_severity"] = "medium"
    incident_in_xdr_latest["modification_time"] += 100

    incident_from_xdr_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_from_xdr_in_context['severity'] = 1

    is_modified, update_args = xdr_script.compare_incident_in_xdr_vs_previous_xdr_in_context(
        incident_in_xdr_latest,
        incident_from_xdr_in_context,
        fields_mapping)

    assert is_modified
    assert {
        "severity": "medium",
    } == update_args


def test_compare_incident_latest_xdr_incident_with_older_xdr_in_context____when_status_and_severity_changed():
    """
    Given
    - incident from xdr - latest
    - incident from xdr - older
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity

    When
    - manual_severity changed from None to medium
    - status changed from new to under_investigation
    -

    Then
    - ensure compare returns is_modified=True
    - ensure compare returns update_args contains severity=medium

    """
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "xdrseverity",
        "manual_severity": "severity"
    }

    incident_in_xdr_latest = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_in_xdr_latest["manual_severity"] = "medium"
    incident_in_xdr_latest["status"] = "under_investigation"
    incident_in_xdr_latest["modification_time"] += 100

    incident_from_xdr_in_context = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_from_xdr_in_context['severity'] = 1

    is_modified, update_args = xdr_script.compare_incident_in_xdr_vs_previous_xdr_in_context(
        incident_in_xdr_latest,
        incident_from_xdr_in_context,
        fields_mapping)

    assert is_modified
    assert {
        "severity": "medium",
        "xdrstatus": "under_investigation"
    } == update_args


def test_args_to_str_1():
    xdr_incident = copy.deepcopy(INCIDENT_FROM_XDR)
    args = {
        "incident_id": "11",
        "assigned_user_mail": "xdrassigneduser",
        "status": "xdrstatus",
        "severity": "xdrseverity",
        "playbook_to_run": "XDR Demo",
        "first": "true"
    }

    actual = xdr_script.args_to_str(args, xdr_incident)

    expected = 'incident_id=`11` assigned_user_mail=`xdrassigneduser` status=`xdrstatus` severity=`xdrseverity` ' \
               'playbook_to_run=`XDR Demo` first=`false` xdr_incident_from_previous_run=`{}` '\
        .format(json.dumps(xdr_incident))

    assert expected == actual


def test_args_to_str_2():
    xdr_incident = copy.deepcopy(INCIDENT_FROM_XDR)
    args = {
        "incident_id": "11",
        "assigned_user_mail": "xdrassigneduser",
        "status": "xdrstatus",
        "severity": "xdrseverity",
        "playbook_to_run": "XDR Demo",
        "first": "false",
        "xdr_incident_from_previous_run": "some previous value"
    }

    actual = xdr_script.args_to_str(args, xdr_incident)

    expected = 'incident_id=`11` assigned_user_mail=`xdrassigneduser` status=`xdrstatus` severity=`xdrseverity` ' \
               'playbook_to_run=`XDR Demo` first=`false` xdr_incident_from_previous_run=`{}` '\
        .format(json.dumps(xdr_incident))

    assert expected == actual


def test_compare_incident_in_demisto_when_the_severity_is_unknown():
    """
    Given
    - incident in demisto
    - incident from xdr - older
    - fields_mapping:
        severity: severity

    When
    - severity in demisto is unknown

    Then
    - ensure severity is not updated in XDR

    """
    incident_id = "100"
    fields_mapping = {
        "severity": "severity"
    }

    incident_in_demisto = copy.deepcopy(INCIDENT_IN_DEMISTO)
    incident_in_demisto["severity"] = 0

    xdr_incident_in_context = copy.deepcopy(INCIDENT_FROM_XDR)

    is_modified, update_args = xdr_script.compare_incident_in_demisto_vs_xdr_context(incident_in_demisto,
                                                                                     xdr_incident_in_context,
                                                                                     incident_id,
                                                                                     fields_mapping)

    assert is_modified is False
    assert {} == update_args


def test_fix_bug_19669(mocker, capfd):
    """
    bug fix https://github.com/demisto/etc/issues/19669

    The script was throwing `local variable 'latest_incident_in_xdr' referenced before assignment`

    Given
    - xdr script

    When
    - script executed and xdr_incident_sync raised an exception

    Then
    - the xdr_script should not fail on syntax error: `local variable 'latest_incident_in_xdr'
    referenced before assignment`
    - the script should return error entry with message `Raised exception`
    """
    import XDRSyncScript_5_9_9 as xdr_script
    import demistomock as demisto
    import sys

    mocker.patch.object(xdr_script, 'xdr_incident_sync', side_effect=Exception('Raised exception'))
    mocker.patch.object(demisto, 'results')

    # mocking exit we make sure that return_error don't stop the test - bad practice but have no choise for now
    mocker.patch.object(sys, 'exit')
    mocker.patch.object(demisto, 'executeCommand', return_value=[{
        'Contents': {
            'id': '1000'
        },
        'Type': entryTypes['note'],
        'Format': formats['json']
    }])
    args = {
        'interval': '1'
    }
    with capfd.disabled():  # this line should prevent the test failing on writing to demisto.error => print => stdout
        xdr_script.main(args)

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['error']
    assert results[0]['Contents'] == 'Raised exception'


def create_test_incident(no_assignee=False, severity=None):
    xdr_incident = copy.deepcopy(INCIDENT_FROM_XDR)
    demisto_incident = copy.deepcopy(INCIDENT_IN_DEMISTO)

    if no_assignee:
        xdr_incident['assigned_user_pretty_name'] = None
        xdr_incident[ASSIGNED_USER_MAIL_XDR_FIELD] = None

        demisto_incident['xdrassignedusermail'] = ''
        demisto_incident['xdrassigneduserprettyname'] = ''

    if severity:
        xdr_incident[SEVERITY_XDR_FIELD] = severity

        # 3=high, 2=medium, 1=low
        demisto_incident['severity'] = {
            'high': 3,
            'medium': 2,
            'low': 1
        }[severity]

    xdr_incident_from_previous_run = copy.deepcopy(xdr_incident)

    if 'alerts' in xdr_incident_from_previous_run:
        del xdr_incident_from_previous_run['alerts']
    if 'file_artifacts' in xdr_incident_from_previous_run:
        del xdr_incident_from_previous_run['file_artifacts']
    if 'network_artifacts' in xdr_incident_from_previous_run:
        del xdr_incident_from_previous_run['network_artifacts']

    return demisto_incident, xdr_incident_from_previous_run, xdr_incident


def get_execute_command_call(mocked_execute_command, script_name):
    """

    Returns:
        is_called - True means script was called via demisto.executeCommand
        script_args - The arguments that demisto.executeCommand was called with

    """
    if mocked_execute_command.call_count == 0:
        return False, None

    for call_args in mocked_execute_command.call_args_list:
        if call_args[0][0] == script_name:
            return True, call_args[0][1]

    return False, None


def test_incident_was_modified_in_xdr(mocker):
    """
    - incident in demisto
    - incident in xdr

    - incident assignee in xdr is updated by the user to be foo@test.com

    - XDRSyncScript executed

    - ensure incident assignee in demisto is updated to be foo@test.com
    - ensure current playbook was re-executed
    - ensure XDRSyncScript is scheduled to be executed in the next internal with
        xdr_incident_from_previous_run has assignee foo@test.com
    """
    import XDRSyncScript_5_9_9 as xdr_script
    import demistomock as demisto

    # - incident in demisto
    # - incident in xdr
    demisto_incident, xdr_incident_from_previous_run, xdr_incident_latest = create_test_incident(no_assignee=True)

    # - incident assignee in xdr is updated by the user to be foo@test.com
    xdr_incident_latest[ASSIGNED_USER_MAIL_XDR_FIELD] = 'foo@test.com'
    xdr_incident_latest[MODIFICATION_TIME_XDR_FIELD] = xdr_incident_from_previous_run[MODIFICATION_TIME_XDR_FIELD] + 100

    mocker.patch.object(demisto, 'incidents', return_value=[demisto_incident])
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', return_value=[{
        'Contents': {
            'incident': xdr_incident_latest,
            'alerts': {
                'data': xdr_incident_latest['alerts']
            },
            'file_artifacts': {
                'data': xdr_incident_latest['file_artifacts']
            },
            'network_artifacts': {
                'data': xdr_incident_latest['network_artifacts']
            }
        },
        'HumanReadable': 'nla',
        'Type': entryTypes['note'],
        'Format': formats['json']
    }])
    args = {
        'interval': '1',
        'verbose': 'true',
        'first': 'false',
        ASSIGNED_USER_MAIL_XDR_FIELD: 'xdrassignedusermail',
        'xdr_alerts': 'xdralerts',
        'xdr_file_artifacts': 'xdrfileartifacts',
        'xdr_network_artifacts': 'xdrnetworkartifacts',
        'xdr_incident_from_previous_run': json.dumps(xdr_incident_from_previous_run)
    }
    xdr_script.main(args)

    # - ensure incident assignee in demisto is updated to be foo@test.com
    is_called, set_incident_args = get_execute_command_call(demisto.executeCommand, 'setIncident')
    assert is_called is True
    assert set_incident_args['xdrassignedusermail'] == 'foo@test.com'

    # - ensure current playbook was re-executed
    is_playbook_executed, _ = get_execute_command_call(demisto.executeCommand, 'setPlaybook')
    assert is_playbook_executed is True

    # - ensure XDRSyncScript is scheduled to be executed in the next internal with
    # xdr_incident_from_previous_run has assignee foo@test.com
    is_called, scheduled_command_args = get_execute_command_call(demisto.executeCommand, 'ScheduleCommand')
    assert is_called is True

    scheduled_command = scheduled_command_args['command']
    assert '"assigned_user_mail": "foo@test.com"' in scheduled_command


def test_incident_was_modified_in_demisto(mocker):
    """
    - incident in demisto and in XDR with low severity

    - incident severity in Demisto is updated by the user to be "high"

    - XDRSyncScript executed

    - ensure incident severity in XDR is updated to be high
    - ensure playbook is NOT executed
    - ensure XDRSyncScript is scheduled to be executed in the next internal with
        xdr_incident_from_previous_run has severity=high
    """
    import XDRSyncScript_5_9_9 as xdr_script
    import demistomock as demisto

    # - incident in demisto
    # - incident in xdr
    demisto_incident, xdr_incident_from_previous_run, xdr_incident_latest = create_test_incident(severity='low')

    # - incident severity in Demisto is updated by the user to be "high"
    demisto_incident['severity'] = 3

    # - XDRSyncScript executed
    mocker.patch.object(demisto, 'incidents', return_value=[demisto_incident])
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', return_value=[{
        'Contents': {
            'incident': xdr_incident_latest,
            'alerts': {
                'data': xdr_incident_latest['alerts']
            },
            'file_artifacts': {
                'data': xdr_incident_latest['file_artifacts']
            },
            'network_artifacts': {
                'data': xdr_incident_latest['network_artifacts']
            }
        },
        'HumanReadable': 'nla',
        'Type': entryTypes['note'],
        'Format': formats['json']
    }])
    args = {
        'interval': '1',
        'verbose': 'true',
        'first': 'false',
        SEVERITY_XDR_FIELD: 'severity',
        'xdr_alerts': 'xdralerts',
        'xdr_file_artifacts': 'xdrfileartifacts',
        'xdr_network_artifacts': 'xdrnetworkartifacts',
        'xdr_incident_from_previous_run': json.dumps(xdr_incident_from_previous_run)
    }
    xdr_script.main(args)

    # - ensure incident severity in XDR is updated to be high
    is_called, xdr_update_args = get_execute_command_call(demisto.executeCommand, 'xdr-update-incident')

    assert is_called is True
    assert xdr_update_args[MANUAL_SEVERITY_XDR_FIELD] == 'high'

    # - ensure playbook is NOT executed
    is_playbook_executed, _ = get_execute_command_call(demisto.executeCommand, 'setPlaybook')
    assert not is_playbook_executed

    # - ensure XDRSyncScript is scheduled to be executed in the next internal with
    #     xdr_incident_from_previous_run has severity=high
    is_called, scheduled_command_args = get_execute_command_call(demisto.executeCommand, 'ScheduleCommand')
    assert is_called is True


EXPECTED_INCIDENT = {
    'incident_id': '697567',
    'manual_severity': None,
    'assigned_user_mail': None,
    'high_severity_alert_count': None,
    'host_count': None,
    'xdr_url': 'http://example.com/incident-view/697567',
    'assigned_user_pretty_name': '',
    'alert_count': 1,
    'med_severity_alert_count': None,
    'user_count': None, 'severity': 1,
    'low_severity_alert_count': None,
    'status': 'new',
    'description': 'WildFire Malware detected on host HostNameFFM8VIP9',
    'resolve_comment': None,
    'notes': None,
    'modification_time': 1559463309323
}


def test_create_incident_from_saved_data_without_extra_data():
    """
    Given
    - incident in demisto
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity
    - include_extra_data = False

    When
    - creating an incident object from the context incident

    Then
    - ensure date fields are parsed correctly
    - ensure all relevant fields are present

    """
    fields_mapping = {
        "alert_count": "xdralertcount",
        "assigned_user_mail": "xdrassigneduseremail",
        "assigned_user_pretty_name": "xdrassigneduserprettyname",
        "description": "xdrdescription",
        "high_severity_alert_count": "xdrhighseverityalertcount",
        "host_count": "xdrhostcount",
        "incident_id": "10",
        "low_severity_alert_count": "xdrlowseverityalertcount",
        "manual_severity": "xdrmanualseverity",
        "med_severity_alert_count": "xdrmediumseverityalertcount",
        "modification_time": "xdrmodificationtime",
        "notes": "xdrnotes",
        "resolve_comment": "xdrresolvecomment",
        "severity": "severity",
        "status": "xdrstatus",
        "user_count": "xdrusercount",
        "xdr_url": "xdrurl"
    }

    incident_from_context = copy.deepcopy(INCIDENT_IN_DEMISTO)

    created_incident = xdr_script.create_incident_from_saved_data(incident_from_context, fields_mapping)

    assert created_incident == EXPECTED_INCIDENT


EXPECTED_INCIDENT_EXTRA_DATA = {
    "xdralerts": [
        {
            "category": "WildFirePostDetection",
            "action_pretty": "Detected (Reported)",
            "description": "Suspicious executable detected",
            "severity": "high",
            "host_ip": "8.8.8.8",
            "source": "Traps",
            "alert_id": "50820",
            "host_name": "HostNameFFM8VIP9",
            "detection_timestamp": 1559215835437,
            "action": "REPORTED",
            "user_name": "N/A",
            "name": "WildFire Malware"
        }
    ],
    "xdrfileartifacts": [
        {
            "file_signature_status": "SIGNATURE_UNAVAILABLE",
            "is_process": None,
            "file_name": "LCTGSK7IML.docx",
            "file_wildfire_verdict": "UNKNOWN",
            "alert_count": 1,
            "is_malicious": None,
            "is_manual": None,
            "file_signature_vendor_name": None,
            "type": "HASH",
            "file_sha256": "384654fa409c7a500a4a843d33a005c9d670d4845d3a9e096efc8b00ad05a621"
        }
    ],
    "xdrnetworkartifacts": []
}


def test_create_incident_from_saved_data_with_extra_data():
    """
    Given
    - incident in demisto
    - fields_mapping:
        status: xdrstatus,
        severity: xdrseverity,
        manual_severity: severity
    - include_extra_data = True

    When
    - creating an incident object from the context incident

    Then
    - ensure date fields are parsed correctly
    - ensure all relevant fields are present

    """
    fields_mapping = {
        "status": "xdrstatus",
        "severity": "severity"
    }

    incident_from_context = copy.deepcopy(INCIDENT_IN_DEMISTO)

    created_incident = xdr_script.create_incident_from_saved_data(incident_from_context, fields_mapping, True)

    assert created_incident == EXPECTED_INCIDENT_EXTRA_DATA


def test_create_incident_from_saved_data_without_extra_data_old_incident():
    """
    Given
    - an old incident in demisto (which means that 'xdrmodificationtime' is not mapped  but present in 'labels')
    - fields_mapping:
        {
        "alert_count": "xdralertcount",
        "assigned_user_mail": "xdrassigneduseremail",
        "assigned_user_pretty_name": "xdrassigneduserprettyname",
        "description": "xdrdescription",
        "high_severity_alert_count": "xdrhighseverityalertcount",
        "host_count": "xdrhostcount",
        "incident_id": "10",
        "low_severity_alert_count": "xdrlowseverityalertcount",
        "manual_severity": "xdrmanualseverity",
        "med_severity_alert_count": "xdrmediumseverityalertcount",
        "modification_time": "xdrmodificationtime",
        "notes": "xdrnotes",
        "resolve_comment": "xdrresolvecomment",
        "severity": "severity",
        "status": "xdrstatus",
        "user_count": "xdrusercount",
        "xdr_url": "xdrurl"
    }
    - include_extra_data = False

    When
    - creating an incident object from the context incident

    Then
    - ensure date fields are parsed correctly
    - ensure all relevant fields are present

    """
    fields_mapping = {
        "alert_count": "xdralertcount",
        "assigned_user_mail": "xdrassigneduseremail",
        "assigned_user_pretty_name": "xdrassigneduserprettyname",
        "description": "xdrdescription",
        "high_severity_alert_count": "xdrhighseverityalertcount",
        "host_count": "xdrhostcount",
        "incident_id": "10",
        "low_severity_alert_count": "xdrlowseverityalertcount",
        "manual_severity": "xdrmanualseverity",
        "med_severity_alert_count": "xdrmediumseverityalertcount",
        "modification_time": "xdrmodificationtime",
        "notes": "xdrnotes",
        "resolve_comment": "xdrresolvecomment",
        "severity": "severity",
        "status": "xdrstatus",
        "user_count": "xdrusercount",
        "xdr_url": "xdrurl"
    }

    incident_from_context = copy.deepcopy(OLD_INCIDENT_IN_DEMISTO)

    created_incident = xdr_script.create_incident_from_saved_data(incident_from_context, fields_mapping)

    assert created_incident == EXPECTED_INCIDENT


def test_create_incident_from_saved_data_old_incident_no_modification_time():
    """
    Given
    - an old incident in demisto (which means that 'xdrmodificationtime' is not mapped and not in 'labels')
    - fields_mapping:
        {
        "alert_count": "xdralertcount",
        "assigned_user_mail": "xdrassigneduseremail",
        "assigned_user_pretty_name": "xdrassigneduserprettyname",
        "description": "xdrdescription",
        "high_severity_alert_count": "xdrhighseverityalertcount",
        "host_count": "xdrhostcount",
        "incident_id": "10",
        "low_severity_alert_count": "xdrlowseverityalertcount",
        "manual_severity": "xdrmanualseverity",
        "med_severity_alert_count": "xdrmediumseverityalertcount",
        "modification_time": "xdrmodificationtime",
        "notes": "xdrnotes",
        "resolve_comment": "xdrresolvecomment",
        "severity": "severity",
        "status": "xdrstatus",
        "user_count": "xdrusercount",
        "xdr_url": "xdrurl"
    }
    - include_extra_data = False

    When
    - creating an incident object from the context incident

    Then
    - ensure date fields are parsed correctly
    - ensure all relevant fields are present

    """
    fields_mapping = {
        "alert_count": "xdralertcount",
        "assigned_user_mail": "xdrassigneduseremail",
        "assigned_user_pretty_name": "xdrassigneduserprettyname",
        "description": "xdrdescription",
        "high_severity_alert_count": "xdrhighseverityalertcount",
        "host_count": "xdrhostcount",
        "incident_id": "10",
        "low_severity_alert_count": "xdrlowseverityalertcount",
        "manual_severity": "xdrmanualseverity",
        "med_severity_alert_count": "xdrmediumseverityalertcount",
        "modification_time": "xdrmodificationtime",
        "notes": "xdrnotes",
        "resolve_comment": "xdrresolvecomment",
        "severity": "severity",
        "status": "xdrstatus",
        "user_count": "xdrusercount",
        "xdr_url": "xdrurl"
    }

    EXPECTED_INCIDENT['modification_time'] = 0

    incident_from_context = copy.deepcopy(OLD_INCIDENT_IN_DEMISTO)
    incident_from_context["labels"] = []

    created_incident = xdr_script.create_incident_from_saved_data(incident_from_context, fields_mapping)

    assert created_incident['modification_time'] == 0
    assert created_incident == EXPECTED_INCIDENT

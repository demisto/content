from CommonServerPython import *
import copy
import json
import XDRSyncScript as xdr_script


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
        "xdrstatus": "new"
    },
    "severity": 1,
    "name": "#697567 - WildFire Malware detected on host HostNameFFM8VIP9",
    "created": "2019-06-02T11:13:54.674006+03:00",
    "sourceBrand": "Palo Alto Networks Cortext XDR IR"
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
        "severity": "severity"
    }

    incident_in_xdr_latest = copy.deepcopy(INCIDENT_FROM_XDR)
    incident_in_xdr_latest["severity"] = "medium"
    incident_in_xdr_latest["modification_time"] += 100

    incident_from_xdr_in_context = copy.deepcopy(INCIDENT_FROM_XDR)

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


def test_fix_bug_19669(mocker):
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
    import XDRSyncScript as xdr_script
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
    xdr_script.main(args)

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['error']
    assert results[0]['Contents'] == 'Raised exception'

import demistomock as demisto
import json
import pytest
from MicrosoftDefenderAdvancedThreatProtection import MsClient, get_future_time, build_std_output, parse_ip_addresses, \
    print_ip_addresses, get_machine_details_command, run_polling_command, run_live_response_script_action, \
    get_live_response_file_action, put_live_response_file_action

ARGS = {'id': '123', 'limit': '2', 'offset': '0'}


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2018-11-26T16:19:21"})
    mocker.patch.object(demisto, 'incidents')


client_mocker = MsClient(
    tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name', base_url='url', verify='use_ssl',
    proxy='proxy', self_deployed='self_deployed', alert_severities_to_fetch='Informational,Low,Medium,High',
    alert_time_to_fetch='3 days', alert_status_to_fetch='New')


def atp_mocker(mocker, file_name):
    with open(f'test_data/{file_name}', 'r') as f:
        alerts = json.loads(f.read())
    mocker.patch.object(client_mocker, 'list_alerts', return_value=alerts)


def test_first_fetch_incidents(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'first_response_alerts.json')

    fetch_incidents(client_mocker, {'last_alert_fetched_time': "2018-11-26T16:19:21"})
    # Check that all 3 incidents are extracted
    assert 3 == len(demisto.incidents.call_args[0][0])
    assert 'Microsoft Defender ATP Alert da636983472338927033_-2077013687' == \
           demisto.incidents.call_args[0][0][2].get('name')


def test_second_fetch_incidents(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'second_response_alerts.json')
    # Check that incident isn't extracted again
    fetch_incidents(client_mocker, {'last_alert_fetched_time': "2019-09-01T13:31:08",
                                    'existing_ids': ['da637029414680409372_735564929']})
    assert [] == demisto.incidents.call_args[0][0]


def test_third_fetch_incidents(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'third_response_alerts.json')
    # Check that new incident is extracted
    fetch_incidents(client_mocker, {'last_alert_fetched_time': "2019-09-01T13:29:37",
                                    'existing_ids': ['da637029413772554314_295039533']})
    assert 'Microsoft Defender ATP Alert da637029414680409372_735564929' == \
           demisto.incidents.call_args[0][0][0].get('name')


def test_get_alert_related_ips_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_alert_related_ips_command
    mocker.patch.object(client_mocker, 'get_alert_related_ips', return_value=ALERT_RELATED_IPS_API_RESPONSE)
    _, res, _ = get_alert_related_ips_command(client_mocker, {'id': '123', 'limit': '1', 'offset': '0'})
    assert res['MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'IPs': ['1.1.1.1']
    }


def test_get_alert_related_domains_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_alert_related_domains_command
    mocker.patch.object(client_mocker, 'get_alert_related_domains', return_value=ALERT_RELATED_DOMAINS_API_RESPONSE)
    _, res, _ = get_alert_related_domains_command(client_mocker, ARGS)
    assert res['MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'Domains': ['www.example.com', 'www.example2.com']
    }


def test_get_alert_related_user_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_alert_related_user_command
    mocker.patch.object(client_mocker, 'get_alert_related_user', return_value=ALERT_RELATED_USER_API_RESPONSE)
    _, res, _ = get_alert_related_user_command(client_mocker, {'id': '123', 'limit': '2', 'offset': '0'})
    assert res['MicrosoftATP.AlertUser(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'User': USER_DATA
    }


def test_get_action_data(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_action_data
    mocker.patch.object(client_mocker, 'get_machine_action_by_id', return_value=ACTION_DATA_API_RESPONSE)
    res = get_machine_action_data(ACTION_DATA_API_RESPONSE)
    assert res['ID'] == "123456"
    assert res['Status'] == "Succeeded"


def test_get_machine_investigation_package_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_investigation_package_command
    mocker.patch.object(client_mocker, 'get_investigation_package', return_value=INVESTIGATION_PACKAGE_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=INVESTIGATION_ACTION_DATA)
    _, res, _ = get_machine_investigation_package_command(client_mocker, {'machine_id': '123', 'comment': 'test'})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == INVESTIGATION_ACTION_DATA


def test_get_investigation_package_sas_uri_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_investigation_package_sas_uri_command
    mocker.patch.object(client_mocker, 'get_investigation_package_sas_uri', return_value=INVESTIGATION_SAS_URI_API_RES)
    _, res, _ = get_investigation_package_sas_uri_command(client_mocker, {})
    assert res['MicrosoftATP.InvestigationURI(val.Link === obj.Link)'] == {
        'Link': 'https://userrequests-us.securitycenter.windows.com:443/safedownload/'
                'WDATP_Investigation_Package.zip?token=test1'}


def test_restrict_app_execution_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import restrict_app_execution_command
    mocker.patch.object(client_mocker, 'restrict_app_execution', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = restrict_app_execution_command(client_mocker, {})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_remove_app_restriction_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import remove_app_restriction_command
    mocker.patch.object(client_mocker, 'remove_app_restriction', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = remove_app_restriction_command(client_mocker, {})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_stop_and_quarantine_file_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import stop_and_quarantine_file_command
    mocker.patch.object(client_mocker, 'stop_and_quarantine_file', return_value=STOP_AND_QUARANTINE_FILE_RAW_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA)
    _, res, _ = stop_and_quarantine_file_command(client_mocker, {})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA


def test_get_investigations_by_id_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import get_investigations_by_id_command
    mocker.patch.object(client_mocker, 'get_investigation_by_id', return_value=INVESTIGATION_API_RESPONSE)
    mocker.patch.object(atp, 'get_investigation_data', return_value=INVESTIGATION_DATA)
    _, res, _ = get_investigations_by_id_command(client_mocker, ARGS)
    assert res['MicrosoftATP.Investigation(val.ID === obj.ID)'] == INVESTIGATION_DATA


def test_get_investigation_data(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_investigation_data
    mocker.patch.object(client_mocker, 'get_investigation_by_id', return_value=INVESTIGATION_API_RESPONSE)
    res = get_investigation_data(INVESTIGATION_API_RESPONSE)
    assert res['ID'] == '123'
    assert res['InvestigationState'] == "Running"


def test_start_investigation_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import start_investigation_command
    mocker.patch.object(client_mocker, 'start_investigation', return_value=INVESTIGATION_API_RESPONSE)
    mocker.patch.object(atp, 'get_investigation_data', return_value=INVESTIGATION_DATA)
    _, res, _ = start_investigation_command(client_mocker, {})
    assert res['MicrosoftATP.Investigation(val.ID === obj.ID)'] == INVESTIGATION_DATA


def test_get_domain_alerts_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import get_domain_alerts_command
    mocker.patch.object(client_mocker, 'get_domain_alerts', return_value=ALERTS_API_RESPONSE)
    mocker.patch.object(atp, 'get_alert_data', return_value=ALERT_DATA)
    _, res, _ = get_domain_alerts_command(client_mocker, {'domain': 'test'})
    assert res['MicrosoftATP.DomainAlert(val.Domain === obj.Domain)'] == {
        'Domain': 'test',
        'Alerts': [ALERT_DATA]
    }


def test_get_alert_data(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_alert_data
    mocker.patch.object(client_mocker, 'get_alert_by_id', return_value=SINGLE_ALERT_API_RESPONSE)
    res = get_alert_data(SINGLE_ALERT_API_RESPONSE)
    assert res['ID'] == '123'
    assert res['Title'] == 'Network connection to a risky host'


def test_get_domain_machine_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import get_domain_machine_command
    mocker.patch.object(client_mocker, 'get_domain_machines', return_value=MACHINE_RESPONSE_API)
    mocker.patch.object(atp, 'get_machine_data', return_value=MACHINE_DATA)
    _, res, _ = get_domain_machine_command(client_mocker, {'domain': 'test'})
    assert res['MicrosoftATP.DomainMachine(val.Domain === obj.Domain)'] == {
        'Domain': 'test',
        'Machines': [MACHINE_DATA]
    }


def test_get_machine_data(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_data
    mocker.patch.object(client_mocker, 'get_machine_details', return_value=SINGLE_MACHINE_RESPONSE_API)
    res = get_machine_data(SINGLE_MACHINE_RESPONSE_API)
    assert res['ID'] == '123'
    assert res['HealthStatus'] in ['Active', 'Inactive']


def test_get_ip_alerts_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import get_ip_alerts_command
    mocker.patch.object(client_mocker, 'get_ip_alerts', return_value=ALERTS_API_RESPONSE)
    mocker.patch.object(atp, 'get_alert_data', return_value=ALERT_DATA)
    _, res, _ = get_ip_alerts_command(client_mocker, {'ip': '1.1.1.1'})
    assert res['MicrosoftATP.IPAlert(val.IPAddress === obj.IPAddress)'] == {
        'IPAddress': '1.1.1.1',
        'Alerts': [ALERT_DATA]
    }


def test_run_antivirus_scan_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    from MicrosoftDefenderAdvancedThreatProtection import run_antivirus_scan_command
    mocker.patch.object(client_mocker, 'run_antivirus_scan', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = run_antivirus_scan_command(client_mocker, {})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_check_limit_and_offset_values_no_error():
    from MicrosoftDefenderAdvancedThreatProtection import check_limit_and_offset_values
    res = check_limit_and_offset_values(limit='2', offset='1')
    assert res == (2, 1)


def test_check_limit_and_offset_values_invalid_limit():
    from MicrosoftDefenderAdvancedThreatProtection import check_limit_and_offset_values
    with pytest.raises(Exception) as e:
        assert check_limit_and_offset_values(limit='abc', offset='1')
    assert str(e.value) == "Error: You can only enter a positive integer or zero to limit argument."


def test_check_limit_and_offset_values_invalid_offset():
    from MicrosoftDefenderAdvancedThreatProtection import check_limit_and_offset_values
    with pytest.raises(Exception) as e:
        assert check_limit_and_offset_values(limit='1', offset='-4')
    assert str(e.value) == "Error: You can only enter a positive integer to offset argument."


def test_check_limit_and_offset_values_limit_zero(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import check_limit_and_offset_values
    with pytest.raises(Exception) as e:
        assert check_limit_and_offset_values(limit='0', offset='1')
    assert str(e.value) == "Error: The value of the limit argument must be a positive integer."


""" API RAW RESULTS """

FILE_DATA_API_RESPONSE = {
    "sha1": "123abc",
    "sha256": "456abc",
    "md5": "789abc",
    "globalPrevalence": 123,
    "globalFirstObserved": "2016-07-16T17:16:55.530433Z",
    "globalLastObserved": "2020-02-26T14:35:12.6778604Z",
    "size": 42,
    "fileType": None,
    "isPeFile": True,
    "filePublisher": None,
    "fileProductName": None,
    "signer": "Microsoft Windows",
    "issuer": "Microsoft issuer",
    "signerHash": "147abc",
    "isValidCertificate": True,
    "determinationType": "Unknown",
    "determinationValue": ""
}

ALERT_RELATED_IPS_API_RESPONSE = {
    "value": [
        {
            "id": "1.1.1.1"
        },
        {
            "id": "2.2.2.2"
        }
    ]
}

ALERT_RELATED_DOMAINS_API_RESPONSE = {
    "value": [
        {
            "host": "www.example.com"
        },
        {
            "host": "www.example2.com"
        }

    ]
}

ALERT_RELATED_USER_API_RESPONSE = {
    "id": "test/user1",
    "accountName": "user1",
    "accountDomain": "test",
    "accountSid": "12345678",
    "firstSeen": "2019-12-08T06:33:39Z",
    "lastSeen": "2020-01-05T06:58:34Z",
    "mostPrevalentMachineId": "1234",
    "leastPrevalentMachineId": "5678",
    "logonTypes": "Network",
    "logOnMachinesCount": 1,
    "isDomainAdmin": "false",
    "isOnlyNetworkUser": "false"
}

USER_DATA = {
    'ID': "test/user1",
    'AccountName': "user1",
    'AccountDomain': "test",
    'AccountSID': "12345678",
    'FirstSeen': "2019-12-08T06:33:39Z",
    'LastSeen': "2020-01-05T06:58:34Z",
    'MostPrevalentMachineID': "1234",
    'LeastPrevalentMachineID': "5678",
    'LogonTypes': "Network",
    'LogonCount': 1,
    'DomainAdmin': "false",
    'NetworkUser': "false"
}

ACTION_DATA_API_RESPONSE = {
    "id": "123456",
    "type": "Unisolate",
    "requestor": "147258",
    "requestorComment": "Test",
    "status": "Succeeded",
    "machineId": "987abc",
    "computerDnsName": "desktop-test",
    "creationDateTimeUtc": "2020-02-26T09:23:12.5820502Z",
    "lastUpdateDateTimeUtc": "2020-02-26T09:23:37.3018521Z",
    "cancellationRequestor": None,
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "errorHResult": 0,
    "scope": None,
    "relatedFileInfo": None
}

INVESTIGATION_PACKAGE_API_RESPONSE = {
    "id": "123",
    "type": "CollectInvestigationPackage",
    "requestor": "456",
    "requestorComment": "Collect forensics due to alert 1234",
    "status": "Pending",
    "machineId": "123abc",
    "computerDnsName": None,
    "creationDateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "lastUpdateDateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "cancellationRequestor": None,
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "errorHResult": 0,
    "scope": None,
    "relatedFileInfo": None
}

INVESTIGATION_ACTION_DATA = {
    "ID": "123",
    "Type": "CollectInvestigationPackage",
    "Scope": None,
    "Requestor": "456",
    "RequestorComment": "Collect forensics due to alert 1234",
    "Status": "Pending",
    "MachineID": "123abc",
    "ComputerDNSName": None,
    "CreationDateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "LastUpdateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "RelatedFileInfo": None
}

INVESTIGATION_SAS_URI_API_RES = {
    "value": 'https://userrequests-us.securitycenter.windows.com:443/safedownload/'
             'WDATP_Investigation_Package.zip?token=test1'
}
STOP_AND_QUARANTINE_FILE_RAW_RESPONSE = {
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "cancellationRequestor": None,
    "commands": [],
    "computerDnsName": None,
    "creationDateTimeUtc": "2020-03-20T14:21:49.9097785Z",
    "errorHResult": 0,
    "id": "123",
    "lastUpdateDateTimeUtc": "2020-03-20T14:21:49.9097785Z",
    "machineId": "12345678",
    "relatedFileInfo": {
        "fileIdentifier": "87654321",
        "fileIdentifierType": "Sha1"
    },
    "requestor": "123abc",
    "requestorComment": "Test",
    "scope": None,
    "status": "Pending",
    "type": "StopAndQuarantineFile"
}

MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA = {
    "ID": "123",
    "Type": "StopAndQuarantineFile",
    "Scope": None,
    "Requestor": "123abc",
    "RequestorComment": "Test",
    "Status": "Pending",
    "MachineID": "12345678",
    "ComputerDNSName": None,
    "CreationDateTimeUtc": "2020-03-20T14:21:49.9097785Z",
    "LastUpdateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "RelatedFileInfo": {"fileIdentifier": "87654321", "fileIdentifierType": "Sha1"}
}
MACHINE_ACTION_API_RESPONSE = {
    "id": "123",
    "type": "test",
    "requestor": "456",
    "requestorComment": "test",
    "status": "Pending",
    "machineId": "123abc",
    "computerDnsName": None,
    "creationDateTimeUtc": "2020-02-27T13:44:07.2851667Z",
    "lastUpdateDateTimeUtc": "2020-02-27T13:44:07.2851667Z",
    "cancellationRequestor": None,
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "errorHResult": 0,
    "scope": None,
    "relatedFileInfo": None
}

MACHINE_ACTION_DATA = {
    "ID": "123",
    "Type": "test",
    "Scope": None,
    "Requestor": "456",
    "RequestorComment": "test",
    "Status": "Pending",
    "MachineID": "123abc",
    "ComputerDNSName": None,
    "CreationDateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "LastUpdateTimeUtc": "2020-02-27T12:21:00.4568741Z",
    "RelatedFileInfo": None
}

INVESTIGATION_LIST_API_RESPONSE = {
    "value": [
        {
            "id": "123",
            "startTime": "2020-01-06T14:11:34Z",
            "endTime": None,
            "state": "Running",
            "cancelledBy": None,
            "statusDetails": None,
            "machineId": "123abc",
            "computerDnsName": "desktop-test",
            "triggeringAlertId": "123-456"
        }
    ]
}

INVESTIGATION_API_RESPONSE = {

    "id": "123",
    "startTime": "2020-01-06T14:11:34Z",
    "endTime": None,
    "state": "Running",
    "cancelledBy": None,
    "statusDetails": None,
    "machineId": "123abc",
    "computerDnsName": "desktop-test",
    "triggeringAlertId": "123-456"
}

INVESTIGATION_DATA = {
    "ID": '123',
    "StartTime": "2020-01-06T14:11:34Z",
    "EndTime": None,
    "CancelledBy": None,
    "State": "Running",
    "StatusDetails": None,
    "MachineID": "123abc",
    "ComputerDNSName": "desktop-test",
    "TriggeringAlertId": "123-456"
}

ALERTS_API_RESPONSE = {
    "value": [{
        "id": "123",
        "incidentId": 123456,
        "investigationId": 654321,
        "investigationState": "Running",
        "assignedTo": "test@test.com",
        "severity": "Low",
        "status": "New",
        "classification": "TruePositive",
        "determination": None,
        "detectionSource": "WindowsDefenderAtp",
        "category": "CommandAndControl",
        "threatFamilyName": None,
        "title": "Network connection to a risky host",
        "description": "A network connection was made to a risky host which has exhibited malicious activity.",
        "alertCreationTime": "2019-11-03T23:49:45.3823185Z",
        "firstEventTime": "2019-11-03T23:47:16.2288822Z",
        "lastEventTime": "2019-11-03T23:47:51.2966758Z",
        "lastUpdateTime": "2019-11-03T23:55:52.6Z",
        "resolvedTime": None,
        "machineId": "123abc",
        "comments": [
            {
                "comment": "test comment for docs",
                "createdBy": "test@test.com",
                "createdTime": "2019-11-05T14:08:37.8404534Z"
            }

        ]
    }
    ]
}
SINGLE_ALERT_API_RESPONSE = {
    "id": "123",
    "incidentId": 123456,
    "investigationId": 654321,
    "investigationState": "Running",
    "assignedTo": "test@test.com",
    "severity": "Low",
    "status": "New",
    "classification": "TruePositive",
    "determination": None,
    "detectionSource": "WindowsDefenderAtp",
    "category": "CommandAndControl",
    "threatFamilyName": None,
    "title": "Network connection to a risky host",
    "description": "A network connection was made to a risky host which has exhibited malicious activity.",
    "alertCreationTime": "2019-11-03T23:49:45.3823185Z",
    "firstEventTime": "2019-11-03T23:47:16.2288822Z",
    "lastEventTime": "2019-11-03T23:47:51.2966758Z",
    "lastUpdateTime": "2019-11-03T23:55:52.6Z",
    "resolvedTime": None,
    "machineId": "123abc",
    "comments": [
        {
            "comment": "test comment for docs",
            "createdBy": "test@test.com",
            "createdTime": "2019-11-05T14:08:37.8404534Z"
        }

    ]
}

ALERT_DATA = {
    "ID": '123',
    "IncidentID": 123456,
    "InvestigationID": 654321,
    "InvestigationState": "Running",
    "AssignedTo": "test@test.com",
    "Severity": "Low",
    "Status": "New",
    "Classification": "TruePositive",
    "Determination": None,
    "DetectionSource": "WindowsDefenderAtp",
    "Category": "CommandAndControl",
    "ThreatFamilyName": None,
    "Title": "Network connection to a risky host",
    "Description": "A network connection was made to a risky host which has exhibited malicious activity.",
    "AlertCreationTime": "2019-11-03T23:49:45.3823185Z",
    "FirstEventTime": "2019-11-03T23:47:16.2288822Z",
    "LastEventTime": "2019-11-03T23:47:51.2966758Z",
    "LastUpdateTime": "2019-11-03T23:55:52.6Z",
    "ResolvedTime": None,
    "MachineID": '123abc',
    "Comments": [
        {
            "Comment": "test comment for docs",
            "CreatedBy": "test@test.com",
            "CreatedTime": "2019-11-05T14:08:37.8404534Z"
        }
    ]

}
MACHINE_RESPONSE_API = {
    'value': [{
        "id": "123",
        "computerDnsName": "test",
        "firstSeen": "2019-11-03T23:47:16.2288822Z",
        "lastSeen": "2019-11-03T23:47:51.2966758Z",
        "osPlatform": "Windows10",
        "version": "1709",
        "osProcessor": "x64",
        "lastIpAddress": "2.2.2.2",
        "lastExternalIpAddress": "1.1.1.1",
        "osBuild": 12345,
        "healthStatus": "Active",
        "rbacGroupId": 140,
        "rbacGroupName": "The-A-Team",
        "riskScore": "Low",
        "exposureLevel": "Medium",
        "isAadJoined": True,
        "aadDeviceId": "12ab34cd",
        "machineTags": ["test tag 1", "test tag 2"]
    }
    ]
}

SINGLE_MACHINE_RESPONSE_API = {
    "@odata.context": "https://api-eu.securitycenter.windows.com/api/$metadata#Machines/$entity",
    "aadDeviceId": None,
    "agentVersion": "10.7740.19041.1151",
    "computerDnsName": "test-node",
    "defenderAvStatus": "Updated",
    "deviceValue": "Normal",
    "exposureLevel": "High",
    "firstSeen": "2021-08-30T20:11:52.7746006Z",
    "healthStatus": "Inactive",
    "id": "123",
    "ipAddresses": [
        {
            "ipAddress": "192.0.2.135",
            "macAddress": "001122334418",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "fe80::2413:e4aa:a3f4:d5bf",
            "macAddress": "001122334418",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "192.0.2.10",
            "macAddress": "001122334436",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "fe80::55b9:7f5a:6e9c:30ed",
            "macAddress": "001122334436",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "192.0.2.11",
            "macAddress": "001122334422",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "fe80::c3:b878:f6fd:ae4b",
            "macAddress": "001122334422",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "192.0.2.12",
            "macAddress": "00112233442C",
            "operationalStatus": "Up",
            "type": "Ethernet"
        },
        {
            "ipAddress": "fe80::65a8:d227:e97b:8220",
            "macAddress": "00112233442C",
            "operationalStatus": "Up",
            "type": "Ethernet"
        }
    ],
    "isAadJoined": False,
    "lastExternalIpAddress": "2.2.2.2",
    "lastIpAddress": "192.0.2.12",
    "lastSeen": "2021-09-12T14:46:04.2458709Z",
    "machineTags": [],
    "managedBy": "Unknown",
    "onboardingStatus": "Onboarded",
    "osArchitecture": "64-bit",
    "osBuild": 19043,
    "osPlatform": "Windows10",
    "osProcessor": "x64",
    "osVersion": None,
    "rbacGroupId": 0,
    "rbacGroupName": None,
    "riskScore": "None",
    "version": "21H1",
    "vmMetadata": None
}

MACHINE_DATA = {
    'ComputerDNSName': 'test',
    'ID': '123',
    'AgentVersion': '1709',
    'FirstSeen': "2019-11-03T23:47:16.2288822Z",
    'LastSeen': "2019-11-03T23:47:51.2966758Z",
    'HealthStatus': "Active",
    'IsAADJoined': True,
    'LastExternalIPAddress': '1.1.1.1',
    'LastIPAddress': '2.2.2.2',
    'Tags': ["test tag 1", "test tag 2"],
    'OSBuild': 12345,
    'OSPlatform': 'Windows10',
    'RBACGroupID': 140,
    'RiskScore': "Low",
    'RBACGroupName': "The-A-Team",
    'AADDeviceID': '12ab34cd',
    'ExposureLevel': "Medium"
}


def tests_get_future_time(mocker):
    from datetime import datetime
    mocker.patch(
        'MicrosoftDefenderAdvancedThreatProtection.parse_date_range',
        return_value=(datetime(1992, 3, 18), datetime(1992, 3, 21)))
    assert '1992-03-24T00:00:00Z' == get_future_time('3 days')


def test_build_std_output_domain():
    domain = "serverity5s55.com"
    res = build_std_output([{
        "domainName": domain
    }])
    assert res['Domain(val.Name && val.Name == obj.Name)'][0]['Name'] == domain


def test_build_std_output_ip():
    ip = "8.8.8.8"
    res = build_std_output([{
        "networkIPv4": ip
    }])
    assert res['IP(val.Address && val.Address == obj.Address)'][0]['Address'] == ip


def test_build_std_output_url():
    url = "https://www.example.com/"
    res = build_std_output([{
        "url": url
    }])
    assert res['URL(val.Data && val.Data == obj.Data)'][0]['Data'] == url


ip_addresses = [
    {
        "ipAddress": "ip1",
        "macAddress": "MAC1",
        "operationalStatus": "Up",
        "type": "Ethernet"
    },
    {
        "ipAddress": "ip2",
        "macAddress": "MAC2",
        "operationalStatus": "Up",
        "type": "Ethernet"
    },
    {
        "ipAddress": "ip3",
        "macAddress": "MAC1",
        "operationalStatus": "Up",
        "type": "Ethernet"
    }
]
ip_addresses_result = [{'MACAddress': 'MAC1', 'IPAddresses': ['ip1', 'ip3'], 'Type': 'Ethernet', 'Status': 'Up'},
                       {'MACAddress': 'MAC2', 'IPAddresses': ['ip2'], 'Type': 'Ethernet', 'Status': 'Up'}]

print_ip_addresses_result = '1. | MAC : MAC1 | IP Addresses : ip1,ip3 | Type : Ethernet | Status : Up\n' \
                            '2. | MAC : MAC2 | IP Addresses : ip2     | Type : Ethernet | Status : Up'


def test_parse_ip_addresses():
    assert parse_ip_addresses(ip_addresses) == ip_addresses_result


def test_print_ip_addresses():
    assert print_ip_addresses(ip_addresses_result) == print_ip_addresses_result


human_readable_result = '### Microsoft Defender ATP machine None details:\n' \
                        '|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|' \
                        'ExposureLevel|IPAddresses|\n' \
                        '|---|---|---|---|---|---|---|---|---|\n' \
                        '| 123 | test-node | Windows10 | 192.0.2.12 | 2.2.2.2 | Inactive | None | High |' \
                        ' 1. \\| MAC : 001122334418 \\| IP Addresses : 192.0.2.135,fe80::2413:e4aa:a3f4:d5bf \\|' \
                        ' Type : Ethernet \\| Status : Up<br>' \
                        '2. \\| MAC : 001122334436 \\| IP Addresses : 192.0.2.10,fe80::55b9:7f5a:6e9c:30ed  \\|' \
                        ' Type : Ethernet \\| Status : Up<br>' \
                        '3. \\| MAC : 001122334422 \\| IP Addresses : 192.0.2.11,fe80::c3:b878:f6fd:ae4b    \\|' \
                        ' Type : Ethernet \\| Status : Up<br>' \
                        '4. \\| MAC : 00112233442C \\| IP Addresses : 192.0.2.12,fe80::65a8:d227:e97b:8220  \\|' \
                        ' Type : Ethernet \\| Status : Up |\n'

outputs_result = """{"ID": "123", "ComputerDNSName": "test-node", "FirstSeen": "2021-08-30T20:11:52.7746006Z",
                  "LastSeen": "2021-09-12T14:46:04.2458709Z", "OSPlatform": "Windows10", "OSVersion": "21H1",
                  "OSProcessor": "x64", "LastIPAddress": "192.0.2.12", "LastExternalIPAddress": "2.2.2.2",
                  "AgentVersion": "10.7740.19041.1151", "OSBuild": 19043, "HealthStatus": "Inactive", "RBACGroupID": 0,
                  "RiskScore": "None", "ExposureLevel": "High", "IsAADJoined": false, "IPAddresses": [
        {"ipAddress": "192.0.2.135", "macAddress": "001122334418", "operationalStatus": "Up", "type": "Ethernet"},
        {"ipAddress": "fe80::2413:e4aa:a3f4:d5bf", "macAddress": "001122334418", "operationalStatus": "Up",
         "type": "Ethernet"},
        {"ipAddress": "192.0.2.10", "macAddress": "001122334436", "operationalStatus": "Up", "type": "Ethernet"},
        {"ipAddress": "fe80::55b9:7f5a:6e9c:30ed", "macAddress": "001122334436", "operationalStatus": "Up",
         "type": "Ethernet"},
        {"ipAddress": "192.0.2.11", "macAddress": "001122334422", "operationalStatus": "Up", "type": "Ethernet"},
        {"ipAddress": "fe80::c3:b878:f6fd:ae4b", "macAddress": "001122334422", "operationalStatus": "Up",
         "type": "Ethernet"},
        {"ipAddress": "192.0.2.12", "macAddress": "00112233442C", "operationalStatus": "Up", "type": "Ethernet"},
        {"ipAddress": "fe80::65a8:d227:e97b:8220", "macAddress": "00112233442C", "operationalStatus": "Up",
         "type": "Ethernet"}]}"""


def test_get_machine_details_command(mocker):
    mocker.patch.object(client_mocker, 'get_machine_details', return_value=SINGLE_MACHINE_RESPONSE_API)
    results = get_machine_details_command(client_mocker, {})
    assert results.outputs == json.loads(outputs_result)
    assert results.readable_output == human_readable_result


FIRST_RUN = {'arguments': "''", 'comment': 'testing',
             'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
SECOND_RUN = {'arguments': "''", 'comment': 'testing',
              'machine_action_id': 'action_id_example',
              'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
LAST_RUN = {'arguments': "''", 'comment': 'testing',
            'machine_action_id': 'action_id_example',
            'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
POLLING_CASES = [
    (FIRST_RUN, '', 'PollingArgs', {'machine_action_id': 'action_id_example', 'interval_in_seconds': 5,
                                    'polling': True, 'arguments': "''", 'comment': 'testing',
                                    'machine_id': 'machine_id_example',
                                    'scriptName': 'test_script.ps1'}),
    (SECOND_RUN, 'InProgress', 'PollingArgs',
     {'interval_in_seconds': 5, 'polling': True, 'arguments': "''", 'comment': 'testing',
      'machine_action_id': 'action_id_example', 'machine_id': 'machine_id_example',
      'scriptName': 'test_script.ps1'}),
    (LAST_RUN, 'Succeeded', 'Contents', {'example_outputs': 'outputs'})

]


@pytest.mark.parametrize('args,request_status,args_to_compare,expected_results', POLLING_CASES)
def test_run_script_polling_second_run(args, request_status, args_to_compare, expected_results):
    from CommonServerPython import CommandResults
    params: dict = demisto.params()
    base_url: str = params.get('url', '').rstrip('/') + '/api'
    tenant_id = params.get('tenant_id') or params.get('_tenant_id')
    auth_id = params.get('auth_id') or params.get('_auth_id')
    enc_key = params.get('enc_key') or (params.get('credentials') or {}).get('password')
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    alert_severities_to_fetch = params.get('fetch_severity')
    alert_status_to_fetch = params.get('fetch_status')
    alert_time_to_fetch = params.get('first_fetch_timestamp', '3 days')
    APP_NAME = 'ms-defender-atp'
    client = MsClient(
        base_url=base_url, tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=APP_NAME, verify=use_ssl,
        proxy=proxy, self_deployed=self_deployed, alert_severities_to_fetch=alert_severities_to_fetch,
        alert_status_to_fetch=alert_status_to_fetch, alert_time_to_fetch=alert_time_to_fetch)

    def mock_action_command(client, args):
        return CommandResults(outputs={'action_id': 'action_id_example'})

    def mock_get_status(client, args):
        return CommandResults(outputs={'status': request_status, 'commands': [{'commandStatus': 'Completed'}]})

    def mock_post_process(client, res):
        assert res == {'commands': [{'commandStatus': 'Completed'}], 'status': 'Succeeded'}
        return CommandResults(outputs={'example_outputs': 'outputs'})

    res = run_polling_command(client, args, 'microsoft-atp-live-response-run-script', mock_action_command,
                              mock_get_status, mock_post_process)
    assert res.to_context()[args_to_compare] == expected_results


RUN_SCRIPT_CASES = [
    (
        {'machine_id': 'machine_id', 'scriptName': 'test_script.ps1', 'comment': 'testing'},
        {'Commands': [{'type': 'RunScript', 'params': [{'key': 'ScriptName', 'value': 'test_script.ps1'}]}],
         'Comment': 'testing'}
    ),
    (
        {'machine_id': 'machine_id', 'scriptName': 'test_script.ps1', 'comment': 'testing', 'arguments': 'example_arg'},
        {'Commands': [{'type': 'RunScript', 'params': [{'key': 'ScriptName', 'value': 'test_script.ps1'},
                                                       {'key': 'Args', 'value': 'example_arg'}]}], 'Comment': 'testing'}

    )
]


@pytest.mark.parametrize('args, expected_results', RUN_SCRIPT_CASES)
def test_run_live_response_script_action(mocker, args, expected_results):
    create_action_mock = mocker.patch.object(MsClient, 'create_action')
    run_live_response_script_action(client_mocker, args)
    assert create_action_mock.call_args[0][1] == expected_results


GET_FILE_CASES = [
    (
        {'machine_id': 'machine_id',
         'comment': "testing",
         'path': "C:\\Users\\example\\Desktop\\test.txt"},
        {'Commands': [
            {'type': 'GetFile', 'params': [{'key': 'Path', 'value': 'C:\\Users\\example\\Desktop\\test.txt'}]}],
            'Comment': 'testing'}
    ),
]


@pytest.mark.parametrize('args, expected_results', GET_FILE_CASES)
def test_get_live_response_file_action(mocker, args, expected_results):
    create_action_mock = mocker.patch.object(MsClient, 'create_action')
    get_live_response_file_action(client_mocker, args)
    assert create_action_mock.call_args[0][1] == expected_results


PUT_FILE_CASES = [
    (
        {'machine_id': 'machine_id',
         'comment': "testing",
         'file_name': "test_script.ps1"},
        {'Commands': [{'type': 'PutFile', 'params': [{'key': 'FileName', 'value': 'test_script.ps1'}]}],
         'Comment': 'testing'}
    ),
]


@pytest.mark.parametrize('args, expected_results', PUT_FILE_CASES)
def test_put_live_response_file_action(mocker, args, expected_results):
    create_action_mock = mocker.patch.object(MsClient, 'create_action')
    put_live_response_file_action(client_mocker, args)
    assert create_action_mock.call_args[0][1] == expected_results

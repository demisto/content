import demistomock as demisto
import json

RETURN_ERROR_TARGET = 'MicrosoftDefenderAdvancedThreatProtection.return_error'


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': True,
                                                         'url': 'https://api.securitycenter.windows.com',
                                                         'tenant_id': '1234',
                                                         'enc_key': 'key',
                                                         'auth_id': '1234567@1234567',
                                                         'fetch_severity': 'Informational,Low,Medium,High',
                                                         'fetch_status': 'New'})
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2018-11-26T16:19:21"})
    mocker.patch.object(demisto, 'incidents')


def atp_mocker(mocker, file_name):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    with open(f'test_data/{file_name}', 'r') as f:
        alerts = json.loads(f.read())
    mocker.patch.object(atp, 'list_alerts_request', return_value=alerts)


def test_first_fetch_incidents(mocker):
    mock_demisto(mocker)
    import MicrosoftDefenderAdvancedThreatProtection as atp
    atp_mocker(mocker, 'first_response_alerts.json')

    atp.fetch_incidents()
    # Check that all 3 incidents are extracted
    assert 3 == len(demisto.incidents.call_args[0][0])
    assert 'Microsoft Defender ATP Alert da636983472338927033_-2077013687' == \
           demisto.incidents.call_args[0][0][2].get('name')


def test_second_fetch_incidents(mocker):
    mock_demisto(mocker)
    import MicrosoftDefenderAdvancedThreatProtection as atp
    atp_mocker(mocker, 'second_response_alerts.json')
    # Check that incident isn't extracted again

    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2019-09-01T13:31:08",
                                                             'existing_ids': ['da637029414680409372_735564929']})
    atp.fetch_incidents()
    assert [] == demisto.incidents.call_args[0][0]


def test_third_fetch_incidents(mocker):
    mock_demisto(mocker)
    import MicrosoftDefenderAdvancedThreatProtection as atp
    atp_mocker(mocker, 'third_response_alerts.json')
    # Check that new incident is extracted
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2019-09-01T13:29:37",
                                                             'existing_ids': ['da637029413772554314_295039533']})
    atp.fetch_incidents()
    assert 'Microsoft Defender ATP Alert da637029414680409372_735564929' == \
           demisto.incidents.call_args[0][0][0].get('name')


def test_get_file_data(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_file_data_request', return_value=FILE_DATA_API_RESPONSE)
    res = atp.get_file_data(FILE_DATA_API_RESPONSE)
    assert res['Sha1'] == "123abc"
    assert res['SizeInBytes'] == 42


def test_get_alert_related_ips_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'id': '123', 'limit': '1', 'offset': '0'})
    mocker.patch.object(atp, 'get_alert_related_ips_request', return_value=ALERT_RELATED_IPS_API_RESPONSE)
    _, res, _ = atp.get_alert_related_ips_command()
    assert res['MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'IPs': ['1.1.1.1']
    }


def test_get_alert_related_domains_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'id': '123', 'limit': '2', 'offset': '0'})
    mocker.patch.object(atp, 'get_alert_related_domains_request', return_value=ALERT_RELATED_DOMAINS_API_RESPONSE)
    _, res, _ = atp.get_alert_related_domains_command()
    assert res['MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'Domains': ['www.example.com', 'www.example2.com']
    }


def test_get_action_data(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_machine_action_by_id_request', return_value=ACTION_DATA_API_RESPONSE)
    res = atp.get_machine_action_data(ACTION_DATA_API_RESPONSE)
    assert res['ID'] == "123456"
    assert res['Status'] == "Succeeded"


def test_get_machine_investigation_package_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_investigation_package_request', return_value=INVESTIGATION_PACKAGE_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=INVESTIGATION_ACTION_DATA)
    _, res, _ = atp.get_machine_investigation_package_command()
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == INVESTIGATION_ACTION_DATA


def test_get_investigation_package_sas_uri_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_investigation_package_sas_uri_request', return_value=INVESTIGATION_SAS_URI_API_RES)
    _, res, _ = atp.get_investigation_package_sas_uri_command()
    assert res['MicrosoftATP.InvestigationURI(val.Link === obj.Link)'] == {
        'Link': 'https://userrequests-us.securitycenter.windows.com:443/safedownload/'
                'WDATP_Investigation_Package.zip?token=test1'}


def test_restrict_app_execution_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'restrict_app_execution_request', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = atp.restrict_app_execution_command()
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_remove_app_restriction_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'remove_app_restriction_request', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = atp.remove_app_restriction_command()
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_stop_and_quarantine_file_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'stop_and_quarantine_file_request', return_value=STOP_AND_QUARANTINE_FILE_RAW_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA)
    _, res, _ = atp.stop_and_quarantine_file_command()
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA


def test_get_investigations_by_id_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'id': '123', 'limit': '1', 'offset': '0'})
    mocker.patch.object(atp, 'get_investigation_by_id_request', return_value=INVESTIGATION_API_RESPONSE)
    mocker.patch.object(atp, 'get_investigation_data', return_value=INVESTIGATION_DATA)
    _, res, _ = atp.get_investigations_by_id_command()
    assert res['MicrosoftATP.Investigation(val.ID === obj.ID)'] == INVESTIGATION_DATA


def test_get_investigation_data(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_investigation_by_id_request', return_value=INVESTIGATION_API_RESPONSE)
    res = atp.get_investigation_data(INVESTIGATION_API_RESPONSE)
    assert res['ID'] == '123'
    assert res['InvestigationState'] == "Running"


def test_start_investigation_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'start_investigation_request', return_value=INVESTIGATION_API_RESPONSE)
    mocker.patch.object(atp, 'get_investigation_data', return_value=INVESTIGATION_DATA)
    _, res, _ = atp.start_investigation_command()
    assert res['MicrosoftATP.Investigation(val.ID === obj.ID)'] == INVESTIGATION_DATA


def test_get_domain_alerts_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'domain': 'test'})
    mocker.patch.object(atp, 'get_domain_alerts_request', return_value=ALERTS_API_RESPONSE)
    mocker.patch.object(atp, 'get_alert_data', return_value=ALERT_DATA)
    _, res, _ = atp.get_domain_alerts_command()
    assert res['MicrosoftATP.DomainAlert(val.Domain === obj.Domain)'] == {
        'Domain': 'test',
        'Alerts': [ALERT_DATA]
    }


def test_get_alert_data(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_alert_by_id_request', return_value=SINGLE_ALERT_API_RESPONSE)
    res = atp.get_alert_data(SINGLE_ALERT_API_RESPONSE)
    assert res['ID'] == '123'
    assert res['Title'] == 'Network connection to a risky host'


def test_get_domain_machine_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'domain': 'test'})
    mocker.patch.object(atp, 'get_domain_machines_request', return_value=MACHINE_RESPONSE_API)
    mocker.patch.object(atp, 'get_machine_data', return_value=MACHINE_DATA)
    _, res, _ = atp.get_domain_machine_command()
    assert res['MicrosoftATP.DomainMachine(val.Domain === obj.Domain)'] == {
        'Domain': 'test',
        'Machines': [MACHINE_DATA]
    }


def test_get_machine_data(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_machine_details_request', return_value=SINGLE_MACHINE_RESPONSE_API)
    res = atp.get_machine_data(SINGLE_MACHINE_RESPONSE_API)
    assert res['ID'] == '123'
    assert res['HealthStatus'] == 'Active'


def test_get_ip_alerts_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'ip': '1.1.1.1'})
    mocker.patch.object(atp, 'get_ip_alerts_request', return_value=ALERTS_API_RESPONSE)
    mocker.patch.object(atp, 'get_alert_data', return_value=ALERT_DATA)
    _, res, _ = atp.get_ip_alerts_command()
    assert res['MicrosoftATP.IPAlert(val.IPAddress === obj.IPAddress)'] == {
        'IPAddress': '1.1.1.1',
        'Alerts': [ALERT_DATA]
    }


def test_run_antivirus_scan_command(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'run_antivirus_scan_request', return_value=MACHINE_ACTION_API_RESPONSE)
    mocker.patch.object(atp, 'get_machine_action_data', return_value=MACHINE_ACTION_DATA)
    _, res, _ = atp.run_antivirus_scan_command()
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'] == MACHINE_ACTION_DATA


def test_check_limit_and_offset_values_no_error():
    import MicrosoftDefenderAdvancedThreatProtection as atp
    res = atp.check_limit_and_offset_values(limit='2', offset='1')
    assert res == (2, 1)


def test_check_limit_and_offset_values_invalid_limit(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    atp.check_limit_and_offset_values(limit='abc', offset='1')
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: You can only enter a positive integer or zero to limit argument.'


def test_check_limit_and_offset_values_invalid_offset(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    atp.check_limit_and_offset_values(limit='1', offset='-4')
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: You can only enter a positive integer to offset argument.'


def test_check_limit_and_offset_values_limit_zero(mocker):
    import MicrosoftDefenderAdvancedThreatProtection as atp
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    atp.check_limit_and_offset_values(limit='0', offset='1')
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error: The value of the limit argument must be a positive integer.'


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

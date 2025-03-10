import dateparser
import requests_mock
from _pytest.python_api import raises
from freezegun import freeze_time

import demistomock as demisto
import json
import pytest
import dataclasses

from CommonServerPython import snakify, DemistoException
from MicrosoftDefenderAdvancedThreatProtection import MsClient, get_future_time, build_std_output, get_machine_by_ip_command, \
    parse_ip_addresses, \
    print_ip_addresses, get_machine_details_command, run_polling_command, run_live_response_script_action, \
    get_live_response_file_action, put_live_response_file_action, HuntingQueryBuilder, FileStatisticsAPIParser, assign_params, \
    get_machine_users_command, get_machine_alerts_command, get_advanced_hunting_command, create_filters_conjunction, \
    create_filters_disjunctions, create_filter, MICROSOFT_DEFENDER_FOR_ENDPOINT_API

ARGS = {'id': '123', 'limit': '2', 'offset': '0'}
with open('test_data/expected_hunting_queries.json') as expected_json:
    EXPECTED_HUNTING_QUERIES = json.load(expected_json)


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2018-11-26T16:19:21"})
    mocker.patch.object(demisto, 'incidents')


client_mocker = MsClient(
    tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name', base_url='url', verify='use_ssl',
    proxy='proxy', self_deployed='self_deployed', alert_severities_to_fetch='Informational,Low,Medium,High',
    alert_time_to_fetch='3 days', alert_status_to_fetch='New', max_fetch='10', auth_code='', auth_type='',
    redirect_uri='', endpoint_type='com', alert_detectionsource_to_fetch='')


def atp_mocker(mocker, file_name):
    with open(f'test_data/{file_name}') as f:
        alerts = json.loads(f.read())
    mocker.patch.object(client_mocker, 'list_alerts_by_params', return_value=alerts)


def test_first_fetch_incidents(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'first_response_alerts.json')

    incidents, _ = fetch_incidents(client_mocker, {'last_alert_fetched_time': "2018-11-26T16:19:21"}, False)
    # Check that all 3 incidents are extracted
    assert len(incidents) == 3
    assert incidents[2].get('name') == \
        'Microsoft Defender ATP Alert da636983472338927033_-2077013687'


def test_second_fetch_incidents(mocker):
    """
    Given: running olf fetch with existing id's
    When: running new fetch-incidents after old one had run
    Then: incidents of the same second will be duplicated
    """
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'second_response_alerts.json')
    # Check that incident isn't extracted again
    incidents, _ = fetch_incidents(client_mocker, {'last_alert_fetched_time': "2019-09-01T13:31:07",
                                                   'existing_ids': ['da637029414680409372_735564929']}, False)
    assert incidents == [{
        'rawJSON': '{"id": "da637029414680409372_735564929", "incidentId": 14, "investigationId": null, '
                   '"assignedTo": null, "severity": "Medium", "status": "New", "classification": null, '
                   '"determination": null, "investigationState": "UnsupportedAlertType", '
                   '"detectionSource": "CustomerTI", "category": "null", "threatFamilyName": null, '
                   '"title": "Demisto Alert", "description": "Created for documentation", '
                   '"alertCreationTime": "2019-09-01T13:31:08.0252869Z", '
                   '"firstEventTime": "2019-08-05T00:53:51.1469367Z", "lastEventTime": "2019-08-05T00:53:51.1469367Z",'
                   ' "lastUpdateTime": "2019-09-01T13:31:08.57Z", "resolvedTime": null, '
                   '"machineId": "43df73d1dac43593d1275e20422f44a949f6dfc3", "alertUser": null, "comments": [], '
                   '"alertFiles": [], "alertDomains": [], "alertIps": []}',
        'name': 'Microsoft Defender ATP Alert da637029414680409372_735564929',
        'occurred': '2019-09-01T13:31:08.0252869Z', 'dbotMirrorId': 'da637029414680409372_735564929'}]


def test_third_fetch_incidents(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mock_demisto(mocker)
    atp_mocker(mocker, 'third_response_alerts.json')
    # Check that new incident is extracted
    incidents, _ = fetch_incidents(client_mocker, {'last_alert_fetched_time': "2019-09-01T13:29:37",
                                                   'existing_ids': ['da637029413772554314_295039533']}, False)
    assert incidents[0].get('name') == \
        'Microsoft Defender ATP Alert da637029414680409372_735564929'


test_get_machine_by_ip_data = [
    ({'ip': '8.8.8.8', 'timestamp': '2024-05-19T01:00:05Z', 'all_results': 'True'},  # case no limit and all_results is True
     '8.8.8.8', '2024-05-19T01:00:05Z', {"value": [{'a': 'b'}, {'c': 'd'}, {'e': 'f'}]}),  # expected two machines
    ({'ip': '8.8.8.8', 'timestamp': '2024-05-19T01:00:05Z', 'limit': '1'},  # case with limit
     '8.8.8.8', '2024-05-19T01:00:05Z', {"value": [{'a': 'b'}]})  # expected only 1 machine
]


@pytest.mark.parametrize('params, ip, timestamp, expected', test_get_machine_by_ip_data)
def test_get_machine_by_ip_with_limit(mocker, params, ip, timestamp, expected):
    """
    Given:
        -A limit argument.
    When:
        -running get-machine-by-ip command.
    Then:
        -The number of machines returned is not grater than the limit and http request is called with the right args.
    """
    from MicrosoftDefenderAdvancedThreatProtection import MsClient
    raw_response = {'value': [{'a': 'b'}, {'c': 'd'}, {'e': 'f'}]}
    mock_get_machines = mocker.patch.object(
        MsClient, 'get_machines_for_get_machine_by_ip_command', return_value=raw_response)
    mock_handle_machines = mocker.patch("MicrosoftDefenderAdvancedThreatProtection.handle_machines")
    get_machine_by_ip_command(client_mocker, params)
    assert mock_get_machines.call_args.args[0] == f"(ip='{ip}',timestamp={timestamp})"
    assert mock_handle_machines.call_args.args[0] == expected


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


def test_offboard_machine_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import offboard_machine_command
    mocker.patch.object(client_mocker, 'offboard_machine', return_value=MACHINE_OFFBOARD_API_RESPONSE)
    args = {'machine_id': '9b898e79b0ed2173cc87577a158d1dba5f61d7a7', 'comment': 'Testing Offboarding'}
    result = offboard_machine_command(client_mocker, args)
    assert result.outputs[0]['ID'] == '947a677a-a11a-4240-ab6q-91277e2386b9'
    assert result.outputs[0]['Status'] == 'Pending'
    assert result.outputs[0]['Type'] == 'Offboard'


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
    res = stop_and_quarantine_file_command(client_mocker, {'machine_id': 'test', 'file_hash': 'hash'})
    assert res[0].outputs == MACHINE_ACTION_STOP_AND_QUARANTINE_FILE_DATA


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
    _, res, _ = run_antivirus_scan_command(client_mocker, {'machine_id': "123abc"})
    assert res['MicrosoftATP.MachineAction(val.ID === obj.ID)'][0] == MACHINE_ACTION_DATA


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

FILE_STATISTICS_API_RESPONSE = {
    '@odata.context': 'https://api.security.microsoft.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgFileStats',
    'sha1': '0991a395da64e1c5fbe8732ed11e6be064081d9f',
    'orgPrevalence': '14850',
    'organizationPrevalence': 14850,  # same as 'orgPrevalence', but as integer
    'orgFirstSeen': '2019-12-07T13:44:16Z',
    'orgLastSeen': '2020-01-06T13:39:36Z',
    'globalPrevalence': '705012',
    'globallyPrevalence': 705012,  # same as 'globalPrevalence', but as integer
    'globalFirstObserved': '2015-03-19T12:20:07.3432441Z',
    'globalLastObserved': '2020-01-06T13:39:36Z',
    'topFileNames': ['MREC.exe']
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
STOP_AND_QUARANTINE_FILE_RAW_RESPONSE: dict = {
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

SINGLE_MACHINE_RESPONSE_API: dict = {
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

MACHINE_USER_DATA = {
    "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Users",
    "value": [
        {
            "id": "contoso\\user1",
            "accountName": "user1",
            "accountDomain": "contoso",
            "firstSeen": "2019-12-18T08:02:54Z",
            "lastSeen": "2020-01-06T08:01:48Z",
            "logonTypes": "Interactive",
            "isDomainAdmin": True,
            "isOnlyNetworkUser": False
        }
    ]
}

MACHINE_USER_OUTPUT = {
    "AccountName": "user1",
    "AccountDomain": "contoso",
    'AccountSID': None,
    "DomainAdmin": True,
    "FirstSeen": "2019-12-18T08:02:54Z",
    "ID": "contoso\\user1",
    "LastSeen": "2020-01-06T08:01:48Z",
    'LeastPrevalentMachineID': None,
    'LogonCount': None,
    "LogonTypes": "Interactive",
    'MachineID': '123abc',
    'MostPrevalentMachineID': None,
    "NetworkUser": False,
}

MACHINE_ALERTS_OUTPUT = {
    'AADTenantID': None,
    'AlertCreationTime': '2019-11-03T23:49:45.3823185Z',
    'AssignedTo': 'test@test.com',
    "Category": "CommandAndControl",
    "Classification": "TruePositive",
    'Comments': [
        {
            'Comment': None,
            'CreatedBy': None,
            'CreatedTime': None
        }
    ],
    'ComputerDNSName': None,
    "Description": "A network connection was made to a risky host which has exhibited malicious activity.",
    'DetectionSource': 'WindowsDefenderAtp',
    'DetectorID': None,
    'Determination': None,
    'Evidence': None,
    'FirstEventTime': '2019-11-03T23:47:16.2288822Z',
    "ID": "123",
    "IncidentID": 123456,
    'InvestigationID': 654321,
    'InvestigationState': 'Running',
    'LastEventTime': '2019-11-03T23:47:51.2966758Z',
    'LastUpdateTime': '2019-11-03T23:55:52.6Z',
    "MachineID": "123abc",
    'MitreTechniques': None,
    'RBACGroupName': None,
    'RelatedUser': None,
    'ResolvedTime': None,
    "Severity": "Low",
    "Status": "New",
    "ThreatFamilyName": None,
    'ThreatName': None,
    "Title": "Network connection to a risky host",
}

MACHINE_OFFBOARD_API_RESPONSE: dict = {
    "@odata.context": "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity",
    "id": "947a677a-a11a-4240-ab6q-91277e2386b9",
    "type": "Offboard",
    "title": None,
    "requestor": "cbceb30b-f2b1-488e-893e-62907e4fe6d5",
    "requestorComment": "Testing Offboarding",
    "status": "Pending",
    "machineId": None,
    "computerDnsName": None,
    "creationDateTimeUtc": "2022-07-12T14:39:19.6103056Z",
    "lastUpdateDateTimeUtc": "2022-07-12T14:39:19.610309Z",
    "cancellationRequestor": None,
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "errorHResult": 0,
    "scope": None,
    "externalId": None,
    "requestSource": "PublicApi",
    "relatedFileInfo": None,
    "commands": [],
    "troubleshootInfo": None
}


def tests_get_future_time(mocker):
    from datetime import datetime
    mocker.patch(
        'MicrosoftDefenderAdvancedThreatProtection.parse_date_range',
        return_value=(datetime(1992, 3, 18), datetime(1992, 3, 21)))
    assert get_future_time('3 days') == '1992-03-24T00:00:00Z'


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


human_readable_result = '### Microsoft Defender ATP machines [\'123abc\'] details:\n' \
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
    results = get_machine_details_command(client_mocker, {'machine_id': "123abc"})
    assert results.outputs[0] == json.loads(outputs_result)
    assert results.readable_output == human_readable_result


@pytest.mark.parametrize('fields_to_filter_by, field_key_from_type_list, expected_query', [
    # field_key_from_type_list does not exist
    ({'ip': '1.2.3.4', 'host': 'example'}, 'id', "ip eq '1.2.3.4' and host eq 'example'"),
    # field_key_from_type_list has only one value in the list
    ({'ip': '1.2.3.4', 'id': ['1'], 'host': 'example'}, 'id', "ip eq '1.2.3.4' and id eq '1' and host eq 'example'"),
    # field_key_from_type_list has more than one value in the list
    ({'ip': '1.2.3.4', 'id': ['1', '2']}, 'id', "(ip eq '1.2.3.4' and id eq '1') or (ip eq '1.2.3.4' and id eq '2')"),
    ({'ip': '1.2.3.4', 'id': ['1', '2'], 'host': 'example'}, 'id',
     ("(ip eq '1.2.3.4' and host eq 'example' and id eq '1') or "
      "(ip eq '1.2.3.4' and host eq 'example' and id eq '2')")),
])
def test_reformat_filter_with_list_arg(fields_to_filter_by, field_key_from_type_list, expected_query):
    from MicrosoftDefenderAdvancedThreatProtection import reformat_filter_with_list_arg
    assert reformat_filter_with_list_arg(fields_to_filter_by, field_key_from_type_list) == expected_query


@pytest.mark.parametrize('hostnames, ips, ids, expected_filter', [
    # only one list is given
    (['example.com'], [], [], "computerDnsName eq 'example.com'"),
    (['example.com', 'b.com'], [], [], "computerDnsName eq 'example.com' or computerDnsName eq 'b.com'"),
    # each list has only one value
    (['b.com'], ['1.2.3.4'], ['1'], "computerDnsName eq 'b.com' or lastIpAddress eq '1.2.3.4' or id eq '1'"),
    # each list has more than 1 value
    (['b.com', 'a.com'], ['1.2.3.4', '1.2.3.5'], ['1', '2'],
     "computerDnsName eq 'b.com' or computerDnsName eq 'a.com' or "
     "lastIpAddress eq '1.2.3.4' or "
     "lastIpAddress eq '1.2.3.5' or "
     "id eq '1' or "
     "id eq '2'"),

])
def test_create_filter_for_endpoint_command(hostnames, ips, ids, expected_filter):
    from MicrosoftDefenderAdvancedThreatProtection import create_filter_for_endpoint_command
    assert create_filter_for_endpoint_command(hostnames, ips, ids) == expected_filter


@pytest.mark.parametrize('machines_list, expected_list', [
    ([{'ID': 1, 'CVE': 'CVE-1'}, {'ID': 1, 'CVE': 'CVE-2'}, {'ID': 2, 'CVE': 'CVE-1'}],
     [{'ID': 1, 'CVE': ['CVE-1', 'CVE-2']}, {'ID': 2, 'CVE': ['CVE-1']}]),

    ([{'ID': 1, 'CVE': 'CVE-1'}, {'ID': 3, 'CVE': 'CVE-3'}, {'ID': 2, 'CVE': 'CVE-1'}],
     [{'ID': 1, 'CVE': ['CVE-1']}, {'ID': 3, 'CVE': ['CVE-3']}, {'ID': 2, 'CVE': ['CVE-1']}, ]),

    ([], []),
    ([{'ID': 1, 'CVE': 'CVE-1'}, {'ID': 1, 'CVE': 'CVE-2'}], [{'ID': 1, 'CVE': ['CVE-1', 'CVE-2']}]),

])
def test_create_related_cve_list_for_machine(machines_list, expected_list):
    from MicrosoftDefenderAdvancedThreatProtection import create_related_cve_list_for_machine
    assert create_related_cve_list_for_machine(machines_list) == expected_list


@pytest.mark.parametrize('machine, expected_result', [
    ({'ipAddresses': [], 'lastIpAddress': "1.2.3.4"}, None),
    ({'ipAddresses': []}, None),
    ({'ipAddresses': [{'ipAddress': "1.1.1.1", 'macAddress': ""}], 'lastIpAddress': "1.2.3.4"}, None),
    ({'ipAddresses': [{'ipAddress': "1.2.3.4", 'macAddress': ""}], 'lastIpAddress': "1.2.3.4"}, ""),
    ({'ipAddresses': [{'ipAddress': "1.2.3.4", 'macAddress': "mac"}], 'lastIpAddress': "1.2.3.4"}, "mac"),
    ({'ipAddresses': [{'ipAddress': "1.2.3.4", 'macAddress': "mac"}, {'ipAddress': "1.1.1.1", 'macAddress': "mac"}],
      'lastIpAddress': "1.2.3.4"}, "mac"),
])
def test_get_machine_mac_address(machine, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_mac_address
    assert get_machine_mac_address(machine) == expected_result


@pytest.mark.parametrize('failed_devices, all_requested_devices, expected_result', [
    ({}, ["id1", "id2"], ""),
    ({'id1': "some error"}, ["id1", "id2"], "Note: you don't see the following IDs in the results as the request was "
                                            "failed for them. \nID id1 failed with the error: some error \n"),
])
def test_add_error_message(failed_devices, all_requested_devices, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import add_error_message
    assert add_error_message(failed_devices, all_requested_devices) == expected_result


@pytest.mark.parametrize('failed_devices, all_requested_devices', [
    ({'id1': "some error", 'id2': "some error"}, ["id1", "id2"]),
    ({'id1': "some error1", 'id2': "some error2"}, ["id1", "id2"]),
])
def test_add_error_message_raise_error(failed_devices, all_requested_devices):
    from MicrosoftDefenderAdvancedThreatProtection import add_error_message
    with raises(DemistoException,
                match=f'Microsoft Defender ATP The command was failed with the errors: {failed_devices}'):
        add_error_message(failed_devices, all_requested_devices)


@pytest.mark.parametrize('indicators_response, expected_result', [
    ({'value': []}, []),
    ({'value': [{"id": '1', "indicator": '2', "isFailed": 'false', "failureReason": "", 'name': "no"}]},
     [{"ID": '1', "Value": '2', "IsFailed": 'false', "FailureReason": ""}]),
    ({'value': [{"id": '1', "indicator": '2', "isFailed": 'false', "failureReason": "", 'name': "no"},
                {"id": '2', "indicator": '4', "isFailed": 'true', "failureReason": "reason", 'name': "no"},
                {'name': "no"}]},
     [{"ID": '1', "Value": '2', "IsFailed": 'false', "FailureReason": ""},
      {"ID": '2', "Value": '4', "IsFailed": 'true', "FailureReason": "reason"},
      {'FailureReason': None, 'ID': None, 'IsFailed': None, 'Value': None}]),
])
def test_parse_indicator_batch_response(indicators_response, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import parse_indicator_batch_response
    assert parse_indicator_batch_response(indicators_response) == expected_result


ALERT_JSON = {'id': '1', 'incidentId': 2, 'investigationId': 3, 'assignedTo': 'Automation', 'severity': 'Informational',
              'status': 'Resolved', 'classification': None, 'determination': None,
              'investigationState': 'SuccessfullyRemediated',
              'detectionSource': 'WindowsDefenderAv', 'detectorId': '4',
              'category': 'Malware', 'threatFamilyName': 'Test_File', 'title': "Test_File",
              'description': 'Test', 'alertCreationTime': '2022-02-07T10:26:40.05748Z',
              'firstEventTime': '2022-02-07T10:20:52.2188896Z',
              'lastEventTime': '2022-02-07T10:20:52.2571395Z', 'lastUpdateTime': '2022-02-07T10:57:13.93Z',
              'resolvedTime': '2022-02-07T10:57:13.773683Z', 'machineId': '4',
              'computerDnsName': 'win2016', 'rbacGroupName': None,
              'aadTenantId': 'ebac1a16-81bf-449b-8d43-5732c3c1d999', 'threatName': 'Test',
              'mitreTechniques': [], 'relatedUser': None, 'comments': [],
              'evidence': [{'entityType': 'File', 'evidenceCreationTime': '2022-02-07T10:26:40.24Z',
                            'sha1': '33', 'sha256': '27', 'fileName': 'test.com',
                            'filePath': 'Downloads', 'processId': None, 'processCommandLine': None,
                            'processCreationTime': None, 'parentProcessId': None, 'parentProcessCreationTime': None,
                            'parentProcessFileName': None, 'parentProcessFilePath': None, 'ipAddress': None,
                            'url': None,
                            'registryKey': None, 'registryHive': None, 'registryValueType': None, 'registryValue': None,
                            'accountName': None, 'domainName': None, 'userSid': None, 'aadUserId': None,
                            'userPrincipalName': None,
                            'detectionStatus': 'Prevented'}]}


def test_get_alert_by_id_command(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import get_alert_by_id_command
    mocker.patch.object(client_mocker, 'get_alert_by_id', return_value=ALERT_JSON)
    results = get_alert_by_id_command(client_mocker, {'alert_ids': ['1']})
    assert results.outputs[0]['ID'] == '1'
    assert len(results.outputs[0]) == len(ALERT_JSON.keys())


FIRST_RUN = {'arguments': "''", 'comment': 'testing',
             'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
SECOND_RUN = {'arguments': "''", 'comment': 'testing',
              'machine_action_id': 'action_id_example',
              'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
LAST_RUN = {'arguments': "''", 'comment': 'testing',
            'machine_action_id': 'action_id_example',
            'machine_id': 'machine_id_example', 'scriptName': 'test_script.ps1'}
POLLING_CASES = [
    (FIRST_RUN, '', 'PollingArgs', {'machine_action_id': 'action_id_example', 'interval_in_seconds': 10,
                                    'polling': True, 'arguments': "''", 'comment': 'testing',
                                    'machine_id': 'machine_id_example',
                                    'scriptName': 'test_script.ps1'}),
    (SECOND_RUN, 'InProgress', 'PollingArgs',
     {'interval_in_seconds': 10, 'polling': True, 'arguments': "''", 'comment': 'testing',
      'machine_action_id': 'action_id_example', 'machine_id': 'machine_id_example',
      'scriptName': 'test_script.ps1'}),
    (LAST_RUN, 'Succeeded', 'Contents', {'example_outputs': 'outputs'})

]


@pytest.mark.parametrize('args,request_status,args_to_compare,expected_results', POLLING_CASES)
def test_run_script_polling(mocker, args, request_status, args_to_compare, expected_results):
    import CommonServerPython

    def mock_action_command(client, args):
        return CommonServerPython.CommandResults(outputs={'action_id': 'action_id_example'})

    def mock_get_status(client, args):
        return CommonServerPython.CommandResults(
            outputs={'status': request_status, 'commands': [{'commandStatus': 'Completed'}]})

    def mock_post_process(client, res):
        assert res == {'commands': [{'commandStatus': 'Completed'}], 'status': 'Succeeded'}
        return CommonServerPython.CommandResults(outputs={'example_outputs': 'outputs'})

    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    res = run_polling_command(client_mocker, args, 'microsoft-atp-live-response-run-script', mock_action_command,
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


ALERTS = [

    {'id': 'id1',
     'incidentId': 1,
     'severity': 'Medium',
     'status': 'Resolved',
     'alertCreationTime': '2022-02-17T02:07:23.6716257Z',
     'evidence': []},
    {'id': 'id2',
     'incidentId': 2,
     'severity': 'Informational',
     'status': 'Resolved',
     'alertCreationTime': '2022-02-17T02:07:24.6716257Z',
     'evidence': []},
    {'id': 'id3',
     'incidentId': 3,
     'severity': 'Informational',
     'status': 'Resolved',
     'alertCreationTime': '2022-02-17T02:20:23.6716257Z',
     'evidence': []},
    {'id': 'id4',
     'incidentId': 4,
     'severity': 'Informational',
     'status': 'Resolved',
     'alertCreationTime': '2022-02-17T02:30:23.6716257Z',
     'evidence': []},
]

EMPTY_LAST_RUN: dict = {}
OLD_LAST_RUN_WITH_IDS = {'last_alert_fetched_time': '2022-02-17T02:07:23',
                         'existing_ids': ['da637806604436477417_-578430041',
                                          'da637806604436712653_-30042333']}
EXISTING_LAST_RUN_MIDDLE_FETCH = {'last_alert_fetched_time': '2022-02-17T02:07:24.6716257Z'}

FIRST_FETCH_NO_INCIDENTS = {'last_run': EMPTY_LAST_RUN, 'incidents': []}
FIRST_FETCH_WITH_INCIDENTS = {'last_run': EMPTY_LAST_RUN, 'incidents': ALERTS}
SECOND_FETCH_WITH_INCIDENTS = {'last_run': EXISTING_LAST_RUN_MIDDLE_FETCH, 'incidents': ALERTS[2:]}
SECOND_FETCH_AFTER_UPDATE = {'last_run': OLD_LAST_RUN_WITH_IDS, 'incidents': ALERTS}

fetch_cases = [
    (FIRST_FETCH_NO_INCIDENTS, {'last_alert_fetched_time': '2022-02-14T14:39:01.391001Z', 'incidents': 0}),
    (FIRST_FETCH_WITH_INCIDENTS, {'last_alert_fetched_time': '2022-02-17T02:30:23.671625Z', 'incidents': 4}),
    (SECOND_FETCH_WITH_INCIDENTS, {'last_alert_fetched_time': '2022-02-17T02:30:23.671625Z', 'incidents': 2}),
    (SECOND_FETCH_AFTER_UPDATE, {'last_alert_fetched_time': '2022-02-17T02:30:23.671625Z', 'incidents': 4}),
]


@pytest.mark.parametrize('case, expected_result', fetch_cases)
def test_fetch(mocker, case, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents

    frozen_time = dateparser.parse('2022-02-17T14:39:01.391001Z',
                                   settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'})

    mocker.patch.object(demisto, 'debug')
    with freeze_time(frozen_time):
        mocker.patch.object(client_mocker, 'list_alerts_by_params', return_value={'value': case['incidents']})
        incidents, last_run = fetch_incidents(client_mocker, case['last_run'], True)
        assert last_run.get('last_alert_fetched_time') == expected_result['last_alert_fetched_time']
        assert len(incidents) == expected_result['incidents']


def test_fetch_fails(mocker):
    from MicrosoftDefenderAdvancedThreatProtection import fetch_incidents
    mocker.patch.object(demisto, 'debug')

    def raise_mock(params=None, overwrite_rate_limit_retry=True):
        raise DemistoException("""Verify that the server URL parameter is correct and that you have access to the server from your host.
Error Type: <requests.exceptions.ConnectionError>
Error Number: [None]
Message: None
""")  # noqa: E501

    mocker.patch.object(client_mocker, 'list_alerts_by_params', side_effect=raise_mock)
    with pytest.raises(Exception) as e:
        fetch_incidents(client_mocker, {}, True)
    assert str(
        e.value) == f'Failed to fetch {client_mocker.max_alerts_to_fetch} alerts. ' \
                    f'This may caused due to large amount of alert. Try using a lower limit.'


QUERY_BUILDING_CASES = [
    (
        'New, Resolved', 'Informational,Low,Medium,High', '5', False, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and "
                       "((status+eq+'New') or (status+eq+'Resolved')) and "
                       "((severity+eq+'Informational') or (severity+eq+'Low') or (severity+eq+'Medium') "
                       "or (severity+eq+'High'))",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        None, 'Informational,Low,Medium,High', '5', False, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and "
                       "((severity+eq+'Informational') or (severity+eq+'Low') "
                       "or (severity+eq+'Medium') or (severity+eq+'High'))",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        'New', None, '5', False, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and (status+eq+'New')",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        None, 'Informational', '5', False, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and (severity+eq+'Informational')",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        None, None, '5', False, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': 'alertCreationTime+gt+2022-02-17T14:39:01.391001Z', '$orderby': 'alertCreationTime asc',
            '$top': '5'
        }
    ),
    (
        'Resolved', 'High', '5', True, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and "
                       "(status+eq+'Resolved') and (severity+eq+'High')",
            '$orderby': 'alertCreationTime asc', '$expand': 'evidence', '$top': '5'
        }
    ),
    (
        None, None, '5', True, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': 'alertCreationTime+gt+2022-02-17T14:39:01.391001Z', '$orderby': 'alertCreationTime asc',
            '$expand': 'evidence', '$top': '5'
        }
    ),
    (
        None, None, '5', True, '2022-02-17T14:39:01.391001Z', None,
        {
            '$filter': 'alertCreationTime+gt+2022-02-17T14:39:01.391001Z', '$orderby': 'alertCreationTime asc',
            '$expand': 'evidence', '$top': '5'
        }
    ),
    (
        None, 'Informational', '5', False, '2022-02-17T14:39:01.391001Z', 'Microsoft Defender for Office 365',
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and "
                       "(detectionSource+eq+'OfficeATP') and (severity+eq+'Informational')",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        'New', None, '5', False, '2022-02-17T14:39:01.391001Z', 'EDR',
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and (detectionSource+eq+'WindowsDefenderAtp') and "
                       "(status+eq+'New')",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    ),
    (
        'New, Resolved', 'Informational,Low,Medium,High', '5', False, '2022-02-17T14:39:01.391001Z', 'Custom detection,Custom TI',
        {
            '$filter': "alertCreationTime+gt+2022-02-17T14:39:01.391001Z and "
                       "((detectionSource+eq+'CustomDetection') or (detectionSource+eq+'CustomerTI')) and "
                       "((status+eq+'New') or (status+eq+'Resolved')) and "
                       "((severity+eq+'Informational') or (severity+eq+'Low') or (severity+eq+'Medium') "
                       "or (severity+eq+'High'))",
            '$orderby': 'alertCreationTime asc', '$top': '5'
        }
    )

]


@pytest.mark.parametrize('status, severity, limit, evidence, last_fetch_time, detection_sources, expected_result',
                         QUERY_BUILDING_CASES)
def test_get_incidents_query_params(status, severity, limit, evidence, last_fetch_time, expected_result, detection_sources):
    from copy import deepcopy
    from MicrosoftDefenderAdvancedThreatProtection import _get_incidents_query_params

    client = deepcopy(client_mocker)
    client.max_alerts_to_fetch = limit
    client.alert_detectionsource_to_fetch = detection_sources
    client.alert_severities_to_fetch = severity
    client.alert_status_to_fetch = status

    query = _get_incidents_query_params(client, fetch_evidence=evidence, last_fetch_time=last_fetch_time)
    assert query == expected_result


class TestHuntingQueryBuilder:
    class TestHelperMethods:
        def test_get_time_range_query__invalid_and_empty(self):
            """
            Tests invalid and empty time_range cases

            Given:
                - empty / Invalid time_range
            When:
                - calling get_time_range_query
            Then:
                - return empty str
            """
            expected = ""
            # empty case:
            assert HuntingQueryBuilder.get_time_range_query(None) == expected
            assert HuntingQueryBuilder.get_time_range_query('') == expected

            # invalid case:
            assert HuntingQueryBuilder.get_time_range_query('invalid') == expected

        def test_get_time_range_query__valid(self):
            """
            Tests valid time_range

            Given:
                - time_range of 1 day ago
            When:
                - calling get_time_range_query
            Then:
                - return a time_query of
            """
            expected = 'Timestamp > ago(1440m)'
            assert HuntingQueryBuilder.get_time_range_query('1 day') == expected

        def test_rebuild_query_with_time_range__table_only(self):
            """
            Tests case for table name only

            Given:
                - query with table name only
            When:
                - calling rebuild_query_with_time_range
            Then:
                - returns a query with time_range
            """
            query = 'tableName'
            time_range = '2 days'
            expected = 'tableName | where Timestamp > ago(2880m)'
            assert HuntingQueryBuilder.rebuild_query_with_time_range(query, time_range) == expected

        def test_rebuild_query_with_time_range__full_query(self):
            """
            Tests full query

            Given:
                - query with table name only
            When:
                - calling rebuild_query_with_time_range
            Then:
                - returns a query with time_range
            """
            query = 'tableName | where a | where b'
            time_range = '2 days'
            expected = 'tableName | where Timestamp > ago(2880m) | where a | where b'
            assert HuntingQueryBuilder.rebuild_query_with_time_range(query, time_range) == expected

        def test_list_to_filter_values__empty(self):
            """
            Tests list_to_filter empty case

            Given:
                - empty list
            When:
                - calling list_to_filter_values
            Then:
                - return an empty str
            """
            assert HuntingQueryBuilder.get_filter_values([]) is None

        def test_list_to_filter_values__invalid(self):
            """
            Tests list_to_filter invalid case

            Given:
                - non list item
            When:
                - calling list_to_filter_values
            Then:
                - return an empty str
            """
            assert HuntingQueryBuilder.get_filter_values(42) is None

        def test_list_to_filter_values__list(self):
            """
            Tests list_to_filter empty case

            Given:
                - list of 1 item
                - list of 3 items
            When:
                - calling list_to_filter_values
            Then:
                - return a string representation of the lists
            """
            list_input = ['a', 'b', 'c']
            assert HuntingQueryBuilder.get_filter_values(list_input) == '("a","b","c")'
            assert HuntingQueryBuilder.get_filter_values(list_input[:1]) == '("a")'

        def test_build_generic_query(self):
            """

            :return:
            """
            query_params = assign_params(
                a='("1")',
                b='("1","2")',
                c='',
                d=None,
                e=('test_op', '"1","2"')
            )
            actual = HuntingQueryBuilder.build_generic_query('some query', ' suffix', query_params, 'or', 'in')
            assert len(actual) == 75
            assert actual[:12] == 'some query ('
            assert '(a in ("1"))' in actual
            assert '(b in ("1","2"))' in actual
            assert 'or' in actual
            assert 'in' in actual
            assert 'e test_op "1","2"' in actual
            assert ' suffix' in actual

    class TestLateralMovementEvidence:
        def test_build_network_connections_query(self):
            """
            Tests network connection query

            Given:
                - LateralMovementEvidence inited with sha1
            When:
                - calling build_network_connections_query
            Then:
                - return a network_connections query
            """
            expected = EXPECTED_HUNTING_QUERIES['LateralMovementEvidence']['network_connections']
            lme = HuntingQueryBuilder.LateralMovementEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = lme.build_network_connections_query()
            assert actual == expected

        def test_build_smb_connections_query(self):
            """
            Tests smb connections query

            Given:
                - LateralMovementEvidence inited with md5
            When:
                - calling build_smb_connections_query
            Then:
                - return a smb_connections query
            """
            expected = EXPECTED_HUNTING_QUERIES['LateralMovementEvidence']['smb_connections']
            lme = HuntingQueryBuilder.LateralMovementEvidence(
                limit='1',
                query_operation='and',
                md5='1,2',
                page='1',
            )
            actual = lme.build_smb_connections_query()
            assert actual == expected

        def test_build_smb_connections_query__with_remote_ip_count(self):
            """
            Tests smb connections query with remote_ip_count

            Given:
                - LateralMovementEvidence inited with md5 and remote_ip_count
            When:
                - calling build_smb_connections_query
            Then:
                - return a smb_connections query
            """
            expected = EXPECTED_HUNTING_QUERIES['LateralMovementEvidence']['smb_connections_w_remote_ip_count']
            lme = HuntingQueryBuilder.LateralMovementEvidence(
                limit='1',
                query_operation='and',
                md5='1,2',
                remote_ip_count=25,
                page='1',
            )
            actual = lme.build_smb_connections_query()
            assert actual == expected

        def test_build_credential_dumping_query(self):
            """
            Tests credential dumping query

            Given:
                - LateralMovementEvidence inited with device_name
            When:
                - calling build_credential_dumping_query
            Then:
                - return a valid credential dumping query
            """
            expected = EXPECTED_HUNTING_QUERIES['LateralMovementEvidence']['credential_dumping']
            lme = HuntingQueryBuilder.LateralMovementEvidence(
                limit=10,
                query_operation='or',
                device_name='1',
                page='1',
            )
            actual = lme.build_credential_dumping_query()
            assert actual == expected

        def test_build_rdp_attempts_query(self):
            """
            Tests build_rdp_attempts_query

            Given:
                - LateralMovementEvidence inited with device_name
            When:
                - calling build_rdp_attempts_query
            Then:
                - return a valid rdp attempts query
            """
            expected = EXPECTED_HUNTING_QUERIES['LateralMovementEvidence']['rdp_attempts']
            lme = HuntingQueryBuilder.LateralMovementEvidence(
                limit=10,
                query_operation='or',
                device_name='1',
                page='1',
            )
            actual = lme.build_management_connection_query()
            assert actual == expected

    class TestPersistenceEvidence:
        def test_build_scheduled_job_query(self):
            """
            Tests scheduled job query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_scheduled_job_query
            Then:
                - return a scheduled_job query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['scheduled_job']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='scheduled_job',
                page='1',
            )
            actual = pe.build_scheduled_job_query()
            assert actual == expected

        def test_registry_entry_query__no_process_cmd(self):
            """
            Tests registry entry query

            Given:
                - PersistenceEvidence inited with sha1
                - PersistenceEvidence inited with query_purpose registry_entry
                - PersistenceEvidence inited without process_cmd
            When:
                - calling build_registry_entry_query
            Then:
                - return a registry_entry query
            """
            with pytest.raises(DemistoException):
                HuntingQueryBuilder.PersistenceEvidence(
                    limit='1',
                    query_operation='and',
                    sha1='1,2',
                    query_purpose='registry_entry',
                    page='1',
                )

        def test_registry_entry_query(self):
            """
            Tests registry entry query

            Given:
                - PersistenceEvidence inited with sha1
                - PersistenceEvidence inited with query_purpose registry_entry
                - PersistenceEvidence inited with process_cmd
            When:
                - calling build_registry_entry_query
            Then:
                - return a registry_entry query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['registry_entry']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='registry_entry',
                process_cmd='something',
                page='1',
            )
            actual = pe.build_registry_entry_query()
            assert actual == expected

        def test_build_startup_folder_changes_query(self):
            """
            Tests startup_folder_changes query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_startup_folder_changes_query
            Then:
                - return a startup_folder_changes query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['startup_folder_changes']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='startup_folder_changes',
                page='1',
            )
            actual = pe.build_startup_folder_changes_query()
            assert actual == expected

        def test_build_new_service_created_query(self):
            """
            Tests new_service_created query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_new_service_created_query
            Then:
                - return a new_service_created query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['new_service_created']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='new_service_created',
                page='1',
            )
            actual = pe.build_new_service_created_query()
            assert actual == expected

        def test_build_service_updated_query(self):
            """
            Tests service_updated query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_service_updated_query
            Then:
                - return a service_updated query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['service_updated']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='service_updated',
                page='1',
            )
            actual = pe.build_service_updated_query()
            assert actual == expected

        def test_build_file_replaced_query(self):
            """
            Tests file_replaced query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_file_replaced_query
            Then:
                - return a file_replaced query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['file_replaced']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='file_replaced',
                page='1',
            )
            actual = pe.build_file_replaced_query()
            assert actual == expected

        def test_build_new_user_query(self):
            """
            Tests new_user query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_new_user_query
            Then:
                - return a new_user query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['new_user']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='new_user',
                page='1',
            )
            actual = pe.build_new_user_query()
            assert actual == expected

        def test_build_new_group_query(self):
            """
            Tests new_group query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_new_group_query
            Then:
                - return a new_group query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['new_group']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='new_group',
                page='1',
            )
            actual = pe.build_new_group_query()
            assert actual == expected

        def test_build_group_user_change_query(self):
            """
            Tests group_user_change query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_group_user_change_query
            Then:
                - return a group_user_change query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['group_user_change']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='group_user_change',
                page='1',
            )
            actual = pe.build_group_user_change_query()
            assert actual == expected

        def test_build_local_firewall_change_query(self):
            """
            Tests local_firewall_change query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_local_firewall_change_query
            Then:
                - return a local_firewall_change query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['local_firewall_change']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='local_firewall_change',
                page='1',
            )
            actual = pe.build_local_firewall_change_query()
            assert actual == expected

        def test_build_host_file_change_query(self):
            """
            Tests host_file_change query

            Given:
                - PersistenceEvidence inited with sha1
            When:
                - calling build_host_file_change_query
            Then:
                - return a host_file_change query
            """
            expected = EXPECTED_HUNTING_QUERIES['PersistenceEvidence']['host_file_change']
            pe = HuntingQueryBuilder.PersistenceEvidence(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='host_file_change',
                page='1',
            )
            actual = pe.build_host_file_change_query()
            assert actual == expected

    class TestFileOrigin:
        def test_build_file_origin_query(self):
            """
            Tests file origin generic query

            Given:
                - FileOrigin inited with sha1
            When:
                - calling build_file_origin_query
            Then:
                - return a file origin query
            """
            expected = EXPECTED_HUNTING_QUERIES['FileOrigin']
            fo = HuntingQueryBuilder.FileOrigin(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = fo.build_file_origin_query()
            assert actual == expected

    class TestProcessDetails:
        def test_build_parent_process_query(self):
            """
            Tests parent process query

            Given:
                - ProcessDetails inited with sha1
            When:
                - calling build_parent_process_query
            Then:
                - return a parent process query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['parent_process']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = pd.build_parent_process_query()
            assert actual == expected

        def test_build_grandparent_process_query(self):
            """
            Tests grandparent process query

            Given:
                - ProcessDetails inited with sha1
            When:
                - calling build_grandparent_process_query
            Then:
                - return a grandparent process query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['grandparent_process']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = pd.build_grandparent_process_query()
            assert actual == expected

        def test_build_process_details_query(self):
            """
            Tests process query

            Given:
                - ProcessDetails inited with sha1
            When:
                - calling build_process_details_query
            Then:
                - return a process query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['process']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = pd.build_process_details_query()
            assert actual == expected

        def test_build_beaconing_evidence_query(self):
            """
            Tests beaconing evidence query

            Given:
                - ProcessDetails inited with sha1
            When:
                - calling build_beaconing_evidence_query
            Then:
                - return a beaconing evidence query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['beaconing_evidence']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                sha1='1,2',
                page='1',
            )
            actual = pd.build_beaconing_evidence_query()
            assert actual == expected

        def test_build_process_excecution_powershell_query(self):
            """
            Tests process_excecution_powershell

            Given:
                - ProcessDetails inited with sha1 and device_id
            When:
                - calling build_process_excecution_powershell_query
            Then:
                - return a process_excecution_powershell query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['process_excecution_powershell']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                sha1='1,2',
                device_id='1',
                query_purpose='process_excecution_powershell',
                page='1',
            )
            actual = pd.build_process_excecution_powershell_query()
            assert actual == expected

        def test_build_powershell_execution_unsigned_files_query(self):
            """
            Tests powershell_execution_unsigned_files query

            Given:
                - NetworkConnections inited with no query arg
            When:
                - calling build_powershell_execution_unsigned_files_query
            Then:
                - return a powershell_execution_unsigned_files query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['powershell_execution_unsigned_files']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                query_purpose='powershell_execution_unsigned_files',
                page='1',
            )
            actual = pd.build_powershell_execution_unsigned_files_query()
            assert actual == expected

        def test_build_powershell_execution_unsigned_files_query__with_md5(self):
            """
            Tests powershell_execution_unsigned_files query

            Given:
                - NetworkConnections inited with md5 query arg
            When:
                - calling build_powershell_execution_unsigned_files_query
            Then:
                - return a powershell_execution_unsigned_files query
            """
            expected = EXPECTED_HUNTING_QUERIES['ProcessDetails']['powershell_execution_unsigned_files__md5']
            pd = HuntingQueryBuilder.ProcessDetails(
                limit='1',
                query_operation='and',
                query_purpose='powershell_execution_unsigned_files',
                md5='1',
                page='1',
            )
            actual = pd.build_powershell_execution_unsigned_files_query()
            assert actual == expected

    class TestNetworkConnections:
        def test_build_external_addresses_query(self):
            """
            Tests external_addresses query

            Given:
                - NetworkConnections inited with sha1
            When:
                - calling build_external_addresses_query
            Then:
                - return a external_addresses query
            """
            expected = EXPECTED_HUNTING_QUERIES['NetworkConnections']['external_addresses']
            nc = HuntingQueryBuilder.NetworkConnections(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='external_addresses',
                page='1',
            )
            actual = nc.build_external_addresses_query()
            assert actual == expected

        def test_build_dns_query(self):
            """
            Tests dns_query query

            Given:
                - NetworkConnections inited with sha1
            When:
                - calling build_dns_query
            Then:
                - return a dns_query query
            """
            expected = EXPECTED_HUNTING_QUERIES['NetworkConnections']['dns_query']
            nc = HuntingQueryBuilder.NetworkConnections(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='dns_query',
                page='1',
            )
            actual = nc.build_dns_query()
            assert actual == expected

        def test_build_encoded_commands_query(self):
            """
            Tests encoded_commands query

            Given:
                - NetworkConnections inited with md5 and device_id
            When:
                - calling build_encoded_commands_query
            Then:
                - return a encoded_commands query
            """
            expected = EXPECTED_HUNTING_QUERIES['NetworkConnections']['encoded_commands']
            nc = HuntingQueryBuilder.NetworkConnections(
                limit='1',
                query_operation='and',
                md5='1',
                device_id='1',
                query_purpose='encoded_commands',
                page='1',
            )
            actual = nc.build_encoded_commands_query()
            assert actual == expected

    class TestPrivilegeEscalation:
        def test_build_query(self):
            """
            Tests query

            Given:
                - PrivilegeEscalation inited with device_id
            When:
                - calling build_query
            Then:
                - return a PrivilegeEscalation query
            """
            expected = EXPECTED_HUNTING_QUERIES['PrivilegeEscalation']
            pe = HuntingQueryBuilder.PrivilegeEscalation(
                limit='1',
                query_operation='and',
                device_id='1',
                page='1',
            )
            actual = pe.build_query()
            assert actual == expected

    class TestTampering:
        def test_build_external_addresses_query(self):
            """
            Tests external_addresses query

            Given:
                - Tampering inited with device_id
            When:
                - calling build_query
            Then:
                - return a Tampering query
            """
            expected = EXPECTED_HUNTING_QUERIES['Tampering']['with_device']
            t = HuntingQueryBuilder.Tampering(
                limit='1',
                query_operation='and',
                device_id='1',
                page='1',
            )
            actual = t.build_query()
            assert actual == expected

        def test_build_external_addresses_query__no_device(self):
            """
            Tests external_addresses query

            Given:
                - Tampering inited without device
            When:
                - calling build_query
            Then:
                - return a Tampering query
            """
            expected = EXPECTED_HUNTING_QUERIES['Tampering']['no_device']
            t = HuntingQueryBuilder.Tampering(
                limit='1',
                query_operation='and',
                page='1',
            )
            actual = t.build_query()
            assert actual == expected

    class TestCoverUp:
        def test_build_file_deleted_query(self):
            """
            Tests file_deleted query

            Given:
                - CoverUp inited with sha1
            When:
                - calling build_file_deleted_query
            Then:
                - return a file_deleted query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['file_deleted']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                sha1='1,2',
                query_purpose='file_deleted',
                page='1',
            )
            actual = cu.build_file_deleted_query()
            assert actual == expected

        def test_build_event_log_cleared_query(self):
            """
            Tests event_log query

            Given:
                - CoverUp inited with device_id
            When:
                - calling build_event_log_cleared_query
            Then:
                - return a event_log query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['event_log']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                device_id='12',
                query_purpose='event_log_cleared',
                page='1',
            )
            actual = cu.build_event_log_cleared_query()
            assert actual == expected

        def test_build_compromised_information_query(self):
            """
            Tests compromised_information query

            Given:
                - CoverUp inited with username
            When:
                - calling build_compromised_information_query
            Then:
                - return a compromised_information query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['compromised_information']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                username='dbot',
                query_purpose='compromised_information',
                page='1',
            )
            actual = cu.build_compromised_information_query()
            assert actual == expected

        def test_build_connected_devices_query(self):
            """
            Tests connected_devices query

            Given:
                - CoverUp inited with username
            When:
                - calling build_connected_devices_query
            Then:
                - return a connected_devices query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['connected_devices']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                username='dbot',
                query_purpose='connected_devices',
                page='1',
            )
            actual = cu.build_connected_devices_query()
            assert actual == expected

        def test_build_action_types_query(self):
            """
            Tests action_types query

            Given:
                - CoverUp inited with username
            When:
                - calling build_action_types_query
            Then:
                - return a action_types query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['action_types']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                username='dbot',
                query_purpose='action_types',
                page='1',
            )
            actual = cu.build_action_types_query()
            assert actual == expected

        def test_build_common_files_query(self):
            """
            Tests common_files query

            Given:
                - CoverUp inited with username
            When:
                - calling build_common_files_query
            Then:
                - return a common_files query
            """
            expected = EXPECTED_HUNTING_QUERIES['CoverUp']['common_files']
            cu = HuntingQueryBuilder.CoverUp(
                limit='1',
                query_operation='and',
                username='dbot',
                query_purpose='common_files',
                page='1',
            )
            actual = cu.build_common_files_query()
            assert actual == expected


def test_get_machine_users_command(mocker):
    """
    Tests conversion of user response

    Given:
        - user response as json
    When:
        - calling for machine users
    Then:
        - return user data dict
    """
    mocker.patch.object(client_mocker, 'get_machine_users', return_value=MACHINE_USER_DATA)
    results = get_machine_users_command(client_mocker, {'machine_id': "123abc"})
    assert results.outputs[0] == MACHINE_USER_OUTPUT


def test_get_machine_alerts_command(mocker):
    """
    Tests conversion of alert response

    Given:
        - alert response as json
    When:
        - calling for machine alerts
    Then:
        - return alert data dict
    """
    mocker.patch.object(client_mocker, 'get_machine_alerts', return_value=ALERTS_API_RESPONSE)
    results = get_machine_alerts_command(client_mocker, {'machine_id': "123abc"})
    assert results.outputs[0] == MACHINE_ALERTS_OUTPUT


@pytest.mark.parametrize('endpoint_type', ("com", "gcc"))
def test_gcc_resource(mocker, endpoint_type):
    """
    Given
         an MsClient object
    When
        Making a http request
    Then
        Validate that the resource called matches the is_gcc attribute, so that GCC-based instance requests go through.
    """
    client = MsClient(
        tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name', base_url='url',
        verify='use_ssl',
        proxy='proxy', self_deployed='self_deployed', alert_severities_to_fetch='Informational,Low,Medium,High',
        alert_time_to_fetch='3 days', alert_status_to_fetch='New', max_fetch='10', endpoint_type=endpoint_type,
        auth_type='', auth_code='', redirect_uri='', alert_detectionsource_to_fetch='')
    # use requests_mock to catch a get to example.com
    req = mocker.patch.object(client.ms_client, 'http_request')
    with requests_mock.Mocker() as m:
        m.get('https://example.com')
    client.indicators_http_request('https://example.com', should_use_security_center=True)
    assert req.call_args[1]['resource'] == MICROSOFT_DEFENDER_FOR_ENDPOINT_API[endpoint_type]


@pytest.mark.parametrize('page_num, page_size, res',
                         [('5', '10600', {'$filter': 'filter', '$skip': '40000', '$top': '10000'}),
                          ('3', '50', {'$filter': 'filter', '$skip': '100', '$top': '50'}),
                          ('1', '3', {'$filter': 'filter', '$skip': '0', '$top': '3'})
                          ]
                         )
def test_get_machines(mocker, page_num, page_size, res):
    """
    Given:
        - page_num, page_size, limit to the get_machines method

    When:
        - Before calling the API to get the machines

    Then:
        - verify that the page_num , page_size, limit are added to the params array correctly.
    """
    req = mocker.patch.object(client_mocker.ms_client, 'http_request', return_value='')
    client_mocker.get_machines('filter', page_num=page_num, page_size=page_size)
    assert res == req.call_args.kwargs.get('params')


@pytest.mark.parametrize('query, query_batch, hr_name, timeout',
                         [('', '[{"query": "DeviceInfo | where OnboardingStatus == Onboarded | limit 10'
                           ' | distinct DeviceName", "name": "name1", "timeout": "20"}]', "name1", 20),
                          ('DeviceInfo | where OnboardingStatus == Onboarded | limit 10 | distinct DeviceName', '', "name", 10)])
def test_get_advanced_hunting_command(mocker, query, query_batch, hr_name, timeout):
    """
    Given:
        - query, query_batch, human readable name and a timeout

    When:
        - Running the get_advanced_hunting_command command

    Then:
        - verify the expected results
    """
    args = {'timeout': '10',
            'time_range': '1 day',
            'name': 'name',
            'query': query,
            'query_batch': query_batch}
    req = mocker.patch.object(client_mocker, 'get_advanced_hunting',
                              return_value={'Results': [{'DeviceName': 'win2016-msde-agent.msde.lab.demisto'},
                                                        {'DeviceName': 'ec2amaz-ua9hieu'}]})
    human_readable, _, _ = get_advanced_hunting_command(client_mocker, args)
    assert f'### Hunt results for {hr_name} query' in human_readable
    assert timeout == req.call_args[0][1]


@pytest.mark.parametrize('query, query_batch, exception, return_value',
                         [('', '', 'Both query and query_batch were not given, please provide one',
                           {'Results': [{'DeviceName': 'win2016-msde-agent.msde.lab.demisto'}]}),
                          ('query', 'query_batch', 'Both query and query_batch were given, please provide just one',
                          {'Results': [{'DeviceName': 'win2016-msde-agent.msde.lab.demisto'}]})])
def test_get_advanced_hunting_command_exception(mocker, query, query_batch, exception, return_value):
    """
    Given:
        - query, query_batch

    When:
        - Running the get_advanced_hunting_command command expecting an exception

    Then:
        - verify the expected exception has the correct value
    """
    args = {'timeout': '10',
            'time_range': '1 day',
            'name': 'name',
            'query': query,
            'query_batch': query_batch}
    mocker.patch.object(client_mocker, 'get_advanced_hunting', return_value=return_value)

    with pytest.raises(Exception) as e:
        get_advanced_hunting_command(client_mocker, args)

    assert str(e.value) == exception


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'id': 'some_id'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicAssetDto)',  # noqa: E501
     'value': [{'id': '1111', 'computerDnsName': 'desktop-11111',
                'osPlatform': 'Windows10', 'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111},
               {'id': '2222',
                'computerDnsName': 'some_computer_name_1',
                'osPlatform': 'WindowsServer2016', 'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111},
               {'id': '3333',
                'computerDnsName': 'some_computer_name_2',
                'osPlatform': 'WindowsServer2016', 'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111}]},
     '### Microsoft Defender ATP list machines by software: some_id\n|id|computerDnsName|osPlatform|rbacGroupName|rbacGroupId|\n|---|---|---|---|---|\n| 1111 | desktop-11111 | Windows10 | UnassignedGroup | 1111 |\n| 2222 | some_computer_name_1 | WindowsServer2016 | UnassignedGroup | 1111 |\n| 3333 | some_computer_name_2 | WindowsServer2016 | UnassignedGroup | 1111 |\n',  # noqa: E501
     [{'id': '1111', 'computerDnsName': 'desktop-11111',
       'osPlatform': 'Windows10', 'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111},
      {'id': '2222',
       'computerDnsName': 'some_computer_name_1',
       'osPlatform': 'WindowsServer2016', 'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111},
      {'id': '3333', 'computerDnsName':
       'some_computer_name_2', 'osPlatform': 'WindowsServer2016',
       'rbacGroupName': 'UnassignedGroup', 'rbacGroupId': 1111}])
])
def test_list_machines_by_software_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_machines_by_software.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_machines_by_software_command
    mocker.patch.object(client_mocker, 'get_list_machines_by_software', return_value=return_value)
    result_list_software = list_machines_by_software_command(client_mocker, args)
    assert result_list_software.readable_output == expected_human_readable
    assert result_list_software.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'id': 'some_id'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicDistributionDto)',  # noqa: E501
     'value': [{'version': '6.2.4.0', 'installations': 1, 'vulnerabilities': 0},
               {'version': '7.0.2.0', 'installations': 2, 'vulnerabilities': 7}]},
     '### Microsoft Defender ATP software version distribution:\n'
     '|version|installations|vulnerabilities|\n|---|---|---|\n|'
     ' 6.2.4.0 | 1 | 0 |\n| 7.0.2.0 | 2 | 7 |\n',
     [{'version': '6.2.4.0', 'installations': 1, 'vulnerabilities': 0},
      {'version': '7.0.2.0', 'installations': 2, 'vulnerabilities': 7}])
])
def test_list_software_version_distribution_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_software_version_distribution_command
    mocker.patch.object(client_mocker, 'get_list_software_version_distribution', return_value=return_value)
    result_list_software = list_software_version_distribution_command(client_mocker, args)
    assert result_list_software.readable_output == expected_human_readable
    assert result_list_software.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'id': 'microsoft-_-.product'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicProductFixDto)',  # noqa: E501
     'value': [{'id': '4556813', 'name': 'some_name', 'osBuild': 11111,
                'productsNames': ['.product'], 'url': 'some_url',
                'machineMissedOn': 1, 'cveAddressed': 2},
               {'id': '4534271', 'name': 'some_name', 'osBuild': 11111,
                'productsNames': ['.product'], 'url': 'some_url',
                'machineMissedOn': 1, 'cveAddressed': 2}]},
     '### Microsoft Defender ATP missing kb by software: microsoft-_-.product\n'
     '|id|name|osBuild|productsNames|url|machineMissedOn|cveAddressed|\n'
     '|---|---|---|---|---|---|---|\n'
     '| 4556813 | some\_name | 11111 | .product | some\_url | 1 | 2 |\n'
     '| 4534271 | some\_name | 11111 | .product | some\_url | 1 | 2 |\n',
     [{'id': '4556813', 'name': 'some_name', 'osBuild': 11111,
       'productsNames': ['.product'], 'url': 'some_url',
       'machineMissedOn': 1, 'cveAddressed': 2},
      {'id': '4534271', 'name': 'some_name', 'osBuild': 11111,
       'productsNames': ['.product'], 'url': 'some_url',
       'machineMissedOn': 1, 'cveAddressed': 2}])
])
def test_list_missing_kb_by_software_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_missing_kb_by_software_command
    mocker.patch.object(client_mocker, 'get_list_missing_kb_by_software', return_value=return_value)
    result_list_software = list_missing_kb_by_software_command(client_mocker, args)
    assert result_list_software.readable_output == expected_human_readable
    assert result_list_software.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'id': 'some_id'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#PublicVulnerabilityDto',
     'value': [{'id': 'CVE-1111-1111', 'name': 'CVE-1111-1111', 'description': 'vulnerability_description',
                'severity': 'Medium', 'cvssV3': 5.3, 'exposedMachines': 2, 'publishedOn': '2023-09-06T00:00:00Z',
                'updatedOn': '2022-11-09T00:00:00Z', 'publicExploit': False, 'exploitVerified': False,
                'exploitInKit': False, 'exploitTypes': [], 'exploitUris': []}]},
     '### Microsoft Defender ATP vulnerability CVE-1111-1111 by software: some_id\n|id|name|description|severity|cvssV3|publishedOn|updatedOn|exposedMachines|exploitVerified|publicExploit|\n|---|---|---|---|---|---|---|---|---|---|\n| CVE-1111-1111 | CVE-1111-1111 | vulnerability\\_description | Medium | 5.3 | 2023-09-06T00:00:00Z | 2022-11-09T00:00:00Z | 2 | false | false |\n',  # noqa: E501
     {'id': 'CVE-1111-1111', 'name': 'CVE-1111-1111', 'description': 'vulnerability_description',
      'severity': 'Medium', 'cvssV3': 5.3, 'exposedMachines': 2,
      'publishedOn': '2023-09-06T00:00:00Z', 'updatedOn': '2022-11-09T00:00:00Z', 'publicExploit': False,
      'exploitVerified': False,
      'exploitInKit': False, 'exploitTypes': [], 'exploitUris': []})
])
def test_list_vulnerabilities_by_software_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_vulnerabilities_by_software_command
    mocker.patch.object(client_mocker, 'get_list_vulnerabilities_by_software', return_value=return_value)
    result_list_software = list_vulnerabilities_by_software_command(client_mocker, args)
    assert result_list_software[0].readable_output == expected_human_readable
    assert result_list_software[0].outputs == expected_outputs


@pytest.mark.parametrize('filters_arg_list, name, expected_result', [
    (['id1'], 'id', "id eq 'id1'"),
    (['id1', 'id2'], 'id', "id eq 'id1' or id eq 'id2'"),
    (['id1', 'id2', 'id3'], 'id', "id eq 'id1' or id eq 'id2' or id eq 'id3'"),
    ([], 'id', ""),

])
def test_create_filters_conjunction(filters_arg_list, name, expected_result):
    """
    Given:
        - filters_arg_list, name.

    When:
        - executing create_filters_conjunction function.

    Then:
        - the returned filter string is valid.
    """
    create_filters_conjunction_result = create_filters_conjunction(filters_arg_list, name)

    assert create_filters_conjunction_result == expected_result


@pytest.mark.parametrize('filters_arg_list, expected_result', [
    (["id eq 'id1' or id eq 'id2' or id eq 'id3'", "vendor eq 'vendor1' or vendor eq 'vendor2' or vendor eq 'vendor3'"],
     "(id eq 'id1' or id eq 'id2' or id eq 'id3') and (vendor eq 'vendor1' or vendor eq 'vendor2' or vendor eq 'vendor3')"),
    (["id eq 'id1' or id eq 'id2' or id eq 'id3'"], "id eq 'id1' or id eq 'id2' or id eq 'id3'"),
    ([], ""),
    (["", "id eq 'id1' or id eq 'id2' or id eq 'id3'", ""], "id eq 'id1' or id eq 'id2' or id eq 'id3'")

])
def test_create_filters_disjunctions(filters_arg_list, expected_result):
    """
    Given:
        - filters_arg_list, name.

    When:
        - executing create_filters_disjunctions function.

    Then:
        - the returned filter string is valid.
    """
    create_filters_disjunctions_result = create_filters_disjunctions(filters_arg_list)

    assert create_filters_disjunctions_result == expected_result


@pytest.mark.parametrize('args_and_name_list, expected_result', [
    ([(['id1'], 'id'), (['vendor1', 'vendor2'], 'vendor')], "(id eq 'id1') and (vendor eq 'vendor1' or vendor eq 'vendor2')"),
    ([(['id1', 'id2'], 'id'), (['vendor1', 'vendor2'], 'vendor')],
     "(id eq 'id1' or id eq 'id2') and (vendor eq 'vendor1' or vendor eq 'vendor2')"),
    ([(['id1'], 'id')], "id eq 'id1'")
])
def test_create_filter(args_and_name_list, expected_result):
    """
    Given:
        - args_and_name_list.

    When:
        - executing create_filter function.

    Then:
        - the returned filter string is valid.
    """
    create_filters_result = create_filter(args_and_name_list)

    assert create_filters_result == expected_result


@pytest.mark.parametrize('id_and_severity, name_equal, name_contains, description, published_on, cvss,'
                         'updated_on, expected_result',
                         [("", "", "", "", "2020-12-16T00:00:00Z", "", "", "publishedOn ge 2020-12-16T00:00:00Z"),
                          ("", "", "", "", "", "", "2020-12-16T00:00:00Z", "updatedOn ge 2020-12-16T00:00:00Z"),
                          ("", "", "", "", "", "some_cvss", "", "cvssV3 ge some_cvss"),
                          ("", "", "", "some_description", "", "", "", "contains(description, 'some_description')"),
                          ("", "some_name_equal", "", "", "", "", "", "name eq 'some_name_equal'"),
                          ("", "", "some_name_contains", "", "", "", "", "contains(name, 'some_name_contains')"),
                          ("", "", "some_name", "", "2020-12-16T00:00:00Z", "", "2020-12-16T00:00:00Z",
                           "(contains(name, 'some_name')) and (updatedOn ge 2020-12-16T00:00:00Z) and "
                           "(publishedOn ge 2020-12-16T00:00:00Z)")
                          ])
def test_create_filter_list_vulnerabilities(id_and_severity, name_equal, name_contains, description, published_on, cvss,
                                            updated_on, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import create_filter_list_vulnerabilities
    result = create_filter_list_vulnerabilities(id_and_severity, name_equal, name_contains, description, published_on,
                                                cvss, updated_on)
    assert result == expected_result


@pytest.mark.parametrize('args, return_value_get_list_software,expected_human_readable,expected_outputs', [
    ({'vendor': 'some_vendor'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Software', 'value':
     [{'id': 'some_id', 'name': 'some_name',
       'vendor': 'some_vendor', 'weaknesses': 0, 'publicExploit': False,
       'activeAlert': False, 'exposedMachines': 0, 'installedMachines': 1, 'impactScore': 0,
       'isNormalized': False, 'category': '', 'distributions': []},
      {'id': 'some_id', 'name': 'some_name', 'vendor': 'some_vendor', 'weaknesses': 0,
       'publicExploit': False, 'activeAlert': False, 'exposedMachines': 0, 'installedMachines': 1,
       'impactScore': 0, 'isNormalized': False, 'category': '', 'distributions': []}]},
        '### Microsoft Defender ATP list software:\n|id|name|vendor|weaknesses|activeAlert|exposedMachines|installedMachines|publicExploit|\n|---|---|---|---|---|---|---|---|\n| some\_id | some\_name | some\_vendor | 0 | false | 0 | 1 | false |\n| some\_id | some\_name | some\_vendor | 0 | false | 0 | 1 | false |\n',  # noqa: E501
     [{'id': 'some_id', 'name': 'some_name', 'vendor': 'some_vendor',
       'weaknesses': 0, 'publicExploit': False, 'activeAlert': False,
       'exposedMachines': 0, 'installedMachines': 1, 'impactScore': 0,
       'isNormalized': False, 'category': '', 'distributions': []},
      {'id': 'some_id', 'name': 'some_name', 'vendor': 'some_vendor',
       'weaknesses': 0, 'publicExploit': False, 'activeAlert': False,
       'exposedMachines': 0, 'installedMachines': 1, 'impactScore': 0,
       'isNormalized': False, 'category': '', 'distributions': []}])
])
def test_list_software_command(mocker, args, return_value_get_list_software, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_software_command
    mocker.patch.object(client_mocker, 'get_list_software', return_value=return_value_get_list_software)
    result_list_software = list_software_command(client_mocker, args)
    assert result_list_software.readable_output == expected_human_readable
    assert result_list_software.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value_get_software_by_machine_id,expected_human_readable,expected_outputs', [
    (
        {'machine_id': 'some_machine'},
        {
            '@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Software',
            '@odata.count': 2,
            'value': [
                {
                    'id': 'some_id',
                    'name': 'some_name',
                    'vendor': 'some_vendor',
                    'weaknesses': 0,
                    'publicExploit': False,
                    'activeAlert': False,
                    'exposedMachines': 0,
                    'installedMachines': 1,
                    'impactScore': 0,
                    'isNormalized': False,
                    'category': '',
                    'distributions': []
                },
                {
                    'id': 'another_id',
                    'name': 'another_name',
                    'vendor': 'another_vendor',
                    'weaknesses': 42,
                    'publicExploit': True,
                    'activeAlert': True,
                    'exposedMachines': 0,
                    'installedMachines': 1,
                    'impactScore': 0,
                    'isNormalized': False,
                    'category': '',
                    'distributions': []
                }
            ]
        },
        '### Microsoft Defender ATP software on machine: some_machine\n|id|name|vendor|publicExploit|activeAlert|exposedMachines|installedMachines|impactScore|isNormalized|\n|---|---|---|---|---|---|---|---|---|\n| some_id | some_name | some_vendor | false | false | 0 | 1 | 0 | false |\n| another_id | another_name | another_vendor | true | true | 0 | 1 | 0 | false |\n',  # noqa: E501
        [
            {
                'id': 'some_id',
                'name': 'some_name',
                'vendor': 'some_vendor',
                'weaknesses': 0,
                'publicExploit': False,
                'activeAlert': False,
                'exposedMachines': 0,
                'installedMachines': 1,
                'impactScore': 0,
                'isNormalized': False,
                'category': '',
                'distributions': []
            },
            {
                'id': 'another_id',
                'name': 'another_name',
                'vendor': 'another_vendor',
                'weaknesses': 42,
                'publicExploit': True,
                'activeAlert': True,
                'exposedMachines': 0,
                'installedMachines': 1,
                'impactScore': 0,
                'isNormalized': False,
                'category': '',
                'distributions': []
            }
        ]
    )
])
def test_get_software_by_machine_id(mocker, args, return_value_get_software_by_machine_id, expected_human_readable, expected_outputs):  # noqa: E501
    """
    Given:
        - args to the command.

    When:
        - executing get_software_by_machine_id.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_software_command
    mocker.patch.object(client_mocker, 'get_software_by_machine_id', return_value=return_value_get_software_by_machine_id)
    result_get_software_by_machine_id = get_machine_software_command(client_mocker, args)
    assert result_get_software_by_machine_id.readable_output == expected_human_readable
    assert result_get_software_by_machine_id.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value_get_machine_missing_kbs_command,expected_human_readable,expected_outputs', [
    (
        {'machine_id': 'some_machine'},
        {
            '@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicProductFixDto)',
            '@odata.count': 1,
            "value": [
                {
                    "id": "1234567",
                    "name": "March 20XX Security Updates",
                    "productsNames": [
                        "windows_10",
                        "edge",
                        "internet_explorer"
                    ],
                    "url": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB1234567",
                    "machineMissedOn": 1,
                    "cveAddressed": 97,
                    "osBuild": 12345
                }
            ]
        },
        '### Missing Security Updates (KBs) for machine: some_machine\n|id|name|osBuild|url|machineMissedOn|cveAddressed|\n|---|---|---|---|---|---|\n| 1234567 | March 20XX Security Updates | 12345 | https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB1234567 | 1 | 97 |\n',  # noqa: E501
        [
            {
                "id": "1234567",
                "name": "March 20XX Security Updates",
                "productsNames": [
                    "windows_10",
                    "edge",
                    "internet_explorer"
                ],
                "url": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB1234567",
                "machineMissedOn": 1,
                "cveAddressed": 97,
                "osBuild": 12345
            }
        ]
    )
])
def test_get_machine_missing_kbs_command(mocker, args, return_value_get_machine_missing_kbs_command, expected_human_readable, expected_outputs):  # noqa: E501
    """
    Given:
        - args to the command.

    When:
        - executing get_machine_missing_kbs_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_missing_kbs_command
    mocker.patch.object(client_mocker, 'get_missing_kbs_by_machine_id', return_value=return_value_get_machine_missing_kbs_command)
    result_get_machine_missing_kbs = get_machine_missing_kbs_command(client_mocker, args)
    assert result_get_machine_missing_kbs.readable_output == expected_human_readable
    assert result_get_machine_missing_kbs.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value_get_machine_vulnerabilities_command,expected_human_readable,expected_outputs', [
    (
        {'machine_id': 'some_machine'},
        {
            '@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicProductFixDto)',
            '@odata.count': 1,
            "value": [
                {
                    "@odata.type": "#microsoft.windowsDefenderATP.api.PublicVulnerabilityDto",
                    "cveSupportability": "Supported",
                    "cvssV3": 3.7,
                    "cvssVector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:F/RL:O/RC:C",
                    "description": "Summary: Foo is vulnerable to a denial of service due to improper server configuration validation.",  # noqa: E501
                    "epss": 0,
                    "exploitInKit": False,
                    "exploitTypes": [
                        "Remote"
                    ],
                    "exploitUris": [],
                    "exploitVerified": False,
                    "exposedMachines": 1,
                    "firstDetected": "20XX-MM-DDThh:mm:ssZ",
                    "id": "CVE-20XX-1234",
                    "name": "CVE-20XX-1234",
                    "publicExploit": False,
                    "publishedOn": "20XX-MM-DDThh:mm:ssZ",
                    "severity": "Low",
                    "tags": [],
                    "updatedOn": "20XX-MM-DDThh:mm:ssZ"
                }
            ]
        },
        '### Microsoft Defender ATP Vulnerabilities for machine: some_machine\n|id|name|cveSupportability|cvssV3|cvssVector|description|epss|exploitInKit|exploitTypes|exploitVerified|exposedMachines|firstDetected|publicExploit|publishedOn|severity|updatedOn|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n| CVE-20XX-1234 | CVE-20XX-1234 | Supported | 3.7 | CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:F/RL:O/RC:C | Summary: Foo is vulnerable to a denial of service due to improper server configuration validation. | 0 | false | Remote | false | 1 | 20XX-MM-DDThh:mm:ssZ | false | 20XX-MM-DDThh:mm:ssZ | Low | 20XX-MM-DDThh:mm:ssZ |\n',  # noqa: E501
        [
            {
                "@odata.type": "#microsoft.windowsDefenderATP.api.PublicVulnerabilityDto",
                "cveSupportability": "Supported",
                "cvssV3": 3.7,
                "cvssVector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:F/RL:O/RC:C",
                "description": "Summary: Foo is vulnerable to a denial of service due to improper server configuration validation.",  # noqa: E501
                "epss": 0,
                "exploitInKit": False,
                "exploitTypes": [
                    "Remote"
                ],
                "exploitUris": [],
                "exploitVerified": False,
                "exposedMachines": 1,
                "firstDetected": "20XX-MM-DDThh:mm:ssZ",
                "id": "CVE-20XX-1234",
                "name": "CVE-20XX-1234",
                "publicExploit": False,
                "publishedOn": "20XX-MM-DDThh:mm:ssZ",
                "severity": "Low",
                "tags": [],
                "updatedOn": "20XX-MM-DDThh:mm:ssZ"
            }
        ]
    )
])
def test_get_machine_vulnerabilities_command(mocker, args, return_value_get_machine_vulnerabilities_command, expected_human_readable, expected_outputs):  # noqa: E501
    """
    Given:
        - args to the command.

    When:
        - executing get_machine_vulnerabilities_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import get_machine_vulnerabilities_command
    mocker.patch.object(client_mocker, 'get_vulnerabilities_by_machine_id',
                        return_value=return_value_get_machine_vulnerabilities_command)
    result_get_machine_vulnerabilities = get_machine_vulnerabilities_command(client_mocker, args)
    assert result_get_machine_vulnerabilities.readable_output == expected_human_readable
    assert result_get_machine_vulnerabilities.outputs == expected_outputs


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'cve_id': 'CVE-3333-33333'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.PublicAssetVulnerabilityDto)',  # noqa: E501
     'value': [{'id': 'some_id', 'cveId': 'CVE-3333-33333', 'machineId': 'some_machine_id',
                'fixingKbId': None, 'productName': 'some_product_name', 'productVendor': 'some_vendor',
                'productVersion': '7.0.2.0', 'severity': 'High'}]},
     '### Microsoft Defender ATP vulnerability CVE-3333-33333:\n'
     '|id|cveId|machineId|productName|productVendor|productVersion|severity|\n'
     '|---|---|---|---|---|---|---|\n|'
     ' some\_id | CVE-3333-33333 |'
     ' some\_machine\_id |'
     ' some\_product\_name | some\_vendor | 7.0.2.0 | High |\n',
     {'id': 'some_id',
      'cveId': 'CVE-3333-33333', 'machineId': 'some_machine_id',
      'fixingKbId': None, 'productName': 'some_product_name', 'productVendor': 'some_vendor',
      'productVersion': '7.0.2.0', 'severity': 'High'})
])
def test_list_vulnerabilities_by_machine_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_vulnerabilities_by_machine_command
    mocker.patch.object(client_mocker, 'get_list_vulnerabilities_by_machine', return_value=return_value)
    result_list_software = list_vulnerabilities_by_machine_command(client_mocker, args)
    assert result_list_software[0].readable_output == expected_human_readable
    assert result_list_software[0].outputs == expected_outputs


@pytest.mark.parametrize('args, return_value,expected_human_readable,expected_outputs', [
    ({'published_on': '1 days ago'},
     {'@odata.context': 'https://api.securitycenter.windows.com/api/$metadata#Vulnerabilities',
     'value': [{'id': 'CVE-2023-11111', 'name': 'CVE-2023-11111',
                'description': 'some_description',
                'severity': 'Critical', 'cvssV3': 9.8, 'exposedMachines': 0, 'publishedOn': '2023-04-24T15:15:00Z',
                'updatedOn': '2023-04-24T15:15:00Z', 'publicExploit': False,
                'exploitVerified': False, 'exploitInKit': False,
                'exploitTypes': [], 'exploitUris': []}]},
     '### Microsoft Defender ATP vulnerabilities:\n|id|name|description|severity|publishedOn|updatedOn|'
     'exposedMachines|exploitVerified|publicExploit|cvssV3|\n'
     '|---|---|---|---|---|---|---|---|---|---|\n|'
     ' CVE-2023-11111 | CVE-2023-11111 | some\\_description | Critical '
     '| 2023-04-24T15:15:00Z | 2023-04-24T15:15:00Z | 0 | false | false | 9.8 |\n',
     {'id': 'CVE-2023-11111',
      'name': 'CVE-2023-11111',
      'description': 'some_description',
      'severity': 'Critical', 'cvssV3': 9.8, 'exposedMachines': 0,
      'publishedOn': '2023-04-24T15:15:00Z',
      'updatedOn': '2023-04-24T15:15:00Z',
      'publicExploit': False, 'exploitVerified': False,
      'exploitInKit': False, 'exploitTypes': [], 'exploitUris': []})
])
def test_list_vulnerabilities_command(mocker, args, return_value, expected_human_readable, expected_outputs):
    """
    Given:
        - args to the command.

    When:
        - executing list_software_command.

    Then:
        -the outputs and human readable are valid.
    """
    from MicrosoftDefenderAdvancedThreatProtection import list_vulnerabilities_command
    mocker.patch.object(client_mocker, 'get_list_vulnerabilities', return_value=return_value)
    result_list_software = list_vulnerabilities_command(client_mocker, args)
    assert result_list_software[0].readable_output == expected_human_readable
    assert result_list_software[0].outputs == expected_outputs


@pytest.mark.parametrize('data_to_escape_with_backslash, expected_result', [(
    [{'id': 'some_id', 'cveId': 'CVE-3333-33333', 'machineId': 'some_machine_id',
      'fixingKbId': None, 'productName': 'some_product_name', 'productVendor': 'some_vendor',
      'productVersion': '7.0.2.0', 'severity': 'High'}],
    [{'id': 'some\\_id', 'cveId': 'CVE-3333-33333', 'machineId': 'some\\_machine\\_id',
      'fixingKbId': None, 'productName': 'some\\_product\\_name', 'productVendor': 'some\\_vendor',
      'productVersion': '7.0.2.0', 'severity': 'High'}])
])
def test_add_backslash_infront_of_underscore_list(data_to_escape_with_backslash, expected_result):
    from MicrosoftDefenderAdvancedThreatProtection import add_backslash_infront_of_underscore_list
    result = add_backslash_infront_of_underscore_list(data_to_escape_with_backslash)
    assert result == expected_result


@pytest.mark.parametrize('client_id', ("test_client_id", None))
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from MicrosoftDefenderAdvancedThreatProtection import main, MANAGED_IDENTITIES_TOKEN_URL
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    security_center = 'https://api.securitycenter.microsoft.com'
    requests_mock.get(re.compile(f'^{security_center}.*'), json={})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'auth_type': 'Azure Managed Identities',
        'url': security_center
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [security_center]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function microsoft-atp-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftDefenderAdvancedThreatProtection import main
    import MicrosoftDefenderAdvancedThreatProtection

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'self_deployed': 'True',
        'tenant_id': tenant_id,
        'auth_id': client_id,
        'credentials': {
            'password': 'client_secret'
        },
        'endpoint_type': 'Worldwide',
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='microsoft-atp-generate-login-url')
    mocker.patch.object(MicrosoftDefenderAdvancedThreatProtection, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   f'response_type=code&scope=offline_access%20' \
                   'https://securitycenter.onmicrosoft.com/windowsatpservice/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = MicrosoftDefenderAdvancedThreatProtection.return_results.call_args[0][0].readable_output
    assert expected_url in res


def test_get_file_statistics_command(mocker):
    """
    Given:
    - SHA1 File hash

    When:
    - Calling the get_file_statistics_command function

    Then:
    - Assert correct context output and raw response
    """
    from MicrosoftDefenderAdvancedThreatProtection import get_file_statistics_command

    # Set
    response = FILE_STATISTICS_API_RESPONSE
    mocker.patch.object(client_mocker, 'get_file_statistics', return_value=response)

    # Arrange
    results = get_file_statistics_command(client_mocker, {'file_hash': '0991a395da64e1c5fbe8732ed11e6be064081d9f'})
    context_output = results.outputs

    assert context_output['Sha1'] == response['sha1']
    assert context_output['Statistics'] == {
        'OrgPrevalence': response['orgPrevalence'],
        'OrganizationPrevalence': response['organizationPrevalence'],
        'OrgFirstSeen': response['orgFirstSeen'],
        'OrgLastSeen': response['orgLastSeen'],
        'GlobalPrevalence': response['globalPrevalence'],
        'GloballyPrevalence': response['globallyPrevalence'],
        'GlobalFirstObserved': response['globalFirstObserved'],
        'GlobalLastObserved': response['globalLastObserved'],
        'TopFileNames': response['topFileNames'],
    }

    assert results.raw_response == response


@pytest.fixture
def file_stats():
    """Fixture to create a FileStatisticsAPIParser instance."""
    return FileStatisticsAPIParser.from_raw_response(FILE_STATISTICS_API_RESPONSE)


def test_file_statistics_api_parser_from_raw_response(file_stats: FileStatisticsAPIParser):
    """
    Given:
    - An instance of FileStatisticsAPIParser created from file statistics API response

    When:
    - Casting the FileStatisticsAPIParser dataclass to a dictionary

    Then:
    - Assert no excluded fields in dictionary
    - Assert all relevant fields in dictionary
    """
    # Set
    response = FILE_STATISTICS_API_RESPONSE
    excluded_key = '@odata.context'

    # Arrange
    file_stats_dict = dataclasses.asdict(file_stats)
    snake_case_response = snakify(response)

    # Assert
    assert excluded_key not in file_stats_dict
    assert file_stats_dict == {key: value for key, value in snake_case_response.items() if key != excluded_key}


def test_file_statistics_api_parser_to_context(file_stats: FileStatisticsAPIParser):
    """
    Given:
    - An instance of FileStatisticsAPIParser created from file statistics API response

    When:
    - Calling the FileStatisticsAPIParser.to_context_output method

    Then:
    - Assert correct context output
    """
    # Set
    response = FILE_STATISTICS_API_RESPONSE

    # Arrange
    context_output = file_stats.to_context_output()

    # Assert
    assert context_output['Sha1'] == response['sha1']
    assert context_output['Statistics'] == {
        'OrgPrevalence': response['orgPrevalence'],
        'OrganizationPrevalence': response['organizationPrevalence'],
        'OrgFirstSeen': response['orgFirstSeen'],
        'OrgLastSeen': response['orgLastSeen'],
        'GlobalPrevalence': response['globalPrevalence'],
        'GloballyPrevalence': response['globallyPrevalence'],
        'GlobalFirstObserved': response['globalFirstObserved'],
        'GlobalLastObserved': response['globalLastObserved'],
        'TopFileNames': response['topFileNames'],
    }


def test_file_statistics_api_parser_to_file_indicator(file_stats: FileStatisticsAPIParser):
    """
    Given:
    - SHA1 file hash and an instance FileStatisticsAPIParser created from file statistics API response

    When:
    - Calling the FileStatisticsAPIParser.to_file_indicator method

    Then:
    - Assert correct human readable table name and data
    """
    # Set
    file_hash = '0991a395da64e1c5fbe8732ed11e6be064081d9f'
    response = FILE_STATISTICS_API_RESPONSE

    # Arrange
    file_indicator = file_stats.to_file_indicator(file_hash)
    indicator_data: dict = next(iter(file_indicator.to_context().values()))
    indicator_data.pop('Hashes', None)  # generated by Common.File, irrelevant in this unit test

    # Assert
    assert indicator_data == {
        'SHA1': response['sha1'],
        'OrganizationPrevalence': response['organizationPrevalence'],
        'GlobalPrevalence': response['globallyPrevalence'],
        'OrganizationFirstSeen': response['orgFirstSeen'],
        'OrganizationLastSeen': response['orgLastSeen'],
        'FirstSeenBySource': response['globalFirstObserved'],
        'LastSeenBySource': response['globalLastObserved'],
    }


def test_file_statistics_api_parser_to_human_readable(mocker, file_stats: FileStatisticsAPIParser):
    """
    Given:
    - SHA1 file hash and an instance FileStatisticsAPIParser created from file statistics API response

    When:
    - Calling the FileStatisticsAPIParser.to_human_readable method

    Then:
    - Assert correct human readable table name and data
    """
    # Set
    file_hash = '0991a395da64e1c5fbe8732ed11e6be064081d9f'
    response = FILE_STATISTICS_API_RESPONSE
    table_to_markdown = mocker.patch('MicrosoftDefenderAdvancedThreatProtection.tableToMarkdown')

    # Arrange
    file_stats.to_human_readable(file_hash)
    table_name, table_data = table_to_markdown.call_args[0]

    # Assert
    assert table_name == f'Statistics on {file_hash} file:'
    assert table_data == {
        'Organization Prevalence': response['organizationPrevalence'],
        'Organization First Seen': response['orgFirstSeen'],
        'Organization Last Seen': response['orgLastSeen'],
        'Global Prevalence': response['globallyPrevalence'],
        'Global First Observed': response['globalFirstObserved'],
        'Global Last Observed': response['globalLastObserved'],
        'Top File Names': response['topFileNames'],
    }

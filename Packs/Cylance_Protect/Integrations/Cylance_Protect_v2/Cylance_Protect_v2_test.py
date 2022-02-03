import json

import demistomock as demisto
from CommonServerPython import Common
from Cylance_Protect_v2 import create_dbot_score_entry, translate_score, FILE_THRESHOLD, threat_to_incident,\
    get_device, get_device_by_hostname, update_device
import Cylance_Protect_v2

THREAT_OUTPUT = {u'cylance_score': -1.0, u'name': u'name',
                 u'classification': u'Malware',
                 u'sub_classification': u'Virus',
                 u'av_industry': None,
                 u'unique_to_cylance': False,
                 u'last_found': u'2019-01-28T23:36:58',
                 u'global_quarantined': False,
                 u'file_size': 2177386,
                 u'safelisted': False,
                 u'sha256': u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE',
                 u'md5': u'B4EA38EB798EA1C1E067DFD176B882BB',
                 }

INCIDENT_OUTPUT = {}

DEVICE_OUTPUT = {u'update_available': False,
                 u'date_last_modified': u'2020-11-09T23:10:24',
                 u'distinguished_name': u'',
                 u'ip_addresses': [u'192.168.95.130'],
                 u'dlcm_status': u'Unknown',
                 u'background_detection': False,
                 u'id': u'8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                 u'days_to_deletion': u'Unknown',
                 u'os_version': u'Microsoft Windows 10 Education',
                 u'state': u'Offline',
                 u'date_first_registered': u'2020-11-09T22:28:48',
                 u'policy': {u'id': u'32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', u'name': u'Default'},
                 u'host_name': u'DESKTOP-M7E991U',
                 u'os_kernel_version': u'10.0.0',
                 u'mac_addresses': [u'00-0C-29-41-20-14'],
                 u'last_logged_in_user': u'DESKTOP-M7E991U\\scott.white',
                 u'name': u'DESKTOP-M7E991U',
                 u'date_offline': u'2020-11-09T23:10:21.902',
                 u'products': [{u'status': u'Offline', u'version': u'2.0.1500', u'name': u'protect'}],
                 u'update_type': None,
                 u'is_safe': True,
                 u'agent_version': u'2.0.1500'
                 }

EXPECTED_DEVICE = {'Name': u'DESKTOP-M7E991U',
                   'Hostname': u'DESKTOP-M7E991U',
                   'State': u'Offline',
                   'DateFirstRegistered': u'2020-11-09T22:28:48',
                   'Policy': {'ID': u'32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', 'Name': u'Default'},
                   'OSVersion': u'Microsoft Windows 10 Education',
                   'LastLoggedInUser': u'DESKTOP-M7E991U\\scott.white',
                   'MACAdress': [u'00-0C-29-41-20-14'],
                   'BackgroundDetection': False,
                   'IsSafe': True,
                   'UpdateAvailable': False,
                   'ID': u'8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                   'DateLastModified': u'2020-11-09T23:10:24',
                   'DateOffline': u'2020-11-09T23:10:21.902',
                   'IPAddress': [u'192.168.95.130']
                   }

EXPECTED_HOSTNAME = {'Name': u'DESKTOP-M7E991U',
                     'Hostname': u'DESKTOP-M7E991U',
                     'State': u'Offline',
                     'DateFirstRegistered': u'2020-11-09T22:28:48',
                     'Policy': {'ID': u'32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', 'Name': u'Default'},
                     'OSVersion': u'Microsoft Windows 10 Education',
                     'LastLoggedInUser': u'DESKTOP-M7E991U\\scott.white',
                     'MACAdress': [u'00-0C-29-41-20-14'],
                     'BackgroundDetection': False,
                     'IsSafe': True,
                     'UpdateAvailable': False,
                     'ID': u'8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                     'DateLastModified': u'2020-11-09T23:10:24',
                     'AgentVersion': u'2.0.1500',
                     'DateOffline': u'2020-11-09T23:10:21.902',
                     'IPAddress': [u'192.168.95.130']
                     }
def test_create_dbot_score_entry():
    """
    Given
        - a threat and a dbot score
    When
        - calls the function create_dbot_score_entry
    Then
        - checks if dbot_score_entry is from type DBotScore
    """

    threat = THREAT_OUTPUT
    dbot_score = translate_score(threat['cylance_score'], FILE_THRESHOLD)
    dbot_score_entry = create_dbot_score_entry(THREAT_OUTPUT, dbot_score)
    assert isinstance(dbot_score_entry, Common.DBotScore)


def test_threat_to_incident(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function threat_to_incident
    Then
        - checks if the output
    """

    threat = THREAT_OUTPUT
    incident = {
        'name': 'Cylance Protect v2 threat ' + threat['name'],
        'occurred': threat['last_found'] + 'Z',
        'rawJSON': json.dumps(threat)
    }
    expected_result = ''
    args = {'id': '8e836c98-102e-4332-b00d-81dcb7a9b6f7'}
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    mocker.patch.object(Cylance_Protect_v2, "get_threat_devices_request", return_value={'page_items': DEVICE_OUTPUT})
    result = threat_to_incident(threat)

    assert result == expected_result


def test_get_device(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device
    Then
        - checks if the output ia as expected
    """
    args = {'id': '8e836c98-102e-4332-b00d-81dcb7a9b6f7'}
    mocker.patch.object(Cylance_Protect_v2, "get_device_request", return_value=DEVICE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_device()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_DEVICE == contents.get('EntryContext').get('CylanceProtect.Device(val.ID && val.ID === obj.ID)')


def test_get_device_by_hostname(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device_by_hostname
    Then
        - checks if the output ia as expected
    """
    args = {'hostname': 'DESKTOP-M7E991U'}
    mocker.patch.object(Cylance_Protect_v2, "get_hostname_request", return_value=DEVICE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_device_by_hostname()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_HOSTNAME == contents.get('EntryContext').get('CylanceProtect.Device(val.ID && val.ID === obj.ID)')


def test_update_device(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function update_device
    Then
        - checks if the output ia as expected
    """
    args = {'id': '8e836c98-102e-4332-b00d-81dcb7a9b6f7',
            'name': 'DESKTOP-M7E991U',
            'policyId': '32e4aacd-7698-4ef0-93e8-3e6f1f5c6857'}
    mocker.patch.object(Cylance_Protect_v2, "update_device_request", return_value=DEVICE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    update_device()

    contents = demisto_results.call_args[0][0]
    assert 'Device 8e836c98-102e-4332-b00d-81dcb7a9b6f7 was updated successfully.' in contents.get('HumanReadable')

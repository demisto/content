import demistomock as demisto
from CommonServerPython import Common
from Cylance_Protect_v2 import create_dbot_score_entry, translate_score, FILE_THRESHOLD, \
    get_device, get_device_by_hostname, update_device, get_device_threats, get_policies, create_zone, get_zones,\
    get_zone, update_zone, get_threat, get_threats, get_threat_devices, get_list
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

DEVICE_OUTPUT = {u'update_available': False,
                 u'date_last_modified': u'2020-11-09T23:10:24',
                 u'distinguished_name': u'',
                 u'ip_addresses': [u'1.1.1.1'],
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
                   'IPAddress': [u'1.1.1.1']
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
                     'IPAddress': [u'1.1.1.1']
                     }

DEVICE_THREAT_OUTPUT = {u'sha256': u'0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09',
                        u'name': u'name',
                        u'classification': u'Malware',
                        u'date_found': u'2018-09-17T07:14:03',
                        u'file_status': u'Default',
                        u'cylance_score': -1.0,
                        u'file_path': u'C:\\Ransomware Samples\\AutoitLocker.exe',
                        u'sub_classification': u'Trojan'
                        }

POLICIES_OUTPUT = {u'zone_count': 1,
                   u'name': u'fff',
                   u'date_modified': u'2020-04-13T10:32:43.5072251',
                   u'device_count': 0,
                   u'date_added': u'2020-04-13T10:32:43.5072251',
                   u'id': u'980fad21-b119-4cc4-ac97-2b2c035b4666'
                   }

EXPECTED_POLICIES = {u'DateAdded': u'2020-04-13T10:32:43.5072251',
                     u'Name': u'fff',
                     u'ZoneCount': 1,
                     u'DateModified': u'2020-04-13T10:32:43.5072251',
                     u'DeviceCount': 0,
                     u'Id': u'980fad21-b119-4cc4-ac97-2b2c035b4666'
                     }

ZONE_OUTPUT = {u'date_created': u'2022-02-03T15:52:30.4108727Z',
               u'policy_id': u'980fad21-b119-4cc4-ac97-2b2c035b4666',
               u'id': u'1998235b-a6ab-4043-86b5-81b0dc63887b',
               u'criticality': u'Low',
               u'name': u'name'
               }

ZONES_OUTPUT = {u'name': u'name',
                u'criticality': u'Low',
                u'date_modified': u'2022-02-03T15:52:30',
                u'zone_rule_id': None,
                u'update_type': u'Production',
                u'date_created': u'2022-02-03T15:52:30',
                u'id': u'1998235b-a6ab-4043-86b5-81b0dc63887b',
                u'policy_id': u'980fad21-b119-4cc4-ac97-2b2c035b4666'
                }

EXPECTED_ZONES = {u'DateModified': u'2022-02-03T15:52:30',
                  u'Name': u'name',
                  u'Criticality': u'Low',
                  u'UpdateType': u'Production',
                  u'DateCreated': u'2022-02-03T15:52:30',
                  u'PolicyId': u'980fad21-b119-4cc4-ac97-2b2c035b4666',
                  u'Id': u'1998235b-a6ab-4043-86b5-81b0dc63887b'
                  }

THREAT_DEVICES_OUTPUT = {u'name': u'DESKTOP-M7E991U',
                         u'ip_addresses': [u'1.1.1.1'],
                         u'mac_addresses': [u'00-0C-29-59-FB-FD'],
                         u'file_path': u'file path',
                         u'state': u'OffLine',
                         u'date_found': u'2019-01-28T23:36:58',
                         u'file_status': u'Quarantined',
                         u'agent_version': u'2.0.1500',
                         u'id': u'6d85a080-ceab-463e-b0e0-331739c35e5b',
                         u'policy_id': u'2f184387-4cb0-4913-8e73-9c13a3af3470'
                         }

EXPECTED_THREAT_DEVICES = {'Path': [{'FilePath': u'file path'}],
                           'SHA256': u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE'
                           }

LIST_OUTPUT = {u'category': u'Admin Tool',
               u'cylance_score': None,
               u'name': u'',
               u'classification': u'',
               u'sub_classification': u'',
               u'av_industry': None,
               u'reason': u'Added by Demisto',
               u'added': u'2018-11-13T13:39:07',
               u'list_type': u'GlobalSafe',
               u'sha256': u'234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487',
               u'added_by': u'14a0944f-d6f9-4054-b338-382b673c32ed',
               u'md5': u''
               }

EXPECTED_LIST = {u'Category': u'Admin Tool',
                 u'Added': u'2018-11-13T13:39:07',
                 'SHA256': u'234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487',
                 u'AddedBy': u'14a0944f-d6f9-4054-b338-382b673c32ed',
                 u'Reason': u'Added by Demisto',
                 u'ListType': u'GlobalSafe',
                 u'Sha256': u'234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487'
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


def test_get_device(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device
    Then
        - checks if the output is as expected
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
        - checks if the output is as expected
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
        - checks if the output is as expected
    """
    args = {'id': '8e836c98-102e-4332-b00d-81dcb7a9b6f7',
            'name': 'DESKTOP-M7E991U',
            'policyId': '32e4aacd-7698-4ef0-93e8-3e6f1f5c6857'
            }
    mocker.patch.object(Cylance_Protect_v2, "update_device_request", return_value=DEVICE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    update_device()

    contents = demisto_results.call_args[0][0]
    assert 'Device 8e836c98-102e-4332-b00d-81dcb7a9b6f7 was updated successfully.' in contents.get('HumanReadable')


def test_get_device_threats(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device_threats
    Then
        - checks if the output is as expected
    """

    args = {'id': 'dbdb7945-369a-4eba-a364-42f2e5f92cc9', 'threshold': -59}
    mocker.patch.object(Cylance_Protect_v2, "get_device_threats_request",
                        return_value={'page_items': [DEVICE_THREAT_OUTPUT]}
                        )
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_device_threats()

    contents = demisto_results.call_args[0][0]
    assert u'0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09' == \
           contents.get('EntryContext').get('File')[0].get('SHA256')


def test_get_policies(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function update_device
    Then
        - checks if the output is as expected
    """

    args = {'hostname': 'DESKTOP-M7E991U'}
    mocker.patch.object(Cylance_Protect_v2, "get_policies_request", return_value={'page_items': [POLICIES_OUTPUT]})
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_policies()

    contents = demisto_results.call_args[0][0]
    assert [EXPECTED_POLICIES] == contents.get('EntryContext').get(
        'CylanceProtect.Policies(val.id && val.id === obj.id)')


def test_create_zone(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function update_device
    Then
        - checks if the output is as expected
    """
    args = {'policy_id': '980fad21-b119-4cc4-ac97-2b2c035b4666',
            'name': 'name',
            'criticality': 'Low'
            }
    mocker.patch.object(Cylance_Protect_v2, "create_zone_request", return_value=ZONE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    create_zone()

    contents = demisto_results.call_args[0][0]
    assert 'Zone name was created successfully.' in contents.get('HumanReadable')


def test_get_zones(mocker):
    """
        Given
            - a threat and a dbot score
        When
            - calls the function update_device
        Then
            - checks if the output is as expected
    """

    args = {'hostname': 'DESKTOP-M7E991U'}
    mocker.patch.object(Cylance_Protect_v2, "get_zones_request", return_value={'page_items': [ZONES_OUTPUT]})
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_zones()

    contents = demisto_results.call_args[0][0]
    assert [EXPECTED_ZONES] == contents.get('EntryContext').get('CylanceProtect.Zones(val.Id && val.Id === obj.Id)')


def test_get_zone(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function update_device
    Then
        - checks if the output is as expected
    """

    args = {'id': '1998235b-a6ab-4043-86b5-81b0dc63887b'}
    mocker.patch.object(Cylance_Protect_v2, "get_zone_request", return_value=ZONES_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_zone()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_ZONES == contents.get('EntryContext').get('CylanceProtect.Zones(val.Id && val.Id === obj.Id)')


def test_update_zone(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function update_device
    Then
        - checks if the output is as expected
    """
    args = {'id': '1998235b-a6ab-4043-86b5-81b0dc63887b',
            'name': 'name'
            }
    mocker.patch.object(Cylance_Protect_v2, "update_zone_request", return_value=ZONE_OUTPUT)
    mocker.patch.object(Cylance_Protect_v2, "get_zone_request", return_value=ZONE_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    update_zone()

    contents = demisto_results.call_args[0][0]
    assert 'Zone was updated successfully.' in contents.get('HumanReadable')


def test_get_threat(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device_threats
    Then
        - checks if the output is as expected
    """

    args = {'sha256': '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE', 'threshold': -59}
    mocker.patch.object(Cylance_Protect_v2, "get_threat_request", return_value=THREAT_OUTPUT)
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_threat()

    contents = demisto_results.call_args[0][0]
    assert u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE' == \
           contents.get('EntryContext').get('File')[0].get('SHA256')


def test_get_threats(mocker):
    """
        Given
            - a threat and a dbot score
        When
            - calls the function update_device
        Then
            - checks if the output is as expected
    """

    mocker.patch.object(Cylance_Protect_v2, "get_threats_request", return_value={'page_items': [THREAT_OUTPUT]})
    mocker.patch.object(demisto, 'args', return_value={'threshold': -59})
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_threats()

    contents = demisto_results.call_args[0][0]
    assert u'055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE' == contents.get('EntryContext').get(
        'File')[0].get('SHA256')


def test_get_threat_devices(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device_threats
    Then
        - checks if the output is as expected
    """

    args = {'sha256': '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE'}
    mocker.patch.object(Cylance_Protect_v2, "get_threat_devices_request",
                        return_value={'page_items': [THREAT_DEVICES_OUTPUT]})
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_threat_devices()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_THREAT_DEVICES == contents.get('EntryContext').get('File')


def test_get_list(mocker):
    """
    Given
        - a threat and a dbot score
    When
        - calls the function get_device_threats
    Then
        - checks if the output is as expected
    """

    args = {'listTypeId': "GlobalSafe", "sha256": "234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487"}
    mocker.patch.object(Cylance_Protect_v2, "get_list_request",
                        return_value={'page_items': [LIST_OUTPUT]})
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_list()

    contents = demisto_results.call_args[0][0]
    assert [EXPECTED_LIST] == contents.get('EntryContext').get('File')


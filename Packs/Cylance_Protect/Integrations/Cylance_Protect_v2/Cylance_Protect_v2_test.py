import json

import demistomock as demisto
from CommonServerPython import Common
from Cylance_Protect_v2 import create_dbot_score_entry, translate_score, \
    get_device, get_device_by_hostname, update_device, get_device_threats, get_policies, create_zone, get_zones, \
    get_zone, update_zone, get_threat, get_threats, get_threat_devices, get_list, get_list_entry_by_hash, \
    add_hash_to_list, delete_hash_from_lists, delete_devices, get_policy_details, create_instaquery, list_instaquery, \
    get_instaquery_result
import Cylance_Protect_v2

THREAT_OUTPUT = {'cylance_score': -1.0, 'name': 'name',
                 'classification': 'Malware',
                 'sub_classification': 'Virus',
                 'av_industry': None,
                 'unique_to_cylance': False,
                 'last_found': '2019-01-28T23:36:58',
                 'global_quarantined': False,
                 'file_size': 2177386,
                 'safelisted': False,
                 'sha256': '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE',
                 'md5': 'B4EA38EB798EA1C1E067DFD176B882BB',
                 }

DEVICE_OUTPUT = {'update_available': False,
                 'date_last_modified': '2020-11-09T23:10:24',
                 'distinguished_name': '',
                 'ip_addresses': ['1.1.1.1'],
                 'dlcm_status': 'Unknown',
                 'background_detection': False,
                 'id': '8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                 'days_to_deletion': 'Unknown',
                 'os_version': 'Microsoft Windows 10 Education',
                 'state': 'Offline',
                 'date_first_registered': '2020-11-09T22:28:48',
                 'policy': {'id': '32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', 'name': 'Default'},
                 'host_name': 'DESKTOP-M7E991U',
                 'os_kernel_version': '10.0.0',
                 'mac_addresses': ['00-0C-29-41-20-14'],
                 'last_logged_in_user': 'DESKTOP-M7E991U\\scott.white',
                 'name': 'DESKTOP-M7E991U',
                 'date_offline': '2020-11-09T23:10:21.902',
                 'products': [{'status': 'Offline', 'version': '2.0.1500', 'name': 'protect'}],
                 'update_type': None,
                 'is_safe': True,
                 'agent_version': '2.0.1500'
                 }

EXPECTED_DEVICE = {'Name': 'DESKTOP-M7E991U',
                   'Hostname': 'DESKTOP-M7E991U',
                   'State': 'Offline',
                   'DateFirstRegistered': '2020-11-09T22:28:48',
                   'Policy': {'ID': '32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', 'Name': 'Default'},
                   'OSVersion': 'Microsoft Windows 10 Education',
                   'LastLoggedInUser': 'DESKTOP-M7E991U\\scott.white',
                   'MACAdress': ['00-0C-29-41-20-14'],
                   'BackgroundDetection': False,
                   'IsSafe': True,
                   'UpdateAvailable': False,
                   'ID': '8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                   'DateLastModified': '2020-11-09T23:10:24',
                   'DateOffline': '2020-11-09T23:10:21.902',
                   'IPAddress': ['1.1.1.1']
                   }

EXPECTED_HOSTNAME = {'Name': 'DESKTOP-M7E991U',
                     'Hostname': 'DESKTOP-M7E991U',
                     'State': 'Offline',
                     'DateFirstRegistered': '2020-11-09T22:28:48',
                     'Policy': {'ID': '32e4aacd-7698-4ef0-93e8-3e6f1f5c6857', 'Name': 'Default'},
                     'OSVersion': 'Microsoft Windows 10 Education',
                     'LastLoggedInUser': 'DESKTOP-M7E991U\\scott.white',
                     'MACAdress': ['00-0C-29-41-20-14'],
                     'BackgroundDetection': False,
                     'IsSafe': True,
                     'UpdateAvailable': False,
                     'ID': '8e836c98-102e-4332-b00d-81dcb7a9b6f7',
                     'DateLastModified': '2020-11-09T23:10:24',
                     'AgentVersion': '2.0.1500',
                     'DateOffline': '2020-11-09T23:10:21.902',
                     'IPAddress': ['1.1.1.1']
                     }

DEVICE_THREAT_OUTPUT = {'sha256': '0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09',
                        'name': 'name',
                        'classification': 'Malware',
                        'date_found': '2018-09-17T07:14:03',
                        'file_status': 'Default',
                        'cylance_score': -1.0,
                        'file_path': 'C:\\Ransomware Samples\\AutoitLocker.exe',
                        'sub_classification': 'Trojan'
                        }

POLICIES_OUTPUT = {'zone_count': 1,
                   'name': 'fff',
                   'date_modified': '2020-04-13T10:32:43.5072251',
                   'device_count': 0,
                   'date_added': '2020-04-13T10:32:43.5072251',
                   'id': '980fad21-b119-4cc4-ac97-2b2c035b4666'
                   }

EXPECTED_POLICIES = {'DateAdded': '2020-04-13T10:32:43.5072251',
                     'Name': 'fff',
                     'ZoneCount': 1,
                     'DateModified': '2020-04-13T10:32:43.5072251',
                     'DeviceCount': 0,
                     'Id': '980fad21-b119-4cc4-ac97-2b2c035b4666'
                     }

ZONE_OUTPUT = {'date_created': '2022-02-03T15:52:30.4108727Z',
               'policy_id': '980fad21-b119-4cc4-ac97-2b2c035b4666',
               'id': '1998235b-a6ab-4043-86b5-81b0dc63887b',
               'criticality': 'Low',
               'name': 'name'
               }

ZONES_OUTPUT = {'name': 'name',
                'criticality': 'Low',
                'date_modified': '2022-02-03T15:52:30',
                'zone_rule_id': None,
                'update_type': 'Production',
                'date_created': '2022-02-03T15:52:30',
                'id': '1998235b-a6ab-4043-86b5-81b0dc63887b',
                'policy_id': '980fad21-b119-4cc4-ac97-2b2c035b4666'
                }

EXPECTED_ZONES = {'Name': 'name',
                  'Criticality': 'Low',
                  'UpdateType': 'Production',
                  'DateCreated': '2022-02-03T15:52:30',
                  'PolicyId': '980fad21-b119-4cc4-ac97-2b2c035b4666',
                  'Id': '1998235b-a6ab-4043-86b5-81b0dc63887b',
                  'DateModified': '2022-02-03T15:52:30'
                  }

THREAT_DEVICES_OUTPUT = {'name': 'DESKTOP-M7E991U',
                         'ip_addresses': ['1.1.1.1'],
                         'mac_addresses': ['00-0C-29-59-FB-FD'],
                         'file_path': 'file path',
                         'state': 'OffLine',
                         'date_found': '2019-01-28T23:36:58',
                         'file_status': 'Quarantined',
                         'agent_version': '2.0.1500',
                         'id': '6d85a080-ceab-463e-b0e0-331739c35e5b',
                         'policy_id': '2f184387-4cb0-4913-8e73-9c13a3af3470'
                         }

EXPECTED_THREAT_DEVICES = {'Path': [{'FilePath': 'file path'}],
                           'SHA256': '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE'
                           }

LIST_OUTPUT = {'category': 'Admin Tool',
               'cylance_score': None,
               'name': '',
               'classification': '',
               'sub_classification': '',
               'av_industry': None,
               'reason': 'Added by Demisto',
               'added': '2018-11-13T13:39:07',
               'list_type': 'GlobalSafe',
               'sha256': '234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487',
               'added_by': '14a0944f-d6f9-4054-b338-382b673c32ed',
               'md5': ''
               }

EXPECTED_LIST = {'Category': 'Admin Tool',
                 'Added': '2018-11-13T13:39:07',
                 'SHA256': '234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487',
                 'AddedBy': '14a0944f-d6f9-4054-b338-382b673c32ed',
                 'Reason': 'Added by Demisto',
                 'ListType': 'GlobalSafe',
                 'Sha256': '234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487'
                 }

POLICY_OUTPUT = {'memoryviolation_actions': {'memory_violations': [],
                                             'memory_exclusion_list': [],
                                             'memory_violations_ext': []},
                 'logpolicy': {'log_upload': None,
                               'maxlogsize': '100',
                               'retentiondays': '30'
                               },
                 'file_exclusions': [],
                 'checksum': '987978644c220a71f6fa67685b06571d',
                 'filetype_actions': {'suspicious_files': [{'file_type': 'executable', 'actions': '0'}],
                                      'threat_files': [{'file_type': 'executable', 'actions': '0'}]},
                 'policy_name': 'fff',
                 'policy_utctimestamp': '/Date(1586773964507+0000)/',
                 'policy': [{'name': 'auto_blocking', 'value': '0'},
                            {'name': 'auto_uploading', 'value': '0'},
                            {'name': 'threat_report_limit', 'value': '500'},
                            {'name': 'low_confidence_threshold',
                             'value': '-600'},
                            {'name': 'full_disc_scan', 'value': '0'},
                            {'name': 'watch_for_new_files', 'value': '0'},
                            {'name': 'memory_exploit_detection', 'value': '0'},
                            {'name': 'trust_files_in_scan_exception_list', 'value': '0'},
                            {'name': 'logpolicy', 'value': '0'},
                            {'name': 'script_control', 'value': '0'},
                            {'name': 'prevent_service_shutdown', 'value': '0'},
                            {'name': 'scan_max_archive_size', 'value': '0'},
                            {'name': 'sample_copy_path', 'value': None},
                            {'name': 'kill_running_threats', 'value': '0'},
                            {'name': 'show_notifications', 'value': '0'},
                            {'name': 'optics_set_disk_usage_maximum_fixed',
                             'value': '1000'},
                            {'name': 'optics_malware_auto_upload', 'value': '0'},
                            {'name': 'optics_memory_defense_auto_upload', 'value': '0'},
                            {'name': 'optics_script_control_auto_upload', 'value': '0'},
                            {'name': 'optics_application_control_auto_upload', 'value': '0'},
                            {'name': 'optics_sensors_dns_visibility', 'value': '0'},
                            {'name': 'optics_sensors_private_network_address_visibility', 'value': '0'},
                            {'name': 'optics_sensors_windows_event_log_visibility', 'value': '0'},
                            {'name': 'optics_sensors_advanced_powershell_visibility', 'value': '0'},
                            {'name': 'optics_sensors_advanced_wmi_visibility', 'value': '0'},
                            {'name': 'optics_sensors_advanced_executable_parsing', 'value': '0'},
                            {'name': 'optics_sensors_enhanced_process_hooking_visibility', 'value': '0'},
                            {'name': 'device_control', 'value': '0'},
                            {'name': 'optics', 'value': '0'},
                            {'name': 'auto_delete', 'value': '0'},
                            {'name': 'days_until_deleted', 'value': '14'},
                            {'name': 'pdf_auto_uploading', 'value': '0'},
                            {'name': 'ole_auto_uploading', 'value': '0'},
                            {'name': 'docx_auto_uploading', 'value': '0'},
                            {'name': 'python_auto_uploading', 'value': '0'},
                            {'name': 'autoit_auto_uploading', 'value': '0'},
                            {'name': 'powershell_auto_uploading', 'value': '0'},
                            {'name': 'data_privacy', 'value': '0'},
                            {'name': 'custom_thumbprint', 'value': None},
                            {'name': 'scan_exception_list', 'value': []}],
                 'policy_id': '980fad21-b119-4cc4-ac97-2b2c035b4666'
                 }

EXPECTED_POLICY = {'Timestamp': '2020-04-13T10:32:44.507000+00:00',
                   'ID': '980fad21-b119-4cc4-ac97-2b2c035b4666',
                   'Name': 'fff'
                   }

INSTAQUERY_OUTPUT = {'match_type': 'Fuzzy',
                     'name': 'Test Instaquery',
                     'created_at': '2022-05-23T00:02:37Z',
                     'artifact': 'File',
                     'case_sensitive': False,
                     'zones': ['6608CA0E88C64647B276271CC5EA4295'],
                     'progress': {},
                     'match_value_type': 'Path',
                     'results_available': False,
                     'match_values': ['cyoptics.exe'],
                     'id': 'CBEB9E9C9A9A41D1BD06C87464F5E2CD',
                     'description': 'Test only'}

INSTAQUERY_RESULT_OUTPUT = {
    'status': 'done',
    'id': 'CBEB9E9C9A9A41D1BD06C87464F5E2CD',
    'result': [
        {
            '@timestamp': 1653264158.3315804,
            'HostName': 'windows-server-',
            'DeviceId': '65DB26864E364409B50DDC23291A3511',
            '@version': '1',
            'CorrelationId': 'CBEB9E9C9A9A41D1BD06C87464F5E2CD',
            'Result': '{"FirstObservedTime": "1970-01-01T00:00:00.000Z", '
                      '"LastObservedTime": "1970-01-01T00:00:00.000Z", '
                      '"Uid": "dHrtLYQzbt9oJPxO8HaeyA==", "Type": "File", "Properties": {"Path": '
                      '"c:\\\\program files\\\\cylance\\\\optics\\\\cyoptics.exe", "CreationDateTime": '
                      '"2021-03-29T22:34:14.000Z", "Md5": "A081D3268531485BF95DC1A15A5BC6B0", "Sha256": '
                      '"256809AABD3AB57949003B9AFCB556A9973222CDE81929982DAE7D306648E462", '
                      '"Owner": "NT AUTHORITY\\\\SYSTEM", '
                      '"SuspectedFileType": "Executable/PE", "FileSignature": "", "Size": "594104", "OwnerUid": '
                      '"P3p6fdq3FlMsld6Rz95EOA=="}}'
        }
    ]
}

LIST_INSTAQUERY_OUTPUT = {
    'page_number': 1,
    'page_items': [
        {
            'match_type': 'Fuzzy',
            'name': 'Test Insta continue 84',
            'created_at': '2022-05-23T00:02:37Z',
            'artifact': 'File', 'case_sensitive': False,
            'zones': ['6608CA0E88C64647B276271CC5EA4295'],
            'progress': {'queried': 1, 'responded': 1},
            'match_value_type': 'Path',
            'results_available': True,
            'match_values': ['cyoptics.exe'],
            'id': 'CBEB9E9C9A9A41D1BD06C87464F5E2CD',
            'description': 'Test only'
        },
        {
            'match_type': 'Exact',
            'name': 'CylanceProtectv2InstaQueryTest Test creation 2',
            'created_at': '2022-05-20T09:15:09Z',
            'artifact': 'File',
            'case_sensitive': True,
            'zones': ['6608CA0E88C64647B276271CC5EA4295'],
            'progress': {'queried': 1, 'responded': 1},
            'match_value_type': 'Path',
            'results_available': False,
            'match_values': ['exe'],
            'id': 'BC522393DD6E666C9EA9A999767EF5DB',
            'description': 'Description here'
        }
    ],
    'total_pages': 13,
    'total_number_of_items': 26,
    'page_size': 2
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
    dbot_score = translate_score(threat['cylance_score'], 2)
    dbot_score_entry = create_dbot_score_entry(THREAT_OUTPUT, dbot_score)
    assert isinstance(dbot_score_entry, Common.DBotScore)


def test_get_device(mocker):
    """
    Given
        - a threat and demisto args
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
    assert sorted(EXPECTED_DEVICE.items()) == sorted(
        contents.get('EntryContext').get('CylanceProtect.Device(val.ID && val.ID === obj.ID)').items()
    )


def test_get_device_by_hostname(mocker):
    """
    Given
        - a threat and demisto args
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
    assert sorted(EXPECTED_HOSTNAME.items()) == sorted(
        contents.get('EntryContext').get('CylanceProtect.Device(val.ID && val.ID === ' 'obj.ID)').items())  # noqa: ISC001


def test_update_device(mocker):
    """
    Given
        - demisto args
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
        - demisto args
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
    assert contents.get('EntryContext').get('File')[0].get('SHA256') == \
        '0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09'


def test_get_policies(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_policies
    Then
        - checks if the output is as expected
    """

    args = {'hostname': 'DESKTOP-M7E991U'}
    mocker.patch.object(Cylance_Protect_v2, "get_policies_request", return_value={'page_items': [POLICIES_OUTPUT]})
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_policies()

    contents = demisto_results.call_args[0][0]
    assert sorted(EXPECTED_POLICIES.items()) == sorted(
        contents.get('EntryContext').get('CylanceProtect.Policies(val.id && val.id === obj.id)')[0].items()
    )


def test_create_zone(mocker):
    """
    Given
        - demisto args
    When
        - calls the function create_zone
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
            - demisto args
        When
            - calls the function create_zones
        Then
            - checks if the output is as expected
    """

    args = {'hostname': 'DESKTOP-M7E991U'}
    mocker.patch.object(Cylance_Protect_v2, "get_zones_request", return_value={'page_items': [ZONES_OUTPUT]})
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_zones()

    contents = demisto_results.call_args[0][0]
    assert sorted(EXPECTED_ZONES.items()) == \
        sorted(contents.get('EntryContext').get('CylanceProtect.Zones(val.Id && val.Id === obj.Id)')[0].items())


def test_get_zone(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_zone
    Then
        - checks if the output is as expected
    """

    args = {'id': '1998235b-a6ab-4043-86b5-81b0dc63887b'}
    mocker.patch.object(Cylance_Protect_v2, "get_zone_request", return_value=ZONES_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_zone()

    contents = demisto_results.call_args[0][0]
    assert sorted(EXPECTED_ZONES.items()) == sorted(
        contents.get('EntryContext').get('CylanceProtect.Zones(val.Id && val.Id === obj.Id)').items()
    )


def test_update_zone(mocker):
    """
    Given
        - demisto args
    When
        - calls the function update_zone
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
        - demisto args
    When
        - calls the function get_threats
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
    assert contents.get('EntryContext').get('File')[0].get('SHA256') == \
        '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE'


def test_get_threats(mocker):
    """
        Given
            - demisto args
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
    assert contents.get('EntryContext').get(
        'File')[0].get('SHA256') == '055D7A25DECF6769BF4FB2F3BC9FD3159C8B42972818177E44975929D97292DE'


def test_get_threat_devices(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_threat_devices
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
    assert sorted(EXPECTED_THREAT_DEVICES.items()) == sorted(
        contents.get('EntryContext').get('File').items())


def test_get_list(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_list
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
    assert contents.get('EntryContext').get('File')[0] == EXPECTED_LIST


def test_get_list_entry_by_hash(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_list_entry_by_hash
    Then
        - checks if the output is as expected
    """

    args = {'listTypeId': "GlobalSafe", "sha256": "234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487"}
    mocker.patch.object(Cylance_Protect_v2, "get_list_request",
                        return_value={'page_items': [LIST_OUTPUT], 'total_pages': 'total_pages'})
    mocker.patch.object(Cylance_Protect_v2, "translate_score", return_value=1)

    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='cylance-protect-get-list-entry')
    demisto_results = mocker.patch.object(demisto, 'results')
    get_list_entry_by_hash()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_LIST.get('Sha256') == contents.get('EntryContext').get('CylanceListSearch').get('Sha256')


def test_add_hash_to_list(mocker):
    """
    Given
        - demisto args
    When
        - calls the function add_hash_to_list
    Then
        - checks if the output is as expected
    """

    args = {'listType': "GlobalSafe",
            "sha256": "234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487",
            "category": "Admin Tool",
            "reason": "Added by Demisto"
            }
    mocker.patch.object(Cylance_Protect_v2, "add_hash_to_list_request", return_value={'page_items': [LIST_OUTPUT]})

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    add_hash_to_list()

    contents = demisto_results.call_args[0][0]
    assert 'The requested threat has been successfully added to GlobalSafe hashlist.' in contents.get('HumanReadable')


def test_delete_hash_from_lists(mocker):
    """
    Given
        - demisto args
    When
        - calls the function delete_hash_from_lists
    Then
        - checks if the output is as expected
    """

    args = {'listType': "GlobalSafe",
            "sha256": "234E5014C239FD89F2F3D56091B87763DCD90F6E3DB42FD2FA1E0ABE05AF0487",
            "category": "Admin Tool",
            "reason": "Added by Demisto"
            }
    mocker.patch.object(Cylance_Protect_v2, "delete_hash_from_lists_request", return_value={})

    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    delete_hash_from_lists()

    contents = demisto_results.call_args[0][0]
    assert 'The requested threat has been successfully removed from GlobalSafe hashlist.' in \
           contents.get('HumanReadable')


def test_delete_devices(mocker):
    """
    Given
        - demisto args
    When
        - calls the function delete_devices
    Then
        - checks if the output is as expected
    """

    args = {'deviceIds': "8e836c98-102e-4332-b00d-81dcb7a9b6f7",
            "batch_size": 1,
            "category": "Admin Tool",
            "reason": "Added by Demisto"
            }

    mocker.patch.object(Cylance_Protect_v2, "get_device_request", return_value=DEVICE_OUTPUT)
    mocker.patch.object(Cylance_Protect_v2, "delete_devices_request", return_value={})
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    delete_devices()

    contents = demisto_results.call_args[0][0]
    assert 'The requested devices have been successfully removed from your organization list.' in \
           contents.get('HumanReadable')


def test_get_policy_details(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_policy_details
    Then
        - checks if the output is as expected
    """

    args = {'policyID': '980fad21-b119-4cc4-ac97-2b2c035b4666'}
    mocker.patch.object(Cylance_Protect_v2, "get_policy_details_request", return_value=POLICY_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_policy_details()

    contents = demisto_results.call_args[0][0]
    assert EXPECTED_POLICY.get("ID") == contents.get('EntryContext').get(
        'Cylance.Policy(val.policy_id && val.policy_id == obj.policy_id)').get("policy_id")


def test_create_instaquery(mocker):
    """
    Given
        - demisto args
    When
        - calls the function create_insta_query
    Then
        - checks if the output is as expected
    """
    args = {
        "name": "Test Instaquery",
        "description": "To collect test result",
        "artifact": "File",
        "match_value_type": "File.Path",
        "match_values": "cyoptics.exe",
        "case_sensitive": False,
        "match_type": "Fuzzy",
        "zone": "6608ca0e-88c6-4647-b276-271cc5ea4295"
    }
    mocker.patch.object(Cylance_Protect_v2, "create_instaquery_request", return_value=INSTAQUERY_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    create_instaquery()

    contents = demisto_results.call_args[0][0]
    assert INSTAQUERY_OUTPUT.get("id") == \
        contents.get('EntryContext').get('InstaQuery.New(val.id && val.id == obj.id)').get("id")


def test_get_instaquery_result(mocker):
    """
    Given
        - demisto args
    When
        - calls the function get_instaquery_result
    Then
        - checks if the output is as expected
    """
    args = {'query_id': 'CBEB9E9C9A9A41D1BD06C87464F5E2CD'}
    mocker.patch.object(Cylance_Protect_v2, "get_instaquery_result_request", return_value=INSTAQUERY_RESULT_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    get_instaquery_result()

    contents = demisto_results.call_args[0][0]
    assert json.loads(INSTAQUERY_RESULT_OUTPUT['result'][0]['Result']).get(
        'Properties').get('Sha256') in contents.get('HumanReadable')


def test_list_instaquery(mocker):
    """
    Given
        - demisto args
    When
        - calls the function list_instaquery
    Then
        - checks if the number of output items is as expected
    """
    args = {'page_number': '1', 'page_size': '2'}
    mocker.patch.object(Cylance_Protect_v2, "list_instaquery_request", return_value=LIST_INSTAQUERY_OUTPUT)
    mocker.patch.object(demisto, 'args', return_value=args)
    demisto_results = mocker.patch.object(demisto, 'results')
    list_instaquery()

    contents = demisto_results.call_args[0][0]
    assert len(LIST_INSTAQUERY_OUTPUT.get("page_items")) == \
        len(contents.get('EntryContext').get("InstaQuery.List").get("page_items"))

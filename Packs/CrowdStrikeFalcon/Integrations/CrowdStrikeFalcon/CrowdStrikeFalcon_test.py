import pytest
import os
import json
from urllib.parse import unquote

from _pytest.python_api import raises

import demistomock as demisto
from CommonServerPython import outputPaths, entryTypes, DemistoException, IncidentStatus, ScheduledCommand
from test_data import input_data
from freezegun import freeze_time

RETURN_ERROR_TARGET = 'CrowdStrikeFalcon.return_error'
SERVER_URL = 'https://4.4.4.4'


def load_json(file: str):
    with open(file) as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def get_access_token(requests_mock, mocker):
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': SERVER_URL,
            'proxy': True,
            'incidents_per_fetch': 2,
            'fetch_incidents_or_detections': ['Detections', 'Incidents'],
            'fetch_time': '3 days',
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/oauth2/token',
        json={
            'access_token': 'token'
        },
        status_code=200
    )


incident_context = {'name': 'Incident ID: inc:afb5d1512a00480f53e9ad91dc3e4b55:1cf23a95678a421db810e11b5db693bd',
                    'occurred': '2020-05-17T17:30:38Z',
                    'rawJSON':
                        '{"incident_id": "inc:afb5d1512a00480f53e9ad91dc3e4b55:1cf23a95678a421db810e11b5db693bd", '
                        '"cid": "24ab288b109b411aba970e570d1ddf58", "host_ids": ["afb5d1512a00480f53e9ad91dc3e4b55"], '
                        '"hosts": [{"device_id": "afb5d1512a00480f53e9ad91dc3e4b55", '
                        '"cid": "24ab288b109b411aba970e570d1ddf58", "agent_load_flags": "0", '
                        '"agent_local_time": "2020-05-06T23:36:34.594Z", "agent_version": "5.28.10902.0", '
                        '"bios_manufacturer": "Apple Inc.", '
                        '"bios_version": "1037.100.359.0.0 (iBridge: 17.16.14263.0.0,0)", '
                        '"config_id_base": "65994753", "config_id_build": "10902", "config_id_platform": "4", '
                        '"external_ip": "1.1.1.1", "hostname": "SFO-M-Y81WHJ", '
                        '"first_seen": "2019-05-10T17:20:39Z", "last_seen": "2020-05-17T16:59:42Z", '
                        '"local_ip": "1.1.1.1", "mac_address": "86-89-ad-65-d0-30", "major_version": "18", '
                        '"minor_version": "7", "os_version": "Mojave (10.14)", "platform_id": "1", '
                        '"platform_name": "Mac", "product_type_desc": "Workstation", "status": "normal", '
                        '"system_manufacturer": "Apple Inc.", "system_product_name": "MacBookPro15,1", '
                        '"modified_timestamp": "2020-05-17T16:59:56Z"}], "created": "2020-05-17T17:30:38Z", '
                        '"start": "2020-05-17T17:30:38Z", "end": "2020-05-17T17:30:38Z", "state": "closed", '
                        '"status": "New", "name": "Incident on SFO-M-Y81WHJ at 2020-05-17T17:30:38Z", '
                        '"description": "Objectives in this incident: Keep Access. '
                        'Techniques: External Remote Services. Involved hosts and end users: SFO-M-Y81WHJ.", '
                        '"tags": ["Objective/Keep Access"], "fine_score": 38, '
                        '"mirror_direction": null, "mirror_instance": ""}'}

IOCS_JSON_LIST = [{'type': 'ipv4', 'value': '4.4.4.4', 'source': 'cortex xsoar', 'action': 'no_action',
                   'severity': 'informational', 'description': 'lala', 'platforms': ['linux'],
                   'tags': ['test'], 'expiration': '2022-02-15T15:55:09Z', 'applied_globally': True,
                   }, {'type': 'ipv4', 'value': '5.5.5.5', 'source': 'cortex xsoar',
                       'action': 'no_action', 'severity': 'informational',
                       'description': 'lala',
                       'platforms': ['linux'], 'tags': ['test'],
                       'expiration': '2022-02-15T15:55:09Z', 'applied_globally': True,
                       }]


def test_incident_to_incident_context():
    from CrowdStrikeFalcon import incident_to_incident_context
    res = incident_to_incident_context(input_data.response_incident.copy())
    assert res == incident_context


def test_idp_detectionin_to_incident_context():
    from CrowdStrikeFalcon import idp_detection_to_incident_context
    res = idp_detection_to_incident_context(input_data.response_idp_detection.copy())
    assert res == input_data.context_idp_detection


def test_create_json_iocs_list():
    from CrowdStrikeFalcon import create_json_iocs_list

    res = create_json_iocs_list(ioc_type='ipv4', iocs_value=['4.4.4.4', '5.5.5.5'], action='no_action',
                                platforms=['linux'], severity='informational', source='cortex xsoar',
                                description='lala', expiration='2022-02-15T15:55:09Z', applied_globally=True,
                                host_groups=[], tags=['test'])
    assert res == IOCS_JSON_LIST


def test_timestamp_length_equalization():
    from CrowdStrikeFalcon import timestamp_length_equalization
    timestamp_in_millisecond = 1574585006000
    timestamp_in_seconds = 1574585015

    timestamp_in_millisecond_after, timestamp_in_seconds_after = timestamp_length_equalization(timestamp_in_millisecond,
                                                                                               timestamp_in_seconds)

    assert timestamp_in_millisecond_after == 1574585006000
    assert timestamp_in_seconds_after == 1574585015000

    timestamp_in_seconds_after, timestamp_in_millisecond_after = timestamp_length_equalization(timestamp_in_seconds,
                                                                                               timestamp_in_millisecond)

    assert timestamp_in_millisecond_after == 1574585006000
    assert timestamp_in_seconds_after == 1574585015000


def test_run_command_failure_sensor_offline(requests_mock, mocker):
    from CrowdStrikeFalcon import run_command
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_ids': '284771ee197e422d5176d6634a62b934',
            'command_type': 'ls',
            'full_command': 'cd C:\\some_directory'
        }
    )
    error_object = {
        "meta": {
            "query_time": 0.505762223,
            "powered_by": "empower-api",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "batch_id": "",
        "resources": {
            "284771ee197e422d5176d6634a62b934": {
                "session_id": "",
                "complete": False,
                "stdout": "",
                "stderr": "",
                "aid": "284771ee197e422d5176d6634a62b934",
                "errors": [
                    {
                        "code": 40407,
                        "message": "Sensor appears to be offline"
                    }
                ],
                "query_time": 0
            }
        },
        "errors": [
            {
                "code": 404,
                "message": "no successful hosts initialized on RTR"
            }
        ]
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-command/v1',
        json=error_object,
        status_code=404,
        reason='Not found'
    )
    with pytest.raises(DemistoException) as error_info:
        run_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
                                    'reason: Not found\nHost ID 284771ee197e422d5176d6634a62b934 - ' \
                                    'Sensor appears to be offline'


def test_run_command_read_scope(requests_mock, mocker):
    from CrowdStrikeFalcon import run_command
    response = {
        'meta': {
            'query_time': 1.178901572,
            'powered_by': 'empower-api',
            'trace_id': '07kk11c3-496g-42df-9157-834e499e279d'
        },
        'combined': {
            'resources': {
                '284771ee197e422d5176d6634a62b934': {
                    'session_id': '1113b475-2c28-4486-8617-d000b8f3bc8d',
                    'task_id': 'e0149c46-4ba0-48c9-9e98-49b806a0033f',
                    'complete': True,
                    'stdout': 'Directory listing for C:\\ -\n\n'
                              'Name                                     Type         Size (bytes)    Size (MB)       '
                              'Last Modified (UTC-5)     Created (UTC-5)          \n----                             '
                              '        ----         ------------    ---------       ---------------------     -------'
                              '--------          \n$Recycle.Bin                             <Directory>  --          '
                              '    --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     \nITAYDI       '
                              '                            <Directory>  --              --              11/19/2018 1:'
                              '31:42 PM     11/19/2018 1:31:42 PM    ',
                    'stderr': '',
                    'base_command': 'ls',
                    'aid': '284771ee197e422d5176d6634a62b934',
                    'errors': None,
                    'query_time': 1.1783866060000001
                }
            }
        },
        'errors': []
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_ids': '284771ee197e422d5176d6634a62b934',
            'command_type': 'ls',
            'full_command': 'ls C:\\'
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-command/v1',
        json=response,
        status_code=201
    )
    results = run_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                'HostID': '284771ee197e422d5176d6634a62b934',
                'SessionID': '1113b475-2c28-4486-8617-d000b8f3bc8d',
                'Stdout': 'Directory listing for C:\\ -\n\n'
                          'Name                                     Type         Size (bytes)    Size (MB)       '
                          'Last Modified (UTC-5)     Created (UTC-5)          \n----                             '
                          '        ----         ------------    ---------       ---------------------     -------'
                          '--------          \n$Recycle.Bin                             <Directory>  --          '
                          '    --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     \nITAYDI       '
                          '                            <Directory>  --              --              11/19/2018 1:'
                          '31:42 PM     11/19/2018 1:31:42 PM    ',
                'Stderr': '',
                'BaseCommand': 'ls',
                'Command': 'ls C:\\'
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_run_command_write_scope(requests_mock, mocker):
    from CrowdStrikeFalcon import run_command
    response = {
        "combined": {
            "resources": {
                "284771ee197e422d5176d6634a62b934": {
                    "aid": "284771ee197e422d5176d6634a62b934",
                    "base_command": "mkdir",
                    "complete": True,
                    "errors": None,
                    "query_time": 0.478191482,
                    "session_id": "ed0743e0-b156-4f98-8bbb-7a720a4192cf",
                    "stderr": "",
                    "stdout": "C:\\demistotest1",
                    "task_id": "e579eee6-ce7a-487c-8fef-439ebc9c3bc0"
                }
            }
        },
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.478696373,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_ids': '284771ee197e422d5176d6634a62b934',
            'command_type': 'mkdir',
            'full_command': 'mkdir C:\\demistotest1',
            'scope': 'write'
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-active-responder-command/v1',
        json=response,
        status_code=201
    )
    results = run_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                'HostID': '284771ee197e422d5176d6634a62b934',
                'SessionID': 'ed0743e0-b156-4f98-8bbb-7a720a4192cf',
                'Stdout': 'C:\\demistotest1',
                'Stderr': '',
                'BaseCommand': 'mkdir',
                'Command': 'mkdir C:\\demistotest1'
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_run_command_with_stderr(requests_mock, mocker):
    from CrowdStrikeFalcon import run_command
    response = {
        "combined": {
            "resources": {
                "284771ee197e422d5176d6634a62b934": {
                    "aid": "284771ee197e422d5176d6634a62b934",
                    "base_command": "runscript",
                    "complete": True,
                    "errors": None,
                    "query_time": 4.111527091,
                    "session_id": "4d41588e-8455-4f0f-a3ee-0515922a8d94",
                    "stderr": "The term 'somepowershellscript' is not recognized as the name of a cmdlet, function,"
                              " script file, or operable program. Check the spelling of the name, or if a path was "
                              "included, verify that the path is correct and try again.",
                    "stdout": "",
                    "task_id": "6d78e0ab-ec8a-4a5b-a948-1dca6381a9d1"
                }
            }
        },
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 4.112103195,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_ids': '284771ee197e422d5176d6634a62b934',
            'command_type': 'runscript',
            'full_command': 'runscript -CloudFile=InvalidPowerShellScript',
            'scope': 'admin'
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-admin-command/v1',
        json=response,
        status_code=201
    )
    results = run_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                'HostID': '284771ee197e422d5176d6634a62b934',
                'SessionID': '4d41588e-8455-4f0f-a3ee-0515922a8d94',
                'Stdout': '',
                'Stderr': "The term 'somepowershellscript' is not recognized as the name of a cmdlet, function,"
                          " script file, or operable program. Check the spelling of the name, or if a path was "
                          "included, verify that the path is correct and try again.",
                'BaseCommand': 'runscript',
                'Command': 'runscript -CloudFile=InvalidPowerShellScript'
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_run_script(requests_mock, mocker):
    from CrowdStrikeFalcon import run_script_command
    response = {
        "combined": {
            "resources": {
                "284771ee197e422d5176d6634a62b934": {
                    "aid": "284771ee197e422d5176d6634a62b934",
                    "base_command": "runscript",
                    "complete": True,
                    "errors": None,
                    "query_time": 4.111527091,
                    "session_id": "4d41588e-8455-4f0f-a3ee-0515922a8d94",
                    "stderr": "",
                    "stdout": 'Hello, World!',
                    "task_id": "6d78e0ab-ec8a-4a5b-a948-1dca6381a9d1"
                }
            }
        },
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 4.112103195,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_id': '284771ee197e422d5176d6634a62b934',
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-admin-command/v1',
        json=response,
        status_code=201
    )
    results = run_script_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                'HostID': '284771ee197e422d5176d6634a62b934',
                'SessionID': '4d41588e-8455-4f0f-a3ee-0515922a8d94',
                'Stdout': 'Hello, World!',
                'Stderr': '',
                'BaseCommand': 'runscript',
                'Command': "runscript -Raw=Write-Output 'Hello, World! -Timeout=30"
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_run_script_failure_bad_inputs(mocker):
    from CrowdStrikeFalcon import run_script_command

    # test failure given both script_name and raw arguments
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_name': 'iloveny',
            'raw': 'RAWR'
        }
    )
    with pytest.raises(ValueError) as e:
        run_script_command()
    assert str(e.value) == 'Only one of the arguments script_name or raw should be provided, not both.'

    # test failure none of the arguments script_name and raw given
    mocker.patch.object(
        demisto,
        'args',
        return_value={}
    )
    with pytest.raises(ValueError) as e:
        run_script_command()
    assert str(e.value) == 'One of the arguments script_name or raw must be provided, none given.'


def test_upload_script_given_content(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_script_command
    response = {
        "meta": {
            "query_time": 0.782968846,
            "writes": {
                "resources_affected": 1
            },
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1',
        json=response,
        status_code=200
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'content': "Write-Output 'Hello, World!'"
        }
    )
    results = upload_script_command()
    assert results['HumanReadable'] == 'The script was uploaded successfully'
    assert results['Contents'] == response


def test_upload_script_given_file(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_script_command
    response = {
        "meta": {
            "query_time": 0.782968846,
            "writes": {
                "resources_affected": 1
            },
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1',
        json=response,
        status_code=200
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'entry_id': '23@32'
        }
    )
    mocker.patch.object(
        demisto,
        'getFilePath',
        return_value={
            'path': 'test_data/HelloWorld.ps1',
            'name': 'HelloWorld.ps1'
        }
    )
    mocker.patch.object(demisto, 'results')
    results = upload_script_command()
    assert results['HumanReadable'] == 'The script was uploaded successfully'
    assert results['Contents'] == response


def test_upload_script_failure_already_exists(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_script_command
    response = {
        "meta": {
            "query_time": 0.01543348,
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "errors": [
            {
                "code": 409,
                "message": "file with given name already exists"
            }
        ]
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1',
        json=response,
        status_code=409,
        reason='Conflict'
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'content': "Write-Output 'Hello, World!'"
        }
    )
    with pytest.raises(DemistoException) as error_info:
        upload_script_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 409 - ' \
                                    'reason: Conflict\nfile with given name already exists'


def test_upload_script_failure_bad_inputs(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_script_command

    # test failure given both content and entry_id arguments
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'content': "Write-Output 'Hello, World!'",
            'entry_id': '23@32'
        }
    )
    with pytest.raises(ValueError) as e:
        upload_script_command()
    assert str(e.value) == 'Only one of the arguments entry_id or content should be provided, not both.'

    # test failure none of the arguments content and entry_id given
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny'
        }
    )
    with pytest.raises(ValueError) as e:
        upload_script_command()
    assert str(e.value) == 'One of the arguments entry_id or content must be provided, none given.'


def test_get_script_without_content(requests_mock, mocker):
    from CrowdStrikeFalcon import get_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "0f047130-1ea2-44cb-a178-e5a85b2ad55a"
        },
        "resources": [
            {
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": script_id,
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "run_attempt_count": 0,
                "run_success_count": 0,
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444,
                'write_access': True
            }
        ]
    }
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/scripts/v2?ids={script_id}',
        json=response,
        status_code=200
    )
    results = get_script_command()
    expected_results = {
        'CrowdStrike.Script(val.ID === obj.ID)': {
            'CreatedBy': 'spongobob@demisto.com',
            'CreatedTime': '2019-10-17T13:41:48.487520845Z',
            'Description': 'Demisto',
            'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
            'RunAttemptCount': 0,
            'RunSuccessCount': 0,
            'WriteAccess': True
        }
    }
    assert results['EntryContext'] == expected_results
    # verify there was no file returned as there no file content was returned
    assert demisto.results.call_count == 0


def test_get_script_with_content(requests_mock, mocker, request):
    from CrowdStrikeFalcon import get_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    script_content = "function Demisto {}"
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "0f047130-1ea2-44cb-a178-e5a85b2ad55a"
        },
        "resources": [
            {
                "content": script_content,
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": script_id,
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "run_attempt_count": 0,
                "run_success_count": 0,
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444,
                'write_access': True
            }
        ]
    }
    file_name = '1_test_file_result'

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    mocker.patch.object(demisto, 'uniqueFile', return_value="test_file_result")
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/scripts/v2?ids={script_id}',
        json=response,
        status_code=200
    )
    results = get_script_command()
    expected_results = {
        'CrowdStrike.Script(val.ID === obj.ID)': {
            'CreatedBy': 'spongobob@demisto.com',
            'CreatedTime': '2019-10-17T13:41:48.487520845Z',
            'Description': 'Demisto',
            'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
            'RunAttemptCount': 0,
            'RunSuccessCount': 0,
            'WriteAccess': True
        }
    }
    assert results['EntryContext'] == expected_results
    # verify there was file returned
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'Demisto.ps1'
    with open(file_name, 'rb') as f:
        assert f.read().decode() == script_content


def test_get_script_does_not_exist(requests_mock, mocker):
    from CrowdStrikeFalcon import get_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "0f047130-1ea2-44cb-a178-e5a85b2ad55a"
        },
        "resources": []
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/scripts/v2?ids={script_id}',
        json=response,
        status_code=200
    )

    assert get_script_command() == 'No script found.'


def test_delete_script(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.535416674,
            "writes": {
                "resources_affected": 1
            },
            "powered_by": "empower",
            "trace_id": "b48fc444-8e80-48bf-akbf-281fb9471e5g"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
        json=response,
        status_code=200
    )

    assert delete_script_command()['HumanReadable'] == f'Script {script_id} was deleted successfully'


def test_delete_script_failure_insufficient_permissions(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.001585675,
            "powered_by": "crowdstrike-api-gateway",
            "trace_id": "01fcdbc6-6319-42e4-8ab1-b3edca76aa2c"
        },
        "errors": [
            {
                "code": 403,
                "message": "access denied, authorization failed"
            }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
        json=response,
        status_code=403,
        reason='Forbidden'
    )

    with pytest.raises(DemistoException) as error_info:
        delete_script_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 403 - ' \
                                    'reason: Forbidden\naccess denied, authorization failed'


def test_delete_script_failure_not_found(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_script_command
    script_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.001585675,
            "powered_by": "empower",
            "trace_id": "01fcdbc6-6319-42e4-8ab1-b3edca76aa2c"
        },
        "errors": [
            {
                "code": 404,
                "message": "Could not find file for deletion"
            }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'script_id': script_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
        json=response,
        status_code=404,
        reason='Not Found'
    )
    with pytest.raises(DemistoException) as error_info:
        delete_script_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
                                    'reason: Not Found\nCould not find file for deletion'


def test_list_scripts(requests_mock):
    from CrowdStrikeFalcon import list_scripts_command
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.031727879,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "resources": [
            {
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": "le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a",
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "run_attempt_count": 0,
                "run_success_count": 0,
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444,
                "platform": [
                    "windows"
                ],
                "write_access": True
            }
        ]
    }
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/scripts/v2',
        json=response
    )
    results = list_scripts_command()
    expected_results = {
        'CrowdStrike.Script(val.ID === obj.ID)': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'RunAttemptCount': 0,
                'RunSuccessCount': 0,
                'Platform': [
                    "windows"
                ],
                'WriteAccess': True
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_upload_file(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_file_command
    response = {
        "meta": {
            "query_time": 0.782968846,
            "writes": {
                "resources_affected": 1
            },
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/put-files/v1',
        json=response,
        status_code=200
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'entry_id': '23@32'
        }
    )
    mocker.patch.object(
        demisto,
        'getFilePath',
        return_value={
            'path': 'test_data/HelloWorld.ps1',
            'name': 'HelloWorld.ps1'
        }
    )
    results = upload_file_command()
    assert results['HumanReadable'] == 'File was uploaded successfully'
    assert results['Contents'] == response


def test_upload_file_failure_already_exists(requests_mock, mocker):
    from CrowdStrikeFalcon import upload_file_command
    response = {
        "meta": {
            "query_time": 0.01543348,
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "errors": [
            {
                "code": 409,
                "message": "file with given name already exists"
            }
        ]
    }
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/put-files/v1',
        json=response,
        status_code=409,
        reason='Conflict'
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'name': 'iloveny',
            'entry_id': "23@32"
        }
    )
    mocker.patch.object(
        demisto,
        'getFilePath',
        return_value={
            'path': 'test_data/HelloWorld.ps1',
            'name': 'HelloWorld.ps1'
        }
    )
    with pytest.raises(DemistoException) as error_info:
        upload_file_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 409 - ' \
                                    'reason: Conflict\nfile with given name already exists'


def test_get_file_without_content(requests_mock, mocker):
    from CrowdStrikeFalcon import get_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "resources": [
            {
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": file_id,
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "run_attempt_count": 0,
                "run_success_count": 0,
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444,
                'write_access': True
            }
        ]
    }
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/put-files/v2?ids={file_id}',
        json=response,
        status_code=200
    )
    results = get_file_command()
    expected_results = {
        'CrowdStrike.File(val.ID === obj.ID)': {
            'CreatedBy': 'spongobob@demisto.com',
            'CreatedTime': '2019-10-17T13:41:48.487520845Z',
            'Description': 'Demisto',
            'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
            'Type': 'script'
        },
        outputPaths['file']: {
            'Name': 'Demisto',
            'Size': 4444,
            'Type': 'script',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc'
        }
    }
    assert results['EntryContext'] == expected_results
    # verify there was no file returned as there no file content was returned
    assert demisto.results.call_count == 0


def test_get_file_with_content(requests_mock, mocker, request):
    from CrowdStrikeFalcon import get_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    file_content = "function Demisto {}"
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "resources": [
            {
                "content": file_content,
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": file_id,
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444,
            }
        ]
    }
    file_name = '1_test_file_result'

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    mocker.patch.object(demisto, 'uniqueFile', return_value="test_file_result")
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/put-files/v2?ids={file_id}',
        json=response,
        status_code=200
    )
    results = get_file_command()
    expected_results = {
        'CrowdStrike.File(val.ID === obj.ID)': {
            'CreatedBy': 'spongobob@demisto.com',
            'CreatedTime': '2019-10-17T13:41:48.487520845Z',
            'Description': 'Demisto',
            'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
            'ModifiedBy': 'spongobob@demisto.com',
            'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
            'Name': 'Demisto',
            'Permission': 'private',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
            'Type': 'script'
        },
        outputPaths['file']: {
            'Name': 'Demisto',
            'Size': 4444,
            'Type': 'script',
            'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc'
        }
    }
    assert results['EntryContext'] == expected_results
    # verify there was file returned
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'Demisto'
    with open(file_name, 'rb') as f:
        assert f.read().decode() == file_content


def test_get_file_does_not_exist(requests_mock, mocker):
    from CrowdStrikeFalcon import get_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "resources": []
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/put-files/v2?ids={file_id}',
        json=response,
        status_code=200
    )

    assert get_file_command() == 'No file found.'


def test_delete_file(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.535416674,
            "writes": {
                "resources_affected": 1
            },
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
        json=response,
        status_code=200
    )

    assert delete_file_command()['HumanReadable'] == f'File {file_id} was deleted successfully'


def test_delete_file_failure_insufficient_permissions(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.001585675,
            "powered_by": "crowdstrike-api-gateway",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "errors": [
            {
                "code": 403,
                "message": "access denied, authorization failed"
            }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
        json=response,
        status_code=403,
        reason='Forbidden'
    )
    with pytest.raises(DemistoException) as error_info:
        delete_file_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 403 - ' \
                                    'reason: Forbidden\naccess denied, authorization failed'


def test_delete_file_failure_not_found(requests_mock, mocker):
    from CrowdStrikeFalcon import delete_file_command
    file_id = 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a'
    response = {
        "meta": {
            "query_time": 0.001585675,
            "powered_by": "empower",
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "errors": [
            {
                "code": 404,
                "message": "Could not find file for deletion"
            }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'file_id': file_id
        }
    )
    requests_mock.delete(
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
        json=response,
        status_code=404,
        reason='Not Found'
    )
    with pytest.raises(DemistoException) as error_info:
        delete_file_command()
    assert str(error_info.value) == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
                                    'reason: Not Found\nCould not find file for deletion'


def test_list_files(requests_mock):
    from CrowdStrikeFalcon import list_files_command
    response = {
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.082774607,
            "trace_id": "07kk11c3-496g-42df-9157-834e499e279d"
        },
        "resources": [
            {
                "content": "function Demisto {}",
                "created_by": "spongobob@demisto.com",
                "created_by_uuid": "94cc8c66-5447-41ft-a1d8-2bd1faabfb9q",
                "created_timestamp": "2019-10-17T13:41:48.487520845Z",
                "description": "Demisto",
                "file_type": "script",
                "id": "le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a",
                "modified_by": "spongobob@demisto.com",
                "modified_timestamp": "2019-10-17T13:41:48.487521161Z",
                "name": "Demisto",
                "permission_type": "private",
                "run_attempt_count": 0,
                "run_success_count": 0,
                "sha256": "5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc",
                "size": 4444
            }
        ]
    }
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/put-files/v2',
        json=response
    )
    results = list_files_command()
    expected_results = {
        'CrowdStrike.File(val.ID === obj.ID)': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'Type': 'script'
            }
        ],
        outputPaths['file']: [
            {
                'Name': 'Demisto',
                'Size': 4444,
                'Type': 'script',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_run_get(requests_mock, mocker):
    from CrowdStrikeFalcon import run_get_command
    response = {
        "batch_get_cmd_req_id": "84ee4d50-f499-482e-bac6-b0e296149bbf",
        "combined": {
            "resources": {
                "edfd6a04ad134c4344f8fb119a3ad88e": {
                    "aid": "edfd6a04ad134c4344f8fb119a3ad88e",
                    "base_command": "get",
                    "complete": True,
                    "errors": [],
                    "query_time": 1.6280021580000001,
                    "session_id": "7f861cda-f19a-4df3-8599-e2a4f6761359",
                    "stderr": "",
                    "stdout": "C:\\Windows\\notepad.exe",
                    "task_id": "b5c8f140-280b-43fd-8501-9900f837510b"
                }
            }
        },
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 1.630543865,
            "trace_id": "8637f34a-7202-445a-818d-816715c5b368"
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_ids': 'edfd6a04ad134c4344f8fb119a3ad88e',
            'file_path': "C:\\Windows\\notepad.exe",
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'batch_id'
        },
        status_code=201
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-get-command/v1',
        json=response,
        status_code=201
    )
    results = run_get_command()
    expected_results = {
        "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
            {
                "HostID": "edfd6a04ad134c4344f8fb119a3ad88e",
                "Stdout": "C:\\Windows\\notepad.exe",
                "Stderr": "",
                "BaseCommand": "get",
                "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b",
                "GetRequestID": "84ee4d50-f499-482e-bac6-b0e296149bbf",
                "Complete": True,
                "FilePath": "C:\\Windows\\notepad.exe"
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_status_get(requests_mock, mocker):
    from CrowdStrikeFalcon import status_get_command
    response = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.00252648,
            "trace_id": "7cd74ed7-4695-403a-a1f5-f7402b7b9409"
        },
        "resources": {
            "edfd6a04ad134c4344f8fb119a3ad88e": {
                "cloud_request_id": "b5c8f140-280b-43fd-8501-9900f837510b",
                "created_at": "2020-05-01T16:09:00Z",
                "deleted_at": None,
                "id": 185596,
                "name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
                "session_id": "7f861cda-f19a-4df3-8599-e2a4f6761359",
                "sha256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
                "size": 0,
                "updated_at": "2020-05-01T16:09:00Z"
            }
        }
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'request_ids': ['84ee4d50-f499-482e-bac6-b0e296149bbf'],
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/combined/batch-get-command/v1',
        json=response,
        status_code=201
    )
    results = status_get_command(demisto.args())
    expected_results = {
        "CrowdStrike.File(val.ID === obj.ID || val.TaskID === obj.TaskID)": [
            {
                "CreatedAt": "2020-05-01T16:09:00Z",
                "DeletedAt": None,
                "ID": 185596,
                "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
                "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
                "Size": 0,
                "TaskID": "b5c8f140-280b-43fd-8501-9900f837510b",
                "UpdatedAt": "2020-05-01T16:09:00Z"
            }
        ],
        "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 "
        "\u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 "
        "\u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 "
        "val.SSDeep == obj.SSDeep)": [
            {
                "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
                "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
                "Size": 0
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_status(requests_mock, mocker):
    from CrowdStrikeFalcon import status_command
    response = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.00635876,
            "trace_id": "083a0a94-87f2-4e66-8621-32eb75b4f205"
        },
        "resources": [{
            "base_command": "ls",
            "complete": True,
            "session_id": "ea68c338-84c9-4870-a3c9-b10e405622c1",
            "stderr": "",
            "stdout": "Directory listing for C:\\ ....",
            "task_id": "ae323961-5aa8-442e-8461-8d05c4541d7d"
        }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'request_id': 'ae323961-5aa8-442e-8461-8d05c4541d7d',
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/command/v1',
        json=response,
        status_code=201
    )
    results = status_command()
    expected_results = {
        "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
            {
                "BaseCommand": "ls",
                "Complete": True,
                "NextSequenceID": 1,
                "SequenceID": 0,
                "Stderr": "",
                "Stdout": "Directory listing for C:\\ ....",
                "TaskID": "ae323961-5aa8-442e-8461-8d05c4541d7d"
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_get_extracted_file(requests_mock, mocker):
    from CrowdStrikeFalcon import get_extracted_file_command
    response_content = b'file-data'

    session_id = 'fdd6408f-6688-441b-8659-41bcad25441c'
    response_session = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.025573986,
            "trace_id": "291d3fda-9684-4ed7-ae88-bcc3940a2104"
        },
        "resources": [{
            "created_at": "2020-05-01T17:52:16.781771496Z",
            "existing_aid_sessions": 1,
            "scripts": [],
            "session_id": f"{session_id}"
        }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_id': 'edfd6a04ad134c4344f8fb119a3ad88e',
            'sha256': 'f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3',
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/sessions/v1',
        json=response_session,
        status_code=201
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/extracted-file-contents/v1',
        headers={
            'Content-Type': 'application/x-7z-compressed',
            'Content-Disposition': 'test.7z'
        },
        content=response_content,
        status_code=201
    )
    results = get_extracted_file_command(demisto.args())

    fpath = demisto.investigation()['id'] + '_' + results['FileID']
    with open(fpath, 'rb') as f:
        assert f.read() == response_content
    os.remove(fpath)


def test_list_host_files(requests_mock, mocker):
    from CrowdStrikeFalcon import list_host_files_command
    response = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.002667573,
            "trace_id": "fe95bfec-54bd-4236-9652-81aa9f6ca66d"
        },
        "resources": [{
            "cloud_request_id": "1269ad9e-c11f-4e38-8aba-1a0275304f9c",
            "created_at": "2020-05-01T17:57:42Z",
            "deleted_at": None,
            "id": 186811,
            "name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
            "session_id": "fdd6408f-6688-441b-8659-41bcad25441c",
            "sha256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
            "size": 0,
            "updated_at": "2020-05-01T17:57:42Z"
        }
        ]
    }

    session_id = 'fdd6408f-6688-441b-8659-41bcad25441c'
    response_session = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.025573986,
            "trace_id": "291d3fda-9684-4ed7-ae88-bcc3940a2104"
        },
        "resources": [{
            "created_at": "2020-05-01T17:52:16.781771496Z",
            "existing_aid_sessions": 1,
            "scripts": [],
            "session_id": f"{session_id}"
        }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_id': 'edfd6a04ad134c4344f8fb119a3ad88e',
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/sessions/v1',
        json=response_session,
        status_code=201
    )
    requests_mock.get(
        f'{SERVER_URL}/real-time-response/entities/file/v2',
        json=response,
        status_code=201
    )
    results = list_host_files_command()
    expected_results = {
        "CrowdStrike.Command(val.TaskID === obj.TaskID)": [
            {
                "HostID": "edfd6a04ad134c4344f8fb119a3ad88e",
                "SessionID": "fdd6408f-6688-441b-8659-41bcad25441c",
                "TaskID": "1269ad9e-c11f-4e38-8aba-1a0275304f9c"
            }
        ],
        "CrowdStrike.File(val.ID === obj.ID)": [
            {
                "CreatedAt": "2020-05-01T17:57:42Z",
                "DeletedAt": None,
                "ID": 186811,
                "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
                "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
                "Size": 0,
                "Stderr": None,
                "Stdout": None,
                "UpdatedAt": "2020-05-01T17:57:42Z"
            }
        ],
        "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 "
        "\u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 "
        "\u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 "
        "val.SSDeep == obj.SSDeep)": [
            {
                "Name": "\\Device\\HarddiskVolume2\\Windows\\notepad.exe",
                "SHA256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3",
                "Size": 0
            }
        ]
    }
    assert results['EntryContext'] == expected_results


def test_list_host_files_with_given_session_id(mocker):
    """
    Given:
        - session_id to use when getting host files
    When:
        - run list_host_files command
    Then:
        - validate the givven session_id was used
    """
    # prepare
    import CrowdStrikeFalcon
    mocker.patch.object(demisto, 'args', return_value={
        'host_id': 'test_host_id',
        'session_id': 'test_session_id'
    })
    mocker.patch.object(CrowdStrikeFalcon, 'list_host_files', return_value={})

    # call
    CrowdStrikeFalcon.list_host_files_command()

    # assert
    CrowdStrikeFalcon.list_host_files.assert_called_with('test_host_id', 'test_session_id')


def test_refresh_session(requests_mock, mocker):
    from CrowdStrikeFalcon import refresh_session_command

    session_id = 'fdd6408f-6688-441b-8659-41bcad25441c'
    response = {
        "errors": [],
        "meta": {
            "powered_by": "empower-api",
            "query_time": 0.025573986,
            "trace_id": "291d3fda-9684-4ed7-ae88-bcc3940a2104"
        },
        "resources": [{
            "created_at": "2020-05-01T17:52:16.781771496Z",
            "existing_aid_sessions": 1,
            "scripts": [{
                "args": [{
                    "arg_name": "Path",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2019-06-25T23:48:59Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "File to concatenate",
                    "encoding": "",
                    "id": 7,
                    "options": None,
                    "required": True,
                    "requires_value": False,
                    "script_id": 6,
                    "sequence": 1,
                    "updated_at": "2019-06-25T23:48:59Z"
                }, {
                    "arg_name": "Count",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2019-06-25T23:48:59Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "Number of bytes to read (max=32768)",
                    "encoding": "",
                    "id": 51,
                    "options": None,
                    "required": False,
                    "requires_value": False,
                    "script_id": 6,
                    "sequence": 2,
                    "updated_at": "2019-06-25T23:48:59Z"
                }, {
                    "arg_name": "Offset",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2019-06-25T23:48:59Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "Offset (in byte value) to start reading from",
                    "encoding": "",
                    "id": 52,
                    "options": None,
                    "required": False,
                    "requires_value": False,
                    "script_id": 6,
                    "sequence": 3,
                    "updated_at": "2019-06-25T23:48:59Z"
                }, {
                    "arg_name": "ShowHex",
                    "arg_type": "flag",
                    "command_level": "non-destructive",
                    "created_at": "2019-06-25T23:48:59Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "Show the results in hexadecimal format instead of ASCII",
                    "encoding": "",
                    "id": 53,
                    "options": None,
                    "required": False,
                    "requires_value": False,
                    "script_id": 6,
                    "sequence": 4,
                    "updated_at": "2019-06-25T23:48:59Z"
                }
                ],
                "command": "cat",
                "description": "Read a file from disk and display as ASCII or hex",
                "examples": "    C:\\\u003e cat c:\\mytextfile.txt",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [{
                    "arg_name": "Path",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2018-11-08T18:27:18Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "Relative or absolute directory",
                    "encoding": "",
                    "id": 8,
                    "options": None,
                    "required": True,
                    "requires_value": False,
                    "script_id": 8,
                    "sequence": 1,
                    "updated_at": "2018-11-08T18:27:18Z"
                }
                ],
                "command": "cd",
                "description": "Change the current working directory",
                "examples": "    C:\\\u003e cd C:\\Users\\Administrator\r\n",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "env",
                "description": "Get environment variables for all scopes (Machine / User / Process)",
                "examples": "",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "eventlog",
                "description": "Inspect event logs.",
                "examples": "",
                "internal_only": False,
                "runnable": False,
                "sub_commands": [{
                    "args": [{
                        "arg_name": "Name",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2018-05-01T19:38:30Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Name of the event log, for example \"Application\", \"System\"",
                        "encoding": "",
                        "id": 35,
                        "options": None,
                        "required": True,
                        "requires_value": False,
                        "script_id": 25,
                        "sequence": 1,
                        "updated_at": "2018-05-01T19:38:30Z"
                    }, {
                        "arg_name": "Count",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2018-05-01T19:38:30Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Optional number of entries to return. Default:100 Max=500",
                        "encoding": "",
                        "id": 36,
                        "options": None,
                        "required": False,
                        "requires_value": False,
                        "script_id": 25,
                        "sequence": 2,
                        "updated_at": "2018-05-01T19:38:30Z"
                    }, {
                        "arg_name": "SourceName",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2018-05-01T19:38:30Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Optional name of the event source, e.x. \"WinLogon\"",
                        "encoding": "",
                        "id": 37,
                        "options": None,
                        "required": False,
                        "requires_value": False,
                        "script_id": 25,
                        "sequence": 3,
                        "updated_at": "2018-05-01T19:38:30Z"
                    }
                    ],
                    "command": "view",
                    "description": "View most recent N events in a given event log",
                    "examples": "    C:\\\u003e eventlog view Application",
                    "internal_only": False,
                    "runnable": True,
                    "sub_commands": []
                }, {
                    "args": [{
                        "arg_name": "Name",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2020-03-17T18:11:22Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Name of the event log, for example \"Application\", \"System\"",
                        "encoding": "",
                        "id": 38,
                        "options": None,
                        "required": True,
                        "requires_value": False,
                        "script_id": 26,
                        "sequence": 1,
                        "updated_at": "2020-03-17T18:11:22Z"
                    }, {
                        "arg_name": "Filename",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2020-03-17T18:11:22Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Target file on disk",
                        "encoding": "",
                        "id": 39,
                        "options": None,
                        "required": True,
                        "requires_value": False,
                        "script_id": 26,
                        "sequence": 2,
                        "updated_at": "2020-03-17T18:11:22Z"
                    }
                    ],
                    "command": "export",
                    "description": "Export the specified event log to a file (.csv) on disk",
                    "examples": "    C:\\\u003eeventlog export System",
                    "internal_only": False,
                    "runnable": True,
                    "sub_commands": []
                }, {
                    "args": [],
                    "command": "list",
                    "description": "Event log list: show available event log sources",
                    "examples": "    C:\\\u003e eventlog list",
                    "internal_only": False,
                    "runnable": True,
                    "sub_commands": []
                }, {
                    "args": [{
                        "arg_name": "Name",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2019-05-09T23:55:03Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Name of the event log, for example \"Application\", \"System\"",
                        "encoding": "",
                        "id": 519,
                        "options": None,
                        "required": True,
                        "requires_value": False,
                        "script_id": 470,
                        "sequence": 1,
                        "updated_at": "2019-05-09T23:55:03Z"
                    }, {
                        "arg_name": "Filename",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2019-05-09T23:55:03Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Target file on disk",
                        "encoding": "",
                        "id": 520,
                        "options": None,
                        "required": True,
                        "requires_value": False,
                        "script_id": 470,
                        "sequence": 2,
                        "updated_at": "2019-05-09T23:55:03Z"
                    }
                    ],
                    "command": "backup",
                    "description": "Back up the specified event log to a file (.evtx) on disk",
                    "examples": "    C:\\\u003eeventlog backup System",
                    "internal_only": False,
                    "runnable": True,
                    "sub_commands": []
                }
                ]
            }, {
                "args": [{
                    "arg_name": "Path",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2020-03-17T18:10:50Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "File to hash",
                    "encoding": "",
                    "id": 72,
                    "options": None,
                    "required": True,
                    "requires_value": False,
                    "script_id": 45,
                    "sequence": 1,
                    "updated_at": "2020-03-17T18:10:50Z"
                }
                ],
                "command": "filehash",
                "description": "Generate the MD5, SHA1, and SHA256 hashes of a file",
                "examples": "C:\\\u003e filehash C:\\Windows\\System32\\cmd.exe",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [{
                    "arg_name": "UserName",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2018-05-10T16:22:42Z",
                    "data_type": "string",
                    "default_value": "",
                    "description": "Partial or full username to filter results",
                    "encoding": "",
                    "id": 42,
                    "options": None,
                    "required": False,
                    "requires_value": False,
                    "script_id": 29,
                    "sequence": 1,
                    "updated_at": "2018-05-10T16:22:42Z"
                }
                ],
                "command": "getsid",
                "description": "Enumerate local users and Security Identifiers (SID)",
                "examples": "\u003egetsid\r\nUserName       SID\r\n",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "ipconfig",
                "description": "Show network configuration information",
                "examples": "",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [{
                    "arg_name": "Path",
                    "arg_type": "arg",
                    "command_level": "non-destructive",
                    "created_at": "2019-02-12T16:44:59Z",
                    "data_type": "string",
                    "default_value": ".",
                    "description": "Directory to list",
                    "encoding": "",
                    "id": 12,
                    "options": None,
                    "required": False,
                    "requires_value": False,
                    "script_id": 14,
                    "sequence": 1,
                    "updated_at": "2019-02-12T16:44:59Z"
                }
                ],
                "command": "ls",
                "description": "Display the contents of the specified path",
                "examples": "    C:\\Windows\u003e ls\r\n",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "mount",
                "description": "List mounted filesystem volumes",
                "examples": "    C:\\\u003e mount\r\n        Display local mounted volumes",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "netstat",
                "description": "Display network statistics and active connections",
                "examples": "",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "ps",
                "description": "Display process information",
                "examples": " C:\\\u003e ps\r\n\r\nName",
                "internal_only": False,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "pwd",
                "description": "Get current working directory",
                "examples": "",
                "internal_only": True,
                "runnable": True,
                "sub_commands": []
            }, {
                "args": [],
                "command": "reg",
                "description": "Windows registry manipulation.",
                "examples": "",
                "internal_only": False,
                "runnable": False,
                "sub_commands": [{
                    "args": [{
                        "arg_name": "Subkey",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2019-12-05T17:37:38Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Registry subkey full path",
                        "encoding": "",
                        "id": 43,
                        "options": None,
                        "required": False,
                        "requires_value": False,
                        "script_id": 30,
                        "sequence": 1,
                        "updated_at": "2019-12-05T17:37:39Z"
                    }, {
                        "arg_name": "Value",
                        "arg_type": "arg",
                        "command_level": "non-destructive",
                        "created_at": "2019-12-05T17:37:38Z",
                        "data_type": "string",
                        "default_value": "",
                        "description": "Name of value to query",
                        "encoding": "",
                        "id": 44,
                        "options": None,
                        "required": False,
                        "requires_value": False,
                        "script_id": 30,
                        "sequence": 2,
                        "updated_at": "2019-12-05T17:37:39Z"
                    }
                    ],
                    "command": "query",
                    "description": "Query a registry subkey or value",
                    "examples": "    C:\\\u003e reg query\r\n",
                    "internal_only": False,
                    "runnable": True,
                    "sub_commands": []
                }
                ]
            }
            ],
            "session_id": f"{session_id}"
        }
        ]
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'host_id': 'edfd6a04ad134c4344f8fb119a3ad88e',
            'raw': "Write-Output 'Hello, World!"
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/entities/refresh-session/v1',
        json=response,
        status_code=201
    )
    results = refresh_session_command()

    assert results['HumanReadable'] == f"CrowdStrike Session Refreshed: {session_id}"


class TestFetch:
    """ Test the logic of the fetch

    """

    @pytest.fixture()
    def set_up_mocks(self, requests_mock, mocker):
        """ Sets up the mocks for the fetch.
        """
        mocker.patch.object(demisto, 'setLastRun')
        requests_mock.get(f'{SERVER_URL}/detects/queries/detects/v1', json={'resources': ['ldt:1', 'ldt:2']})
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:1',
                                                'created_timestamp': '2020-09-04T09:16:11Z',
                                                'max_severity_displayname': 'Low',
                                                'first_behavior': '2020-09-04T09:16:11Z'
                                                },
                                               {'detection_id': 'ldt:2',
                                                'created_timestamp': '2020-09-04T09:20:11Z',
                                                'max_severity_displayname': 'Low',
                                                'first_behavior': '2020-09-04T09:16:11Z'}]})
        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={})
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1', json={})

    @freeze_time("2020-08-26 17:22:13 UTC")
    def test_old_fetch_to_new_fetch(self, set_up_mocks, mocker):
        """
        Tests the change of logic done in fetch. Validates that it's done smoothly
        Given:
            Old getLastRun which holds `first_behavior_time` and `last_detection_id`
        When:
            2 results are returned (which equals the FETCH_LIMIT)
        Then:
            The `first_behavior_time` doesn't change and an `offset` of 2 is added.

        """
        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'params', return_value={})
        mocker.patch.object(demisto, 'getLastRun',
                            return_value={'first_behavior_detection_time': '2020-09-04T09:16:10Z',
                                          'detection_offset': 2,
                                          'first_behavior_incident_time': '2020-09-04T09:22:10Z',
                                          'last_fetched_incident': '3',
                                          'incident_offset': 4,
                                          })
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0] == [{'time': '2020-09-04T09:16:10Z'}, {'time': '2020-09-04T09:22:10Z'}, {}]

    @freeze_time("2020-08-26 17:22:13 UTC")
    def delete_offset_test(self, set_up_mocks, mocker):
        """
        Tests the change of logic done in fetch. Validates that it's done smoothly
        Given:
            Old getLastRun which holds two lists with offset key
        When:
            The offset is inside the lastRun
        Then:
            The offset is deleted from the lastRun

        """

        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'params', return_value={})
        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{'time': '2020-09-04T09:16:10Z', 'offset': 2},
                                          {'time': '2020-09-04T09:22:10Z', 'offset': 4}])
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0] == [{'time': '2020-09-04T09:16:10Z'},
                                                          {'time': '2020-09-04T09:22:10Z'}]

    @freeze_time("2020-09-04T09:16:10Z")
    def test_new_fetch(self, set_up_mocks, mocker, requests_mock):
        """
        Tests the correct flow of fetch
        Given:
            `getLastRun` which holds  `first_behavior_time` and `offset`
        When:
            1 result is returned (which is less than the FETCH_LIMIT)
        Then:
            The `first_behavior_time` changes and no `offset` is added.
        """
        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{'time': '2020-09-04T09:16:10Z',
                                          'offset': 2}, {}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:1',
                                                'created_timestamp': '2020-09-04T09:16:11Z',
                                                'max_severity_displayname': 'Low', 'first_behavior': '2020-09-04T09:16:11Z'},
                                               {'detection_id': 'ldt:2',
                                                'created_timestamp': '2020-09-04T09:16:11Z',
                                                'max_severity_displayname': 'Low', 'first_behavior': '2020-09-04T09:16:11Z'}
                                               ]})
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0][0] == {
            'time': '2020-09-04T09:16:11Z', 'limit': 2, "found_incident_ids": {'Detection ID: ldt:1': 1599210970,
                                                                               'Detection ID: ldt:2': 1599210970}}

    def test_fetch_incident_type(self, set_up_mocks, mocker):
        """
        Tests the addition of incident_type field to the context
        Given:
            Old getLastRun which holds `first_behavior_time` and `last_detection_id`
        When:
            2 results are returned (which equals the FETCH_LIMIT)
        Then:
            "incident_type": "detection" is in raw result returned by the indicator

        """
        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'getLastRun', return_value=[{
            'time': '2020-09-04T09:16:10Z',
        }, {}, {}])
        incidents = fetch_incidents()
        for incident in incidents:
            assert "\"incident_type\": \"detection\"" in incident.get('rawJSON', '')

    @pytest.mark.parametrize(
        "expected_name, fetch_incidents_or_detections,incidents_len",
        [
            ('Incident ID:', ['Incidents'], 2),
            ('Detection ID:', ['Detections'], 2),
            ('Detection ID:', ['Detections', 'Incidents'], 4),
            ('Incident ID:', ['Endpoint Incident'], 2),
            ('Detection ID:', ['Endpoint Detection'], 2),
            ('Detection ID:', ['Endpoint Detection', 'Endpoint Incident'], 4),
            ('IDP Detection ID: ', ['IDP Detection'], 2)
        ],
    )
    def test_fetch_returns_all_types(self, requests_mock, set_up_mocks, mocker, expected_name,
                                     fetch_incidents_or_detections, incidents_len):
        """
        Tests that fetch incidents returns incidents, detections, endpoint incidents, endpoint detection,
        and idp detections types. depends on the value of fetch_incidents_or_detections.
        Given:
            fetch_incidents_or_detections parameter.
        When:
            Fetching incidents.
        Then:
            Validate the results contains only detection when fetch_incidents_or_detections = ['Detections'],
            Validate the results contains only incidents when fetch_incidents_or_detections = ['Incidents']
            Validate the results contains detection and incidents when
             fetch_incidents_or_detections = ['Detections', 'Incidents']
            Validate the results contains only detection when fetch_incidents_or_detections = ['Endpoint Detections'],
            Validate the results contains only incidents when fetch_incidents_or_detections = ['Endpoint Incidents']
            Validate the results contains detection and incidents when
             fetch_incidents_or_detections = ['Endpoint Detections', 'Endpoint Incidents']
            Validate the results contains only IDP detection when fetch_incidents_or_detections = ['IDP Detections'],

        """
        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'getLastRun', return_value=[{'time': '2020-09-04T09:16:10Z'}, {}, {}])

        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:1', 'ldt:2']})
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1', 'start': '2020-09-04T09:16:11Z'},
                                               {'incident_id': 'ldt:2', 'start': '2020-09-04T09:16:11Z'}]})
        requests_mock.get(f'{SERVER_URL}/alerts/queries/alerts/v1', json={'resources': ['a:ind:1', 'a:ind:2']})
        requests_mock.post(f'{SERVER_URL}/alerts/entities/alerts/v1',
                           json={'resources': [{'composite_id': 'a:ind:1', 'start_time': '2020-09-04T09:16:11.000Z'},
                                               {'composite_id': 'a:ind:2', 'start_time': '2020-09-04T09:16:11.000Z'}]})

        mocker.patch.object(
            demisto,
            'params',
            return_value={
                'url': SERVER_URL,
                'proxy': True,
                'incidents_per_fetch': 2,
                'fetch_incidents_or_detections': fetch_incidents_or_detections,
                'fetch_time': '3 days',
            }
        )

        incidents = fetch_incidents()
        assert len(incidents) == incidents_len

        if incidents_len == 4:
            assert 'Incident ID:' in incidents[0]['name']
            assert 'Incident ID:' in incidents[1]['name']
            assert 'Detection ID:' in incidents[2]['name']
            assert 'Detection ID:' in incidents[3]['name']
        else:
            assert expected_name in incidents[0]['name']
            assert expected_name in incidents[1]['name']


class TestIncidentFetch:
    """ Test the logic of the fetch

    """

    @pytest.fixture()
    def set_up_mocks(self, requests_mock, mocker):
        """ Sets up the mocks for the fetch.
        """
        mocker.patch.object(demisto, 'setLastRun')
        requests_mock.get(f'{SERVER_URL}/detects/queries/detects/v1', json={})
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={})
        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:1', 'ldt:2']})
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1', 'start': '2020-09-04T09:16:11Z'},
                                               {'incident_id': 'ldt:2', 'start': '2020-09-04T09:16:11Z'}]})

    def delete_offset_test(self, set_up_mocks, mocker):
        """
        Tests the change of logic done in fetch. Validates that it's done smoothly
        Given:
            Old getLastRun which holds two lists with offset key
        When:
            The offset is inside the lastRun
        Then:
            The offset is deleted from the lastRun
        """

        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'params', return_value={})
        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{'time': '2020-09-04T09:16:10Z', 'offset': 2},
                                          {'time': '2020-09-04T09:22:10Z', 'offset': 4}])
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0] == [{'time': '2020-09-04T09:16:10Z'},
                                                          {'time': '2020-09-04T09:22:10Z'}]

    @freeze_time("2020-08-26 17:22:13 UTC")
    def test_new_fetch(self, set_up_mocks, mocker, requests_mock):
        mocker.patch.object(demisto, 'getLastRun', return_value=[{}, {'time': '2020-09-04T09:16:10Z',
                                                                      'offset': 2}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1', 'start': '2020-09-04T09:16:11Z'},
                                               {'incident_id': 'ldt:2', 'start': '2020-09-04T09:16:11Z'}]})
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0][1] == {'time': '2020-09-04T09:16:11Z',
                                                             'limit': 2,
                                                             'found_incident_ids': {'Incident ID: ldt:1': 1598462533,
                                                                                    'Incident ID: ldt:2': 1598462533}}

    def test_incident_type_in_fetch(self, set_up_mocks, mocker):
        """Tests the addition of incident_type field to the context
        Given:
            Old getLastRun which holds `first_behavior_time` and `last_incident_id`
        When:
            2 results are returned (which equals the FETCH_LIMIT)
        Then:
            "incident_type": "incident" is in raw result returned by the indicator
        """
        mocker.patch.object(demisto, 'getLastRun', return_value=[{}, {'time': '2020-09-04T09:16:10Z',
                                                                      }])
        from CrowdStrikeFalcon import fetch_incidents
        incidents = fetch_incidents()
        for incident in incidents:
            assert "\"incident_type\": \"incident\"" in incident.get('rawJSON', '')


def get_fetch_data():
    with open('./test_data/test_data.json') as f:
        return json.loads(f.read())


def get_fetch_data2():
    with open('./test_data/test_data2.json') as f:
        return json.loads(f.read())


test_data = get_fetch_data()
test_data2 = get_fetch_data2()


def test_get_indicator_device_id(mocker, requests_mock):
    from CrowdStrikeFalcon import get_indicator_device_id
    requests_mock.get("https://4.4.4.4/indicators/queries/devices/v1",
                      json=test_data['response_for_get_indicator_device_id'])
    mocker.patch.object(demisto, 'args', return_value={'type': 'sha256', 'value': 'example_sha'})
    res = get_indicator_device_id()

    # Expecting both DeviceIOC and DeviceID outputs for BC.
    assert set(res.outputs.keys()) - {'DeviceIOC', 'DeviceID'} == set()
    assert res.outputs['DeviceIOC']['Type'] == 'sha256'
    assert res.outputs['DeviceIOC']['Value'] == 'example_sha'
    assert res.outputs['DeviceIOC']['DeviceID'] == res.outputs['DeviceID']


def test_validate_response():
    from CrowdStrikeFalcon import validate_response
    true_res = validate_response({"resources": "1234"})
    false_res = validate_response({"error": "404"})
    assert true_res
    assert not false_res


def test_build_error_message():
    from CrowdStrikeFalcon import build_error_message

    res_error_data = build_error_message({'meta': 1234})
    assert res_error_data == 'Error: error code: None, error_message: something got wrong, please try again.'

    res_error_data_with_specific_error = build_error_message({'errors': [{"code": 1234, "message": "hi"}]})
    assert res_error_data_with_specific_error == 'Error: error code: 1234, error_message: hi.'


def test_search_iocs_command_does_not_exist(requests_mock):
    """
    Test cs-falcon-search-iocs when no ioc is found

    Given:
     - There is no ioc in the system
    When:
     - Searching for iocs using cs-falcon-search-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do not populate the entry context
    """
    from CrowdStrikeFalcon import search_iocs_command
    response = {'resources': []}
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/iocs/v1',
        json=response,
        status_code=200
    )
    results = search_iocs_command()
    assert results["HumanReadable"] == 'Could not find any Indicators of Compromise.'
    assert results["EntryContext"] is None


def test_search_iocs_command_exists(requests_mock):
    """
    Test cs-falcon-search-iocs when an ioc is found

    Given:
     - There is a single md5 ioc in the system
    When:
     - Searching for iocs using cs-falcon-search-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import search_iocs_command
    id_response = {'resources': ['md5:testmd5'], 'errors': []}
    ioc_response = {
        'resources': [{
            'type': 'md5',
            'value': 'testmd5',
            'policy': 'detect',
            'share_level': 'red',
            'description': 'Eicar file',
            'created_timestamp': '2020-10-01T09:09:04Z',
            'modified_timestamp': '2020-10-01T09:09:04Z'
        }]
    }
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/iocs/v1',
        json=id_response,
        status_code=200
    )
    requests_mock.get(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=ioc_response,
        status_code=200
    )
    results = search_iocs_command()
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_search_iocs_command__no_iocs(requests_mock, mocker):
    """
    Test cs-falcon-search-iocs when encountering an error

    Given:
     - No iocs exist
    When:
     - Searching for non existing iocs using cs-falcon-search-iocs command
    Then:
     - Display an appropriate info in the HR
    """
    from CrowdStrikeFalcon import search_iocs_command
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/iocs/v1',
        json={}
    )
    mocker.patch.object(demisto, 'results')
    res = search_iocs_command()
    assert 'Could not find any Indicators of Compromise.' in res['HumanReadable']


def test_get_ioc_command_does_not_exist(requests_mock):
    """
    Test cs-falcon-get-ioc when no ioc is found

    Given:
     - There is no ioc in the system
    When:
     - Searching for iocs using cs-falcon-get-ioc command
     - The server returns an error
    Then:
     - Raise the error back from the server
    """
    from CrowdStrikeFalcon import get_ioc_command
    response = {'resources': [], 'errors': [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}]}
    requests_mock.get(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=response,
        status_code=200
    )
    with pytest.raises(DemistoException) as excinfo:
        get_ioc_command(ioc_type='md5', value='testmd5')
    assert [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}] == excinfo.value.args[0]


def test_get_ioc_command_exists(requests_mock):
    """
    Test cs-falcon-get-ioc when an ioc is found

    Given:
     - There is a single md5 ioc in the system
    When:
     - Looking for iocs using cs-falcon-get-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import get_ioc_command
    ioc_response = {
        'resources': [{
            'type': 'md5',
            'value': 'testmd5',
            'policy': 'detect',
            'share_level': 'red',
            'description': 'Eicar file',
            'created_timestamp': '2020-10-01T09:09:04Z',
            'modified_timestamp': '2020-10-01T09:09:04Z'
        }]
    }
    requests_mock.get(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=ioc_response,
        status_code=200
    )
    results = get_ioc_command(ioc_type='md5', value='testmd5')
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_upload_ioc_command_fail(requests_mock, mocker):
    """
    Test cs-falcon-upload-ioc where it fails to create the ioc

    Given:
     - The user tries to create an IOC
    When:
     - The server fails to create an IOC
    Then:
     - Display error message to user
    """
    from CrowdStrikeFalcon import upload_ioc_command
    upload_response = {'resources': []}
    get_response = {'resources': [], 'errors': [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}]}
    requests_mock.post(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=upload_response,
        status_code=200
    )
    requests_mock.get(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=get_response,
        status_code=200
    )
    with pytest.raises(DemistoException) as excinfo:
        upload_ioc_command(ioc_type='md5', value='testmd5')
    assert excinfo.value.args[0] == "Failed to create IOC. Please try again."


def test_upload_ioc_command_successful(requests_mock):
    """
    Test cs-falcon-upload-ioc when an upload is successful

    Given:
     - The user tries to create an IOC
    When:
     - The server creates an IOC
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import upload_ioc_command
    upload_response = {'resources': []}
    ioc_response = {
        'resources': [{
            'type': 'md5',
            'value': 'testmd5',
            'policy': 'detect',
            'share_level': 'red',
            'description': 'Eicar file',
            'created_timestamp': '2020-10-01T09:09:04Z',
            'modified_timestamp': '2020-10-01T09:09:04Z'
        }]
    }
    requests_mock.post(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=upload_response,
        status_code=200
    )
    requests_mock.get(
        f'{SERVER_URL}/indicators/entities/iocs/v1',
        json=ioc_response,
        status_code=200
    )
    results = upload_ioc_command(ioc_type='md5', value='testmd5')
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_search_custom_iocs_command_does_not_exist(requests_mock):
    """
    Test cs-falcon-search-custom-iocs when no ioc is found

    Given:
     - There is no ioc in the system
    When:
     - Searching for iocs using cs-falcon-search-custom-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do not populate the entry context
    """
    from CrowdStrikeFalcon import search_custom_iocs_command
    response = {'resources': []}
    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1',
        json=response,
        status_code=200
    )
    results = search_custom_iocs_command()
    assert results["HumanReadable"] == 'Could not find any Indicators of Compromise.'
    assert results["EntryContext"] is None


def test_search_custom_iocs_command_exists(requests_mock):
    """
    Test cs-falcon-search-custom-iocs when an ioc is found

    Given:
     - There is a single md5 ioc in the system
    When:
     - Searching for iocs using cs-falcon-search-custom-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import search_custom_iocs_command
    ioc_response = {
        'resources': [{
            'id': '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r',
            'type': 'md5',
            'value': 'testmd5',
            'action': 'prevent',
            'severity': 'high',
            'description': 'Eicar file',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }
    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1',
        json=ioc_response,
        status_code=200
    )
    results = search_custom_iocs_command()
    assert '| 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | prevent | high | md5 |' \
           in results[0]["HumanReadable"]
    assert results[0]["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_search_custom_iocs_command__no_iocs(requests_mock, mocker):
    """
    Test cs-falcon-search-custom-iocs when no iocs exist

    Given:
     - No iocs exist
    When:
     - Searching for non existing iocs using cs-falcon-search-custom-iocs command
    Then:
     - Display an appropriate info in HR
    """
    from CrowdStrikeFalcon import search_custom_iocs_command
    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1',
        json={}
    )
    mocker.patch.object(demisto, 'results')
    mocker.patch(RETURN_ERROR_TARGET)
    res = search_custom_iocs_command()
    assert 'Could not find any Indicators of Compromise.' in res['HumanReadable']


def test_search_custom_iocs_command_filter(requests_mock):
    """
    Test cs-falcon-search-custom-iocs when running with filter

    Given:
     - Domain IOC with test.com value
    When:
     - Searching for the domain IOC using cs-falcon-search-custom-iocs command
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import search_custom_iocs_command
    ioc_type = 'domain'
    ioc_value = 'test.com'
    ioc_response = {
        'resources': [{
            'id': '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r',
            'type': ioc_type,
            'value': ioc_value,
            'action': 'prevent',
            'severity': 'high',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }
    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1?filter=type%3A%5B%27{ioc_type}%27%5D%2Bvalue%3A%5B%27{ioc_value}%27'
        f'%5D&limit=50',
        # noqa: E501
        json=ioc_response,
        status_code=200
    )
    results = search_custom_iocs_command(
        types=ioc_type,
        values=ioc_value,
    )
    assert f'| 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r | prevent | high | {ioc_type} |' \
           f' {ioc_value} |' in results[0]["HumanReadable"]  # noqa: E501
    assert results[0]["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == ioc_value


def test_get_custom_ioc_command_exists(requests_mock):
    """
    Test cs-falcon-get-custom-ioc when an ioc is found

    Given:
     - There is a single md5 ioc in the system
    When:
     - Looking for iocs using cs-falcon-get-custom-ioc command
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import get_custom_ioc_command
    ioc_type = 'md5'
    ioc_value = 'testmd5'
    ioc_response = {
        'resources': [{
            'id': '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r',
            'type': ioc_type,
            'value': ioc_value,
            'action': 'prevent',
            'severity': 'high',
            'description': 'Eicar file',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }

    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1?filter=type%3A%5B%27{ioc_type}%27%5D%2Bvalue%3A%5B%27{ioc_value}%27'
        f'%5D&limit=50',
        # noqa: E501
        json=ioc_response,
        status_code=200,
    )
    results = get_custom_ioc_command(ioc_type=ioc_type, value=ioc_value)
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == ioc_value


def test_get_custom_ioc_command_does_not_exist(requests_mock):
    """
    Test cs-falcon-get-custom-ioc when no ioc is found

    Given:
     - There is no ioc in the system
    When:
     - Searching for iocs using cs-falcon-get-custom-ioc command
     - The server returns an error
    Then:
     - Raise the error back from the server
    """
    from CrowdStrikeFalcon import get_custom_ioc_command
    response = {'resources': [], 'errors': [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}]}
    requests_mock.get(
        f'{SERVER_URL}/iocs/combined/indicator/v1',
        json=response,
        status_code=200
    )
    with pytest.raises(DemistoException) as excinfo:
        get_custom_ioc_command(ioc_type='md5', value='testmd5')
    assert [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}] == excinfo.value.args[0]


def test_get_custom_ioc_command_by_id(requests_mock):
    """
    Given:
     - ID of IOC to retrieve
    When:
     - Looking for IOC using cs-falcon-get-custom-ioc command
    Then:
     - Do populate the entry context with the right ID
    """
    from CrowdStrikeFalcon import get_custom_ioc_command
    ioc_id = '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r'
    ioc_response = {
        'resources': [{
            'id': ioc_id,
            'type': 'domain',
            'value': 'test.com',
            'action': 'prevent',
            'severity': 'high',
            'description': 'Eicar file',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }

    requests_mock.get(
        f'{SERVER_URL}/iocs/entities/indicators/v1?ids={ioc_id}',  # noqa: E501
        json=ioc_response,
        status_code=200,
    )
    results = get_custom_ioc_command(ioc_id=ioc_id)
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["ID"] == ioc_id


def test_upload_custom_ioc_command_successful(requests_mock):
    """
    Test cs-falcon-upload-custom-ioc when an upload is successful

    Given:
     - The user tries to create an IOC
    When:
     - The server creates an IOC
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import upload_custom_ioc_command
    ioc_response = {
        'resources': [{
            'id': '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r',
            'type': 'md5',
            'value': 'testmd5',
            'action': 'prevent',
            'severity': 'high',
            'description': 'Eicar file',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }
    requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        json=ioc_response,
        status_code=200,
    )
    results = upload_custom_ioc_command(
        ioc_type='md5',
        value='testmd5',
        action='prevent',
        severity='high',
        platforms='mac,linux',
    )
    assert '| 2020-10-01T09:09:04Z | Eicar file | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r |' \
           in results[0]["HumanReadable"]
    assert results[0]["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_upload_custom_ioc_command_fail(requests_mock):
    """
    Test cs-falcon-upload-custom-ioc where it fails to create the ioc

    Given:
     - The user tries to create an IOC
    When:
     - The server fails to create an IOC
    Then:
     - Display error message to user
    """
    from CrowdStrikeFalcon import upload_custom_ioc_command
    response = {
        'resources': [{
            'row': 1,
            'value': None,
            'type': None,
            'message_type': 'error',
            'field_name': 'value',
            'message': 'required string is missing'
        }],
        'errors': [{'code': 400, 'message': 'one or more inputs are invalid'}]
    }
    requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        json=response,
        status_code=200
    )
    with pytest.raises(DemistoException) as excinfo:
        upload_custom_ioc_command(
            ioc_type='md5',
            value='testmd5',
            action='prevent',
            severity='high',
            platforms='mac,linux',
        )
    assert response['errors'] == excinfo.value.args[0]


def test_upload_custom_ioc_command_duplicate(requests_mock, mocker):
    """
    Test cs-falcon-upload-custom-ioc where it fails to create the ioc due to duplicate

    Given:
     - IOC of type domain to upload
    When:
     - The API fails to create an IOC to duplication warning
    Then:
     - Display error message to user
    """
    from CrowdStrikeFalcon import upload_custom_ioc_command
    ioc_type = 'domain'
    ioc_value = 'test.com'
    response = {
        'errors': [{
            'code': 400,
            'message': 'One or more indicators have a warning or invalid input'
        }],
        'resources': [{
            'row': 1,
            'value':
                'test2.com',
            'type': 'domain',
            'message_type': 'warning',
            'message': f"Warning: Duplicate type: '{ioc_type}' and value: '{ioc_value}' combination."
        }]
    }
    requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        json=response,
        status_code=400,
        reason='Bad Request',
    )
    with pytest.raises(DemistoException) as error_info:
        upload_custom_ioc_command(
            ioc_type=ioc_type,
            value=ioc_value,
            action='prevent',
            severity='high',
            platforms='mac,linux',
        )
    assert response['resources'][0]['message'] in str(error_info.value)


def test_update_custom_ioc_command(requests_mock):
    """
    Test cs-falcon-update-custom-ioc when an upload is successful

    Given:
     - The user tries to update an IOC
    When:
     - The server updates an IOC
    Then:
     - Ensure the request is sent as expected
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import update_custom_ioc_command
    ioc_id = '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r'
    ioc_response = {
        'resources': [{
            'id': ioc_id,
            'type': 'md5',
            'value': 'testmd5',
            'action': 'prevent',
            'severity': 'high',
            'description': 'Eicar file',
            'created_on': '2020-10-01T09:09:04Z',
            'modified_on': '2020-10-01T09:09:04Z',
        }]
    }
    updated_severity = 'medium'

    def match_req_body(request):
        if request.json() == {
            'indicators': [{'id': ioc_id, 'severity': updated_severity}]
        }:
            return True
        return None

    requests_mock.patch(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        json=ioc_response,
        status_code=200,
        additional_matcher=match_req_body,
    )

    results = update_custom_ioc_command(
        ioc_id=ioc_id,
        severity=updated_severity,
    )
    assert 'Custom IOC was updated successfully' in results["HumanReadable"]
    assert results["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == 'testmd5'


def test_delete_custom_ioc_command(requests_mock):
    """
    Test cs-falcon-delete-custom-ioc where it deletes IOC successfully

    Given:
     - The user tries to delete an IOC
    When:
     - Running the command to delete an IOC
    Then:
     - Ensure expected output is returned
    """
    from CrowdStrikeFalcon import delete_custom_ioc_command
    ioc_id = '4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r'
    response = {
        'resources': [ioc_id],
        'errors': []
    }
    requests_mock.delete(
        f'{SERVER_URL}/iocs/entities/indicators/v1?ids={ioc_id}',
        json=response,
        status_code=200
    )
    command_res = delete_custom_ioc_command(ioc_id)
    assert f'Custom IOC {ioc_id} was successfully deleted.' in command_res['HumanReadable']


def test_get_ioc_device_count_command_does_not_exist(requests_mock, mocker):
    """
    Test cs-falcon-device-count-ioc with an unsuccessful query (doesn't exist)

    Given
     - There is no device with a process that ran md5:testmd5
    When
     - The user is running cs-falcon-device-count-ioc with md5:testmd5
    Then
     - Raise an error
    """
    from CrowdStrikeFalcon import get_ioc_device_count_command
    expected_error = [{'code': 404, 'message': 'md5:testmd5 - Resource Not Found'}]
    response = {'resources': [], 'errors': expected_error}
    requests_mock.get(
        f'{SERVER_URL}/indicators/aggregates/devices-count/v1',
        json=response,
        status_code=404,
        reason='Not found'
    )
    mocker.patch(RETURN_ERROR_TARGET)
    res = get_ioc_device_count_command(ioc_type='md5', value='testmd5')
    assert res == 'No results found for md5 - testmd5'


def test_get_ioc_device_count_command_exists(requests_mock):
    """
    Test cs-falcon-device-count-ioc with a successful query

    Given
     - There is a device with a process that ran md5:testmd5
    When
     - The user is running cs-falcon-device-count-ioc with md5:testmd5
    Then
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
    """
    from CrowdStrikeFalcon import get_ioc_device_count_command
    response = {'resources': [{'id': 'md5:testmd5', 'type': 'md5', 'value': 'testmd5', 'device_count': 1}]}
    requests_mock.get(
        f'{SERVER_URL}/indicators/aggregates/devices-count/v1',
        json=response,
        status_code=200,
    )
    result = get_ioc_device_count_command(ioc_type='md5', value='testmd5')
    assert result['HumanReadable'] == 'Indicator of Compromise **md5:testmd5** device count: **1**'
    assert result['EntryContext']['CrowdStrike.IOC(val.ID === obj.ID)'][0]['ID'] == 'md5:testmd5'


def test_get_process_details_command_not_exists(requests_mock, mocker):
    """
    Test cs-falcon-process-details with an unsuccessful query (doesn't exist)

    Given
     - There is no device with a process `pid:fake:process`
    When
     - The user is running cs-falcon-process-details with pid:fake:process
    Then
     - Raise an error
    """
    from CrowdStrikeFalcon import get_process_details_command
    expected_error = [{'code': 404, 'message': 'pid:fake:process'}]
    response = {'resources': [], 'errors': expected_error}
    requests_mock.get(
        f'{SERVER_URL}/processes/entities/processes/v1',
        json=response,
        status_code=200,
    )
    mocker.patch(RETURN_ERROR_TARGET)
    with pytest.raises(DemistoException) as excinfo:
        get_process_details_command(ids='pid:fake:process')
    assert expected_error == excinfo.value.args[0]


def test_get_process_details_command_exists(requests_mock):
    """
    Test cs-falcon-process-details with a successful query

    Given
     - There is a device with a process `pid:fake:process`
    When
     - The user is running cs-falcon-process-details with pid:fake:process
    Then
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
     """
    from CrowdStrikeFalcon import get_process_details_command
    resources = {
        'device_id': 'process',
        'command_line': 'command_line',
        'start_timestamp': '2020-10-01T09:05:51Z',
        'start_timestamp_raw': '132460167512852140',
        'stop_timestamp': '2020-10-02T06:43:45Z',
        'stop_timestamp_raw': '132460946259334768'
    }
    response = {'resources': [resources]}
    requests_mock.get(
        f'{SERVER_URL}/processes/entities/processes/v1',
        json=response,
        status_code=200,
    )
    result = get_process_details_command(ids='pid:fake:process')
    assert '| command_line | process | 2020-10-01T09:05:51Z | 132460167512852140 |' in result['HumanReadable']
    assert resources == result['EntryContext']['CrowdStrike.Process(val.process_id === obj.process_id)'][0]


def test_get_proccesses_ran_on_command_exists(requests_mock):
    """
    Test cs-falcon-processes-ran-on with a successful query

    Given
     - There is a device with a process `pid:fake:process`
    When
     - The user is running cs-falcon-processes-ran-on with pid:fake:process
    Then
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right value
     """
    from CrowdStrikeFalcon import get_proccesses_ran_on_command
    response = {'resources': ['pid:fake:process']}
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/processes/v1',
        json=response,
        status_code=200,
    )
    result = get_proccesses_ran_on_command(ioc_type='test', value='mock', device_id='123')
    assert '### Processes with custom IOC test:mock on device 123.' in result['HumanReadable']
    assert '| pid:fake:process |' in result['HumanReadable']

    expected_proc_result = {'DeviceID': '123', 'ID': ['pid:fake:process']}
    actual_proc_result = result['EntryContext']['CrowdStrike.IOC(val.ID === obj.ID)']['Process']
    assert expected_proc_result == actual_proc_result


def test_get_proccesses_ran_on_command_not_exists(requests_mock):
    """
    Test cs-falcon-processes-ran-on with an unsuccessful query

    Given
     - There is no device with a process `pid:fake:process`
    When
     - The user is running cs-falcon-processes-ran-on with pid:fake:process
    Then
     - Raise an error
     """
    from CrowdStrikeFalcon import get_proccesses_ran_on_command
    expected_error = [{'code': 404, 'message': 'pid:fake:process - Resource Not Found'}]
    response = {'resources': [], 'errors': expected_error}
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/processes/v1',
        json=response,
        status_code=200,
    )
    with pytest.raises(DemistoException) as excinfo:
        get_proccesses_ran_on_command(ioc_type='test', value='mock', device_id='123')
    assert expected_error == excinfo.value.args[0]


def test_search_device_command(requests_mock):
    """
    Test search_device_command with a successful id
    Given
     - There is a device that is found
    When
     - The user is running cs-falcon-search-device with an id
    Then
     - Return a CrowdStrike context output
     - Return an Endpoint context output
     """
    from CrowdStrikeFalcon import search_device_command
    response = {'resources': {'meta': {'query_time': 0.010188508, 'pagination': {'offset': 1, 'limit': 100, 'total': 1},
                                       'powered_by': 'device-api', 'trace_id': 'c876614b-da71-4942-88db-37b939a78eb3'},
                              'resources': ['15dbb9d8f06b45fe9f61eb46e829d986'], 'errors': []}}
    device_context = {'ID': 'identifier_number', 'ExternalIP': '1.1.1.1', 'MacAddress': '42-01-0a-80-00-07',
                      'Hostname': 'FALCON-CROWDSTR', 'FirstSeen': '2020-02-10T12:40:18Z',
                      'LastSeen': '2021-04-05T13:48:12Z', 'LocalIP': '1.1.1.1', 'OS': 'Windows Server 2019',
                      'Status': 'normal'}
    endpoint_context = {'Hostname': 'FALCON-CROWDSTR', 'ID': 'identifier_number', 'IPAddress': '1.1.1.1',
                        'MACAddress': '42-01-0a-80-00-07', 'OS': 'Windows', 'OSVersion': 'Windows Server 2019',
                        'Status': 'Offline', 'Vendor': 'CrowdStrike Falcon'}
    status_res = {
        "meta": {
            "query_time": 0.002455124,
            "powered_by": "device-api",
            "trace_id": "c876614b-da71-4942-88db-37b939a78eb3"
        },
        "resources": [
            {
                "id": "15dbb9d8f06b45fe9f61eb46e829d986",
                "cid": "20879a8064904ecfbb62c118a6a19411",
                "last_seen": "2022-09-03T10:48:12Z",
                "state": "offline"
            }
        ],
        "errors": []
    }

    requests_mock.get(
        f'{SERVER_URL}/devices/queries/devices/v1',
        json=response,
        status_code=200,
    )
    requests_mock.get(
        f'{SERVER_URL}/devices/entities/devices/v2?ids=meta&ids=resources&ids=errors',
        json=test_data2,
        status_code=200,
    )

    requests_mock.get(
        f'{SERVER_URL}/devices/entities/online-state/v1',
        json=status_res,
        status_code=200,
    )

    outputs = search_device_command()
    result = outputs[0].to_context()

    context = result.get('EntryContext')
    for key, _value in context.items():
        if 'Device' in key:
            assert context[key] == device_context
        if 'Endpoint' in key:
            assert context[key] == [endpoint_context]


def test_get_endpoint_command(requests_mock, mocker):
    """
    Test get_endpint_command with a successful id
    Given
     - There is a device that is found
    When
     - The user is running cs-falcon-search-device with an id
    Then
     - Return an Endpoint context output
     """
    from CrowdStrikeFalcon import get_endpoint_command
    response = {'resources': {'meta': {'query_time': 0.010188508, 'pagination': {'offset': 1, 'limit': 100, 'total': 1},
                                       'powered_by': 'device-api', 'trace_id': 'c876614b-da71-4942-88db-37b939a78eb3'},
                              'resources': ['15dbb9d8f06b45fe9f61eb46e829d986'], 'errors': []}}
    endpoint_context = {'Hostname': 'FALCON-CROWDSTR', 'ID': 'identifier_number', 'IPAddress': '1.1.1.1',
                        'MACAddress': '42-01-0a-80-00-07', 'OS': 'Windows', 'OSVersion': 'Windows Server 2019',
                        'Status': 'Online', 'Vendor': 'CrowdStrike Falcon'}

    status_res = {
        "meta": {
            "query_time": 0.002455124,
            "powered_by": "device-api",
            "trace_id": "c876614b-da71-4942-88db-37b939a78eb3"
        },
        "resources": [
            {
                "id": "15dbb9d8f06b45fe9f61eb46e829d986",
                "cid": "20879a8064904ecfbb62c118a6a19411",
                "last_seen": "2022-09-03T10:48:12Z",
                "state": "online"
            }
        ],
        "errors": []
    }

    requests_mock.get(
        f'{SERVER_URL}/devices/entities/online-state/v1',
        json=status_res,
        status_code=200,
    )

    query_mocker = requests_mock.get(
        f'{SERVER_URL}/devices/queries/devices/v1',
        json=response,
        status_code=200,
    )
    requests_mock.get(
        f'{SERVER_URL}/devices/entities/devices/v2?ids=meta&ids=resources&ids=errors',
        json=test_data2,
        status_code=200,
    )

    mocker.patch.object(demisto, 'args', return_value={'id': 'dentifier_numbe', 'hostname': 'falcon-crowdstr'})

    outputs = get_endpoint_command()
    result = outputs[0].to_context()
    context = result.get('EntryContext')

    assert unquote(query_mocker.last_request.query) == "filter=device_id:'dentifier_numbe',hostname:'falcon-crowdstr'"
    assert context['Endpoint(val.ID && val.ID == obj.ID && val.Vendor == obj.Vendor)'] == [endpoint_context]


def test_create_hostgroup_invalid(requests_mock, mocker):
    """
    Test Create hostgroup with valid args with unsuccessful args
    Given
     - Invalid arguments for hostgroup
    When
     - Calling create hostgroup command
    Then
     - Throw an error
     """
    from CrowdStrikeFalcon import create_host_group_command
    response_data = load_json('test_data/test_create_hostgroup_invalid_data.json')
    requests_mock.post(
        f'{SERVER_URL}/devices/entities/host-groups/v1',
        json=response_data,
        status_code=400,
        reason='Bad Request'
    )
    with pytest.raises(DemistoException):
        create_host_group_command(name="dem test",
                                  description="dem des",
                                  group_type='static',
                                  assignment_rule="device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7']")


def test_update_hostgroup_invalid(requests_mock):
    """
    Test Create hostgroup with valid args with unsuccessful args
    Given
     - Invalid arguments for hostgroup
    When
     - Calling create hostgroup command
    Then
     - Throw an error
     """
    from CrowdStrikeFalcon import update_host_group_command
    response_data = load_json('test_data/test_create_hostgroup_invalid_data.json')
    requests_mock.patch(
        f'{SERVER_URL}/devices/entities/host-groups/v1',
        json=response_data,
        status_code=400,
        reason='Bad Request'
    )
    with pytest.raises(DemistoException):
        update_host_group_command(
            host_group_id='b1a0cd73ecab411581cbe467fc3319f5',
            name="dem test",
            description="dem des",
            assignment_rule="device_id:[''],hostname:['falcon-crowdstrike-sensor-centos7']")


@pytest.mark.parametrize('status, expected_status_api', [('New', "20"),
                                                         ('Reopened', "25"),
                                                         ('In Progress', "30"),
                                                         ('Closed', "40")])
def test_resolve_incidents(requests_mock, status, expected_status_api):
    """
    Test Create resolve incidents with valid status code
    Given
     - Valid status, as expected by product description
    When
     - Calling resolve incident command
    Then
     - Map the status to the status number that the api expects
     """
    from CrowdStrikeFalcon import resolve_incident_command
    m = requests_mock.post(
        f'{SERVER_URL}/incidents/entities/incident-actions/v1',
        json={})
    resolve_incident_command(['test'], status)
    assert m.last_request.json()['action_parameters'][0]['value'] == expected_status_api


@pytest.mark.parametrize('status', ['', 'new', 'BAD ARG'])
def test_resolve_incident_invalid(status):
    """
    Test Create resolve incidents with invalid status code
    Given
     - Invalid status, which is not expected by product description
    When
     - Calling resolve incident command
    Then
     - Throw an error
     """
    from CrowdStrikeFalcon import resolve_incident_command
    with pytest.raises(DemistoException):
        resolve_incident_command(['test'], status)


def test_update_incident_comment(requests_mock):
    """
    Test Update incident comment
    Given
     - Comment
    When
     - Calling update incident comment command
    Then
     - Update incident comment
     """
    from CrowdStrikeFalcon import update_incident_comment_command
    m = requests_mock.post(
        f'{SERVER_URL}/incidents/entities/incident-actions/v1',
        json={})
    update_incident_comment_command(['test'], 'comment')
    assert m.last_request.json()['action_parameters'][0]['value'] == 'comment'


def test_list_host_group_members(requests_mock):
    """
    Test list host group members with not arguments given
    Given
     - No arguments given, as is
    When
     - Calling list_host_group_members_command
    Then
     - Return all the hosts
     """
    from CrowdStrikeFalcon import list_host_group_members_command
    test_list_hostgroup_members_data = load_json('test_data/test_list_hostgroup_members_data.json')
    requests_mock.get(
        f'{SERVER_URL}/devices/combined/host-group-members/v1',
        json=test_list_hostgroup_members_data,
        status_code=200
    )
    command_results = list_host_group_members_command()
    expected_results = load_json('test_data/expected_list_hostgroup_members_results.json')
    for expected_result, ectual_results in zip(expected_results, command_results.outputs):
        assert expected_result == ectual_results


def test_upload_batch_custom_ioc_command(requests_mock):
    """
    Test cs-falcon-batch-upload-custom-ioc when an upload of iocs batch is successful

    Given:
     - The user tries to create multiple IOCs
    When:
     - The server creates IOCs
    Then:
     - Return a human readable result with appropriate message
     - Do populate the entry context with the right values
    """
    from CrowdStrikeFalcon import upload_batch_custom_ioc_command
    ioc_response = {
        'meta': {'query_time': 0.132378491, 'pagination': {'limit': 0, 'total': 2}, 'powered_by': 'ioc-manager',
                 'trace_id': '121f377b-016a-4e34-bca7-992cec821ab3'}, 'errors': None, 'resources': [
            {'id': '1196afeae04528228e782d4efc0c1d8257554dcd99552e1151ca3a3d2eed03f1', 'type': 'ipv4',
             'value': '8.9.6.8', 'source': 'Cortex XSOAR', 'action': 'no_action', 'mobile_action': 'no_action',
             'severity': 'informational', 'platforms': ['linux'], 'expiration': '2022-02-16T11:41:01Z',
             'expired': False, 'deleted': False, 'applied_globally': True, 'from_parent': False,
             'created_on': '2022-02-15T11:42:17.397548307Z', 'created_by': '2bf188d347e44e08946f2e61ef590c24',
             'modified_on': '2022-02-15T11:42:17.397548307Z', 'modified_by': '2bf188d347e44e08946f2e61ef590c24'},
            {'id': '1156f19c5a384117e7e6023f467ed3b58412ddd5d0591872f3a111335fae79a5', 'type': 'ipv4',
             'value': '4.5.8.6', 'source': 'Cortex XSOAR', 'action': 'no_action', 'mobile_action': 'no_action',
             'severity': 'informational', 'platforms': ['linux'], 'expiration': '2022-02-16T11:40:47Z',
             'expired': False, 'deleted': False, 'applied_globally': True, 'from_parent': False,
             'created_on': '2022-02-15T11:42:17.397548307Z', 'created_by': '2bf188d347e44e08946f2e61ef590c24',
             'modified_on': '2022-02-15T11:42:17.397548307Z', 'modified_by': '2bf188d347e44e08946f2e61ef590c24'}]}

    requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        json=ioc_response,
        status_code=200,
    )
    results = upload_batch_custom_ioc_command(json.dumps(IOCS_JSON_LIST))
    assert '2022-02-16T11:41:01Z | 1196afeae04528228e782d4efc0c1d8257554dcd99552e1151ca3a3d2eed03f1 | ' \
           '2bf188d347e44e08946f2e61ef590c24 | 2022-02-15T11:42:17.397548307Z | linux | informational | Cortex XSOAR ' \
           '| ipv4 | 8.9.6.8 |' in results[0]["HumanReadable"]

    assert '2022-02-16T11:40:47Z | 1156f19c5a384117e7e6023f467ed3b58412ddd5d0591872f3a111335fae79a5 | ' \
           '2bf188d347e44e08946f2e61ef590c24 | 2022-02-15T11:42:17.397548307Z | linux | informational | Cortex XSOAR ' \
           '| ipv4 | 4.5.8.6 |' in results[1]["HumanReadable"]

    assert results[0]["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == '8.9.6.8'
    assert results[1]["EntryContext"]["CrowdStrike.IOC(val.ID === obj.ID)"][0]["Value"] == '4.5.8.6'


@pytest.mark.parametrize('endpoint_status, status, is_isolated',
                         [('Normal', 'Online', ''),
                          ('normal', 'Online', ''),
                          ('containment_pending', '', 'Pending isolation'),
                          ('contained', '', 'Yes'),
                          ('lift_containment_pending', '', 'Pending unisolation'),
                          ])
def test_get_isolation_status(endpoint_status, status, is_isolated):
    """
    Test valid call for generate status field
    Given
     - valid status
    When
     - Calling generate_status_field function
    Then
     - Return status and is_isolated
     """
    from CrowdStrikeFalcon import get_isolation_status

    assert is_isolated == get_isolation_status(endpoint_status)


def test_get_isolation_status_invalid():
    """
    Test invalid call for generate status field
    Given
     - invalid status
    When
     - Calling generate_status_field function
    Then
     - Raise an exception
     """
    from CrowdStrikeFalcon import get_isolation_status
    with pytest.raises(DemistoException):
        get_isolation_status('unknown status')


def test_list_incident_summaries_command_no_given_ids(requests_mock, mocker):
    """
    Test list_incident_summaries_command without ids arg
    Given
     - No arguments given, as is
    When
     - The user is running list_incident_summaries_command with no ids
    Then
     - Function is executed properly and get_incidents_ids func was called once
     """
    from CrowdStrikeFalcon import list_incident_summaries_command

    query_response = {"errors": [], "meta": {"pagination": {"limit": 0, "offset": 0, "total": 0},
                                             "powered_by": "string", "query_time": 0, "trace_id": "string",
                                             "writes": {"resources_affected": 0}}, "resources": ['id1']}

    entity_response = {"errors": [],
                       "meta": {"pagination": {"limit": 0, "offset": 0, "total": 0}, "powered_by": "string"},
                       "resources": [{"assigned_to": "Test no ids", "assigned_to_name": "string", "cid": "string",
                                      "created": "2022-02-21T16:36:57.759Z", "description": "string",
                                      "end": "2022-02-21T16:36:57.759Z",
                                      "events_histogram": [{"count": 0}], "fine_score": 0, "host_ids": ["string"],
                                      "hosts": [{"agent_load_flags": "string", "tags": ["string"]}],
                                      "incident_id": "string", "incident_type": 0,
                                      "lm_host_ids": ["string"], "start": "2022-02-21T16:36:57.759Z", "state": "string",
                                      "status": 0,
                                      "tactics": ["string"], "tags": ["string"], "techniques": ["string"],
                                      "users": ["string"], "visibility": 0}]}

    requests_mock.get(
        f'{SERVER_URL}/incidents/queries/incidents/v1',
        json=query_response,
        status_code=200,
    )
    get_incidents_ids_func = requests_mock.post(
        f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
        json=entity_response,
        status_code=200,
    )
    mocker.patch.object(demisto, 'args', return_value={})

    outputs = list_incident_summaries_command().outputs

    assert outputs[0]['assigned_to'] == 'Test no ids'
    assert get_incidents_ids_func.call_count == 1


def test_list_incident_summaries_command_with_given_ids(requests_mock, mocker):
    """
    Test list_incident_summaries_command with ids arg
    Given
     - ids
    When
     - The user is running list_incident_summaries_command with ids
    Then
     - Function is executed properly and get_incidents_ids func was not called
     """
    from CrowdStrikeFalcon import list_incident_summaries_command

    query_response = {"errors": [], "meta": {"pagination": {"limit": 0, "offset": 0, "total": 0},
                                             "powered_by": "string", "query_time": 0, "trace_id": "string",
                                             "writes": {"resources_affected": 0}}, "resources": ['id1']}

    entity_response = {"errors": [],
                       "meta": {"pagination": {"limit": 0, "offset": 0, "total": 0}, "powered_by": "string"},
                       "resources": [{"assigned_to": "Test with ids", "assigned_to_name": "string", "cid": "string",
                                      "created": "2022-02-21T16:36:57.759Z", "description": "string",
                                      "end": "2022-02-21T16:36:57.759Z",
                                      "events_histogram": [{"count": 0}], "fine_score": 0, "host_ids": ["string"],
                                      "hosts": [{"agent_load_flags": "string", "tags": ["string"]}],
                                      "incident_id": "string", "incident_type": 0,
                                      "lm_host_ids": ["string"], "start": "2022-02-21T16:36:57.759Z", "state": "string",
                                      "status": 0,
                                      "tactics": ["string"], "tags": ["string"], "techniques": ["string"],
                                      "users": ["string"], "visibility": 0}]}

    get_incidents_ids_func = requests_mock.get(
        f'{SERVER_URL}/incidents/queries/incidents/v1',
        json=query_response,
        status_code=200,
    )
    requests_mock.post(
        f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
        json=entity_response,
        status_code=200,
    )
    mocker.patch.object(demisto, 'args', return_value={'ids': 'id1,id2'})

    outputs = list_incident_summaries_command().outputs

    assert outputs[0]['assigned_to'] == 'Test with ids'
    assert get_incidents_ids_func.call_count == 0


def test_parse_rtr_command_response_host_exists_stderr_output():
    from CrowdStrikeFalcon import parse_rtr_command_response
    response_data = load_json('test_data/rtr_outputs_with_stderr.json')
    parsed_result = parse_rtr_command_response(response_data, ["1"])
    assert len(parsed_result) == 1
    assert parsed_result[0].get('HostID') == "1"
    assert parsed_result[0].get('Error') == "Cannot find a process with the process identifier 5260."


def test_parse_rtr_command_response_host_exists_error_output():
    from CrowdStrikeFalcon import parse_rtr_command_response
    response_data = load_json('test_data/rtr_outputs_with_error.json')
    parsed_result = parse_rtr_command_response(response_data, ["1"])
    assert len(parsed_result) == 1
    assert parsed_result[0].get('HostID') == "1"
    assert parsed_result[0].get('Error') == "Some error"


def test_parse_rtr_command_response_host_not_exist():
    from CrowdStrikeFalcon import parse_rtr_command_response
    response_data = load_json('test_data/rtr_outputs_host_not_exist.json')
    parsed_result = parse_rtr_command_response(response_data, ["1", "2"])
    assert len(parsed_result) == 2
    for res in parsed_result:
        if res.get('HostID') == "1":
            assert res.get('Error') == "Success"
        elif res.get('HostID') == "2":
            assert res.get('Error') == "The host ID was not found."


def test_parse_rtr_stdout_response(mocker):
    from CrowdStrikeFalcon import parse_rtr_stdout_response
    response_data = load_json('test_data/rtr_list_processes_response.json')
    mocker.patch('CrowdStrikeFalcon.fileResult',
                 return_value={'Contents': '', 'ContentsFormat': 'text', 'Type': 3, 'File': 'netstat-1', 'FileID': 'c'})
    parsed_result = parse_rtr_stdout_response(["1"], response_data, "netstat")
    assert parsed_result[0][0].get('Stdout') == "example stdout"
    assert parsed_result[0][0].get('FileName') == "netstat-1"
    assert parsed_result[1][0].get('File') == "netstat-1"


@pytest.mark.parametrize('failed_devices, all_requested_devices, expected_result', [
    ({}, ["id1", "id2"], ""),
    ({'id1': "some error"}, ["id1", "id2"], "Note: you don't see the following IDs in the results as the request was"
                                            " failed for them. \nID id1 failed as it was not found. \n"),
])
def test_add_error_message(failed_devices, all_requested_devices, expected_result):
    from CrowdStrikeFalcon import add_error_message
    assert add_error_message(failed_devices, all_requested_devices) == expected_result


@pytest.mark.parametrize('failed_devices, all_requested_devices', [
    ({'id1': "some error", 'id2': "some error"}, ["id1", "id2"]),
    ({'id1': "some error1", 'id2': "some error2"}, ["id1", "id2"]),
])
def test_add_error_message_raise_error(failed_devices, all_requested_devices):
    from CrowdStrikeFalcon import add_error_message
    with raises(DemistoException,
                match=f'CrowdStrike Falcon The command was failed with the errors: {failed_devices}'):
        add_error_message(failed_devices, all_requested_devices)


def test_rtr_kill_process_command(mocker):
    from CrowdStrikeFalcon import rtr_kill_process_command
    mocker.patch('CrowdStrikeFalcon.init_rtr_batch_session', return_value="1")
    response_data = load_json('test_data/rtr_general_response.json')
    args = {'host_id': "1", 'process_ids': "2,3"}
    mocker.patch('CrowdStrikeFalcon.execute_run_batch_write_cmd_with_timer', return_value=response_data)
    parsed_result = rtr_kill_process_command(args).outputs
    for res in parsed_result:
        assert res.get('Error') == "Success"


@pytest.mark.parametrize('operating_system, expected_result', [
    ("Windows", "rm 'test.txt' --force"),
    ("Linux", "rm 'test.txt' -r -d"),
    ("Mac", "rm 'test.txt' -r -d"),
    ("bla", ""),
])
def test_match_remove_command_for_os(operating_system, expected_result):
    from CrowdStrikeFalcon import match_remove_command_for_os
    assert match_remove_command_for_os(operating_system, "test.txt") == expected_result


def test_rtr_remove_file_command(mocker):
    from CrowdStrikeFalcon import rtr_remove_file_command
    mocker.patch('CrowdStrikeFalcon.init_rtr_batch_session', return_value="1")
    response_data = load_json('test_data/rtr_general_response.json')
    args = {'host_ids': "1", 'file_path': "c:\\test", 'os': "Windows"}
    mocker.patch('CrowdStrikeFalcon.execute_run_batch_write_cmd_with_timer', return_value=response_data)
    parsed_result = rtr_remove_file_command(args).outputs
    for res in parsed_result:
        assert res.get('Error') == "Success"


def test_rtr_read_registry_keys_command(mocker):
    from CrowdStrikeFalcon import rtr_read_registry_keys_command
    mocker.patch('CrowdStrikeFalcon.init_rtr_batch_session', return_value="1")
    response_data = load_json('test_data/rtr_general_response.json')
    args = {'host_ids': "1", 'registry_keys': "key", 'os': "Windows"}
    mocker.patch('CrowdStrikeFalcon.execute_run_batch_write_cmd_with_timer', return_value=response_data)
    mocker.patch('CrowdStrikeFalcon.fileResult',
                 return_value={'Contents': '', 'ContentsFormat': 'text', 'Type': 3, 'File': 'netstat-1', 'FileID': 'c'})
    parsed_result = rtr_read_registry_keys_command(args)
    assert len(parsed_result) == 2
    assert "reg-1key" in parsed_result[0].readable_output


detections = {'resources': [
    {'behavior_id': 'example_behavior_1',
     'detection_ids': ['example_detection'],
     'incident_id': 'example_incident_id',
     'some_field': 'some_example',
     },
    {'behavior_id': 'example_behavior_2',
     'detection_ids': ['example_detection2'],
     'incident_id': 'example_incident_id',
     'some_field': 'some_example2',
     }
]}

DETECTION_FOR_INCIDENT_CASES = [
    (
        detections,
        ['a', 'b'],
        [
            {'incident_id': 'example_incident_id', 'behavior_id': 'example_behavior_1',
             'detection_ids': ['example_detection']},
            {'incident_id': 'example_incident_id', 'behavior_id': 'example_behavior_2',
             'detection_ids': ['example_detection2']}],
        [
            {'behavior_id': 'example_behavior_1',
             'detection_ids': ['example_detection'],
             'incident_id': 'example_incident_id',
             'some_field': 'some_example'},
            {'behavior_id': 'example_behavior_2',
             'detection_ids': ['example_detection2'],
             'incident_id': 'example_incident_id',
             'some_field': 'some_example2'}
        ],
        'CrowdStrike.IncidentDetection',
        '### Detection For Incident\n|behavior_id|detection_ids|incident_id|\n|---|---|---|'
        '\n| example_behavior_1 | example_detection | example_incident_id |\n'
        '| example_behavior_2 | example_detection2 | example_incident_id |\n'),
    ({'resources': []}, [], None, None, None, 'Could not find behaviors for incident zz')
]


@pytest.mark.parametrize(
    'detections, resources, expected_outputs, expected_raw, expected_prefix, expected_md',
    DETECTION_FOR_INCIDENT_CASES)
def test_get_detection_for_incident_command(mocker, detections, resources, expected_outputs, expected_raw,
                                            expected_prefix,
                                            expected_md):
    """
    Given: An incident ID
    When: When running cs-falcon-get-detections-for-incident command
    Then: validates the created command result contains the correct data (whether found or not).
    """

    from CrowdStrikeFalcon import get_detection_for_incident_command

    mocker.patch('CrowdStrikeFalcon.get_behaviors_by_incident',
                 return_value={'resources': resources, 'meta': {'pagination': {'total': len(resources)}}})

    mocker.patch('CrowdStrikeFalcon.get_detections_by_behaviors',
                 return_value=detections)

    res = get_detection_for_incident_command(incident_id='zz')

    assert res.outputs == expected_outputs
    assert res.raw_response == expected_raw
    assert res.readable_output == expected_md
    assert res.outputs_prefix == expected_prefix


@pytest.mark.parametrize('remote_id, close_incident, incident_status, detection_status, mirrored_object, entries',
                         input_data.get_remote_data_command_args)
def test_get_remote_data_command(mocker, remote_id, close_incident, incident_status, detection_status, mirrored_object,
                                 entries):
    """
    Given
        - arguments - id and lastUpdate time set to a lower than incident modification time
        - a raw update (get_incidents_entities and get_detections_entities results)
        - the state of the incident/detection in CrowdStrike Falcon
    When
        - running get_remote_data_command with changes to make
    Then
        - the mirrored_object in the GetRemoteDataResponse contains the modified incident fields
        - the entries in the GetRemoteDataResponse contain expected entries (an incident closure/reopen entry when needed)
    """
    from CrowdStrikeFalcon import get_remote_data_command
    incident_entity = input_data.response_incident.copy()
    incident_entity['status'] = incident_status
    mocker.patch('CrowdStrikeFalcon.get_incidents_entities', return_value={'resources': [incident_entity]})
    detection_entity = input_data.response_detection.copy()
    detection_entity['status'] = detection_status
    mocker.patch('CrowdStrikeFalcon.get_detections_entities', return_value={'resources': [detection_entity]})
    mocker.patch.object(demisto, 'params', return_value={'close_incident': close_incident})

    result = get_remote_data_command({'id': remote_id, 'lastUpdate': '2022-03-08T08:17:09Z'})
    assert result.mirrored_object == mirrored_object
    assert result.entries == entries


def test_find_incident_type():
    """
    Given
        - an incident or detection ID on the remote system
    When
        - running get_remote_data_command or update_remote_system_command when we want to know the relevant incident type
    Then
        - returns the right incident type
    """
    from CrowdStrikeFalcon import find_incident_type, IncidentType
    assert find_incident_type(input_data.remote_incident_id) == IncidentType.INCIDENT
    assert find_incident_type(input_data.remote_detection_id) == IncidentType.DETECTION
    assert find_incident_type('') is None


def test_get_remote_incident_data(mocker):
    """
    Given
        - an incident ID on the remote system
    When
        - running get_remote_data_command with changes to make on an incident
    Then
        - returns the relevant incident entity from the remote system with the relevant incoming mirroring fields
    """
    from CrowdStrikeFalcon import get_remote_incident_data
    incident_entity = input_data.response_incident.copy()
    mocker.patch('CrowdStrikeFalcon.get_incidents_entities', return_value={'resources': [incident_entity.copy()]})
    mirrored_data, updated_object = get_remote_incident_data(input_data.remote_incident_id)
    incident_entity['status'] = 'New'
    assert mirrored_data == incident_entity
    assert updated_object == {'state': 'closed', 'status': 'New', 'tags': ['Objective/Keep Access'],
                              'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident'}


def test_get_remote_detection_data(mocker):
    """
    Given
        - a detection ID on the remote system
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - returns the relevant detection entity from the remote system with the relevant incoming mirroring fields
    """
    from CrowdStrikeFalcon import get_remote_detection_data
    detection_entity = input_data.response_detection.copy()
    mocker.patch('CrowdStrikeFalcon.get_detections_entities', return_value={'resources': [detection_entity.copy()]})
    mirrored_data, updated_object = get_remote_detection_data(input_data.remote_detection_id)
    detection_entity['severity'] = 2
    assert mirrored_data == detection_entity
    assert updated_object == {'status': 'new', 'severity': 2, 'behaviors.tactic': 'Malware',
                              'behaviors.scenario': 'suspicious_activity',
                              'behaviors.objective': 'Falcon Detection Method',
                              'behaviors.technique': 'Malicious File', 'device.hostname': 'FALCON-CROWDSTR',
                              'incident_type': 'detection'}


@pytest.mark.parametrize('updated_object, entry_content, close_incident', input_data.set_xsoar_incident_entries_args)
def test_set_xsoar_incident_entries(mocker, updated_object, entry_content, close_incident):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
    When
        - running get_remote_data_command with changes to make on a incident
    Then
        - adds the relevant entry (closure/reopen) to the entries
    """
    from CrowdStrikeFalcon import set_xsoar_incident_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': close_incident})
    entries = []
    set_xsoar_incident_entries(updated_object, entries, input_data.remote_incident_id)
    if entry_content:
        assert entry_content in entries[0].get('Contents')
    else:
        assert entries == []


@pytest.mark.parametrize('updated_object, entry_content, close_incident', input_data.set_xsoar_detection_entries_args)
def test_set_xsoar_detection_entries(mocker, updated_object, entry_content, close_incident):
    """
    Given
        - the detection status from the remote system
        - the close_incident parameter that was set when setting the integration
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - adds the relevant entry (closure/reopen) to the entries
    """
    from CrowdStrikeFalcon import set_xsoar_detection_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': close_incident})
    entries = []
    set_xsoar_detection_entries(updated_object, entries, input_data.remote_incident_id)
    if entry_content:
        assert entry_content in entries[0].get('Contents')
    else:
        assert entries == []


@pytest.mark.parametrize('updated_object, mirrored_data, mirroring_fields, output', input_data.set_updated_object_args)
def test_set_updated_object(updated_object, mirrored_data, mirroring_fields, output):
    """
    Given
        - an entity from the remote system
        - the relevant incoming mirroring fields
    When
        - get-remote-data command runs when mirroring in and determines what the updated object is
    Then
        - the updated object is set correctly, also for nested mirroring fields
    """
    from CrowdStrikeFalcon import set_updated_object
    set_updated_object(updated_object, mirrored_data, mirroring_fields)
    assert updated_object == output


def test_get_modified_remote_data_command(mocker):
    """
    Given
        - arguments - lastUpdate time
        - raw incidents, detection, and idp_detection (results of get_incidents_ids, get_fetch_detections,
          and get_idp_detections_ids)
    When
        - running get_modified_remote_data_command
    Then
        - returns a list of incidents, detections, and idp detections IDs that were modified since the lastUpdate time
    """
    from CrowdStrikeFalcon import get_modified_remote_data_command
    mock_get_incidents = mocker.patch('CrowdStrikeFalcon.get_incidents_ids',
                                      return_value={'resources': [input_data.remote_incident_id]})
    mock_get_detections = mocker.patch('CrowdStrikeFalcon.get_fetch_detections',
                                       return_value={'resources': [input_data.remote_detection_id]})
    mock_get_idp_detections = mocker.patch('CrowdStrikeFalcon.get_idp_detections_ids',
                                           return_value={'resources': [input_data.remote_idp_detection_id]})
    last_update = '2022-03-08T08:17:09Z'
    last_update_idp_detection = '2022-03-08T08:17:09.000000Z'
    result = get_modified_remote_data_command({'lastUpdate': last_update})
    assert mock_get_incidents.call_args.kwargs['last_updated_timestamp'] == last_update
    assert mock_get_detections.call_args.kwargs['last_updated_timestamp'] == last_update
    assert last_update_idp_detection in mock_get_idp_detections.call_args.kwargs['filter_arg']
    assert result.modified_incident_ids == [input_data.remote_incident_id, input_data.remote_detection_id,
                                            input_data.remote_idp_detection_id]


@pytest.mark.parametrize('status',
                         ['new', 'in_progress', 'true_positive', 'false_positive', 'ignored', 'closed', 'reopened'])
def test_update_detection_request_good(mocker, status):
    """
    Given
        - list of detections IDs
        - status to change for the given detection in the remote system, which is one of the permitted statuses
    When
        - running update_remote_system_command
    Then
        - the resolve_detection command is called successfully with the right arguments
    """
    from CrowdStrikeFalcon import update_detection_request
    mock_resolve_detection = mocker.patch('CrowdStrikeFalcon.resolve_detection')
    update_detection_request([input_data.remote_detection_id], status)
    assert mock_resolve_detection.call_args[1]['ids'] == [input_data.remote_detection_id]
    assert mock_resolve_detection.call_args[1]['status'] == status


@pytest.mark.parametrize('status', ['other', ''])
def test_update_detection_request_bad(status):
    """
    Given
        - list of detections IDs
        - status to change for the given detection in the remote system, which is not one of the permitted statuses
    When
        - running update_remote_system_command
    Then
        - an exception is raised
    """
    from CrowdStrikeFalcon import update_detection_request
    with pytest.raises(DemistoException) as de:
        update_detection_request([input_data.remote_detection_id], status)
    assert 'CrowdStrike Falcon Error' in str(de.value)


@pytest.mark.parametrize('args, to_mock, call_args, remote_id, prev_tags, close_in_cs_falcon_param',
                         input_data.update_remote_system_command_args)
def test_update_remote_system_command(mocker, args, to_mock, call_args, remote_id, prev_tags, close_in_cs_falcon_param):
    """
    Given
        - incident or detection changes (one of the mirroring field changed or it was closed in XSOAR)
    When
        - outgoing mirroring triggered by a change in the incident/detection
    Then
        - the relevant incident/detection is updated with the corresponding fields in the remote system
        - the returned result corresponds to the incident/detection ID
    """
    from CrowdStrikeFalcon import update_remote_system_command
    mock_call = mocker.patch(f'CrowdStrikeFalcon.{to_mock}')
    mocker.patch('CrowdStrikeFalcon.get_previous_tags', return_value=prev_tags)
    mocker.patch.object(demisto, 'params', return_value={'close_in_cs_falcon': close_in_cs_falcon_param})
    command_result = update_remote_system_command(args)
    assert command_result == remote_id
    for i, call in enumerate(call_args):
        assert mock_call.call_args_list[i][0] == call


@pytest.mark.parametrize('delta, close_in_cs_falcon_param, to_close', input_data.close_in_cs_falcon_args)
def test_close_in_cs_falcon(mocker, delta, close_in_cs_falcon_param, to_close):
    """
    Given
        - incident or detection changes (one of the mirroring field changed or it was closed in XSOAR)
        - the close_in_cs_falcon parameter that was set when setting the integration
    When
        - outgoing mirroring triggered by a change in the incident/detection
    Then
        - returns true if the incident/detection was closed in XSOAR and the close_in_cs_falcon parameter was set to true
    """
    from CrowdStrikeFalcon import close_in_cs_falcon
    mocker.patch.object(demisto, 'params', return_value={'close_in_cs_falcon': close_in_cs_falcon_param})
    assert close_in_cs_falcon(delta) == to_close


@pytest.mark.parametrize('delta, inc_status, close_in_cs_falcon, detection_request_status',
                         input_data.update_remote_detection_args)
def test_update_remote_detection(mocker, delta, inc_status, close_in_cs_falcon, detection_request_status):
    """
    Given
        - detection changes (one of the mirroring field changed or it was closed in XSOAR)
        - arguments - delta (the change in the relevant fields), XSOAR status and remote detection id
    When
        - outgoing mirroring triggered by a change in the detection
    Then
        - the relevant detection is updated with the corresponding fields in the remote system
    """
    from CrowdStrikeFalcon import update_remote_detection
    mocker.patch.object(demisto, 'params', return_value={'close_in_cs_falcon': close_in_cs_falcon})
    mock_update_detection_request = mocker.patch('CrowdStrikeFalcon.update_detection_request')
    update_remote_detection(delta, inc_status, input_data.remote_detection_id)
    if detection_request_status:
        assert mock_update_detection_request.call_args[0][1] == detection_request_status
    else:
        assert mock_update_detection_request.call_count == 0


def test_update_remote_incident(mocker):
    """
    Given
        - incident changes (one of the mirroring field changed or it was closed in XSOAR)
        - arguments - delta (the change in the relevant fields), XSOAR status and remote incident id
    When
        - outgoing mirroring triggered by a change in the incident
    Then
        - the relevant incident is updated with the corresponding fields in the remote system
    """
    from CrowdStrikeFalcon import update_remote_incident
    mock_update_tags = mocker.patch('CrowdStrikeFalcon.update_remote_incident_tags')
    mock_update_status = mocker.patch('CrowdStrikeFalcon.update_remote_incident_status')
    update_remote_incident({}, IncidentStatus.ACTIVE, input_data.remote_incident_id)
    assert mock_update_tags.called
    assert mock_update_status.called


@pytest.mark.parametrize('delta, inc_status, close_in_cs_falcon, resolve_incident_status',
                         input_data.update_remote_incident_status_args)
def test_update_remote_incident_status(mocker, delta, inc_status, close_in_cs_falcon, resolve_incident_status):
    """
    Given
        - incident status changes
        - arguments - delta (the change in the relevant fields), XSOAR status and remote incident id
    When
        - outgoing mirroring triggered by a change in the incident status
    Then
        - the relevant incident is updated with the corresponding status in the remote system
    """
    from CrowdStrikeFalcon import update_remote_incident_status
    mocker.patch.object(demisto, 'params', return_value={'close_in_cs_falcon': close_in_cs_falcon})
    mock_resolve_incident = mocker.patch('CrowdStrikeFalcon.resolve_incident')
    update_remote_incident_status(delta, inc_status, input_data.remote_incident_id)
    if resolve_incident_status:
        assert mock_resolve_incident.call_args[0][1] == resolve_incident_status
    else:
        assert mock_resolve_incident.call_count == 0


def test_update_remote_incident_tags(mocker):
    """
    Given
        - incident tags changes
        - arguments - delta (the change in the relevant fields) and remote incident id
    When
        - outgoing mirroring triggered by a change in the incident tags
    Then
        - the relevant incident is updated with the corresponding tags (added or removed) in the remote system
    """
    from CrowdStrikeFalcon import update_remote_incident_tags
    mocker.patch('CrowdStrikeFalcon.get_previous_tags', return_value={'tag_stays', 'old_tag'})
    mock_remote_incident_handle_tags = mocker.patch('CrowdStrikeFalcon.remote_incident_handle_tags')
    update_remote_incident_tags({'tag': ['new_tag', 'tag_stays']}, input_data.remote_incident_id)
    assert mock_remote_incident_handle_tags.call_args_list[0][0][0] == {'old_tag'}
    assert mock_remote_incident_handle_tags.call_args_list[0][0][1] == 'delete_tag'
    assert mock_remote_incident_handle_tags.call_args_list[1][0][0] == {'new_tag'}
    assert mock_remote_incident_handle_tags.call_args_list[1][0][1] == 'add_tag'


def test_get_previous_tags(mocker):
    """
    Given
        - incident tags changes
    When
        - outgoing mirroring triggered by a change in the incident tags
    Then
        - returns the current remote system tags
    """
    from CrowdStrikeFalcon import get_previous_tags
    incident_response = {'meta': {'query_time': 0.013811475, 'powered_by': 'incident-api',
                                  'trace_id': '7fce39d4-d695-4aac-bdcf-2d9138bea57c'},
                         'resources': [input_data.response_incident],
                         'errors': []}
    mock_get_incidents_entities = mocker.patch('CrowdStrikeFalcon.get_incidents_entities',
                                               return_value=incident_response)
    assert get_previous_tags(input_data.remote_incident_id) == set(input_data.response_incident["tags"])
    assert mock_get_incidents_entities.call_args[0][0] == [input_data.remote_incident_id]


@pytest.mark.parametrize('tags, action_name', input_data.remote_incident_handle_tags_args)
def test_remote_incident_handle_tags(mocker, tags, action_name):
    """
    Given
        - incident tag changes
    When
        - outgoing mirroring triggered by a change in the incident tags
    Then
        - sends the right request to the remote system
    """
    from CrowdStrikeFalcon import remote_incident_handle_tags
    mock_update_incident_request = mocker.patch('CrowdStrikeFalcon.update_incident_request')
    remote_incident_handle_tags(tags, action_name, input_data.remote_incident_id)
    assert mock_update_incident_request.call_count == len(tags)
    if len(tags):
        assert mock_update_incident_request.call_args[0][2] == action_name


def test_get_mapping_fields_command():
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping scheme
    """
    from CrowdStrikeFalcon import get_mapping_fields_command
    result = get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == 'CrowdStrike Falcon Incident'
    assert result.scheme_types_mappings[0].fields.keys() == {'status', 'tag'}
    assert result.scheme_types_mappings[1].type_name == 'CrowdStrike Falcon Detection'
    assert result.scheme_types_mappings[1].fields.keys() == {'status'}


def test_error_in_get_detections_by_behaviors(mocker):
    """
    Given
        - Error occurred in call to get_detections_by_behaviors
    When
        - Run the cs-falcon-get-detections-for-incident command
    Then
        - Assert empty object returned and demisto.error was called
    """

    # prepare
    from CrowdStrikeFalcon import get_detection_for_incident_command
    mocker.patch('CrowdStrikeFalcon.get_behaviors_by_incident',
                 return_value={'resources': [{'dummy': 'test'}], 'meta': {'pagination': {'total': 1}}})

    def excpetion_raiser(*args, **kwargs):
        raise Exception

    mocker.patch('CrowdStrikeFalcon.http_request', side_effect=excpetion_raiser)
    mocker.patch.object(demisto, 'error')

    res = get_detection_for_incident_command(incident_id='zz')
    assert res.readable_output
    demisto.error.assert_called_once_with('Error occurred when trying to get detections by behaviors: ')


ARGS_vulnerability = [
    (
        {'display_remediation_info': 'True',
         'display_evaluation_logic_info': 'True',
         'display_host_info': 'False',
         'limit': '1'}, False,
        None, 'Please add a at least one filter argument'
    ),
    (
        {"cve_severity": "LOW", 'display_remediation_info': 'True',
         'display_evaluation_logic_info': 'True',
         'display_host_info': 'False', 'status': "open,closed"},
        True,  # Valid case
        {"resources":
         [
             {"id": "id1",
              "cid": "cid1",
              "aid": "aid1",
              "created_timestamp": "2021-09-16T15:12:42Z",
              "updated_timestamp": "2022-10-19T00:54:43Z",
              "status": "open",
              "cve": {
               "id": "cveid1",
               "base_score": 3.3,
               "severity": "LOW",
               "exploit_status": 0,
               "exprt_rating": "LOW",
               "remediation_level": "O",
               "spotlight_published_date": "2021-09-15T18:33:00Z",
               "description": "secd",
               "published_date": "2021-09-15T12:15:00Z"}},
             {"id": "ID2",
              "cid": "cid2",
              "aid": "aid2",
              "created_timestamp": "2022-10-12T22:12:49Z",
              "updated_timestamp": "2022-10-18T02:54:43Z",
              "status": "open",
              "cve": {"id": "idcve4",
                        "spotlight_published_date": "2022-10-12T14:57:00Z",
                        "description": "desc3",
                        "published_date": "2022-10-11T19:15:00Z",
                        "exploitability_score": 1.8,
                        "impact_score": 1.4}}
         ]
         },
        '### List Vulnerabilities\n' \
        '|ID|Severity|Status|Base Score|Published Date|Impact Score|Exploitability Score|\n' \
        '|---|---|---|---|---|---|---|\n' \
        '| cveid1 | LOW | open | 3.3 | 2021-09-15T12:15:00Z |  |  |\n' \
        '| idcve4 |  | open |  | 2022-10-11T19:15:00Z | 1.4 | 1.8 |\n'  # args list

    )
]


@pytest.mark.parametrize('args, is_valid, result_key_json, expected_hr', ARGS_vulnerability)
def test_cs_falcon_spotlight_search_vulnerability_command(mocker, args, is_valid, result_key_json, expected_hr):
    """
    Test cs_falcon_spotlight_search_vulnerability_command,
        with a the filters:  cve_severity, status
    Given
     - There is a vulnerability that are found
    When
     - The user is running cs_falcon_spotlight_search_vulnerability_command with an id
    Then
     - Return a CrowdStrike Falcon Vulnerability context output
     - Return an Endpoint context output
     """
    from CrowdStrikeFalcon import cs_falcon_spotlight_search_vulnerability_command
    from CommonServerPython import DemistoException
    mocker.patch("CrowdStrikeFalcon.http_request", return_value=result_key_json)
    if is_valid:
        outputs = cs_falcon_spotlight_search_vulnerability_command(args)
        assert outputs.readable_output == expected_hr
    else:
        with pytest.raises(DemistoException) as e:
            cs_falcon_spotlight_search_vulnerability_command(args)
        assert str(e.value) == expected_hr


def test_cs_falcon_spotlight_search_vulnerability_host_by_command(mocker):
    """
    Test cs_falcon_spotlight_list_host_by_vulnerability_command,
        with a the filters:  cve_severity, status
    Given
     - There is a vulnerability that are found
    When
     - The user is running cs_falcon_spotlight_list_host_by_vulnerability_command with an id
    Then
     - Return a CrowdStrike Falcon Vulnerability context output
     - Return an Endpoint context output
     """
    from CrowdStrikeFalcon import cs_falcon_spotlight_list_host_by_vulnerability_command

    result_key_json = {
        "resources": [
            {
                "id": "id1",
                "cid": "cid1",
                "aid": "aid1",
                "created_timestamp": "2022-01-25T22:44:53Z",
                "updated_timestamp": "2022-10-19T13:56:17Z",
                "status": "open",
                "host_info": {
                    "hostname": "host",
                    "local_ip": "ip_addr",
                    "machine_domain": "",
                    "os_version": "os_ver_example",
                    "ou": "",
                    "site_name": "",
                    "system_manufacturer": "manu_example",
                    "tags": [],
                    "platform": "Windows",
                    "instance_id": "int_id",
                    "service_provider_account_id": "id1_account",
                    "service_provider": "id_ser_prov",
                    "os_build": "1",
                    "product_type_desc": "Server"
                },
                "cve": {
                    "id": "CVE-2013-3900"
                }
            }
        ]
    }
    expected_hr = '### List Vulnerabilities For Host\n'\
                  '|CVE ID|hostname|os Version|Product Type Desc|Local IP|\n' \
                  '|---|---|---|---|---|\n' \
                  '| CVE-2013-3900 | host | os_ver_example | Server | ip_addr |\n'
    args = {'cve_ids': 'CVE-2013-3900', 'limit': 1}
    mocker.patch("CrowdStrikeFalcon.http_request", return_value=result_key_json)

    outputs = cs_falcon_spotlight_list_host_by_vulnerability_command(args)
    assert outputs.readable_output == expected_hr


def test_create_ml_exclusion_command(requests_mock):
    from CrowdStrikeFalcon import create_ml_exclusion_command
    requests_mock.post(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = create_ml_exclusion_command({'value': '/test', 'excluded_from': ['blocking'], 'groups': 123456})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('value') == '/test'


def test_update_ml_exclusion_command_with_args(requests_mock):
    from CrowdStrikeFalcon import update_ml_exclusion_command
    requests_mock.patch(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = update_ml_exclusion_command({'id': 123456, 'value': '/test', 'excluded_from': ['blocking'], 'groups': 123456})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('value') == '/test'


def test_update_ml_exclusion_command_without_args(requests_mock):
    from CrowdStrikeFalcon import update_ml_exclusion_command
    requests_mock.patch(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    with pytest.raises(Exception) as e:
        update_ml_exclusion_command({'id': 123456})

    assert str(e.value) == 'At least one argument (besides the id argument) should be provided to update the exclusion.'


def test_delete_ml_exclusion_command(requests_mock):
    from CrowdStrikeFalcon import delete_ml_exclusion_command
    requests_mock.delete(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = delete_ml_exclusion_command({'ids': '123456 789456'})

    assert results.readable_output == "The machine learning exclusions with IDs 123456 789456 was successfully deleted."


def test_search_ml_exclusion_command_by_ids(requests_mock):
    from CrowdStrikeFalcon import search_ml_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1?ids=123456&ids=789012',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = search_ml_exclusion_command({'ids': '123456,789012'})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('value') == '/test'


def test_search_ml_exclusion_command_by_value(requests_mock):
    from CrowdStrikeFalcon import search_ml_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ml-exclusions/v1?filter=value%3A%27%2Ftest%27',
        json={'resources': ['123456']}
    )
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1?ids=123456',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = search_ml_exclusion_command({'value': '/test'})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('value') == '/test'


def test_search_ml_exclusion_command_by_value_no_results(requests_mock):
    from CrowdStrikeFalcon import search_ml_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ml-exclusions/v1?filter=value%3A%27%2Ftest-mock%27',
        json={}
    )

    results = search_ml_exclusion_command({'value': '/test-mock'})

    assert results.readable_output == 'The arguments/filters you provided did not match any exclusion.'


def test_search_ml_exclusion_command_by_filter(requests_mock):
    from CrowdStrikeFalcon import search_ml_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ml-exclusions/v1?filter=value%3A%27%2Ftest%27',
        json={'resources': ['123456']}
    )
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ml-exclusions/v1?ids=123456',
        json=load_json('test_data/create_ml_exclusion.json')
    )

    results = search_ml_exclusion_command({'filter': 'value:\'/test\''})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('value') == '/test'


def test_create_ioa_exclusion_command(requests_mock):
    from CrowdStrikeFalcon import create_ioa_exclusion_command
    requests_mock.post(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = create_ioa_exclusion_command({'exclusion_name': 'test', 'pattern_id': 123456, 'groups': 123456})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('name') == 'test'


def test_update_ioa_exclusion_command_with_args(requests_mock):
    from CrowdStrikeFalcon import update_ioa_exclusion_command
    requests_mock.patch(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = update_ioa_exclusion_command({'id': 123456, 'exclusion_name': 'test'})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('name') == 'test'


def test_update_ioa_exclusion_command_without_args(requests_mock):
    from CrowdStrikeFalcon import update_ioa_exclusion_command
    requests_mock.patch(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    with pytest.raises(Exception) as e:
        update_ioa_exclusion_command({'id': 123456})

    assert str(e.value) == 'At least one argument (besides the id argument) should be provided to update the exclusion.'


def test_delete_ioa_exclusion_command(requests_mock):
    from CrowdStrikeFalcon import delete_ioa_exclusion_command
    requests_mock.delete(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = delete_ioa_exclusion_command({'ids': '123456, 456789'})

    assert results.readable_output == "The IOA exclusions with IDs 123456 456789 was successfully deleted."


def test_search_ioa_exclusion_command_by_ids(requests_mock):
    from CrowdStrikeFalcon import search_ioa_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1?ids=123456&ids=789012',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = search_ioa_exclusion_command({'ids': '123456,789012'})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('name') == 'test'


def test_search_ioa_exclusion_command_by_name(requests_mock):
    from CrowdStrikeFalcon import search_ioa_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ioa-exclusions/v1?filter=name%3A~%27test%27',
        json={'resources': ['123456']}
    )
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1?ids=123456',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = search_ioa_exclusion_command({'name': 'test'})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('name') == 'test'


def test_search_ioa_exclusion_command_by_name_no_results(requests_mock):
    from CrowdStrikeFalcon import search_ioa_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ioa-exclusions/v1?filter=name%3A~%27test-mock%27',
        json={}
    )

    results = search_ioa_exclusion_command({'name': 'test-mock'})

    assert results.readable_output == 'The arguments/filters you provided did not match any exclusion.'


def test_search_ioa_exclusion_command_by_filter(requests_mock):
    from CrowdStrikeFalcon import search_ioa_exclusion_command
    requests_mock.get(
        f'{SERVER_URL}/policy/queries/ioa-exclusions/v1?filter=name%3A%27test%27',
        json={'resources': ['123456']}
    )
    requests_mock.get(
        f'{SERVER_URL}/policy/entities/ioa-exclusions/v1?ids=123456',
        json=load_json('test_data/create_ioa_exclusion.json')
    )

    results = search_ioa_exclusion_command({'filter': 'name:\'test\''})

    assert len(results.outputs) == 1
    assert results.outputs[0].get('id') == '123456'
    assert results.outputs[0].get('name') == 'test'


def test_list_quarantined_file_command(requests_mock):
    from CrowdStrikeFalcon import list_quarantined_file_command
    requests_mock.get(
        f'{SERVER_URL}/quarantine/queries/quarantined-files/v1?q=hostname%3A%27%5B%27INSTANCE-1%27%5D%27&limit=50',
        json={'resources': ['121212', '171717']}
    )
    requests_mock.post(
        f'{SERVER_URL}/quarantine/entities/quarantined-files/GET/v1',
        json=load_json('test_data/list_quarantine_files.json')
    )

    results = list_quarantined_file_command({'hostname': 'INSTANCE-1'})

    assert len(results.outputs) == 2
    assert results.outputs[0].get('id') == '121212'
    assert results.outputs[1].get('id') == '171717'


def test_list_quarantined_file_command_no_results(requests_mock):
    from CrowdStrikeFalcon import list_quarantined_file_command
    requests_mock.get(
        f'{SERVER_URL}/quarantine/queries/quarantined-files/v1?q=hostname%3A%27%5B%27INSTANCE-1%27%5D%27&limit=50',
        json={}
    )

    results = list_quarantined_file_command({'hostname': 'INSTANCE-1'})

    assert results.readable_output == 'The arguments/filters you provided did not match any files.'


def test_apply_quarantine_file_action_command(requests_mock):
    from CrowdStrikeFalcon import apply_quarantine_file_action_command
    requests_mock.get(
        f'{SERVER_URL}/quarantine/queries/quarantined-files/v1?q=hostname%3A%27%5B%27INSTANCE-1%27%5D%27&limit=50',
        json={'resources': ['121212', '171717']}
    )
    mock_request = requests_mock.patch(
        f'{SERVER_URL}/quarantine/entities/quarantined-files/v1',
        json={}
    )

    results = apply_quarantine_file_action_command({'hostname': 'INSTANCE-1', 'comment': 'Added a test comment.'})

    assert results.readable_output == "The Quarantined File with IDs ['121212', '171717'] was successfully updated."
    assert mock_request.last_request.text == '{"ids": ["121212", "171717"], "comment": "Added a test comment."}'


filter_args = {'key1': 'val1,val2', 'key2': 'val3', 'key3': None}
custom_filter = 'key1:"val1"+key2:["val3","val4"]'


@pytest.mark.parametrize(
    'filter_args, custom_filter, output_filter',
    (
        (filter_args, custom_filter, 'key1:"val1"%2Bkey2:["val3","val4"]%2Bkey1:[\'val1\', \'val2\']%2Bkey2:[\'val3\']'),
        (filter_args, None, 'key1:[\'val1\', \'val2\']%2Bkey2:[\'val3\']'),
        ({}, custom_filter, 'key1:"val1"%2Bkey2:["val3","val4"]')
    )
)
def test_build_cs_falcon_filter(filter_args, custom_filter, output_filter):
    """
    Test build_cs_falcon_filter.

    Given
        - A dictionary filter and a custom filter.

    When
        - Before an cs-falcon query.

    Then
        - Return a merged FQL filter as a single string.
    """
    from CrowdStrikeFalcon import build_cs_falcon_filter

    result = build_cs_falcon_filter(custom_filter, **filter_args)

    assert output_filter == result


@pytest.mark.parametrize(
    'command_args, query_result, entites_result, readable_output',
    (
        ({'wait_for_result': False}, [], {}, 'No scans match the arguments/filter.'),
        ({'wait_for_result': False}, ['123456'], {'resources': [{'id': '123456'}]},
         ('### CrowdStrike Falcon ODS Scans\n'
          '|ID|Status|Severity|File Count|Description|Hosts/Host groups|End time|Start time|Run by|\n'
          '|---|---|---|---|---|---|---|---|---|\n'
          '| 123456 |  |  |  |  |  |  |  |  |\n')),
        ({'wait_for_result': True, 'ids': '123456'}, [], {'resources': [{'status': 'pending'}]}, 'Retrieving scan results:'),
    )
)
def test_cs_falcon_ODS_query_scans_command(mocker, command_args, query_result, entites_result, readable_output):
    """
    Test cs_falcon_ODS_query_scans_command.

    Given
        - A request for a list of ODS endpoint scans by id.

    When
        - The user runs the "cs-falcon-ods-query-scan" command or the "cs-falcon-ods-create-scan".

    Then
        - Get a list of scans from CS Falcon and poll for results if wait_for_results is True.
    """

    from CrowdStrikeFalcon import cs_falcon_ODS_query_scans_command

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch('CrowdStrikeFalcon.get_ODS_scan_ids', return_value=query_result)
    mocker.patch('CrowdStrikeFalcon.ODS_get_scans_by_id_request', return_value=entites_result)

    result = cs_falcon_ODS_query_scans_command(command_args)

    assert result.readable_output == readable_output


@pytest.mark.parametrize(
    'input_params, call_params',
    (
        ({'key1': 'val1', 'key2': None}, 'key1=val1'),
        ({'key1': 'val1', 'key2': 'val2'}, 'key1=val1&key2=val2')
    )
)
def test_ODS_query_scans_request(mocker, input_params, call_params):
    """
    Test ODS_query_scans_request.

    Given
        - A request for a list of ODS endpoint scans by id.

    When
        - The user runs the "cs-falcon-ods-query-scan" command without specifying ids.

    Then
        - Call /ods/queries/scans/v1 with a filter, limit and offset if given and return the ids in response.
    """

    from CrowdStrikeFalcon import ODS_query_scans_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_query_scans_request(**input_params)
    http_request.assert_called_with('GET', f'/ods/queries/scans/v1?{call_params}')


def test_ODS_get_scans_by_id_request(mocker):
    """
    Test ODS_get_scans_by_id_request.

    Given
        - A request for info on ODS endpoint scans.

    When
        - The user runs the "cs-falcon-ods-query-scan" command and we obtain a non-empty list of ids.

    Then
        - Call /ods/entities/scans/v1 with the ids and return the response.
    """

    from CrowdStrikeFalcon import ODS_get_scans_by_id_request

    ids_list = ['<id1>', '<id2>', '<id3>']
    ids_string = 'ids=<id1>&ids=<id2>&ids=<id3>'

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')

    ODS_get_scans_by_id_request(ids_list)
    http_request.assert_called_with('GET', f'/ods/entities/scans/v1?{ids_string}')


def test_map_scan_resource_to_UI(mocker):
    """
    Test map_scan_resource_to_UI.

    Given
        - A dictionary response from /ods/entities/scans.

    When
        - The user runs the "cs-falcon-ods-query-scan" command

    Then
        - Return a dict with keys corresponding the cs-falcon UI.
    """
    from CrowdStrikeFalcon import map_scan_resource_to_UI

    resource = {
        "id": "91000dbf0a4e4f5eb2a02528c00fa902",
        "cid": "20879a8064904ecfbb62c118a6a19411",
        "profile_id": "0e313756da21480c8eb5cf37da77a97a",
        "description": "desc3456346",
        "scan_inclusions": [
            "*"
        ],
        "initiated_from": "cloud_scheduled",
        "quarantine": True,
        "cpu_priority": 2,
        "preemption_priority": 15,
        "metadata": [
            {
                "host_id": "046761c46ec84f40b27b6f79ce7cd32c",
                "host_scan_id": "38588c1b29aa9946a3de95e997ad7948",
                "scan_host_metadata_id": "6aec6c04ab2e4c99b4e843637d3e37d0",
                "filecount": {
                    "scanned": 0,
                    "malicious": 0,
                    "quarantined": 0,
                    "skipped": 0,
                    "traversed": 518464
                },
                "status": "completed",
                "started_on": "2023-03-15T15:57:37.59543591Z",
                "completed_on": "2023-03-15T16:02:20.845829991Z",
                "last_updated": "2023-03-15T16:02:20.845909034Z"
            },
            {
                "host_id": "15dbb9d8f06b45fe9f61eb46e829d986",
                "scan_host_metadata_id": "2e99e4fc7a4f4b1e9254e0af210a6994",
                "filecount": {
                    "scanned": 0,
                    "malicious": 0,
                    "quarantined": 0,
                    "skipped": 0,
                    "traversed": 209
                },
                "status": "failed",
                "last_updated": "2023-04-05T02:23:10.316500752Z"
            }
        ],
        "filecount": {},
        "status": "failed",
        "host_groups": [
            "7471ba0636b34cbb8c65fae7979a6a9b"
        ],
        "endpoint_notification": True,
        "pause_duration": 2,
        "max_duration": 2,
        "max_file_size": 60,
        "sensor_ml_level_detection": 2,
        "sensor_ml_level_prevention": 2,
        "cloud_ml_level_detection": 2,
        "cloud_ml_level_prevention": 2,
        "policy_setting": [
            26439818674573,
            26439818674574,
        ],
        "scan_started_on": "2023-03-15T15:57:37.59543591Z",
        "scan_completed_on": "2023-04-18T14:56:38.527255649Z",
        "created_on": "2023-03-15T15:57:37.59543591Z",
        "created_by": "f7acf1bd5d3d4b40afe77546cbbaefde",
        "last_updated": "2023-04-05T02:23:10.316500752Z"
    }
    mapped_resource = {
        'ID': "91000dbf0a4e4f5eb2a02528c00fa902",
        'Status': "failed",
        'Severity': None,
        'Description': "desc3456346",
        'File Count': ('scanned: 0\nmalicious: 0\n'
                       'quarantined: 0\nskipped: 0\ntraversed: 518464'
                       '\n-\nscanned: 0\nmalicious: 0\n'
                       'quarantined: 0\nskipped: 0\ntraversed: 209'),
        'Hosts/Host groups': [
            "7471ba0636b34cbb8c65fae7979a6a9b"
        ],
        'Start time': "2023-03-15T15:57:37.59543591Z",
        'End time': "2023-04-18T14:56:38.527255649Z",
        'Run by': "f7acf1bd5d3d4b40afe77546cbbaefde"
    }

    output = map_scan_resource_to_UI(resource)

    assert output == mapped_resource


@pytest.mark.parametrize(
    'input_params, call_params',
    (
        ({'key1': 'val1', 'key2': None}, 'key1=val1'),
        ({'key1': 'val1', 'key2': 'val2'}, 'key1=val1&key2=val2')
    )
)
def test_ODS_query_scheduled_scans_request(mocker, input_params, call_params):
    """
    Test ODS_query_scheduled_scans_request.

    Given
        - A request for a list of ODS endpoint scheduled scans by id.

    When
        - The user runs the "cs-falcon-ods-query-scheduled-scan" command without specifying ids.

    Then
        - Call /ods/queries/scheduled-scans/v1 with a filter, limit and offset if given and return the ids in response.
    """

    from CrowdStrikeFalcon import ODS_query_scheduled_scans_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_query_scheduled_scans_request(**input_params)
    http_request.assert_called_with('GET', f'/ods/queries/scheduled-scans/v1?{call_params}')


def test_ODS_get_scheduled_scans_by_id_request(mocker):
    """
    Test ODS_get_scheduled_scans_by_id_request.

    Given
        - A request for info on ODS endpoint scheduled scans.

    When
        - The user runs the "cs-falcon-ods-query-scheduled-scan" command and we obtain a non-empty list of ids.

    Then
        - Call /ods/entities/scheduled-scans/v1 with the ids and return the response.
    """

    from CrowdStrikeFalcon import ODS_get_scheduled_scans_by_id_request

    ids_list = ['<id1>', '<id2>', '<id3>']
    ids_string = 'ids=<id1>&ids=<id2>&ids=<id3>'

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')

    ODS_get_scheduled_scans_by_id_request(ids_list)
    http_request.assert_called_with('GET', f'/ods/entities/scheduled-scans/v1?{ids_string}')


def test_map_scheduled_scan_resource_to_UI(mocker):
    """
    Test map_scan_resource_to_UI.

    Given
        - A dictionary response from /ods/entities/scheduled-scans.

    When
        - The user runs the "cs-falcon-ods-query-scheduled-scan" command

    Then
        - Return a dict with keys corresponding the cs-falcon UI.
    """
    from CrowdStrikeFalcon import map_scheduled_scan_resource_to_UI

    resource = {
        "id": "9055945bdfbc4b42bf7c9c16976186ca",
        "cid": "20879a8064904ecfbb62c118a6a19411",
        "description": "desc3456346",
        "scan_inclusions": [
            "*"
        ],
        "initiated_from": "cloud_scheduled",
        "quarantine": True,
        "cpu_priority": 2,
        "preemption_priority": 15,
        "metadata": [
            {
                "host_id": "046761c46ec84f40b27b6f79ce7cd32c",
                "last_updated": "2023-05-01T13:54:48.51553853Z"
            }
        ],
        "status": "scheduled",
        "host_groups": [
            "7471ba0636b34cbb8c65fae7979a6a9b"
        ],
        "endpoint_notification": True,
        "pause_duration": 2,
        "max_duration": 2,
        "max_file_size": 60,
        "sensor_ml_level_detection": 2,
        "sensor_ml_level_prevention": 2,
        "cloud_ml_level_detection": 2,
        "cloud_ml_level_prevention": 2,
        "policy_setting": [
            26439818674573,
        ],
        "schedule": {
            "start_timestamp": "2023-06-15T15:57",
            "interval": 0
        },
        "created_on": "2023-05-01T13:54:48.51553853Z",
        "created_by": "f7acf1bd5d3d4b40afe77546cbbaefde",
        "last_updated": "2023-05-01T13:54:48.51553853Z",
        "deleted": False
    }

    mapped_resource = {
        'ID': '9055945bdfbc4b42bf7c9c16976186ca',
        'Hosts targeted': 1,
        'Description': 'desc3456346',
        'Host groups': ['7471ba0636b34cbb8c65fae7979a6a9b'],
        'Start time': '2023-06-15T15:57',
        'Created by': 'f7acf1bd5d3d4b40afe77546cbbaefde',
    }

    output = map_scheduled_scan_resource_to_UI(resource)

    assert output == mapped_resource


@pytest.mark.parametrize(
    'input_params, call_params',
    (
        ({'key1': 'val1', 'key2': None}, 'key1=val1'),
        ({'key1': 'val1', 'key2': 'val2'}, 'key1=val1&key2=val2')
    )
)
def test_ODS_query_scan_hosts_request(mocker, input_params, call_params):
    """
    Test ODS_query_scan_hosts_request.

    Given
        - A request for a list of ODS endpoint scan hosts by id.

    When
        - The user runs the "cs-falcon-ods-query-scan-host" command without specifying ids.

    Then
        - Call /ods/queries/scan-hosts/v1 with a filter, limit and offset if given and return the ids in response.
    """

    from CrowdStrikeFalcon import ODS_query_scan_hosts_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_query_scan_hosts_request(**input_params)
    http_request.assert_called_with('GET', f'/ods/queries/scan-hosts/v1?{call_params}')


def test_ODS_get_scan_hosts_by_id_request(mocker):
    """
    Test ODS_get_scan_hosts_by_id_request.

    Given
        - A request for info on ODS endpoint scan hosts.

    When
        - The user runs the "cs-falcon-ods-query-scan-hosts" command and we obtain a non-empty list of ids.

    Then
        - Call /ods/entities/scan-hosts/v1 with the ids and return the response.
    """

    from CrowdStrikeFalcon import ODS_get_scan_hosts_by_id_request

    ids_list = ['<id1>', '<id2>', '<id3>']
    ids_string = 'ids=<id1>&ids=<id2>&ids=<id3>'

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')

    ODS_get_scan_hosts_by_id_request(ids_list)
    http_request.assert_called_with('GET', f'/ods/entities/scan-hosts/v1?{ids_string}')


def test_map_scan_host_resource_to_UI(mocker):
    """
    Test map_scan_resource_to_UI.

    Given
        - A dictionary response from /ods/entities/scan-hosts.

    When
        - The user runs the "cs-falcon-ods-query-scan-host" command

    Then
        - Return a dict with keys corresponding the cs-falcon UI.
    """
    from CrowdStrikeFalcon import map_scan_host_resource_to_UI

    resource = {
        "id": "185a0ad5e159418e8927d956c1a793d8",
        "cid": "3c74ca9ad4k43592ea2adf4ca94k4359",
        "scan_id": "fadde07ee8a44a07988e009b3152e339",
        "profile_id": "ddf8914cca5f4ac595272fe8122e308f",
        "host_id": "82395m302t8zea2u25978416be1973c5",
        "host_scan_id": "7e80aa16a44d30cb819e27144d2603b0",
        "filecount": {
            "scanned": 1021,
            "malicious": 104,
            "quarantined": 0,
            "skipped": 9328
        },
        "status": "completed",
        "severity": 70,
        "started_on": "2022-11-01T18:54:59.39861174Z",
        "completed_on": "2022-11-01T19:08:17.903700092Z",
        "last_updated": "2022-11-01T19:08:17.903732519Z"
    }

    mapped_resource = {
        'ID': "185a0ad5e159418e8927d956c1a793d8",
        'Scan ID': "fadde07ee8a44a07988e009b3152e339",
        'Host ID': "82395m302t8zea2u25978416be1973c5",
        'Filecount': {
            "scanned": 1021,
            "malicious": 104,
            "quarantined": 0,
            "skipped": 9328
        },
        'Status': "completed",
        'Severity': 70,
        'Started on': "2022-11-01T18:54:59.39861174Z",
    }

    output = map_scan_host_resource_to_UI(resource)

    assert output == mapped_resource


@pytest.mark.parametrize(
    'input_params, call_params',
    (
        ({'key1': 'val1', 'key2': None}, 'key1=val1'),
        ({'key1': 'val1', 'key2': 'val2'}, 'key1=val1&key2=val2')
    )
)
def test_ODS_query_malicious_files_request(mocker, input_params, call_params):
    """
    Test ODS_query_malicious_files_request.

    Given
        - A request for a list of ODS endpoint malicious files by id.

    When
        - The user runs the "cs-falcon-ods-query-malicious-file" command without specifying ids.

    Then
        - Call /ods/queries/malicious-files/v1 with a filter, limit and offset if given and return the ids in response.
    """

    from CrowdStrikeFalcon import ODS_query_malicious_files_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_query_malicious_files_request(**input_params)
    http_request.assert_called_with('GET', f'/ods/queries/malicious-files/v1?{call_params}')


def test_ODS_get_malicious_files_by_id_request(mocker):
    """
    Test ODS_get_malicious_files_by_id_request.

    Given
        - A request for info on ODS endpoint malicious files.

    When
        - The user runs the "cs-falcon-ods-query-malicious-files" command and we obtain a non-empty list of ids.

    Then
        - Call /ods/entities/malicious-files/v1 with the ids and return the response.
    """

    from CrowdStrikeFalcon import ODS_get_malicious_files_by_id_request

    ids_list = ['<id1>', '<id2>', '<id3>']
    ids_string = 'ids=<id1>&ids=<id2>&ids=<id3>'

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')

    ODS_get_malicious_files_by_id_request(ids_list)
    http_request.assert_called_with('GET', f'/ods/entities/malicious-files/v1?{ids_string}')


def test_map_malicious_file_resource_to_UI(mocker):
    """
    Test map_scan_resource_to_UI.

    Given
        - A dictionary response from /ods/entities/malicious-files.

    When
        - The user runs the "cs-falcon-ods-query-malicious-file" command

    Then
        - Return a dict with keys corresponding the cs-falcon UI.
    """
    from CrowdStrikeFalcon import map_malicious_file_resource_to_UI

    resource = {
        "id": "d684849d4cea435daec706e473743863",
        "cid": "91a0649f84749a38f6d939423bed5576",
        "scan_id": "81c8009a59be4570b5c66f8946559205",
        "host_id": "3c7be1c5ea21849fa5c74ca9842f46a9",
        "host_scan_id": "4f9fea030a0626ed4dc53a7dec70a100",
        "filepath": "C:\\\\Windows\\Malicious\\Mimikatz_newzipp\\Mimikatz\\x86\\mimilib.dll",
        "filename": "mimilib.dll",
        "hash": "9ff1a527861a69b436b51a8d464aaee8d416e39ff1a52aee16e39b436b564a78",
        "pattern_id": 4004,
        "severity": 70,
        "quarantined": True,
        "last_updated": "2022-11-01T17:06:18.900620631Z"
    }
    mapped_resource = {
        'ID': 'd684849d4cea435daec706e473743863',
        'Scan id': '81c8009a59be4570b5c66f8946559205',
        'Filename': 'mimilib.dll',
        'Hash': '9ff1a527861a69b436b51a8d464aaee8d416e39ff1a52aee16e39b436b564a78',
        'Severity': 70,
        'Last updated': '2022-11-01T17:06:18.900620631Z',
    }

    output = map_malicious_file_resource_to_UI(resource)

    assert output == mapped_resource


@pytest.mark.parametrize(
    'args, is_scheduled, expected_result',
    (
        ({'quarantine': 'false', 'schedule_interval': 'every other week',
          'schedule_start_timestamp': 'tomorrow'}, True, {'quarantine': False}),
        ({'cpu_priority': 'Low', 'max_duration': 1}, False, {'cpu_priority': 2, 'max_duration': 1}),
    )
)
def test_make_create_scan_request_body(args, is_scheduled, expected_result):
    """
    Test make_create_scan_request_body.

    Given
        - Arguments to create a scan/scheduled-scan.

    When
        - The user runs the "cs-falcon-ods-create-scan" command

    Then
        - Return a dict to send as the body for a create scan request.
    """

    from CrowdStrikeFalcon import make_create_scan_request_body

    output = make_create_scan_request_body(args, is_scheduled)

    if is_scheduled:
        assert 'hosts' not in output
        assert isinstance(output['schedule']['interval'], int)  # function doesn't enforce this
    else:
        assert 'hosts' in output
        assert 'schedule' not in output

    for key, value in expected_result.items():
        assert output[key] == value


@pytest.mark.parametrize(
    'args, is_error, expected_error_info',
    (
        ({}, True, 'MUST set either hosts OR host_groups.'),
        ({'hosts': 'john doe'}, True, 'MUST set either file_paths OR scan_inclusions.'),
        ({'hosts': 'john doe', 'file_paths': '*'}, False, None),
    )
)
def test_ODS_verify_create_scan_command(args, is_error, expected_error_info):
    """
    Test ODS_verify_create_scan_command.

    Given
        - Arguments to create a scan/scheduled-scan.

    When
        - The user runs the "cs-falcon-ods-create-scan" command

    Then
        - Return a dict to send as the body for a create scan request.
    """
    from CrowdStrikeFalcon import ODS_verify_create_scan_command

    if is_error:
        with pytest.raises(DemistoException) as error_info:
            ODS_verify_create_scan_command(args)
        assert str(error_info.value) == expected_error_info
    else:
        ODS_verify_create_scan_command(args)


def test_cs_falcon_ods_create_scan_command(mocker):
    """
    Test cs_falcon_ods_create_scan_command.

    Given
        - Arguments to create a scan.

    When
        - The user runs the "cs-falcon-ods-create-scan" command

    Then
        - Create an ODS scan.
    """

    from CrowdStrikeFalcon import cs_falcon_ods_create_scan_command

    mocker.patch('CrowdStrikeFalcon.ods_create_scan', return_value={'id': 'random_id'})
    query_scans_command = mocker.patch('CrowdStrikeFalcon.cs_falcon_ODS_query_scans_command')

    cs_falcon_ods_create_scan_command({'interval_in_seconds': 1, 'timeout_in_seconds': 1})

    query_scans_command.assert_called_with({
        'ids': 'random_id',
        'wait_for_result': True,
        'interval_in_seconds': 1,
        'timeout_in_seconds': 1,
    })


def test_cs_falcon_ods_create_scheduled_scan_command(mocker):
    """
    Test cs_falcon_ods_create_scheduled_scan_command.

    Given
        - Arguments to create a scheduled-scan.

    When
        - The user runs the "cs-falcon-ods-create-scheduled-scan" command

    Then
        - Create a scheduled scan.
    """

    from CrowdStrikeFalcon import cs_falcon_ods_create_scheduled_scan_command

    mocker.patch('CrowdStrikeFalcon.ods_create_scan', return_value={'id': 'random_id'})
    result = cs_falcon_ods_create_scheduled_scan_command(
        {'quarantine': 'false', 'schedule_interval': 'every other week'})
    assert result.readable_output == 'Successfully created scheduled scan with ID: random_id'


@pytest.mark.parametrize(
    'args, is_scheduled, body',
    (
        ({'quarantine': 'false', 'schedule_interval': 'every other week',
          'schedule_start_timestamp': 'tomorrow'}, True,
         {'quarantine': False, 'schedule': {'interval': 14, 'start_timestamp': '2020-09-27T17:22'}}),
        ({'cpu_priority': 'Low'}, False, {'cpu_priority': 2}),
    )
)
@freeze_time("2020-09-26 17:22:13 UTC")
def test_ODS_create_scan_request(mocker, args, is_scheduled, body):
    """
    Test ODS_create_scan_request.

    Given
        - Arguments to create a scan/scheduled-scan.

    When
        - The user runs the "cs-falcon-ods-create-scan" command

    Then
        - Create a scan/scheduled-scan.
    """

    from CrowdStrikeFalcon import ODS_create_scan_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_create_scan_request(args, is_scheduled)
    http_request.assert_called_with('POST', f'/ods/entities/{"scheduled-scans" if is_scheduled else "scans"}/v1', json=body)


@pytest.mark.parametrize(
    'ids, scans_filter, url_params',
    (
        (['id1', 'id2'], None, 'ids=id1&ids=id2'),
        ([], 'key1:val1+key2:val2', 'filter=key1:val1%2Bkey2:val2'),
        (['id1', 'id2'], 'key1:val1+key2:val2', 'ids=id1&ids=id2&filter=key1:val1%2Bkey2:val2'),
    )
)
def test_ODS_delete_scheduled_scans_request(mocker, ids, scans_filter, url_params):
    """
    Test ODS_delete_scheduled_scans_request.

    Given
        - Arguments to delete a scheduled-scans.

    When
        - The user runs the "cs-falcon-ods-delete-scheduled-scan" command

    Then
        - Delete ODS scheduled scans.
    """

    from CrowdStrikeFalcon import ODS_delete_scheduled_scans_request

    http_request = mocker.patch('CrowdStrikeFalcon.http_request')
    ODS_delete_scheduled_scans_request(ids, scans_filter)
    http_request.assert_called_with('DELETE', f'/ods/entities/scheduled-scans/v1?{url_params}', status_code=500)


class mocker_gql_client:
    def __init__(self, mock_responses, expected_after):
        self.mock_responses = mock_responses
        self.expected_after = expected_after
        self.index = 0

    def execute(self, idp_query, variable_values):
        if 'after' not in variable_values or self.expected_after == variable_values.get('after', ""):
            response = self.mock_responses[self.index]
            self.index += 1
            return response
        return None


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_identity_entities_command(mocker, test_case):
    """
        Given:
        - test case that point to the relevant test case in the json test data which include:
          args, response mock, expected_after, expected_raw_response_len, expected hr, and expected_ec.
        - Case 1: args with limit=1, some filter args, mock_response with 1 identity entity, and an empty expected_after
        - Case 2: args with limit=50, page=size=1, page=2 mock_response with 2 response each have 1 identity entity,
        and an empty expected_after that matches the endCursor of the first response.

        When:
        - Running list_identity_entities_command.

        Then:
        - Ensure that the response was parsed correctly and right HR, raw_response, and EC are returned.
        - Case 1: Should return the parsed identity from the response and 1 response in the rew_response list.
        - Case 2: Should return onle the second identity entity, and have 2 responses in the rew_response list.
    """
    from CrowdStrikeFalcon import list_identity_entities_command
    import CrowdStrikeFalcon
    test_data = load_json("./test_data/test_list_identity_entities_command.json").get(test_case, {})
    expected_after = test_data.get('expected_after', "")
    mock_responses = test_data.get('mock_responses', "")
    mock_client = mocker_gql_client(mock_responses, expected_after)
    mocker.patch.object(CrowdStrikeFalcon, "create_gql_client", return_value=mock_client)
    args = test_data.get("args", {})
    command_results = list_identity_entities_command(args)
    assert test_data.get('expected_hr') == command_results.readable_output
    assert test_data.get('expected_ec') == command_results.outputs
    assert test_data.get('expected_res_len') == len(command_results.raw_response)


@pytest.mark.parametrize("timeout, expected_timeout", [(60, 60), (None, 30)])
def test_run_batch_write_cmd_timeout_argument(mocker, timeout, expected_timeout):
    """
    Given
        - Different timeout argument
    When
        - Run the run_batch_write_cmd function
    Then
        - Asserst the expected timeout called with the http request function
    """
    from CrowdStrikeFalcon import run_batch_write_cmd
    batch_id = '12345'
    command_type = 'ls'
    full_command = 'ls -l'
    request_mock = mocker.patch('CrowdStrikeFalcon.http_request', return_value={})
    run_batch_write_cmd(batch_id, command_type, full_command, timeout=timeout)
    assert request_mock.call_args[1].get('params').get('timeout') == expected_timeout


def test_list_detection_summaries_command_no_results(mocker):
    """
    Test cs-falcon-list-detection-summaries when no detections found

    Given:
     - There is no detection in the system
    When:
     - Searching for detections using cs-falcon-list-detection-summaries command
     - The server returns empty list
    Then:
     - The command not fails
    """
    from CrowdStrikeFalcon import list_detection_summaries_command
    response = {'meta': {'query_time': 0.028057688, }, 'resources': [], 'errors': []}
    mocker.patch('CrowdStrikeFalcon.http_request', return_value=response)
    res = list_detection_summaries_command()
    assert res.readable_output == '### CrowdStrike Detections\n**No entries.**\n'


def test_sort_incidents_summaries_by_ids_order():
    """
    Test sort incidents in the order by incidents ids

    Given:
     - Full incidents response, sorted ids
    When:
     - Searching for detections using fetch_incidents()
    Then:
     - The incidents returned in sorted order
    """
    from CrowdStrikeFalcon import sort_incidents_summaries_by_ids_order
    full_incidents = [{"id": "2", "name": "test2"},
                      {"id": "3", "name": "test3"},
                      {"id": "1", "name": "test1"}]
    res = sort_incidents_summaries_by_ids_order(ids_order=["1", "2", "3"], full_incidents=full_incidents, id_field="id")
    assert res == [{"id": "1", "name": "test1"}, {"id": "2", "name": "test2"},
                   {"id": "3", "name": "test3"},
                   ]

import pytest
import os
import json
from urllib.parse import unquote
from _pytest.python_api import raises

import demistomock as demisto
from CommonServerPython import (outputPaths, entryTypes, DemistoException, IncidentStatus, ScheduledCommand,
                                CommandResults, requests)
from test_data import input_data
from freezegun import freeze_time
from typing import Any
from pytest_mock import MockerFixture
from unittest.mock import ANY

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


def test_detection_to_incident_context():
    from CrowdStrikeFalcon import detection_to_incident_context
    res = detection_to_incident_context(input_data.response_idp_detection.copy(), "IDP Detection", 'created_timestamp')
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
                'BatchID': 'batch_id',
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
                'BatchID': 'batch_id',
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
                'BatchID': 'batch_id',
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
    mocker.patch.object(demisto, 'debug', return_value=None)
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
        requests_mock.get(f'{SERVER_URL}/detects/queries/detects/v1', json={'resources': ['ldt:1', 'ldt:2'],
                                                                            'meta': {'pagination': {'total': 2}}})
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:1',
                                                'created_timestamp': '2020-09-04T09:16:11.000000Z',
                                                'max_severity_displayname': 'Low'},
                                               {'detection_id': 'ldt:2',
                                                'created_timestamp': '2020-09-04T09:20:11.000000Z',
                                                'max_severity_displayname': 'Low'}]})
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
                            return_value={'first_behavior_detection_time': '2020-09-04T09:16:10.000000Z',
                                          'detection_offset': 2,
                                          'first_behavior_incident_time': '2020-09-04T09:22:10.000000Z',
                                          'last_fetched_incident': '3',
                                          'incident_offset': 4,
                                          })
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0] == [
            {'time': '2020-09-04T09:16:10Z'}, {'time': '2020-09-04T09:22:10Z'}, {}, {}, {}, {}, {}, {}]

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
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{'time': '2020-09-04T09:16:10.000000Z',
                                          'offset': 2}, {}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:1',
                                                'created_timestamp': '2020-09-04T09:16:11.000000Z',
                                                'max_severity_displayname': 'Low'}],
                                 })
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0][0] == {
            'time': '2020-09-04T09:16:11.000000Z', 'limit': 2, 'offset': 0, "found_incident_ids":
                {'Detection ID: ldt:1': 1599210970}}

    @freeze_time("2020-09-04T09:16:10Z")
    def test_fetch_with_offset(self, set_up_mocks, mocker, requests_mock):
        """
        Tests the correct flow of fetch with offset
        Given:
            `getLastRun` which holds  `first_behavior_time` and `offset`
        When:
            2 result is returned (which is less than the total which is 4)
        Then:
            - The offset increases to 2 in the next run, and the last time remains
            - In the next call, the offset will be reset to 0 and the last time will be the latest detection time

        """
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
        # mock the total number of detections to be 4, so offset will be set
        requests_mock.get(f'{SERVER_URL}/detects/queries/detects/v1', json={'resources': ['ldt:1', 'ldt:2'],
                                                                            'meta': {'pagination': {'total': 4}}})

        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{'time': '2020-09-04T09:16:10.000000Z',
                                          'offset': 0}, {}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:1',
                                                'created_timestamp': '2020-09-04T09:16:11.000000Z',
                                                'max_severity_displayname': 'Low'}],
                                 })
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        # the offset should be increased to 2, and the time should be stay the same
        expected_last_run = {
            'time': '2020-09-04T09:16:10.000000Z', 'limit': 2, 'offset': 2, "found_incident_ids":
                {'Detection ID: ldt:1': 1599210970}}
        assert demisto.setLastRun.mock_calls[0][1][0][0] == expected_last_run

        requests_mock.get(f'{SERVER_URL}/detects/queries/detects/v1', json={'resources': ['ldt:3', 'ldt:4'],
                                                                            'meta': {'pagination': {'total': 4}}})

        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[expected_last_run, {}, {}])

        requests_mock.post(f'{SERVER_URL}/detects/entities/summaries/GET/v1',
                           json={'resources': [{'detection_id': 'ldt:2',
                                                'created_timestamp': '2020-09-04T09:16:13.000000Z',
                                                'max_severity_displayname': 'Low'}],
                                 })

        fetch_incidents()
        # the offset should be 0 because all detections were fetched, and the time should update to the latest detection
        assert demisto.setLastRun.mock_calls[1][1][0][0] == {
            'time': '2020-09-04T09:16:13.000000Z', 'limit': 2, 'offset': 0, "found_incident_ids":
                {'Detection ID: ldt:1': 1599210970,
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
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
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
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
        from CrowdStrikeFalcon import fetch_incidents
        mocker.patch.object(demisto, 'getLastRun', return_value=[{'time': '2020-09-04T09:16:10Z'}, {}, {}])

        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:1', 'ldt:2'],
                                                                                'meta': {'pagination': {'total': 2}}})
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1', 'start': '2020-09-04T09:16:11Z'},
                                               {'incident_id': 'ldt:2', 'start': '2020-09-04T09:16:11Z'}]})
        requests_mock.get(f'{SERVER_URL}/alerts/queries/alerts/v1', json={'resources': ['a:ind:1', 'a:ind:2']})
        requests_mock.post(f'{SERVER_URL}/alerts/entities/alerts/v1',
                           json={'resources': [{'composite_id': 'a:ind:1', 'start_time': '2020-09-04T09:16:11.000Z',
                                                "created_timestamp": "2020-09-04T09:16:11.000Z"},
                                               {'composite_id': 'a:ind:2', 'start_time': '2020-09-04T09:16:11.000Z',
                                                "created_timestamp": "2020-09-04T09:16:11.000Z"}]})

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
        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:1', 'ldt:2'],
                                                                                'meta': {'pagination': {'total': 2}}})
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
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
        mocker.patch.object(demisto, 'getLastRun', return_value=[{}, {'time': '2020-09-04T09:16:10Z',
                                                                      'offset': 2}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1', 'start': '2020-09-04T09:16:11Z'}]})
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        assert demisto.setLastRun.mock_calls[0][1][0][1] == {'time': '2020-09-04T09:16:11Z',
                                                             'limit': 2,
                                                             'offset': 0,
                                                             'found_incident_ids': {'Incident ID: ldt:1': 1598462533}}

    @freeze_time("2020-09-04T09:16:10.000000Z")
    def test_fetch_with_offset(self, set_up_mocks, mocker, requests_mock):
        """
        Tests the correct flow of fetch with offset
        Given:
            `getLastRun` which holds  `first_behavior_time` and `offset`
        When:
            2 result is returned (which is less than the total which is 4)
        Then:
            - The offset increases to 2 in the next run, and the last time remains
            - In the next call, the offset will be reset to 0 and the last time will be the latest detection time

        """
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
        # mock the total number of detections to be 4, so offset will be set
        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:1', 'ldt:2'],
                                                                                'pagination': {'meta': {'total': 4}}})

        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{}, {'time': '2020-09-04T09:16:10Z',
                                          'offset': 0}, {}])
        # Override post to have 1 results so FETCH_LIMIT won't be reached
        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:1',
                                                'start': '2020-09-04T09:16:11Z',
                                                'max_severity_displayname': 'Low'}],
                                 })
        from CrowdStrikeFalcon import fetch_incidents
        fetch_incidents()
        # the offset should be increased to 2, and the time should be stay the same
        expected_last_run = {
            'time': '2020-09-04T09:16:10Z', 'limit': 2, 'offset': 2, "found_incident_ids": {'Incident ID: ldt:1': 1599210970}}
        assert demisto.setLastRun.mock_calls[0][1][0][1] == expected_last_run

        requests_mock.get(f'{SERVER_URL}/incidents/queries/incidents/v1', json={'resources': ['ldt:3', 'ldt:4'],
                                                                                'meta': {'pagination': {'total': 4}}})

        mocker.patch.object(demisto, 'getLastRun',
                            return_value=[{}, expected_last_run, {}])

        requests_mock.post(f'{SERVER_URL}/incidents/entities/incidents/GET/v1',
                           json={'resources': [{'incident_id': 'ldt:2',
                                                'start': '2020-09-04T09:16:13Z',
                                                'max_severity_displayname': 'Low'}],
                                 })

        fetch_incidents()
        # the offset should be 0 because all detections were fetched, and the time should update to the latest detection
        assert demisto.setLastRun.mock_calls[1][1][0][1] == {
            'time': '2020-09-04T09:16:13Z', 'limit': 2, 'offset': 0, "found_incident_ids": {'Incident ID: ldt:1': 1599210970,
                                                                                            'Incident ID: ldt:2': 1599210970}}

    def test_incident_type_in_fetch(self, set_up_mocks, mocker):
        """Tests the addition of incident_type field to the context
        Given:
            Old getLastRun which holds `first_behavior_time` and `last_incident_id`
        When:
            2 results are returned (which equals the FETCH_LIMIT)
        Then:
            "incident_type": "incident" is in raw result returned by the indicator
        """
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
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
    assert '| 2020-10-01T09:09:04Z | Eicar file |  | 4f8c43311k1801ca4359fc07t319610482c2003mcde8934d5412b1781e841e9r |' \
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


def test_upload_custom_ioc_command_filename(requests_mock):
    """
    Test that providing a filename to custom ioc works as expected

    Given:
        - A filename attached to a custom IOC

    When:
        - The user tries to upload a custom IOC with a filename

    Then:
        - Make sure that the filename is included in the request to CrowdStrike
    """
    from CrowdStrikeFalcon import upload_custom_ioc_command
    mock = requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        status_code=200,
        json={"result": "ok"}
    )

    upload_custom_ioc_command(
        action='prevent',
        severity='high',
        platforms='mac,linux',
        ioc_type="sha256",
        value="testsha256",
        file_name="test.txt"
    )

    body = mock.last_request.json()
    assert body['indicators'][0]['metadata']['filename'] == "test.txt"


def test_upload_custom_ioc_command_filename_nosha5(requests_mock):
    """
    Test that providing a filename to non-hash custom ioc being ignored

    Given:
        - A filename attached to a custom non hash IOC

    When:
        - The user tries to upload a custom non hash IOC with a filename

    Then:
        - Make sure that the filename is ignored in the request to CrowdStrike
    """
    from CrowdStrikeFalcon import upload_custom_ioc_command
    mock = requests_mock.post(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        status_code=200,
        json={"result": "ok"}
    )
    upload_custom_ioc_command(
        action='prevent',
        severity='high',
        platforms='mac,linux',
        ioc_type="ip",
        value="someip",
        file_name="test.txt"
    )
    assert 'metadata' not in mock.last_request.json()['indicators'][0]


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


def test_update_custom_ioc_command_filename(requests_mock):
    """
    Test that providing a filename to custom ioc works as expected

    Given:
        - A filename attached to a custom IOC

    When:
        - The user tries to update a custom IOC with a filename

    Then:
        - Make sure that the filename is included in the request to CrowdStrike
    """
    from CrowdStrikeFalcon import update_custom_ioc

    mock = requests_mock.patch(
        f'{SERVER_URL}/iocs/entities/indicators/v1',
        status_code=200,
        json={"result": "ok"}
    )

    update_custom_ioc(
        ioc_id="3",
        file_name="test.txt"
    )

    body = mock.last_request.json()
    assert body['indicators'][0]['metadata']['filename'] == "test.txt"


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


def test_get_ioc_device_count_command_rate_limit_exceeded(requests_mock):
    """
    Test cs-falcon-device-count-ioc with rate limit exceeded

    Given
    - There is a rate limit in CS side
    When
    - The user is running cs-falcon-device-count-ioc with md5:testmd5
    Then
    - ensure the correct count is returned by the offset mechanism
    """
    from CrowdStrikeFalcon import get_ioc_device_count_command
    response = {'resources': [{'id': 'md5:testmd5', 'type': 'md5',
                               'value': 'testmd5', 'limit_exceeded': 'true', 'device_count': 1}]}
    indicators_queries_res = {'resources': ["res_1", "res_2", "res_3"]}
    indicators_queries_res_with_offset = indicators_queries_res | {'meta': {'pagination': {'offset': 1}}}
    requests_mock.get(
        f'{SERVER_URL}/indicators/aggregates/devices-count/v1',
        json=response,
        status_code=200,
    )
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/devices/v1',
        json=indicators_queries_res_with_offset,
        status_code=200,
    )
    requests_mock.get(
        f'{SERVER_URL}/indicators/queries/devices/v1?type=md5&value=testmd5&offset=1',
        json=indicators_queries_res,
        status_code=200,
    )

    res = get_ioc_device_count_command(ioc_type='md5', value='testmd5')

    assert 'device count: **6**' in res['HumanReadable']


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
    device_context = {'ID': '15dbb9d8f06b45fe9f61eb46e829d986', 'ExternalIP': '1.1.1.1', 'MacAddress': '42-01-0a-80-00-07',
                      'Hostname': 'FALCON-CROWDSTR', 'FirstSeen': '2020-02-10T12:40:18Z',
                      'LastSeen': '2021-04-05T13:48:12Z', 'LocalIP': '1.1.1.1', 'OS': 'Windows Server 2019',
                      'Status': 'normal'}
    endpoint_context = {'Hostname': 'FALCON-CROWDSTR', 'ID': '15dbb9d8f06b45fe9f61eb46e829d986', 'IPAddress': '1.1.1.1',
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
    requests_mock.post(
        f'{SERVER_URL}/devices/entities/devices/v2',
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
    endpoint_context = {'Hostname': 'FALCON-CROWDSTR', 'ID': '15dbb9d8f06b45fe9f61eb46e829d986', 'IPAddress': '1.1.1.1',
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
    requests_mock.post(
        f'{SERVER_URL}/devices/entities/devices/v2',
        json=test_data2,
        status_code=200,
    )

    mocker.patch.object(demisto, 'args', return_value={'id': 'identifier_numbe', 'hostname': 'falcon-crowdstr'})

    outputs = get_endpoint_command()
    result = outputs[0].to_context()
    context = result.get('EntryContext')

    api_query = "filter=device_id:'identifier_numbe',hostname:'falcon-crowdstr'&limit=50&offset=0&sort="
    assert unquote(query_mocker.last_request.query) == api_query
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


def test_resolve_incidents(mocker):
    """
    Given
     -
    When
     - Calling resolve incident command
    Then

     """
    import CrowdStrikeFalcon
    http_request_mock = mocker.patch.object(CrowdStrikeFalcon, 'http_request')
    CrowdStrikeFalcon.resolve_incident_command(ids=['test_id'], user_uuid='test',
                                               status='New', add_tag='test', remove_tag='test', add_comment='test')
    assert http_request_mock.call_count == 1
    assert http_request_mock.call_args.kwargs == {
        "method": "POST",
        "url_suffix": "/incidents/entities/incident-actions/v1",
        "json": {
            "action_parameters": [
                {
                    "name": "update_status",
                    "value": "20"
                },
                {
                    "name": "update_assigned_to_v2",
                    "value": "test"
                },
                {
                    "name": "add_tag",
                    "value": "test"
                },
                {
                    "name": "delete_tag",
                    "value": "test"
                },
                {
                    "name": "add_comment",
                    "value": "test"
                }
            ],
            "ids": [
                "test_id"
            ]
        }
    }


@pytest.mark.parametrize('status, expected_status_api', [('New', "20"),
                                                         ('Reopened', "25"),
                                                         ('In Progress', "30"),
                                                         ('Closed', "40")])
def test_resolve_incidents_statuses(requests_mock, status, expected_status_api):
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


detections_legacy = {'resources': [
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

detections_new = {'resources': [
    {'behavior_id': 'example_behavior',
     'alert_ids': ['example_detection'],
     'incident_id': 'example_incident_id',
     'some_field': 'some_example',
     }
]}

DETECTION_FOR_INCIDENT_CASES = [
    (
        detections_legacy,
        True,
        ['a', 'b'],
        [
            {'incident_id': 'example_incident_id', 'behavior_id': 'example_behavior_1',
             'detection_ids': ['example_detection']},
            {'incident_id': 'example_incident_id', 'behavior_id': 'example_behavior_2',
             'detection_ids': ['example_detection2']}
        ],
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
    (
        detections_new,
        False,
        ['a', 'b'],
        [{'incident_id': 'example_incident_id', 'behavior_id': 'example_behavior',
          'detection_ids': ['example_detection']}
         ],
        [
            {'behavior_id': 'example_behavior',
             'alert_ids': ['example_detection'],
             'incident_id': 'example_incident_id',
             'some_field': 'some_example'}
        ],
        'CrowdStrike.IncidentDetection',
        '### Detection For Incident\n|behavior_id|detection_ids|incident_id|\n|---|---|---|'
        '\n| example_behavior | example_detection | example_incident_id |\n',
    ),
    ({'resources': []}, False, [], None, None, None, 'Could not find behaviors for incident zz')
]


@pytest.mark.parametrize(
    'detections, use_legacy, resources, expected_outputs, expected_raw, expected_prefix, expected_md',
    DETECTION_FOR_INCIDENT_CASES)
def test_get_detection_for_incident_command(mocker, detections, use_legacy, resources, expected_outputs, expected_raw,
                                            expected_prefix,
                                            expected_md):
    """
    Given: An incident ID.
    When: When running cs-falcon-get-detections-for-incident command in legacy and new API.
    Then: validates the created command result contains the correct data (whether found or not).
    """

    from CrowdStrikeFalcon import get_detection_for_incident_command

    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', new=use_legacy)

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
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
    from CrowdStrikeFalcon import get_remote_data_command
    incident_entity = input_data.response_incident.copy()
    incident_entity['status'] = incident_status
    mocker.patch('CrowdStrikeFalcon.get_incidents_entities', return_value={'resources': [incident_entity]})
    detection_entity = input_data.response_detection.copy()
    detection_entity['status'] = detection_status
    mocker.patch('CrowdStrikeFalcon.get_detections_entities', return_value={'resources': [detection_entity]})
    reopen_statuses = 'New,In progress,True positive,False positive,Reopened,Ignored'
    mocker.patch.object(demisto, 'params', return_value={'close_incident': close_incident, 'reopen_statuses': reopen_statuses})

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
    assert find_incident_type(input_data.remote_detection_id) == IncidentType.LEGACY_ENDPOINT_DETECTION
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
                              'hosts.hostname': 'SFO-M-Y81WHJ', 'incident_type': 'incident', 'fine_score': 38,
                              'incident_id': 'inc:afb5d1512a00480f53e9ad91dc3e4b55:1cf23a95678a421db810e11b5db693bd'}


def test_get_remote_detection_data(mocker):
    """
    Given
        - a detection ID on the remote system
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - returns the relevant detection entity from the remote system with the relevant incoming mirroring fields
    """
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
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
                              'incident_type': 'detection',
                              'detection_id': 'ldt:15dbb9d8f06b89fe9f61eb46e829d986:528715079668',
                              'behaviors.display_name': 'SampleTemplateDetection'}


def test_get_remote_detection_data_for_multiple_types__idp(mocker):
    """
    Given
        - an idp detection ID on the remote system
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - returns the relevant detection entity from the remote system with the relevant incoming mirroring fields
    """
    from CrowdStrikeFalcon import get_remote_detection_data_for_multiple_types
    detection_entity = input_data.response_idp_detection.copy()
    mocker.patch('CrowdStrikeFalcon.get_detection_entities', return_value={'resources': [detection_entity.copy()]})
    mocker.patch.object(demisto, 'debug', return_value=None)
    mirrored_data, updated_object, detection_type = get_remote_detection_data_for_multiple_types(
        input_data.remote_idp_detection_id)
    detection_entity['severity'] = 2
    assert mirrored_data == detection_entity
    assert detection_type == 'IDP'
    assert updated_object == {'incident_type': 'IDP detection',
                              'status': 'closed',
                              'id': 'ind:20879a8064904ecfbb62c118a6a19411:C0BB6ACD-8FDC-4CBA-9CF9-EBF3E28B3E56'}


def test_get_remote_detection_data_for_multiple_types__mobile_detection(mocker):
    """
    Given
        - an idp detection ID on the remote system
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - returns the relevant detection entity from the remote system with the relevant incoming mirroring fields
    """
    from CrowdStrikeFalcon import get_remote_detection_data_for_multiple_types
    detection_entity = input_data.response_mobile_detection.copy()
    mocker.patch('CrowdStrikeFalcon.get_detection_entities', return_value={'resources': [detection_entity.copy()]})
    mocker.patch.object(demisto, 'debug', return_value=None)
    mirrored_data, updated_object, detection_type = get_remote_detection_data_for_multiple_types(
        input_data.remote_mobile_detection_id)
    detection_entity['severity'] = 90
    assert mirrored_data == detection_entity
    assert detection_type == 'Mobile'
    assert updated_object == {'incident_type': 'MOBILE detection',
                              'status': 'new',
                              'mobile_detection_id': '1111111111111111111'}


def test_get_remote_detection_data_for_multiple_types__endpoint_detection(mocker):
    """
    Given
        - an endpoint detection ID on the remote system
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - returns the relevant detection entity from the remote system with the relevant incoming mirroring fields
    """
    from CrowdStrikeFalcon import get_remote_detection_data_for_multiple_types
    detection_entity = input_data.response_detection_new_version.copy()
    mocker.patch('CrowdStrikeFalcon.get_detection_entities', return_value={'resources': [detection_entity.copy()]})
    mocker.patch.object(demisto, 'debug', return_value=None)
    mirrored_data, updated_object, detection_type = get_remote_detection_data_for_multiple_types(
        input_data.remote_detection_id_new_version)
    detection_entity['severity'] = 90
    assert mirrored_data == detection_entity
    assert detection_type == 'Detection'
    assert updated_object == {'incident_type': 'detection',
                              'status': 'new',
                              'severity': 90}


@pytest.mark.parametrize('updated_object, entry_content, close_incident', input_data.set_xsoar_incident_entries_args)
def test_set_xsoar_entries__incident(mocker, updated_object, entry_content, close_incident):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
    When
        - running get_remote_data_command with changes to make on a incident
    Then
        - adds the relevant entry (closure/reopen) to the entries
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': close_incident})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = ['New', 'Reopened', 'In Progress']
    set_xsoar_entries(updated_object, entries, input_data.remote_incident_id, "Incident", reopen_statuses)
    if entry_content:
        assert entry_content in entries[0].get('Contents')
    else:
        assert entries == []


@pytest.mark.parametrize('updated_object', input_data.check_reopen_set_xsoar_incident_entries_args)
def test_set_xsoar_entries__reopen(mocker, updated_object):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
        - the reopen statuses set.
    When
        - running get_remote_data_command with changes to make on an incident
    Then
        - add the relevant entries only if the status is Reopened.
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = ['Reopened']  # Add a reopen entry only if the status in CS Falcon is reopened
    set_xsoar_entries(updated_object, entries, input_data.remote_incident_id, 'Incident', reopen_statuses)
    if updated_object.get('status') == 'Reopened':
        assert 'dbotIncidentReopen' in entries[0].get('Contents')
    else:
        assert entries == []


@pytest.mark.parametrize('updated_object', input_data.check_reopen_set_xsoar_incident_entries_args)
def test_set_xsoar_entries__empty(mocker, updated_object):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
        - empty reopen statuses set.
    When
        - running get_remote_data_command with reopen_statuses = []
    Then
        - A reopen entry wasn't added in any case.
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = []  # don't add a reopen entry in any case
    set_xsoar_entries(updated_object, entries, input_data.remote_incident_id, 'Incident', reopen_statuses)
    assert entries == []


@pytest.mark.parametrize('updated_object', input_data.check_reopen_set_xsoar_detections_entries_args)
def test_set_xsoar_detection_entries_empty_check(mocker, updated_object):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
        - empty reopen statuses set.
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - add the relevant entries only if the status is Reopened.
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = []  # don't add a reopen entry in any case
    set_xsoar_entries(updated_object, entries, input_data.remote_detection_id, 'Detection', reopen_statuses)
    assert entries == []


@pytest.mark.parametrize('updated_object', input_data.set_xsoar_idp_or_mobile_detection_entries)
def test_set_xsoar_entries___idp_or_mobile_detection(mocker, updated_object):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
        - the reopen statuses set.
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - add the relevant entries only if the status is Reopened.
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = ['Reopened']  # Add a reopen entry only if the status in CS Falcon is reopened
    set_xsoar_entries(updated_object, entries, input_data.remote_idp_detection_id, 'IDP', reopen_statuses)
    if updated_object.get('status') == 'reopened':
        assert 'dbotIncidentReopen' in entries[0].get('Contents')
    elif updated_object.get('status') == 'closed':
        assert 'dbotIncidentClose' in entries[0].get('Contents')
        assert 'closeReason' in entries[0].get('Contents')
        assert entries[0].get('Contents', {}).get('closeReason') == 'IDP was closed on CrowdStrike Falcon'
    else:
        assert entries == []


@pytest.mark.parametrize('updated_object', input_data.set_xsoar_idp_or_mobile_detection_entries)
def test_set_xsoar_entries__empty_reopen_statuses(mocker, updated_object):
    """
    Given
        - the incident status from the remote system
        - the close_incident parameter that was set when setting the integration
        - empty reopen statuses set.
    When
        - running get_remote_data_command with changes to make on a detection
    Then
        - add the relevant entries.
    """
    from CrowdStrikeFalcon import set_xsoar_entries
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    mocker.patch.object(demisto, 'debug', return_value=None)
    entries = []
    reopen_statuses = []  # don't add a reopen entry in any case
    set_xsoar_entries(updated_object, entries, input_data.remote_idp_detection_id, 'IDP', reopen_statuses)
    if updated_object.get('status') == 'closed':
        assert 'dbotIncidentClose' in entries[0].get('Contents')
        assert 'closeReason' in entries[0].get('Contents')
        assert entries[0].get('Contents', {}).get('closeReason') == 'IDP was closed on CrowdStrike Falcon'
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
          and get_detections_ids)
    When
        - running get_modified_remote_data_command
    Then
        - returns a list of incidents, detections, and idp detections IDs that were modified since the lastUpdate time
    """
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
    from CrowdStrikeFalcon import get_modified_remote_data_command
    mock_get_incidents = mocker.patch('CrowdStrikeFalcon.get_incidents_ids',
                                      return_value={'resources': [input_data.remote_incident_id]})
    mock_get_detections = mocker.patch('CrowdStrikeFalcon.get_fetch_detections',
                                       return_value={'resources': [input_data.remote_detection_id]})
    last_update = '2022-03-08T08:17:09Z'
    result = get_modified_remote_data_command({'lastUpdate': last_update})
    assert mock_get_incidents.call_args.kwargs['last_updated_timestamp'] == last_update
    assert mock_get_detections.call_args.kwargs['last_updated_timestamp'] == last_update
    assert result.modified_incident_ids == [input_data.remote_incident_id, input_data.remote_detection_id]


@pytest.mark.parametrize('status',
                         ['new', 'in_progress', 'true_positive', 'false_positive', 'ignored', 'closed', 'reopened'])
def test_update_detection_request_good__legacy(mocker, status):
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
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
    update_detection_request([input_data.remote_detection_id], status)
    assert mock_resolve_detection.call_args[1]['ids'] == [input_data.remote_detection_id]
    assert mock_resolve_detection.call_args[1]['status'] == status


@pytest.mark.parametrize('status',
                         ['new', 'in_progress', 'closed', 'reopened'])
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
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', False)
    update_detection_request([input_data.remote_detection_id], status)
    assert mock_resolve_detection.call_args[1]['ids'] == [input_data.remote_detection_id]
    assert mock_resolve_detection.call_args[1]['status'] == status


@pytest.mark.parametrize('status', ['other', ''])
def test_update_detection_request_bad__lagacy(status):
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


@pytest.mark.parametrize('status', ['true_positive', ''])
def test_update_detection_request_bad(status, mocker):
    """
    Given
        - list of detections IDs
        - status to change for the given detection in the remote system, which is not one of the permitted statuses
            'true_positive' is not a valid status for the new version of the API
    When
        - running update_remote_system_command
    Then
        - an exception is raised
    """
    from CrowdStrikeFalcon import update_detection_request
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', False)
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
        if to_mock == 'update_incident_request':
            assert mock_call.call_args_list[i].kwargs == call

        else:
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
    import CrowdStrikeFalcon

    mocker.patch.object(demisto, 'params', return_value={'close_in_cs_falcon': close_in_cs_falcon})
    mock_http_request = mocker.patch.object(CrowdStrikeFalcon, 'http_request')
    CrowdStrikeFalcon.update_remote_incident_status(delta, inc_status, input_data.remote_incident_id)
    if resolve_incident_status:
        expected_status_value = CrowdStrikeFalcon.STATUS_TEXT_TO_NUM[resolve_incident_status]
        assert mock_http_request.call_args_list[0].kwargs['json']['action_parameters'][0]['value'] == expected_status_value
    else:
        assert mock_http_request.call_count == 0


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
    import CrowdStrikeFalcon
    mock_update_incident_request = mocker.patch.object(CrowdStrikeFalcon, 'http_request')
    CrowdStrikeFalcon.remote_incident_handle_tags(tags, action_name, input_data.remote_incident_id)
    assert mock_update_incident_request.call_count == len(tags)
    if len(tags):
        assert mock_update_incident_request.call_args_list[0].kwargs['json']['action_parameters'][0]['name'] == action_name


def test_get_mapping_fields_command(mocker):
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command on the new version of the API
    Then
        - the result fits the expected mapping scheme
    """
    from CrowdStrikeFalcon import get_mapping_fields_command
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', False)
    result = get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == 'CrowdStrike Falcon Incident'
    assert result.scheme_types_mappings[0].fields.keys() == {'status', 'tag'}
    assert result.scheme_types_mappings[1].type_name == 'CrowdStrike Falcon Detection'
    assert result.scheme_types_mappings[1].fields.keys() == {'status'}
    assert result.scheme_types_mappings[2].type_name == 'CrowdStrike Falcon OFP Detection'
    assert result.scheme_types_mappings[2].fields.keys() == {'status'}
    assert result.scheme_types_mappings[3].type_name == 'CrowdStrike Falcon On-Demand Scans Detection'
    assert result.scheme_types_mappings[3].fields.keys() == {'status'}


def test_get_mapping_fields_command__legacy(mocker):
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command on the legacy version of the API
    Then
        - the result fits the expected mapping scheme
    """
    from CrowdStrikeFalcon import get_mapping_fields_command
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', True)
    result = get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == 'CrowdStrike Falcon Incident'
    assert result.scheme_types_mappings[0].fields.keys() == {'status', 'tag'}
    assert result.scheme_types_mappings[1].type_name == 'CrowdStrike Falcon Detection - LAGACY'
    assert result.scheme_types_mappings[1].fields.keys() == {'status'}
    assert len(result.scheme_types_mappings) == 2


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
        '### List Vulnerabilities\n'
        '|ID|Severity|Status|Base Score|Published Date|Impact Score|Exploitability Score|\n'
        '|---|---|---|---|---|---|---|\n'
        '| cveid1 | LOW | open | 3.3 | 2021-09-15T12:15:00Z |  |  |\n'
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


def assert_command_results(command_results_to_assert: CommandResults, expected_outputs: list | dict,
                           expected_outputs_key_field: str | list[str],
                           expected_outputs_prefix: str):
    """This function is used to assert the command results object returned from running command using mocked data.
    It checks the three important fields, which are:
    1. outputs
    2. outputs_key_field
    3. outputs_prefix

    Args:
        command_results_to_check (CommandResults): The command results object to assert.
        expected_outputs (list | dict): The expected outputs object.
        expected_outputs_key_field (str | list[str]): The expected outputs key field object.
        expected_outputs_prefix (str): The expected outputs prefix object.
    """
    assert command_results_to_assert.outputs == expected_outputs
    assert command_results_to_assert.outputs_key_field == expected_outputs_key_field
    assert command_results_to_assert. outputs_prefix == expected_outputs_prefix


class TestCSFalconCSPMListPolicyDetialsCommand:

    def test_http_request_with_status_code_400_500_207(self, mocker: MockerFixture):
        """
        Given:
            - Policy IDs to retrieve their details.
        When
            - Making a http request for the cs-falcon-cspm-list-policy-details command.
        Then
            - Validate that the http_request function accepts the status codes 500, 400, and 207,
            since we deal with them manually.
        """
        from CrowdStrikeFalcon import cspm_list_policy_details_request
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        cspm_list_policy_details_request(policy_ids=['1', '2'])
        assert http_request_mocker.call_args_list[0][1].get('status_code') == [500, 400, 207]

    def test_get_policy_details(self, mocker: MockerFixture):
        """
        Given:
            - Policy IDs to retrieve their details.
        When
            - Calling the cs-falcon-cspm-list-policy-details command.
        Then
            - Validate the data of the CommandResults object returned.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_list_policy_details_command
        raw_response = load_json('test_data/policy_details/policy_details_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        command_results = cs_falcon_cspm_list_policy_details_command(args={'policy_ids': '1,2'})
        expected_context_data = load_json('test_data/policy_details/policy_details_context_data.json')
        assert_command_results(command_results_to_assert=command_results, expected_outputs=expected_context_data,
                               expected_outputs_key_field='ID', expected_outputs_prefix='CrowdStrike.CSPMPolicy')

    def test_get_policy_details_error_500(self, mocker: MockerFixture):
        """
        Given
            - A wrong a policy id.
        When
            - Running the cs-falcon-cspm-list-policy-details command, and receiving a 500 status code.
        Then
            - Validate that we output an error with the correct message.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_list_policy_details_command
        raw_response = load_json('test_data/policy_details/policy_details_error_500_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        with pytest.raises(DemistoException) as e:
            cs_falcon_cspm_list_policy_details_command(args={'policy_ids': '12123123123123'})
        assert 'Perhaps the policy IDs are invalid?' in str(e)

    def test_get_policy_details_error_400(self, mocker: MockerFixture):
        """
        Given
            - A wrong a policy id.
        When
            - Running the cs-falcon-cspm-list-policy-details command, and receiving a 400 status code.
        Then
            - Validate that we output a warning with the correct message.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_list_policy_details_command
        raw_response = load_json('test_data/policy_details/policy_details_error_400_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        demisto_results_mocker = mocker.patch.object(demisto, 'results')
        command_results = cs_falcon_cspm_list_policy_details_command(args={'policy_ids': '1,121231'})
        expected_context_data = load_json('test_data/policy_details/policy_details_error_400_context_data.json')
        assert_command_results(command_results_to_assert=command_results, expected_outputs=expected_context_data,
                               expected_outputs_key_field='ID', expected_outputs_prefix='CrowdStrike.CSPMPolicy')
        # Entry type '11' means warning
        assert demisto_results_mocker.call_args_list[0][0][0].get('Type') == 11
        assert 'Invalid policy ID 121231 provided' in demisto_results_mocker.call_args_list[0][0][0].get('Contents')


class TestCSFalconCSPMListServicePolicySettingsCommand:

    def test_http_request_arguments(self, mocker: MockerFixture):
        """
        Given:
            - Policy ID to retrieve their details.
        When
            - Making a http request for the cs-falcon-cspm-list-service-policy-settings command.
        Then
            - Validate that the http_request function accepts the status code 207, since we deal with it manually,
            and that the arguments are mapped correctly to the appropriate params.
        """
        from CrowdStrikeFalcon import cspm_list_service_policy_settings_request
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        cspm_list_service_policy_settings_request(policy_id='1', cloud_platform='aws', service='IAM')
        assert http_request_mocker.call_args_list[0][1].get('status_code') == [207]
        assert http_request_mocker.call_args_list[0][1].get('params') == {'service': 'IAM', 'policy-id': '1',
                                                                          'cloud-platform': 'aws'}

    def test_get_service_policy_settings(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the command.
        When
            - Calling the cs-falcon-cspm-list-service-policy-settings command.
        Then
            - Validate the data of the CommandResults object returned.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_list_service_policy_settings_command
        raw_response = load_json('test_data/service_policy_settings/policy_settings_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        command_results = cs_falcon_cspm_list_service_policy_settings_command(args={'cloud_platform': 'aws',
                                                                                    'service': 'IAM'})
        expected_context_data = load_json('test_data/service_policy_settings/policy_settings_context_data.json')
        assert_command_results(command_results_to_assert=command_results, expected_outputs=expected_context_data,
                               expected_outputs_key_field='policy_id', expected_outputs_prefix='CrowdStrike.CSPMPolicySetting')

    def test_get_service_policy_settings_manual_pagination(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the command, with the limit argument.
        When
            - Calling the cs-falcon-cspm-list-service-policy-settings command.
        Then
            - Validate the code does a manual pagination, since the API does not offer it.
        """
        # The raw response in the test data has 2 values, we set a limit of 1 to assert the manual pagination
        from CrowdStrikeFalcon import cs_falcon_cspm_list_service_policy_settings_command
        raw_response = load_json('test_data/service_policy_settings/policy_settings_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        command_results = cs_falcon_cspm_list_service_policy_settings_command(args={'cloud_platform': 'aws',
                                                                                    'service': 'IAM', 'limit': '1'})
        assert isinstance(command_results.outputs, list)
        assert len(command_results.outputs) == 1


class TestCSFalconCSPMUpdatePolicySettingsCommand:

    def test_http_request_arguments(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the cs-falcon-cspm-update-policy_settings command.
        When
            - Making a http request.
        Then
            - Validate that the http_request function accepts the status code 500, since we deal with it manually,
            and that the arguments are mapped correctly to the json body.
        """
        from CrowdStrikeFalcon import cspm_update_policy_settings_request
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        cspm_update_policy_settings_request(account_id='12', enabled=True, policy_id=1,
                                            regions=['eu-west', 'eu-east'], severity='high', tag_excluded=False)
        assert http_request_mocker.call_args_list[0][1].get('status_code') == 500
        assert http_request_mocker.call_args_list[0][1].get('json') == {'resources':
                                                                        [{'account_id': '12', 'enabled': True, 'policy_id': 1,
                                                                          'regions': ['eu-west', 'eu-east'], 'severity': 'high',
                                                                          'tag_excluded': False}]}

    def test_update_policy_settings_error_500(self, mocker: MockerFixture):
        """
        Given
            - A wrong a account id.
        When
            - Running the cs-falcon-cspm-update-policy_settings command, and receiving a 500 status code.
        Then
            - Validate that we output an error with the correct message.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_update_policy_settings_command
        raw_response = load_json('test_data/update_policy_settings/update_settings_error_500_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        with pytest.raises(DemistoException) as e:
            cs_falcon_cspm_update_policy_settings_command(args={'account_id': 'wrong_account_id',
                                                                'policy_id': 1})
        assert 'Perhaps the policy ID or account ID are invalid?' in str(e)

    def test_update_policy_settings(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the command.
        When
            - Calling the cs-falcon-cspm-update-policy_settings command.
        Then
            - Validate the data of the CommandResults object returned.
        """
        from CrowdStrikeFalcon import cs_falcon_cspm_update_policy_settings_command
        raw_response = load_json('test_data/update_policy_settings/update_settings_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        command_results = cs_falcon_cspm_update_policy_settings_command(args={'policy_id': 1})
        assert isinstance(command_results.readable_output, str)
        assert 'Policy 1 was updated successfully' in command_results.readable_output


class TestCSFalconResolveIdentityDetectionCommand:
    @pytest.mark.parametrize('Legacy_version, url_suffix, ids_request_key', [
        (False, '/alerts/entities/alerts/v3', 'composite_ids'),
        (True, '/alerts/entities/alerts/v2', 'ids')])
    def test_http_request_arguments(self, mocker: MockerFixture, Legacy_version, url_suffix, ids_request_key):
        """
        Given:
            - Arguments for the cs-falcon-resolve-identity-detection command.
            case 1: Legacy_version is False
            case 2: Legacy_version is True
        When
            - Making a http request.
        Then
            - Validate that the arguments are mapped correctly to the json body.
            - Validate the url_suffix and the ids_request_key according to the Legacy_version value:
                case 1: url_suffix should be '/alerts/entities/alerts/v3' and the ids_request_key should be 'composite_ids'
                case 2: url_suffix should be '/alerts/entities/alerts/v2' and the ids_request_key should be 'ids'
        """
        from CrowdStrikeFalcon import resolve_detections_request
        mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        ids = ['1,2']
        action_param_values = {'update_status': 'new', 'assign_to_name': 'bot'}
        action_params_http_body = [{'name': 'update_status', 'value': 'new'}, {'name': 'assign_to_name', 'value': 'bot'}]
        resolve_detections_request(ids=ids, **action_param_values)
        assert http_request_mocker.call_args_list[0][1].get('url_suffix') == url_suffix
        assert http_request_mocker.call_args_list[0][1].get('json') == {'action_parameters': action_params_http_body,
                                                                        ids_request_key: ids}

    def test_resolve_identity_detection(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the command.
        When
            - Calling the cs-falcon-resolve-identity-detection command.
        Then
            - Validate the data of the CommandResults object returned.
        """
        from CrowdStrikeFalcon import cs_falcon_resolve_identity_detection
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=requests.Response())
        command_results = cs_falcon_resolve_identity_detection(args={'ids': '1,2'})
        assert isinstance(command_results.readable_output, str)
        assert 'IDP Detection(s) 1, 2 were successfully updated' in command_results.readable_output

    def test_resolve_mobile_detection(self, mocker: MockerFixture):
        """
        Given:
            - Arguments for the command.
        When
            - Calling the cs-falcon-resolve-mobile-detection command.
        Then
            - Validate the data of the CommandResults object returned.
        """
        from CrowdStrikeFalcon import cs_falcon_resolve_mobile_detection
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=requests.Response())
        command_results = cs_falcon_resolve_mobile_detection(args={'ids': '1,2'})
        assert isinstance(command_results.readable_output, str)
        assert 'Mobile Detection(s) 1, 2 were successfully updated' in command_results.readable_output


class TestIOAFetch:
    # Since this integration fetches multiple incidents, the last run object contains a list of
    # last run objects for each incident type, for IOA, that is the 5th position
    @pytest.mark.parametrize('fetch_query, error_message',
                             [('account_id=1', 'A cloud provider is required as part of the IOA fetch query'),
                              ("cloud_provider!='aws'", 'An unsupported parameter has been entered'),
                              ("cloud_provider='aws'&weird_param=val",
                               'An unsupported parameter has been entered'),
                              ("cloud_provider='aws'&state=", 'cannot be an empty string'),
                              ("cloud_provider='aws'&state:val", 'does not match the parameter=value format'),
                              ("cloud_provider='aws'&state==val", 'does not match the parameter=value format')])
    def test_validate_ioa_fetch_query_error(self, fetch_query, error_message):
        """
        Given:
            - An incorrect IOA fetch query to validate.
        When
            - Validating the query supplied by the user.
        Then
            - Validate that the correct error message is returned for the incorrect fetch query.
        """
        from CrowdStrikeFalcon import validate_ioa_fetch_query
        with pytest.raises(DemistoException) as e:
            validate_ioa_fetch_query(ioa_fetch_query=fetch_query)
        assert error_message in str(e)

    def test_fetch_query_with_paginating(self, mocker: MockerFixture):
        """
        Given:
            - The query of the last fetch, and the next token.
        When
            - Performing pagination and receiving the next token from the previous run.
        Then
            - Validate that the last fetch query is used in the current run, and the next token is added to the API call.
        """
        from CrowdStrikeFalcon import fetch_incidents
        fetch_query = 'cloud_provider=aws'
        last_fetch_query = f'{fetch_query}&date_time_since=some_time'
        ioa_next_token = 'dummy_token'
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'ioa_next_token': ioa_next_token,
                                                  'last_fetch_query': last_fetch_query,
                                                  'last_date_time_since': '2023-01-01T00:00:00Z'}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': fetch_query})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        fetch_incidents()
        assert last_fetch_query in http_request_mocker.call_args_list[0][1].get('url_suffix')
        assert f'next_token={ioa_next_token}' in http_request_mocker.call_args_list[0][1].get('url_suffix')

    def test_fetch_query_with_paginating_empty_last_filter_error(self, mocker: MockerFixture):
        """
        Given:
            - An empty query as the last fetch query, and the next token.
        When
            - Performing pagination and receiving the next token from the previous run.
        Then
            - Validate that an error is thrown if the last fetch filter is an empty string.
        """
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'ioa_next_token': 'dummy_token',
                                                  'last_fetch_query': '',
                                                  'last_date_time_since': '2023-01-01T00:00:00Z'}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': 'cloud_provider=aws'})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.http_request')
        with pytest.raises(DemistoException) as e:
            fetch_incidents()
        assert 'Last fetch query must not be empty when doing pagination' in str(e)

    def test_fetch_query_without_pagination(self, mocker: MockerFixture):
        """
        Given:
            - The date_time_since date from the previous fetch, and the fetch query.
        When
            - Performing fetch without pagination.
        Then
            - Validate that the passed date_date_since date is appended to the supplied fetch query.
        """
        from CrowdStrikeFalcon import fetch_incidents
        last_date_time_since = '2023-01-01T00:00:00Z'
        fetch_query = 'cloud_provider=aws'
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'last_date_time_since': last_date_time_since}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': fetch_query})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        fetch_incidents()
        assert fetch_query in http_request_mocker.call_args_list[0][1].get('url_suffix')
        assert f'date_time_since={last_date_time_since}' in http_request_mocker.call_args_list[0][1].get('url_suffix')

    @pytest.mark.parametrize('next_toke_object, expected_next_token', [({'next_token': 'dummy_token'}, 'dummy_token'),
                                                                       ({}, None)])
    def test_return_values_get_ioa_events(self, mocker: MockerFixture, next_toke_object, expected_next_token):
        """
        Given:
            - The response of the API when a pagination object is returned or not.
        When
            - Doing an API call to retrieve the IOA events.
        Then
            - Validate that we extract the events and next token from the raw response, if they exist.
        """
        from CrowdStrikeFalcon import get_ioa_events
        exepcted_events = ['event_1', 'event_2']
        raw_response = {'meta':
                        {
                            'pagination': next_toke_object
                        },
                        'resources': {'events': exepcted_events}
                        }
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        events, next_token = get_ioa_events(ioa_fetch_query='some_query', ioa_next_token='not_important')
        assert exepcted_events == events
        assert expected_next_token == next_token

    def test_ioa_events_pagination(self, mocker: MockerFixture):
        """
        Given:
            - 2 responses from the API that includes a pagination object.
        When
            - Fetching incidents, and the fetch limit is greater than the API limit of a single call (If the fetch limit is 4,
            and the API limit is 2, that means in each fetch, we should do 2 API calls, using pagination, to acquire 4 results, or
            until no more results are found).
        Then
            - Validate that we do API calls using the correct pagination arguments, and that we get the next token so it can be
            used in the next fetch round.
        """
        # We saved two responses, where both of them return a next token. We have that the api_limit=2,
        # and the fetch_limit=3, that way, we would need to do a request twice, and on the second request,
        # we would make it while having a limit of 1. We will check the arguments of the method get_ioa_events,
        # and the return values of ioa_events_pagination.
        from CrowdStrikeFalcon import ioa_events_pagination, get_ioa_events
        page_1_raw_response = load_json('test_data/ioa_fetch_incidents.json/ioa_events_page_1_raw_response.json')
        page_2_raw_response = load_json('test_data/ioa_fetch_incidents.json/ioa_events_page_2_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', side_effect=[page_1_raw_response, page_2_raw_response])
        get_events_for_fetch_mocker = mocker.patch(
            'CrowdStrikeFalcon.get_ioa_events', side_effect=get_ioa_events)
        events, next_token = ioa_events_pagination(ioa_fetch_query='dummy_fetch_query',
                                                   ioa_next_token='dummy_token',
                                                   fetch_limit=3,
                                                   api_limit=2)
        # We retrieved 3 events from the pagination phase, therefore, we assert that we acquire them
        assert events == [{'event_id': 'event_1'}, {'event_id': 'event_2'}, {'event_id': 'event_3'}]
        # The first time we do pagination, we won't have any fetched incidents, and since the fetch limit is 3,
        # and api limit is 2, that means we do an API request to retrieve the first 2 events
        assert get_events_for_fetch_mocker.call_args_list[0][1].get('limit') == 2
        # After the first API request, the second one should use the token that was retrieved from the previous request
        assert get_events_for_fetch_mocker.call_args_list[1][1].get('ioa_next_token') == 'next_token_1'
        # After the first pagination, we would have fetched two incidents, and only 1 incident is left, therefore, we
        # do an API request with a limit of 1 in order to get the last incident of the current round
        assert get_events_for_fetch_mocker.call_args_list[1][1].get('limit') == 1
        # Since there are more results to be returned from the API, we assert that we get the next token so we can
        # use it in the next fetching round
        assert next_token == 'next_token_2'

    def test_no_ioa_events_added_if_found_in_last_run(self, mocker: MockerFixture):
        """
        Given:
            - The event ids of the last fetch run.
        When
            - Converting the fetched events to incidents.
        Then
            - Validate that we do not create incidents of events that have been fetched in the previous round.
        """
        # Make last_event_ids have the values ['1', '2'], and return the values ['2', '3'] when fetching,
        # and once we enter the for loop to go over the fetched events, '2' will not get picked up, since it
        # was already fetched, therfore, we check that in the returned incidents object, only the event with id '3'
        # was added as an incident
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'last_event_ids': ['1', '2']}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': 'cloud_provider=aws'})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        # The function ioa_events_pagination returns the fetched events, and the next token (for the sake of testing, it is None)
        mocker.patch('CrowdStrikeFalcon.ioa_events_pagination',
                     return_value=([{'event_id': '2', 'event_created': '2023-01-01T00:00:00Z'},
                                    {'event_id': '3', 'event_created': '2023-01-01T00:00:00Z'}], None))
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00Z')
        fetched_incidents = fetch_incidents()
        assert len(fetched_incidents) == 1
        rawJSON = json.loads(fetched_incidents[0].get('rawJSON'))
        assert rawJSON.get('incident_type') == 'ioa_events'
        assert rawJSON.get('event_id') == '3'

    def test_save_fetched_events_when_paginating(self, mocker: MockerFixture):
        """
        Given:
            - The event ids of the last fetch run.
        When
            - Saving the fetched event ids.
        Then
            - Validate that we add the newly fetched event ids to the previous ones, and not override them, when we are
            doing pagination.
        """
        # Make sure that we save all the events that have been fetched throught the whole pagination process,
        # which can span on many fetches. We will have ids in last_event_ids (['1']), and configure that we are
        # doing pagination, and that we fetched event '2', and in the new returned last run, the key last_event_ids
        # has a value of ['1', '2']
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'last_event_ids': ['1']}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': 'cloud_provider=aws'})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.ioa_events_pagination',
                     return_value=([{'event_id': '2', 'event_created': '2023-01-01T00:00:00Z'}], 'next_token'))
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00Z')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][4].get('last_event_ids') == ['2', '1']

    def test_save_fetched_events_when_starting_pagination(self, mocker: MockerFixture):
        """
        Given:
            - The event ids of the last fetch run.
        When
            - Saving the fetched event ids.
        Then
            - Validate that we add the newly fetched event ids to the previous ones, and not override them, when we are
            going to start pagination in the next fetch run.
        """
        # Make sure that we save all the events that have been fetched before when starting the pagination process.
        # We will have ids in last_event_ids (['1']), and configure that we are, doing pagination, and that we fetched event '2',
        # and in the new returned last run, the key last_event_ids has a value of ['1', '2']
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'last_event_ids': ['1'], 'ioa_next_token': 'next_token',
                                                  'last_fetch_query': 'cloud_provider=aws'}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': 'cloud_provider=aws'})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.ioa_events_pagination',
                     return_value=([{'event_id': '2', 'event_created': '2023-01-01T00:00:00Z'}], None))
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00Z')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][4].get('last_event_ids') == ['2', '1']

    def test_fetch_ioa_events(self, mocker: MockerFixture):
        """
        Given:
            - A last run object.
        When
            - Fetching IOA events.
        Then
            - Validate that we construct the correct last run object for the next run by:
                1. The next token is saved.
                2. The largest date_time_since date between the dates of all fetched events is saved.
                3. The fetch query that was used in the API call is saved.
                4. The fetched event ids are saved.
        """
        # A successful fetch of incidents
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {}, {},
                                                 {'last_event_ids': ['1'], 'ioa_next_token': 'next_token',
                                                  'last_fetch_query': 'last_dummy_query',
                                                  'last_date_time_since': '2022-01-01T00:00:00Z'}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Attack',
                                          'ioa_fetch_query': 'cloud_provider=aws'})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.ioa_events_pagination',
                     return_value=([{'event_id': '3', 'event_created': '2024-01-01T00:00:00Z'},
                                    {'event_id': '2', 'event_created': '2023-01-01T00:00:00Z'}], 'new_next_token'))
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetched_incidents = fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][4] == {'ioa_next_token': 'new_next_token',
                                                                  'last_date_time_since': '2024-01-01T00:00:00Z',
                                                                  'last_fetch_query': 'last_dummy_query',
                                                                  'last_event_ids': ['3', '2', '1']}
        assert len(fetched_incidents) == 2


class TestIOMFetch:
    # Since this integration fetches multiple incidents, the last run object contains a list of
    # last run objects for each incident type, for IOM, that is the 4th position
    def test_validate_iom_fetch_query(self):
        """
        Given:
            - An incorrect IOM fetch query to validate.
        When
            - Validating the query supplied by the user.
        Then
            - Validate that the correct error message is returned for the incorrect fetch query.
        """
        from CrowdStrikeFalcon import validate_iom_fetch_query
        with pytest.raises(DemistoException) as e:
            validate_iom_fetch_query(iom_fetch_query='scan_time: >some_time')
        assert 'scan_time is not allowed as part of the IOM fetch query' in str(e)

    def test_fetch_query_with_paginating(self, mocker: MockerFixture):
        """
        Given:
            - The query of the last fetch, and the next token.
        When
            - Performing pagination and receiving the next token from the previous run.
        Then
            - Validate that the last fetch query is used in the current run, and the next token is added to the API call.
        """
        from CrowdStrikeFalcon import fetch_incidents
        fetch_filter = "cloud_provider: 'aws'"
        last_fetch_filter = f'scan_time: some_time+{fetch_filter}'
        iom_next_token = 'dummy_token'
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'iom_next_token': iom_next_token,
                                                  'last_fetch_filter': last_fetch_filter,
                                                  'last_scan_time': '2023-01-01T00:00:00.000000Z'},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': fetch_filter})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        fetch_incidents()
        assert http_request_mocker.call_args_list[0][1].get('params').get('filter') == last_fetch_filter
        assert http_request_mocker.call_args_list[0][1].get('params').get('next_token') == iom_next_token

    def test_fetch_query_with_paginating_empty_last_filter_error(self, mocker: MockerFixture):
        """
        Given:
            - An empty filter as the last fetch filter, and the next token.
        When
            - Performing pagination and receiving the next token from the previous run.
        Then
            - Validate that an error is thrown if the last fetch filter is an empty string.
        """
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'iom_next_token': 'dummy_token',
                                                  'last_fetch_filter': '',
                                                  'last_scan_time': '2023-01-01T00:00:00.000000Z'},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': "cloud_provider: 'aws'"})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.http_request')
        with pytest.raises(DemistoException) as e:
            fetch_incidents()
        assert 'Last fetch filter must not be empty when doing pagination' in str(e)

    def test_fetch_query_without_pagination_and_not_first_run(self, mocker: MockerFixture):
        """
        Given:
            - The last_scan_time date from the previous fetch, and the fetch query..
        When
            - Performing fetch without pagination, and this is not the first fetch run.
        Then
            - Validate that we append the last_scan_time date, while using '>' in the fetch query.
        """
        from CrowdStrikeFalcon import fetch_incidents
        last_scan_time = '2023-01-01T00:00:00.000000Z'
        fetch_filter = "cloud_provider: 'aws'"
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'last_scan_time': last_scan_time},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': fetch_filter})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        fetch_incidents()
        assert f"scan_time: >'{last_scan_time}'+{fetch_filter}" == \
            http_request_mocker.call_args_list[0][1].get('params').get('filter')

    @freeze_time("2023-01-04T00:00:00Z")
    def test_fetch_query_without_pagination_and_first_run(self, mocker: MockerFixture):
        """
        Given:
            - The fetch query.
        When
            - Performing fetch without pagination, and this is the first fetch run.
        Then
            - Validate that we append the last_scan_time date, while using '>=' in the fetch query.
        """
        from CrowdStrikeFalcon import fetch_incidents
        # The date configured in @freeze_time minues 3 days, which is the default FETCH_TIME
        last_scan_time = '2023-01-01T00:00:00.000000Z'
        fetch_filter = "cloud_provider: 'aws'"
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': fetch_filter})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
        fetch_incidents()
        assert f"scan_time: >='{last_scan_time}'+{fetch_filter}" == \
            http_request_mocker.call_args_list[0][1].get('params').get('filter')

    @pytest.mark.parametrize('next_toke_object, expected_next_token', [({'next_token': 'dummy_token'}, 'dummy_token'),
                                                                       ({}, None)])
    def test_return_values_get_iom_resource_ids(self, mocker: MockerFixture, next_toke_object, expected_next_token):
        """
        Given:
            - The response of the API when a pagination object is returned or not.
        When
            - Doing an API call to retrieve the IOM resources.
        Then
            - Validate that we extract the resources and next token from the raw response, if they exist.
        """
        from CrowdStrikeFalcon import get_iom_ids_for_fetch
        exepcted_resource_ids = ['resource_1', 'resource_2']
        raw_response = {'meta':
                        {
                            'pagination': next_toke_object
                        },
                        'resources': exepcted_resource_ids
                        }
        mocker.patch('CrowdStrikeFalcon.http_request', return_value=raw_response)
        resource_ids, next_token = get_iom_ids_for_fetch(filter='some_filter', iom_next_token='not_important')
        assert exepcted_resource_ids == resource_ids
        assert expected_next_token == next_token

    def test_iom_events_pagination(self, mocker: MockerFixture):
        """
        Given:
            - 2 responses from the API that includes a pagination object.
        When
            - Fetching incidents, and the fetch limit is greater than the API limit of a single call (If the fetch limit is 4,
            and the API limit is 2, that means in each fetch, we should do 2 API calls, using pagination, to acquire 4 results, or
            until no more results are found).
        Then
            - Validate that we do API calls using the correct pagination arguments, and that we get the next token so it can be
            used in the next fetch round.
        """
        # Save two responses, where both of them return a next token with them. Make the api_limit=2,
        # and the fetch_limit=3, that way, we would need to do a request twice, and on the second request,
        # we would make it while having a limit of 1. We will check the arguments of the method get_iom_ids_for_fetch,
        # and the return values of iom_ids_pagination.
        from CrowdStrikeFalcon import iom_ids_pagination, get_iom_ids_for_fetch
        page_1_raw_response = load_json('test_data/iom_fetch_incidents/iom_resource_ids_page_1_raw_response.json')
        page_2_raw_response = load_json('test_data/iom_fetch_incidents/iom_resource_ids_page_2_raw_response.json')
        mocker.patch('CrowdStrikeFalcon.http_request', side_effect=[page_1_raw_response, page_2_raw_response])
        get_events_for_fetch_mocker = mocker.patch(
            'CrowdStrikeFalcon.get_iom_ids_for_fetch', side_effect=get_iom_ids_for_fetch)
        events, next_token = iom_ids_pagination(filter='dummy_filter',
                                                iom_next_token='dummy_token',
                                                fetch_limit=3,
                                                api_limit=2)
        # We retrieved 3 events from the pagination phase, therefore, we assert that we acquire them
        assert events == ['resource_1', 'resource_2', 'resource_3']
        # The first time we do pagination, we won't have any fetched incidents, and since the fetch limit is 3,
        # and api limit is 2, that means we do an API request to retrieve the first 2 events
        assert get_events_for_fetch_mocker.call_args_list[0][1].get('limit') == 2
        # After the first API request, the second one should use the token that was retrieved from the previous request
        assert get_events_for_fetch_mocker.call_args_list[1][1].get('iom_next_token') == 'next_token_1'
        # After the first pagination, we would have fetched two incidents, and only 1 incident is left, therefore, we
        # do an API request with a limit of 1 in order to get the last incident of the current round
        assert get_events_for_fetch_mocker.call_args_list[1][1].get('limit') == 1
        # Since there are more results to be returned from the API, we assert that we get the next token so we can
        # use it in the next fetching round
        assert next_token == 'next_token_2'

    def test_no_iom_resources_added_if_found_in_last_run(self, mocker: MockerFixture):
        """
        Given:
            - The resources ids of the last fetch run.
        When
            - Converting the fetched resources to incidents.
        Then
            - Validate that we do not create incidents of resources that have been fetched in the previous round.
        """
        # Make last_resource_ids have the values ['1', '2'], and return the values ['2', '3'] when fetching,
        # and once we enter the for loop to go over the fetched resources, '2' will not get picked up, since it
        # was already fetched, therfore, we check that in the returned incidents object, only the resource with id '3'
        # was added as an incident
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'last_resource_ids': ['1', '2']},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': "cloud_provider: 'aws'"})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        # The function iom_ids_pagination returns the ids of the fetched events, and the
        # next token (for the sake of testing, it is None)
        mocker.patch('CrowdStrikeFalcon.iom_ids_pagination', return_value=(['2', '3'], None))
        mocker.patch('CrowdStrikeFalcon.get_iom_resources',
                     return_value=[{'id': '2', 'scan_time': '2023-01-01T00:00:00.00Z'},
                                   {'id': '3', 'scan_time': '2023-01-01T00:00:00.00Z'}])
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00.00Z')
        fetched_incidents = fetch_incidents()
        assert len(fetched_incidents) == 1
        rawJSON = json.loads(fetched_incidents[0].get('rawJSON'))
        assert rawJSON.get('incident_type') == 'iom_configurations'
        assert rawJSON.get('id') == '3'

    def test_save_fetched_resources_when_paginating(self, mocker: MockerFixture):
        """
        Given:
            - The resource ids of the last fetch run.
        When
            - Saving the fetched resource ids.
        Then
            - Validate that we add the newly fetched resource ids to the previous ones, and not override them, when we are
            doing pagination.
        """
        # Make sure that we save all the resources that have been fetched throught the whole pagination process,
        # which can span on many fetches. We will have ids in last_resource_ids (['1']), and configure that we are
        # doing pagination, and that we fetched resource '2', and in the new returned last run, the key last_resource_ids
        # has a value of ['1', '2']
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'last_resource_ids': ['1']},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': "cloud_provider: 'aws'"})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.iom_ids_pagination', return_value=(['2'], 'next_token'))
        mocker.patch('CrowdStrikeFalcon.get_iom_resources',
                     return_value=[{'id': '2', 'scan_time': '2023-01-01T00:00:00.00Z'}])
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00.00Z')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][3].get('last_resource_ids') == ['2', '1']

    def test_save_fetched_resources_when_starting_pagination(self, mocker: MockerFixture):
        """
        Given:
            - The resource ids of the last fetch run.
        When
            - Saving the fetched resource ids.
        Then
            - Validate that we add the newly fetched resource ids to the previous ones, and not override them, when we are
            going to start pagination in the next fetch run.
        """
        # Make sure that we save all the resources that have been fetched before when starting the pagination process.
        # We will have ids in last_resource_ids (['1']), and configure that we are, doing pagination, and that we fetched
        # resource '2', and in the new returned last run, the key last_resource_ids has a value of ['1', '2']
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'last_resource_ids': ['1'], 'iom_next_token': 'next_token',
                                                  'last_fetch_filter': 'previous_filter'},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': "cloud_provider: 'aws'"})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)
        mocker.patch('CrowdStrikeFalcon.iom_ids_pagination', return_value=(['2'], None))
        mocker.patch('CrowdStrikeFalcon.get_iom_resources',
                     return_value=[{'id': '2', 'scan_time': '2023-01-01T00:00:00.00Z'}])
        mocker.patch('CrowdStrikeFalcon.reformat_timestamp', return_value='2023-01-01T00:00:00.00Z')
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][3].get('last_resource_ids') == ['2', '1']

    def test_fetch_iom_events(self, mocker: MockerFixture):
        """
        Given:
            - A last run object.
        When
            - Fetching IOM resources.
        Then
            - Validate that we construct the correct last run object for the next run by:
                1. The next token is saved.
                2. The largest scan_time date between the dates of all fetched resources is saved.
                3. The fetch query that was used in the API call is saved.
                4. The fetched resource ids are saved.
        """
        # A successful fetch of incidents
        from CrowdStrikeFalcon import fetch_incidents
        last_run_object: list[dict[str, Any]] = [{}, {}, {},
                                                 {'last_resource_ids': ['1'], 'iom_next_token': 'next_token',
                                                  'last_fetch_filter': 'last_dummy_filter',
                                                  'last_scan_time': '2022-01-01T00:00:00.00Z'},
                                                 {}]
        mocker.patch.object(demisto, 'params',
                            return_value={'fetch_incidents_or_detections': 'Indicator of Misconfiguration',
                                          'iom_fetch_query': "cloud_provider: 'aws'"})
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_object)

        mocker.patch('CrowdStrikeFalcon.iom_ids_pagination', return_value=(['3', '2'], 'new_next_token'))
        mocker.patch('CrowdStrikeFalcon.get_iom_resources',
                     return_value=[{'id': '3', 'scan_time': '2024-01-01T00:00:00.00Z'},
                                   {'id': '2', 'scan_time': '2023-01-01T00:00:00.00Z'}])
        set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', side_effect=demisto.setLastRun)
        fetched_incidents = fetch_incidents()
        assert set_last_run_mocker.call_args_list[0][0][0][3] == {'iom_next_token': 'new_next_token',
                                                                  'last_scan_time': '2024-01-01T00:00:00.000000Z',
                                                                  'last_fetch_filter': 'last_dummy_filter',
                                                                  'last_resource_ids': ['3', '2', '1']}
        assert len(fetched_incidents) == 2


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


def test_run_command_batch_id(requests_mock, mocker):
    """
    Test cs-falcon-run-command when batch_id is given as an argument.

    Given:
     - A batch_id host_ids, command_type, full_command.
    When:
     - Running the command cs-falcon-run-command
    Then:
     - Check that the batch_id is correct.
    """
    from CrowdStrikeFalcon import run_command
    args = {
        'host_ids': 'host_id',
        'command_type': 'ls',
        'full_command': 'ls',
        'batch_id': 'batch_id'
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value=args
    )
    response = load_json('test_data/run_command/run_command_with_batch.json')
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-command/v1',
        json=response,
        status_code=201
    )
    results = run_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                "BaseCommand": "ls",
                "BatchID": "batch_id",
                "Command": "ls",
                "HostID": "aid",
                "SessionID": "session_id",
                "Stderr": "",
                "Stdout": 'Directory listing for C:\\ -\n\n'
                          'Name                                     Type         Size (bytes)    Size (MB)       '
                          'Last Modified (UTC+2)     Created (UTC+2)          \n'
                          '----                                     ----         ------------    ---------       '
                          '---------------------     ---------------          \n'
                          '$Recycle.Bin                             <Directory>  --              --              '
                          '6/19/2023 4:11:43 PM      9/15/2018 10:19:00 AM    \n'
                          'Config.Msi                               <Directory>  --              --              '
                          '11/14/2023 1:56:25 AM     8/17/2023 1:49:07 AM     \n'
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_run_command_without_batch_id(requests_mock, mocker):
    """
    Test cs-falcon-run-command when batch_id isn't given as an argument.

    Given:
     - host_ids, command_type, full_command.
    When:
     - Running the command cs-falcon-run-command
    Then:
     - Check that the batch_id is correct.
    """
    from CrowdStrikeFalcon import run_command
    args = {
        'host_ids': 'host_id',
        'command_type': 'ls',
        'full_command': 'ls',
    }
    mocker.patch.object(
        demisto,
        'args',
        return_value=args
    )
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-init-session/v1',
        json={
            'batch_id': 'new_batch_id'
        },
        status_code=201
    )
    response = load_json('test_data/run_command/run_command_with_batch.json')
    requests_mock.post(
        f'{SERVER_URL}/real-time-response/combined/batch-command/v1',
        json=response,
        status_code=201
    )
    results = run_command()
    expected_results = {
        'CrowdStrike': {
            'Command': [{
                "BaseCommand": "ls",
                "BatchID": "new_batch_id",
                "Command": "ls",
                "HostID": "aid",
                "SessionID": "session_id",
                "Stderr": "",
                "Stdout": 'Directory listing for C:\\ -\n\n'
                          'Name                                     Type         Size (bytes)    Size (MB)       '
                          'Last Modified (UTC+2)     Created (UTC+2)          \n'
                          '----                                     ----         ------------    ---------       '
                          '---------------------     ---------------          \n'
                          '$Recycle.Bin                             <Directory>  --              --              '
                          '6/19/2023 4:11:43 PM      9/15/2018 10:19:00 AM    \n'
                          'Config.Msi                               <Directory>  --              --              '
                          '11/14/2023 1:56:25 AM     8/17/2023 1:49:07 AM     \n'
            }]
        }
    }
    assert results['EntryContext'] == expected_results


def test_list_users_command(mocker):
    """
    Test cs-falcon-list-users command.

    Given:
     - No arguments.
    When:
     - Running the command cs-falcon-list-users
    Then:
     - Check that the command returns the correct results.
    """
    import CrowdStrikeFalcon
    entities_api_mock = load_json('test_data/list_users_command/entities_users_response.json')
    queries_api_mock = load_json('test_data/list_users_command/queries_users_response.json')
    mocker.patch.object(CrowdStrikeFalcon, 'http_request', side_effect=[entities_api_mock, queries_api_mock])

    result = CrowdStrikeFalcon.cs_falcon_list_users_command(args={})
    assert result.outputs_prefix == 'CrowdStrike.Users'
    assert result.outputs_key_field == 'uuid'
    assert result.outputs == queries_api_mock['resources']


def test_get_incident_behavior_command(mocker):
    import CrowdStrikeFalcon
    api_mock = load_json('test_data/entities_behaviors_response.json')
    mocker.patch.object(CrowdStrikeFalcon, 'http_request', return_value=api_mock)

    result = CrowdStrikeFalcon.get_incident_behavior_command(args={'behavior_ids': 'ind:XX:XX'})
    assert result.outputs_prefix == 'CrowdStrike.IncidentBehavior'
    assert result.outputs_key_field == 'behavior_id'
    assert result.outputs == api_mock['resources']


def test_get_cve_command(mocker):
    """
    Given:
        - Raw response with duplicates
    When:
        - Running cve command
    Then:
        - Validate that the response doesn't contain duplicates
    """
    import CrowdStrikeFalcon

    raw1 = {"id": "CVE-2023-12345", "description": "A1", "published_date": "2023-12-10T10:15:00Z", "base_score": 10,
            "vector": "A1B2C3D4", "cisa_info": {"due_date": "2023-12-24T00:00:00Z", "is_cisa_kev": True},
            "actors": ["ALPHA", "BETA", "GAMMA"]}
    raw2 = {"id": "CVE-2023-12345", "description": "A1", "published_date": "2023-12-10T10:15:00Z", "base_score": 10,
            "vector": "A1B2C3D4", "cisa_info": {"due_date": "2023-12-24T00:00:00Z", "is_cisa_kev": False},
            "actors": ["ALPHA", "BETA", "GAMMA"]}
    http_response = {'resources': [{'cve': raw1}, {'cve': raw1}, {'cve': raw1}, {'cve': raw2}, {'cve': raw1}, {'cve': raw2}]}

    mocker.patch.object(CrowdStrikeFalcon, 'http_request', return_value=http_response)

    results = CrowdStrikeFalcon.get_cve_command(args={'cve': 'CVE-2023-12345'})
    assert len(results) == 2


def test_http_request(mocker):
    """
    Given:
        - arguments of a http_request
    When:
        - Running any command
    Then:
        - Validate that the in case of 429 error code, get_token() will be called again in order to create a new token and
            generic_http_request will be called again as well.
    """
    from requests import Response
    from CrowdStrikeFalcon import http_request
    res_429 = Response()
    res_429.status_code = 429
    res_200 = Response()
    res_200.status_code = 200
    mock_request_get_token = mocker.patch('CrowdStrikeFalcon.get_token', return_value='token')
    mock_request_generic_http_request = mocker.patch('CrowdStrikeFalcon.generic_http_request', side_effect=[res_429, res_200])
    http_request(url_suffix='url_suffix',
                 method='method',
                 headers={},
                 no_json=True)
    # validate that in a case of 429, we will try again
    assert mock_request_generic_http_request.call_count == 2
    assert mock_request_get_token.call_count == 2


def test_http_request_get_token_request(mocker):
    """
    Given:
        - arguments of a http_request send by get_token_request()
    When:
        - requesting a new token
    Then:
        - validate that the correct arguments were sent
    """
    from requests import Response
    from CrowdStrikeFalcon import http_request
    res_200 = Response()
    res_200.status_code = 200
    mock_request_generic_http_request = mocker.patch('CrowdStrikeFalcon.generic_http_request', side_effect=[res_200])
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': SERVER_URL,
            'proxy': True
        }
    )
    body = {
        'client_id': 'client_id',
        'client_secret': 'client_secret'
    }
    retries = 5
    status_list_to_retry = [429]
    valid_status_codes = [200, 201, 202, 204]
    int_timeout = 60
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    method = 'POST'
    url_suffix = '/oauth2/token'
    http_request(url_suffix=url_suffix,
                 method=method,
                 data=body,
                 get_token_flag=False,
                 headers=headers,
                 no_json=True)
    headers['User-Agent'] = 'PANW-XSOAR'
    assert mock_request_generic_http_request.call_count == 1
    mock_request_generic_http_request.assert_called_with(
        method=method,
        server_url=SERVER_URL,
        headers=headers,
        url_suffix=url_suffix,
        data=body,
        files=ANY,
        params=ANY,
        proxy=ANY,
        resp_type='response',
        verify=True,
        error_handler=ANY,
        json_data=ANY,
        timeout=int_timeout,
        ok_codes=valid_status_codes,
        retries=retries,
        status_list_to_retry=status_list_to_retry)


def test_http_request_get_token_request_429(mocker, requests_mock):
    """
    Given:
        - arguments of a http_request send by get_token_request()
    When:
        - requesting a new token
    Then:
        - Validate that in case of 429 error code when trying to create a new token won't return None at the end of http_request,
            but raise an exception with the relevant error.
    """
    from CrowdStrikeFalcon import http_request

    requests_mock.post(
        f'{SERVER_URL}/oauth2/token',
        json={
            "meta": {
                "query_time": 0.000875986,
                "powered_by": "crowdstrike-api-gateway",
                "trace_id": "trace_id"
            },
            "errors": [
                {
                    "code": 429,
                    "message": "API rate limit exceeded."
                }
            ]
        },
        status_code=429
    )
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': SERVER_URL,
            'proxy': True
        }
    )
    mock_request_generic_http_request = mocker.patch('CrowdStrikeFalcon.generic_http_request')
    mock_request_error_handler = mocker.patch('CrowdStrikeFalcon.error_handler')
    body = {
        'client_id': 'client_id',
        'client_secret': 'client_secret'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    method = 'POST'
    url_suffix = '/oauth2/token'
    http_request(url_suffix=url_suffix,
                 method=method,
                 data=body,
                 get_token_flag=False,
                 headers=headers,
                 no_json=True)
    assert mock_request_generic_http_request.call_count == 1
    assert mock_request_error_handler.call_count == 1


class ResMocker:
    def __init__(self, http_response, status_code, reason):
        self.http_response = http_response
        self.status_code = status_code
        self.reason = reason
        self.ok = False

    def json(self):
        return self.http_response


def test_error_handler():
    """
    Given:
        - A response with an error from the API.
    When:
        - Running any command
    Then:
        - Validate that the error message contains the correct info
    """
    from CrowdStrikeFalcon import error_handler
    status_code = 429
    reason = "Too Many Requests API rate limit exceeded."
    res_json = {
        "meta": {
            "query_time": 0.00571046,
            "pagination": {
                "offset": 0,
                "limit": 100,
                "total": 2
            },
            "powered_by": "legacy-detects",
            "trace_id": "11111111-1111-1111-1111-111111111111"
        },
        "errors": [],
    }

    arg_res = ResMocker(res_json, status_code, reason)
    try:
        error_handler(arg_res)
    except DemistoException as e:
        assert e.message == f'Error in API call to CrowdStrike Falcon: code: {status_code} - reason: {reason}'


@pytest.mark.parametrize('Legacy_version, url_suffix, expected_len', [
    (False,
     "alerts/queries/alerts/v2?filter=product%3A%27epp%27%2Btype%3A%27ldt%27%2Bcreated_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27",
     3),
    (True, '/detects/queries/detects/v1', 3)
])
def test_get_detection___url_and_params(mocker, Legacy_version, url_suffix, expected_len):
    """
    Given:
    - The `Legacy_version` flag
When:
    - Invoking `get_fetch_detections` with various input parameters
Then:
    - Verify that the correct `url_suffix` is used

Test Scenarios:
    1. When `Legacy_version` is False, the `url_suffix` should be:
       "alerts/queries/alerts/v2?filter=product%3A%27epp%27%2Btype%3A%27ldt%27%2Bcreated_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27"
       since all parameters are part of the URL and are URL-encoded, and the expected len should be 2 since no parameters
       are passed.
    2. When `Legacy_version` is True, the `url_suffix` should be:
       "/detects/queries/detects/v1" and the expected len is 3 since all the provided parameters are passed under 'parameters'.
    """
    from CrowdStrikeFalcon import get_detections
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')

    get_detections(last_behavior_time='2024-06-19T15:25:00Z', behavior_id=123,
                   filter_arg="created_timestamp:>'2024-06-19T15:25:00Z'")
    assert http_request_mocker.call_args_list[0][0][1] == url_suffix
    assert len(http_request_mocker.call_args_list[0][0]) == expected_len


@pytest.mark.parametrize('Legacy_version, tag, url_suffix, data', [
    (False, "test_tag", "/alerts/entities/alerts/v3",
     '{"action_parameters": [{"name": "show_in_ui", "value": "True"}, {"name": "assign_to_uuid", "value": "123"}, {"name": "update_status", "value": "resolved"}, {"name": "append_comment", "value": "comment"}, {"name": "add_tag", "value": "test_tag"}], "composite_ids": ["123"]}'),  # noqa: E501
    (True, None, '/detects/entities/detects/v2',
     '{"ids": ["123"], "status": "resolved", "assigned_to_uuid": "123", "show_in_ui": "True", "comment": "comment"}')
                                                             ])
def test_resolve_detection(mocker, Legacy_version, tag, url_suffix, data):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running resolve_detection
    Then:
        - Validate that the correct url_suffix is used
            case 1: Legacy_version is False, the url_suffix should be alerts/entities/alerts/v2
            case 2: Legacy_version is True, the url_suffix should be /detects/entities/detects/v1
    """
    from CrowdStrikeFalcon import resolve_detection
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')

    resolve_detection(ids=["123"], status="resolved", assigned_to_uuid="123", show_in_ui="True", comment="comment", tag=tag)
    assert http_request_mocker.call_args_list[0][0][1] == url_suffix
    assert http_request_mocker.call_args_list[0][1]["data"] == data


@pytest.mark.parametrize('Legacy_version, url_suffix, request_params', [
    (False,
     "/alerts/queries/alerts/v2?filter=product%3A%27epp%27%2Btype%3A%27ldt%27%2Bupdated_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27",
     {'sort': 'created_timestamp.asc', 'offset': 5, 'limit': 3}),
    (True, '/detects/queries/detects/v1', {'sort': 'first_behavior.asc',
     'offset': 5, 'limit': 3, 'filter': "date_updated:>'2024-06-19T15:25:00Z'"})
])
def test_get_fetch_detections__url(mocker, Legacy_version, url_suffix, request_params):
    """
    Given:
        - The `Legacy_version` flag
    When:
        - Invoking `get_fetch_detections` with various input parameters
    Then:
        - Verify that the correct `url_suffix` is used and the input parameters are correctly passed

    Test Scenarios:
        1. When `Legacy_version` is False, the `url_suffix` should be:
        '/alerts/queries/alerts/v2?filter=product%3A%27epp%27%2Btype%3A%27ldt%27%2Bupdated_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27'
        All parameters (except 'limit') are part of the URL and are URL-encoded.
        2. When `Legacy_version` is True, the `url_suffix` should be "/detects/queries/detects/v1"
        All the provided parameters are passed under 'parameters'.
    """
    from CrowdStrikeFalcon import get_fetch_detections
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')

    get_fetch_detections(filter_arg=None, offset=5,
                         last_updated_timestamp='2024-06-19T15:25:00Z',
                         has_limit=True, limit=3)

    assert http_request_mocker.call_args_list[0][0][1] == url_suffix
    assert http_request_mocker.call_args_list[0][0][2] == request_params


@pytest.mark.parametrize('Legacy_version, expected_output', [
    (False, [{'status': 'open', 'max_severity': 'critical', 'detection_id': '123', 'created_time': '2022-01-01T00:00:00Z'}]),
    (True, [{'status': 'open', 'max_severity': 'high', 'detection_id': '123', 'created_time': '2022-01-01T00:00:00Z'}])])
def test_detections_to_human_readable(mocker, expected_output, Legacy_version):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running detections_to_human_readable
    Then:
        - Validate that the correct output is returned based on the Legacy_version flag
    """
    from CrowdStrikeFalcon import detections_to_human_readable
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    mock_table_to_markdown = mocker.patch('CrowdStrikeFalcon.tableToMarkdown')
    input = {'status': 'open', 'max_severity_displayname': 'high', 'detection_id': '123',
             'created_timestamp': '2022-01-01T00:00:00Z', 'severity_name': 'critical'},
    detections_to_human_readable(input)

    assert mock_table_to_markdown.call_args[0][1] == expected_output


def test_modify_detection_summaries_outputs():
    """
    Given:
        - A detection dictionary
    When:
        - Running modify_detection_summaries_outputs
    Then:
        - Validate that the output is correctly modified
    """
    from CrowdStrikeFalcon import modify_detection_summaries_outputs

    detection = {
        "pattern_disposition_details": "details",
        "timestamp": "time",
        "device": {"device_id": "device1", "hostinfo": "info"},
        "filename": "file",
        "cmdline": "cmd",
        "pattern_disposition": "disposition",
        "parent_details": {"sha256": "parent_sha256_test", "cmdline": "parent_cmd_test",
                           "md5": "parent_md5_test", "process_graph_id": "parent_id_test"},
        "composite_id": "composite"
    }

    modified_detection = modify_detection_summaries_outputs(detection)

    assert modified_detection["behaviors"]["device_id"] == "device1"
    assert modified_detection["behaviors"]["filename"] == "file"
    assert modified_detection["hostinfo"] == "info"
    assert modified_detection["detection_id"] == "composite"
    assert modified_detection["behaviors"]["parent_details"]["parent_sha256"] == "parent_sha256_test"
    assert modified_detection["behaviors"]["parent_details"]["parent_cmdline"] == "parent_cmd_test"
    assert modified_detection["behaviors"]["parent_details"]["parent_md5"] == "parent_md5_test"
    assert modified_detection["behaviors"]["timestamp"] == "time"


def test_truncate_long_time_str():
    """
    Given:
        - A list of detections
    When:
        - Running truncate_long_time_str
    Then:
        - Validate that the time string is correctly truncated to 6 digits after the dot
    """
    from CrowdStrikeFalcon import truncate_long_time_str

    detections = [{"time": "2022-01-01T00:00:00.000000000000000000000000000Z"},
                  {"time": "2022-01-01T00:00:00.000000Z"},
                  {"time": "2022-01-01T00:00:00.000000000000000000000000000Z"},
                  {"time": "2022-01-01T00:00:00Z"}
                  ]
    time_key = "time"

    assert truncate_long_time_str(detections, time_key) == [{'time': '2022-01-01T00:00:00.000000Z'},
                                                            {'time': '2022-01-01T00:00:00.000000Z'},
                                                            {'time': '2022-01-01T00:00:00.000000Z'},
                                                            {"time": "2022-01-01T00:00:00Z"}
                                                            ]


@pytest.mark.parametrize('Legacy_version, expected_url', [
    (False, '/alerts/entities/alerts/v2'),
    (True, '/detects/entities/summaries/GET/v1')
])
def test_get_detections_entities__url(mocker, Legacy_version, expected_url):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running get_detections_entities
    Then:
        - Validate that the correct url is used based on the Legacy_version flag
    """
    from CrowdStrikeFalcon import get_detections_entities
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
    get_detections_entities(["123"])
    assert http_request_mocker.call_args_list[0][0][1] == expected_url


@pytest.mark.parametrize('Legacy_version, expected_url, exepted_parameters', [
    (False, '/alerts/queries/alerts/v2?filter=created_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27',
     {'sort': 'created_timestamp.asc', 'offset': 0, 'limit': 2}),
    (True, '/alerts/queries/alerts/v1',
     {'sort': 'created_timestamp.asc', 'offset': 0, 'filter': "created_timestamp:>'2024-06-19T15:25:00Z'", 'limit': 2}
     )
])
def test_get_detections_ids__url_and_params(mocker, Legacy_version, expected_url, exepted_parameters):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running get_detections_ids
    Then:
        - Validate that the correct url and params are sent based on the Legacy_version flag
        case 1:
            Legacy_version is False, the url_suffix should be:
            '/alerts/queries/alerts/v2?filter=created_timestamp%3A%3E%272024-06-19T15%3A25%3A00Z%27'
            and the parameters are passed under are:
            {'sort': 'created_timestamp.asc', 'offset': 0, 'limit': 2}
        case 2:
            Legacy_version is True, the url_suffix should be:
            '/alerts/queries/alerts/v1'
            and the parameters are passed under are:
            {'sort': 'created_timestamp.asc', 'offset': 0, 'filter': "created_timestamp:>'2024-06-19T15:25:00Z'", 'limit': 2}


    """
    from CrowdStrikeFalcon import get_detections_ids
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
    get_detections_ids(filter_arg="created_timestamp:>'2024-06-19T15:25:00Z'")
    assert http_request_mocker.call_args_list[0][0][1] == expected_url
    assert http_request_mocker.call_args_list[0][0][2] == exepted_parameters


def test_modify_detection_outputs(mocker):
    """
    Given:
        - A detection dictionary
    When:
        - Running modify_detection_outputs
    Then:
        - Validate that the output is correctly modified
    """
    from CrowdStrikeFalcon import modify_detection_outputs
    mocker.patch('CrowdStrikeFalcon.DETECTIONS_BEHAVIORS_KEY_MAP', {"key1": "value1", "key2": "value2"})

    detection = {"key1": "value1", "key2": "value2", "key3": "value3", "parent_details": "details",
                 "triggering_process_graph_id": "id", "testing": "test"}

    assert modify_detection_outputs(detection) == {'key3': 'value3', 'testing': 'test',
                                                   'behaviors': [{'key1': 'value1',
                                                                  'key2': 'value2',
                                                                  'parent_details': 'details',
                                                                  'triggering_process_graph_id': 'id'}]}


@pytest.mark.parametrize('Legacy_version, expected_results', [
    (False, {'action_parameters': [{'name': 'key1', 'value': 'value1'}], 'composite_ids': ['123']}),
    (True, {'action_parameters': [{'name': 'key1', 'value': 'value1'}], 'ids': ['123']})
])
def test_resolve_detections_prepare_body_request(mocker, Legacy_version, expected_results):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running resolve_detections_prepare_body_request
    Then:
        - Validate that the correct body is returned based on the Legacy_version flag
    """
    from CrowdStrikeFalcon import resolve_detections_prepare_body_request
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    assert resolve_detections_prepare_body_request(ids=["123"], action_params_values={"key1": "value1"}) == expected_results


@pytest.mark.parametrize('Legacy_version, expected_url', [
    (False, '/alerts/entities/alerts/v3'),
    (True, '/alerts/entities/alerts/v2')
])
def test_resolve_detections_request__url(mocker, Legacy_version, expected_url):
    """
    Given:
        - The Legacy_version flag
    When:
        - Running resolve_detections_request
    Then:
        - Validate that the correct url is used based on the Legacy_version flag
    """
    from CrowdStrikeFalcon import resolve_detections_request
    mocker.patch('CrowdStrikeFalcon.LEGACY_VERSION', Legacy_version)
    http_request_mocker = mocker.patch('CrowdStrikeFalcon.http_request')
    resolve_detections_request(ids=["123"])
    assert http_request_mocker.call_args_list[0][1]['url_suffix'] == expected_url


def test_get_status(mocker):
    """
    Given:
        - Raw response of get_status_request
    When:
        - Running get_status command
    Then:
        - Validate that the contains the ids and state
    """
    import CrowdStrikeFalcon
    device_ids = ["0bde2c4645294245aca522971ccc4567", "04a75a2d15b44a5995c9c17200ad1212", "046761c46ec84f40b27b6f79ce7c6543",
                  "8ed44198a6f64f9fabd0479c30989876", "d4210a0957e640f18c237a2fa1141122"]

    response = load_json('test_data/online_states_response.json')

    mocker.patch.object(CrowdStrikeFalcon, 'http_request', return_value=response)

    results = CrowdStrikeFalcon.get_status(device_ids)
    assert len(results) == 5
    assert results == {'0bde2c4645294245aca522971ccc4567': 'Online',
                       '04a75a2d15b44a5995c9c17200ad1212': 'Online',
                       '046761c46ec84f40b27b6f79ce7c6543': 'Online',
                       '8ed44198a6f64f9fabd0479c30989876': 'Online',
                       'd4210a0957e640f18c237a2fa1141122': 'Online'}


def test_fix_time_field():
    """
    Given:
        - A detection, a string representing the key of the time we want to fix.
    When:
        - Running fetch_incidents command
    Then:
        - Validate that the value of the given key in the detection was updated correctly.
    """
    from CrowdStrikeFalcon import fix_time_field
    detection_1 = {
        'created_timestamp': '2023-04-20T11:13:10.424647194Z'
    }
    detection_2 = {
        'created_timestamp': '2023-04-20T11:13:10.424647Z'
    }
    detection_3 = {
        'created_timestamp': '2023-04-20T11:13:10.424Z'
    }

    fix_time_field(detection_1, 'created_timestamp')
    fix_time_field(detection_2, 'created_timestamp')
    fix_time_field(detection_3, 'created_timestamp')

    assert detection_1['created_timestamp'] == '2023-04-20T11:13:10.424647Z'
    assert detection_2['created_timestamp'] == '2023-04-20T11:13:10.424647Z'
    assert detection_3['created_timestamp'] == '2023-04-20T11:13:10.424Z'


def test_enrich_groups_no_resources(mocker):
    """
    Given:
        - A non exist group id.
    When:
        - Running enrich_groups.
    Then:
        - Validate that the result are empty and no exception raised.
    """
    import CrowdStrikeFalcon

    group_ids = "test_group_id"

    mocker.patch.object(CrowdStrikeFalcon, 'http_request', return_value={"resources": None})

    assert CrowdStrikeFalcon.enrich_groups(group_ids) == {}

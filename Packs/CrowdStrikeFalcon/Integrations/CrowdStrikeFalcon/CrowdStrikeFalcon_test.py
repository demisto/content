import pytest
import os
import demistomock as demisto
from CommonServerPython import outputPaths, entryTypes

RETURN_ERROR_TARGET = 'CrowdStrikeFalcon.return_error'
SERVER_URL = 'https://4.4.4.4'


@pytest.fixture(autouse=True)
def get_access_token(requests_mock, mocker):
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': SERVER_URL,
            'proxy': True
        }
    )
    requests_mock.post(
        f'{SERVER_URL}/oauth2/token',
        json={
            'access_token': 'token'
        },
        status_code=200
    )


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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
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
    run_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
                      'reason: Not found\nHost ID 284771ee197e422d5176d6634a62b934 - Sensor appears to be offline'


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
                'Command': "runscript -Raw=Write-Output 'Hello, World!"
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    upload_script_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 409 - ' \
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
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
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
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
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
        f'{SERVER_URL}/real-time-response/entities/scripts/v1?ids={script_id}',
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    delete_script_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 403 - ' \
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    delete_script_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
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
        f'{SERVER_URL}/real-time-response/entities/scripts/v1',
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    upload_file_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 409 - ' \
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
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
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
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
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
        f'{SERVER_URL}/real-time-response/entities/put-files/v1?ids={file_id}',
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    delete_file_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 403 - ' \
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
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    delete_file_command()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Error in API call to CrowdStrike Falcon: code: 404 - ' \
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
        f'{SERVER_URL}/real-time-response/entities/put-files/v1',
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
    results = status_get_command()
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
    results = get_extracted_file_command()

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
        f'{SERVER_URL}/real-time-response/entities/file/v1',
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

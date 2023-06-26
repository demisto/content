import json
import demistomock as demisto
import pytest


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.content = "test_content"


def test_login_failed(requests_mock, mocker):
    """
    Given:
        - Cybereason instance with invalid credentials

    When:
        - Running test module

    Then:
        - Ensure an indicative error is returned that authorization failed
    """
    login_failed_html = b"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Cybereason | Login</title>
    <base href="/">

    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="favicon.ico">
<link rel="shortcut icon" href="favicon.ico"><link href="public/vendors_c29907a62751511cc002.css" rel="stylesheet"><link href="public/login_62faa8ec0f21f2d2949f.css" rel="stylesheet"></head>  # noqa: E501
<body class="cbr-theme-dark">
    <app-login></app-login>
<script type="text/javascript" src="public/vendors_c29907a62751511cc002.js"></script><script type="text/javascript" src="public/login_62faa8ec0f21f2d2949f.js"></script></body>  # noqa: E501
</html>
"""
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'http://server',
        'credentials': {
            'identifier': 'username',
            'password': 'password'
        },
        'proxy': True
    })
    mocker.patch.object(demisto, 'command', return_value='test-module')
    return_error_mock = mocker.patch('Cybereason.return_error')
    requests_mock.post('http://server/login.html', content=login_failed_html)
    requests_mock.post('http://server/rest/visualsearch/query/simple', content=login_failed_html)
    requests_mock.get('http://server/logout')
    from Cybereason import main
    main()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert 'Failed to process the API response. Authentication failed, verify the credentials are correct.' in err_msg


params = {
    'server': 'http://server',
    'credentials': {
        'identifier': 'username',
        'password': 'password'},
    'proxy': True}


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def test_one_query_file(mocker):
    from Cybereason import Client, query_file_command
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    args = {'file_hash': '4778901e54f55d54435b2626923054a8'}
    machine_raw_response = json.loads(load_mock_response('machine_outputs.json'))
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=machine_raw_response)
    raw_response = json.loads(load_mock_response('file_outputs.json'))
    mocker.patch('Cybereason.query_file', return_value=raw_response)
    command_output = query_file_command(client, args)
    assert command_output.outputs_prefix == "Cybereason.File"


def test_two_query_file(mocker):
    from Cybereason import Client, query_file_command
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    args = {'file_hash': '4778901e54f55d54435b2626923054a8'}
    machine_raw_response = json.loads(load_mock_response('machine_outputs.json'))
    mocker.patch('Cybereason.get_file_machine_details', return_value=machine_raw_response)

    raw_response = {'status': "SUCCESS", "data": None}
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        query_file_command(client, args)
    assert exc_info.match(r"No results found.")
    args = {'file_hash': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value={})
    with pytest.raises(Exception) as exc_info:
        query_file_command(client, args)
    assert exc_info.match(r"Hash type is not supported.")


def test_malop_processes_command(mocker):
    from Cybereason import malop_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGuids": "11.-6236127207710541535", "machineName": "desktop", "dateTime": "None"}
    raw_response = json.loads(load_mock_response('malop_processes_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    command_output = malop_processes_command(client, args)
    assert command_output.outputs[0].get('Name', '') == 'bdata.bin'
    assert command_output.outputs[0].get('SHA1', '') ==\
        'f56238da9fbfa3864d443a85bb80743bd2415682'

    args = {"malopGuids": None, "machineName": "desktop", "dateTime": "2022/08/01 00:00:00"}
    mocker.patch.object(demisto, 'results')
    with pytest.raises(Exception) as exc_info:
        command_output = malop_processes_command(client, args)
    assert exc_info.match(r"malopGuids must be array of strings")


def test_is_probe_connected_command(mocker):
    from Cybereason import is_probe_connected_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    args = {"machine": "desktop-j60ivd0", "is_remediation_commmand": True}
    raw_response = json.loads(load_mock_response('is_probe_connected_raw_response.json'))
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=raw_response)
    command_output = is_probe_connected_command(client, args)
    assert command_output.readable_output == 'True'


def test_query_processes_command(mocker):
    from Cybereason import query_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machine": ["desktop-vg9ke2u"], "hasOutgoingConnection": "true", "hasIncomingConnection": "true",
            "hasExternalConnection": "true", "unsignedUnknownReputation": "true", "fromTemporaryFolder": "true",
            "privilegesEscalation": "true", "maliciousPsExec": "true",
            "processName": "test_process", "onlySuspicious": "true"}
    raw_response = json.loads(load_mock_response('query_processes_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = query_processes_command(client, args)
    assert command_output.outputs[0].get('SHA1', '') == "1bc5066ddf693fc034d6514618854e26a84fd0d1"


def test_query_connections_command(mocker):
    from Cybereason import query_connections_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    args = {"ip": "192.168.1.103"}
    raw_response = json.loads(load_mock_response('query_processes_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = query_connections_command(client, args)
    assert command_output.outputs[0]['Name'] == "svchost.exe"

    args = {"machine": "desktop"}
    command_output = query_connections_command(client, args)
    assert command_output.outputs[0]['Name'] == "svchost.exe"

    args = {"machine": "desktop", "ip": "192.168.1.103"}
    with pytest.raises(Exception) as exc_info:
        command_output = query_connections_command(client, args)
    assert exc_info.match(r"Too many arguments given.")

    args = {}
    with pytest.raises(Exception) as exc_info:
        command_output = query_connections_command(client, args)
    assert exc_info.match(r"Not enough arguments given.")


def test_isolate_machine_command(mocker):
    from Cybereason import isolate_machine_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    args = {"machine": "desktop-vg9ke2u"}
    raw_response = json.loads(load_mock_response('isolate_machine_raw_response.json'))
    mocker.patch("Cybereason.get_pylum_id", return_value="PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F")
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = isolate_machine_command(client, args)

    assert command_output[0].outputs_prefix == "Cybereason"


def test_unisolate_machine_command(mocker):
    from Cybereason import unisolate_machine_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machine": "desktop-vg9ke2u"}

    raw_response = json.loads(load_mock_response('isolate_machine_raw_response.json'))
    mocker.patch("Cybereason.get_pylum_id", return_value="PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F")
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = unisolate_machine_command(client, args)

    assert command_output[0].outputs_prefix == "Cybereason"


def test_get_non_edr_malop_data(mocker):
    from Cybereason import get_non_edr_malop_data
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "lastUpdateTime": 1672848355574
    }
    raw_response = json.loads(load_mock_response('malop_detection_data.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = get_non_edr_malop_data(client, args)
    assert command_output[0]['guid'] == 'AAAA0yUlnvXGQODT'


def test_query_malops_command(mocker):
    from Cybereason import query_malops_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"withinLastDays": 10}
    malop_process_raw_response = json.loads(load_mock_response('query_malop_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=malop_process_raw_response)
    command_output = query_malops_command(client, args)
    assert command_output.outputs[0]['AffectedMachine'] == ['desktop-j60ivd0']


def test_update_malop_status_command(mocker):
    from Cybereason import update_malop_status_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGuid": "11.-7780537507363356527", "status": "To Review"}
    raw_response = {
        'status': "SUCCESS"
    }
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = update_malop_status_command(client, args)
    assert command_output.outputs['GUID'] == "11.-7780537507363356527"
    assert command_output.outputs['Status'] == "To Review"

    raw_response = {
        'status': "SUCESS"
    }
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        command_output = update_malop_status_command(client, args)
    assert exc_info.match(r"message")

    args = {"malopGuid": "11.-7780537507363356527", "status": "test"}
    with pytest.raises(Exception) as exc_info:
        command_output = update_malop_status_command(client, args)
    assert exc_info.match(r"Invalid status.")


def test_prevent_file_command(mocker):
    from Cybereason import prevent_file_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"md5": "fc61fdcad5a9d52a01bd2d596f2c92b9"}

    raw_response = json.loads(load_mock_response('prevent_file_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = prevent_file_command(client, args)
    assert command_output.outputs['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"

    raw_response = {
        'outcome': "failure"
    }
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        command_output = prevent_file_command(client, args)
    assert exc_info.match(r"Failed to prevent file")


def test_unprevent_file_command(mocker):
    from Cybereason import unprevent_file_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"md5": "fc61fdcad5a9d52a01bd2d596f2c92b9"}
    raw_response = json.loads(load_mock_response('prevent_file_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = unprevent_file_command(client, args)
    assert command_output.outputs['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"

    raw_response = {
        'outcome': "failure"
    }
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        command_output = unprevent_file_command(client, args)
    assert exc_info.match(r"Failed to unprevent file")


def test_query_domain_command(mocker):
    from Cybereason import query_domain_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"domain": "www2.bing.com"}
    raw_response = json.loads(load_mock_response('query_domain_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = query_domain_command(client, args)
    assert command_output.outputs_prefix == "Cybereason.Domain"

    mocker.patch("Cybereason.Client.cybereason_api_call", return_value={})
    with pytest.raises(Exception) as exc_info:
        command_output = query_domain_command(client, args)
    assert exc_info.match(r"Error occurred while trying to query the file.")

    raw_response = {'status': "SUCCESS", "data": None}
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        command_output = query_domain_command(client, args)
    assert exc_info.match(r"No results found.")


def test_query_user_command(mocker):
    from Cybereason import query_user_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"username": "desktop-vg9ke2u"}
    raw_response = json.loads(load_mock_response('query_user_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = query_user_command(client, args)
    assert command_output.outputs[0]['Username'] == "desktop-vg9ke2u"

    mocker.patch("Cybereason.Client.cybereason_api_call", return_value={})
    with pytest.raises(Exception) as exc_info:
        command_output = query_user_command(client, args)
    assert exc_info.match(r"Error occurred while trying to query the file.")

    raw_response = {'status': "SUCCESS", "data": None}
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        command_output = query_user_command(client, args)
    assert exc_info.match(r"No results found.")


def test_available_remediation_actions_command(mocker):
    from Cybereason import available_remediation_actions_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGuid": "11.-7780537507363356527"}
    raw_response = json.loads(load_mock_response('available_remediation_actions_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = available_remediation_actions_command(client, args)

    assert command_output.outputs_prefix == "Cybereason.Remediation"


def test_start_fetchfile_command(mocker):
    from Cybereason import start_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGUID": "11.-7780537507363356527", "userName": "desktop-vg9ke2u"}
    raw_response = json.loads(load_mock_response('get_file_guids_raw_response.json'))
    mocker.patch("Cybereason.get_file_guids", return_value=raw_response)
    raw_response = json.loads(load_mock_response('start_fetch_file_raw_response.json'))
    mocker.patch("Cybereason.start_fetchfile", return_value=raw_response)
    command_output = start_fetchfile_command(client, args)
    assert command_output.readable_output[0] == 'S'


def test_fetchfile_progress_command(mocker):
    from Cybereason import fetchfile_progress_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGuid": "11.-7780537507363356527"}
    raw_response = json.loads(load_mock_response('get_file_guids_raw_response.json'))
    mocker.patch("Cybereason.get_file_guids", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_batch_id_raw_response.json'))
    mocker.patch("Cybereason.get_batch_id", return_value=raw_response)
    command_output = fetchfile_progress_command(client, args)

    assert command_output.outputs['MalopID'] == "11.-7780537507363356527"


def test_quarantine_file_command(mocker):
    from Cybereason import quarantine_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Quarantine the File",
        "timeout": 60}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        quarantine_file_command(client, args)
    assert exc_info.match(r"Quarantine file remediation")


def test_unquarantine_file_command(mocker):
    from Cybereason import unquarantine_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Unquarantine the File",
        "timeout": 60}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        unquarantine_file_command(client, args)
    assert exc_info.match(r"Unquarantine file remediation")


def test_block_file_command(mocker):
    from Cybereason import block_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Block the File",
        "timeout": 60}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        block_file_command(client, args)
    assert exc_info.match(r"Block file remediation")


def test_kill_process_command(mocker):
    from Cybereason import kill_process_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Kill the Process"}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        kill_process_command(client, args)
    assert exc_info.match(r"Kill process remediation")


def test_get_sensor_id_command(mocker):
    from Cybereason import get_sensor_id_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machineName": 'desktop-vg9ke2u'}
    raw_response = json.loads(load_mock_response('get_sensor_id_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = get_sensor_id_command(client, args)
    assert command_output.readable_output == ("Available Sensor IDs are {'desktop-vg9ke2u': "
                                              "'5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F'}")

    mocker.patch("Cybereason.Client.cybereason_api_call", return_value={"sensors": []})
    with pytest.raises(Exception) as exc_info:
        command_output = get_sensor_id_command(client, args)
    assert exc_info.match(r"Could not find any Sensor ID for the machine")


def test_number_one_fetch_scan_status_command(mocker):
    from Cybereason import fetch_scan_status_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"batchID": "-1112786456"}
    raw_response = json.loads(load_mock_response('fetch_scan_status_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = fetch_scan_status_command(client, args)
    assert command_output.raw_response == "The given batch ID does not match with any actions on sensors."


def test_malware_query_command(mocker):
    from Cybereason import malware_query_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "limit": "5",
        "needsAttention": "True",
        "status": "Done",
        "type": "KnownMalware",
        "timestamp": "1582206286000"}
    raw_response = raw_response = json.loads(load_mock_response('malware_query_raw_data.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = malware_query_command(client, args)
    assert command_output.raw_response['status'] == "SUCCESS"

    args = {
        "limit": "0"
    }
    with pytest.raises(Exception) as exc_info:
        command_output = malware_query_command(client, args)
    assert exc_info.match(r"Limit cannot be zero or a negative number.")


def test_unsuspend_process_command(mocker):
    from Cybereason import unsuspend_process_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Unsuspend Process"}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        unsuspend_process_command(client, args)
    assert exc_info.match(r"Unsuspend process remediation")


def test_kill_prevent_unsuspend_command(mocker):
    from Cybereason import kill_prevent_unsuspend_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Kill Prevent",
        "timeout": "30"}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        kill_prevent_unsuspend_command(client, args)
    assert exc_info.match(r"Kill prevent unsuspend")


def test_delete_registry_key_command(mocker):
    from Cybereason import delete_registry_key_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "desktop-vg9ke2u",
        "comment": "Remove the registry key",
        "timeout": 30}
    mocker.patch("Cybereason.is_probe_connected_command", return_value=True)
    raw_response = json.loads(load_mock_response('get_remediation_action.json'))
    mocker.patch("Cybereason.get_remediation_action", return_value=raw_response)
    raw_response = json.loads(load_mock_response('get_remediation_action_status.json'))
    mocker.patch("Cybereason.get_remediation_action_status", return_value=raw_response)
    with pytest.raises(Exception) as exc_info:
        delete_registry_key_command(client, args)
    assert exc_info.match(r"Delete registry key")


def test_add_comment_command(mocker):
    from Cybereason import add_comment_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "comment": "New comment",
        "malopGuid": "11.-7780537507363356527"}
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value={})
    command_output = add_comment_command(client, args)

    assert command_output.readable_output == "Comment added successfully"


def test_fetch_incidents(mocker):
    from Cybereason import fetch_incidents
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    raw_response = json.loads(load_mock_response('query_malop_raw_response.json'))
    mocker.patch("Cybereason.query_malops", return_value=(raw_response, {}))
    raw_response = json.loads(load_mock_response('non_edr.json'))
    mocker.patch("Cybereason.get_non_edr_malop_data", return_value=(raw_response, {}))
    raw_response = json.loads(load_mock_response('malop_to_incident.json'))
    mocker.patch("Cybereason.malop_to_incident", return_value=(raw_response, {}))

    command_output = fetch_incidents(client)
    command_output = str(command_output)

    assert command_output == 'None'


def test_archive_sensor_command(mocker):
    from Cybereason import archive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    test_reponse = MockResponse({"key1": "val1"}, 204)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = archive_sensor_command(client, args)
    assert command_output.readable_output == ('The selected Sensor with Sensor ID: 5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ'
                                              ' is not available for archive.')

    test_reponse = MockResponse({"key1": "val1"}, 404)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = archive_sensor_command(client, args)
    assert exc_info.match(r"Your request failed")


def test_unarchive_sensor_command(mocker):
    from Cybereason import unarchive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    test_reponse = MockResponse({"key1": "val1"}, 204)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = unarchive_sensor_command(client, args)
    assert command_output.readable_output == ('The selected Sensor with Sensor ID: 5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ '
                                              'is not available for unarchive.')

    test_reponse = MockResponse({"key1": "val1"}, 404)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = unarchive_sensor_command(client, args)
    assert exc_info.match(r"Your request failed")


def test_delete_sensor_command(mocker):
    from Cybereason import delete_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    test_reponse = MockResponse({"key1": "val1"}, 200)
    args = {
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = delete_sensor_command(client, args)
    assert command_output.readable_output == 'Sensor deleted successfully.'

    test_reponse = MockResponse({"key1": "val1"}, 204)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = delete_sensor_command(client, args)
    assert command_output.readable_output == ('The selected Sensor with Sensor ID: 5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ '
                                              'is not available for deleting.')

    test_reponse = MockResponse({"key1": "val1"}, 404)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ"}
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = delete_sensor_command(client, args)
    assert exc_info.match(r"Your request failed")


def test_start_host_scan_command(mocker):
    from Cybereason import start_host_scan_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "sensorID": "5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ",
        "scanType": "FULL"}

    test_reponse = MockResponse({"key1": "val1"}, 204)
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = start_host_scan_command(client, args)
    assert command_output.readable_output == ('Given Sensor ID/ID\'s [\'5e778834ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ\'] is/are '
                                              'not available for scanning.')

    test_reponse = MockResponse({"key1": "val1"}, 404)
    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = start_host_scan_command(client, args)
    assert exc_info.match(r"Your request failed")


def test_number_two_fetch_scan_status_command(mocker):
    from Cybereason import fetch_scan_status_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "batchID": "123456"
    }

    test_reponse = [
        {
            'batchId': 123456
        }
    ]

    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = fetch_scan_status_command(client, args)
    assert command_output.raw_response == test_reponse[0]

    test_reponse = [
        {
            'batchId': "123456"
        }
    ]

    mocker.patch('Cybereason.Client.cybereason_api_call', return_value=test_reponse)
    command_output = fetch_scan_status_command(client, args)
    assert command_output.raw_response == 'The given batch ID does not match with any actions on sensors.'


def test_download_fetchfile_command(mocker):
    from Cybereason import download_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"batchID": "-1044817479"}

    test_reponse = MockResponse({"key1": "val1"}, 404)
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = download_fetchfile_command(client, args)
    assert exc_info.match(r"request failed with the following error:")

    test_reponse = MockResponse({"key1": "val1"}, 200)
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=test_reponse)
    command_output = download_fetchfile_command(client, args)
    assert command_output['File'] == 'download.zip'


def test_close_fetchfile_command(mocker):
    from Cybereason import close_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"batchID": "-796720096"}

    test_reponse = MockResponse({"key1": "val1"}, 200)
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        close_fetchfile_command(client, args)
    assert exc_info.match(r"The given Batch ID does not exist")


def test_malop_to_incident(mocker):
    from Cybereason import malop_to_incident
    args = {
        "guidString": "12345A"
    }
    command_output = malop_to_incident(args)

    assert command_output['name'] == "Cybereason Malop 12345A"

    with pytest.raises(Exception) as exc_info:
        command_output = malop_to_incident("args")
    assert exc_info.match(r"Cybereason raw response is not valid")


def test_get_pylum_id(mocker):
    from Cybereason import get_pylum_id, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    test_reponse = {
        'data': {
            'resultIdToElementDataMap': {
                "-1845090846.1198775089551518743": {
                    "simpleValues": {
                        "pylumId": {
                            "totalValues": 1,
                            "values": [
                                None
                            ]
                        }
                    },
                }
            }
        }
    }
    raw_response = json.loads(load_mock_response('get_pylum_id_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = get_pylum_id(client, "test_machine")
    assert command_output == "PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F"

    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=test_reponse)
    with pytest.raises(Exception) as exc_info:
        command_output = get_pylum_id(client, "test_machine")
    assert exc_info.match(r"Could not find machine")


def test_get_machine_guid(mocker):
    from Cybereason import get_machine_guid, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    raw_response = json.loads(load_mock_response('get_machine_guid_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    command_output = get_machine_guid(client, "test_machine")
    assert command_output == "-1826875736.1198775089551518743"

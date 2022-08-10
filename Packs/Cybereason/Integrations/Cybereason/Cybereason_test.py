# from CommonServerPython import *
import json
import demistomock as demisto


def test_login_failed(requests_mock, mocker):
    """
    Given:
        - Cybereason instance with invalid credentials

    When:
        - Running test module

    Then:
        - Ensure an indicative error is returned that authorization failed
    """
    login_failed_html = """<!doctype html>
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
""".encode('utf-8')
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
    with open(f'test_files/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def test_query_file(mocker):
    args = {'file_hash': '4778901e54f55d54435b2626923054a8'}
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    raw_response = json.loads(load_mock_response('machine_outputs.json'))
    mocker.patch('Cybereason.get_file_machine_details', return_value=raw_response)
    raw_response = json.loads(load_mock_response('file_outputs.json'))
    mocker.patch('Cybereason.query_file', return_value=raw_response)
    from Cybereason import Client, query_file_command
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    out = query_file_command(client, args)
    assert out.outputs['Cybereason.File(val.MD5 && val.MD5===obj.MD5 || val.SHA1 && val.SHA1===obj.SHA1)']\
        [0]['Machine'] == 'desktop-p0m5vad'


def test_malop_processes_command(mocker):
    from Cybereason import malop_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"malopGuids": "11.-6236127207710541535"}
    raw_response = json.loads(load_mock_response('malop_processes_raw_response.json'))
    mocker.patch("Cybereason.malop_processes", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    out = malop_processes_command(client, args)
    assert out.outputs[0].get('Name', '') == 'bdata.bin'
    assert out.outputs[0].get('SHA1', '') ==\
        'f56238da9fbfa3864d443a85bb80743bd2415682'


def test_is_probe_connected_command(mocker):
    from Cybereason import is_probe_connected_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machine": "desktop-j60ivd0"}
    raw_response = json.loads(load_mock_response('is_probe_connected_raw_response.json'))
    mocker.patch('Cybereason.is_probe_connected', return_value=raw_response)
    out = is_probe_connected_command(client, args)
    assert out.outputs['Name'] == 'desktop-j60ivd0'


def test_query_processes_command(mocker):
    from Cybereason import query_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machine": ["desktop-vg9ke2u"], "hasOutgoingConnection": "true", "hasIncomingConnection": "true"}
    raw_response = json.loads(load_mock_response('query_processes_raw_response.json'))
    mocker.patch("Cybereason.query_processes", return_value=raw_response)
    out = query_processes_command(client, args)
    assert out.outputs[0].get('SHA1', '') == "1bc5066ddf693fc034d6514618854e26a84fd0d1"


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
    mocker.patch("Cybereason.query_connections", return_value=raw_response)
    out = query_connections_command(client, args)

    assert out.outputs[0]['Name'] == "svchost.exe"


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
    mocker.patch("Cybereason.isolate_machine", return_value=(
        raw_response, "PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F"))
    out = isolate_machine_command(client, args)

    assert out.outputs['Cybereason(val.Machine && val.Machine === obj.Machine)']['Machine'] == "desktop-vg9ke2u"


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
    mocker.patch("Cybereason.unisolate_machine", return_value=(
        raw_response, "PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F"))
    out = unisolate_machine_command(client, args)

    assert out.outputs['Cybereason(val.Machine && val.Machine === obj.Machine)']['Machine'] == "desktop-vg9ke2u"


def test_query_malops_command(mocker):
    from Cybereason import query_malops_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {}

    raw_response = json.loads(load_mock_response('query_malop_raw_response.json'))
    mocker.patch("Cybereason.query_malops", return_value=(raw_response, raw_response))
    out = query_malops_command(client, args)

    assert out.outputs == []


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

    mocker.patch("Cybereason.update_malop_status", return_value={})
    out = update_malop_status_command(client, args)

    assert out.outputs['GUID'] == "11.-7780537507363356527"
    assert out.outputs['Status'] == "To Review"


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
    mocker.patch("Cybereason.prevent_file", return_value=raw_response)
    out = prevent_file_command(client, args)

    assert out.outputs['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"
    assert out.outputs['Prevent'] == True


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
    mocker.patch("Cybereason.unprevent_file", return_value=raw_response)
    out = unprevent_file_command(client, args)

    assert out.outputs['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"
    assert out.outputs['Prevent'] == False


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
    mocker.patch("Cybereason.query_domain", return_value=raw_response)
    out = query_domain_command(client, args)
    assert out.outputs['Cybereason.Domain(val.Name && val.Name===obj.Name)'][0]['Name'] == "www2.bing.com"


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
    mocker.patch("Cybereason.query_user", return_value=raw_response)
    out = query_user_command(client, args)
    assert out.outputs[0]['Username'] == "desktop-vg9ke2u"


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
    out = available_remediation_actions_command(client, args)

    assert out.raw_response['status'] == "SUCCESS"


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
    out = start_fetchfile_command(client, args)
    assert out.readable_output[0] == 'S'


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
    out = fetchfile_progress_command(client, args)

    assert out.outputs['MalopID'] == "11.-7780537507363356527"


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = quarantine_file_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_quarantine_file_command(mocker):  # _with_connection
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
    out = quarantine_file_command(client, args)

    assert out.readable_output[0:15] == 'Quarantine file'


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = unquarantine_file_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_unquarantine_file_command(mocker):  # _with_connection
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
    out = unquarantine_file_command(client, args)

    assert out.readable_output[0:17] == 'Unquarantine file'


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = block_file_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_block_file_command(mocker):  # _with_connection
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
    out = block_file_command(client, args)

    assert out.readable_output[0:10] == 'Block file'


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = kill_process_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_kill_process_command(mocker):  # _with_connection
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
    out = kill_process_command(client, args)

    assert out.readable_output[0:12] == 'Kill process'


def test_get_sensor_id_command(mocker):
    from Cybereason import get_sensor_id_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {"machine": 'desktop-vg9ke2u'}
    raw_response = json.loads(load_mock_response('get_sensor_id_raw_response.json'))
    mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    out = get_sensor_id_command(client, args)

    assert out.readable_output == "Available Sensor IDs are {'desktop-vg9ke2u': '5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F'}"


def test_fetch_scan_status_command(mocker):
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
    out = fetch_scan_status_command(client, args)
    assert out.raw_response == "The given batch ID does not match with any actions on sensors."


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
    mocker.patch("Cybereason.malware_query_filter", return_value=raw_response)
    out = malware_query_command(client, args)

    assert out.raw_response['status'] == "SUCCESS"


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = unsuspend_process_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_unsuspend_process_command(mocker):  # _with_connection
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
    out = unsuspend_process_command(client, args)

    assert out.readable_output[0:17] == 'Unsuspend process'


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = kill_prevent_unsuspend_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_kill_prevent_unsuspend_command(mocker):  # _with_connection
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
    out = kill_prevent_unsuspend_command(client, args)

    assert out.readable_output[0:13] == 'Kill prevent '


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
    mocker.patch("Cybereason.is_probe_connected_command", return_value=False)
    out = delete_registry_key_command(client, args)

    assert out.readable_output == "Machine must be connected to Cybereason in order to perform this action."


def test_delete_registry_key_command(mocker):  # _with_connection
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
    out = delete_registry_key_command(client, args)

    assert out.readable_output[0:20] == 'Delete registry key '


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
    mocker.patch("Cybereason.add_comment", return_value={})
    out = add_comment_command(client, args)

    assert out.readable_output == "Comment added successfully"


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
    out = fetch_incidents(client)

    assert out == None


def test_archive_sensor_command(mocker):
    from Cybereason import archive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
        "archiveReason": "Archive this Sensor"}
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    # raw_response = json.loads(load_mock_response('archive_sensor.json'))
    # mocker.patch("Cybereason.Client.cybereason_api_call", return_value=raw_response)
    out = archive_sensor_command(client, args)

    assert out.readable_output[0] == 'E'


def test_unarchive_sensor_command(mocker):
    from Cybereason import unarchive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    # mocker.patch.object(demisto, 'params', return_value=params)
    # mocker.patch.object(demisto, 'args', return_value={
    #     "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
    #     "archiveReason": "Unarchive this Sensor"})
    args = {
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
        "archiveReason": "Archive this Sensor"}
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    out = unarchive_sensor_command(client, args)
    # result = demisto.results.call_args[0]
    assert out.readable_output[0] == 'E'


def test_delete_sensor_command(mocker):
    from Cybereason import delete_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    args = {
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
        "archiveReason": "Archive this Sensor"}
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    # mocker.patch.object(demisto, 'params', return_value=params)
    # mocker.patch.object(demisto, 'args', return_value={
    #     "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5"})
    out = delete_sensor_command(client, args)
    # result = demisto.results.call_args[0]
    assert out.readable_output[0] == 'S'


# def test_start_host_scan_command(mocker):
#     from Cybereason import start_host_scan_command, Client
#     HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
#     client = Client(
#         base_url="https://integration.cybereason.net:8443",
#         verify=False,
#         headers=HEADERS,
#         proxy=True)
#     args = {
#         "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F",
#         "scanType": "FULL"}
#     # mocker.patch.object(demisto, 'params', return_value=params)
#     # mocker.patch.object(demisto, 'args', return_value={
#     #     "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F",
#     #     "scanType": "FULL"})
#     out = start_host_scan_command(client, args)
#     # result = demisto.results.call_args[0]
#     # assert out.readable_output[0] == 'S'


# def test_download_fetchfile_command(mocker):
#     from Cybereason import download_fetchfile_command, Client
#     HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
#     client = Client(
#         base_url="https://integration.cybereason.net:8443",
#         verify=False,
#         headers=HEADERS,
#         proxy=True)
#     args = {"batchID": "-1044817479"}
#     raw_response = json.loads(fetch_file_progress_raw_response)
#     mocker.patch("Cybereason.download_fetchfile", return_value=raw_response)
#     download_fetchfile_command(client, args)
#     result = demisto.results.call_args[0]

#     assert result[0]['File']['SHA1'] == "9d5ef11989f0294929b572fdd4be2aefae94810d"
#     assert result[0]['File']['MD5'] == "753ce5f6014c7cd549f751752978d4cf"


# def test_close_fetchfile_command(mocker):
#     from Cybereason import close_fetchfile_command, Client
#     HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
#     client = Client(
#         base_url="https://integration.cybereason.net:8443",
#         verify=False,
#         headers=HEADERS,
#         proxy=True)
#     args = {"batchID": "-796720096"}
#     raw_response = json.loads(fetch_file_progress_raw_response)
#     mocker.patch("Cybereason.close_fetchfile", return_value=raw_response)    
#     out = close_fetchfile_command(client, args)

#     try:
#         assert out.readable_output[0] == 'S'
#     except Exception as e:
#         raise Exception(f'error: ' + str(out.readable_output))
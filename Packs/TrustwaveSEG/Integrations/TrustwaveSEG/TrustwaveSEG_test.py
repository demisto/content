import json
import dateparser
from datetime import datetime


def util_load_json(path: str) -> dict:
    """Load json file to dict object

    Args:
        path (str): The path of the file

    Returns:
        dict: The JSON data from the file
    """
    with open(path, encoding='utf-8') as file:
        return json.loads(file.read())


def test_trustwave_seg_get_version_command(requests_mock):
    """Tests trustwave_seg_get_version_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_get_version_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_get_version_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_get_version_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get('https://1.1.1.1:2/seg/api/version', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_get_version_command(client)

    assert response.outputs_prefix == 'TrustwaveSEG.Version'
    assert response.raw_response['configVersion'] == 39
    assert response.raw_response['productVersion'] == '10.0.1.2030'
    assert response.raw_response['rpcInterfaceVersion'] == 31


def test_trustwave_seg_statistics_command(requests_mock):
    """Tests trustwave_seg_statistics_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_statistics_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_statistics_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_statistics_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    start_time = dateparser.parse('2021-04-04 07:35:58 PM')
    end_time = dateparser.parse('2021-05-05 07:35:58 PM')
    start_time = int(datetime.timestamp(
        datetime.utcfromtimestamp(datetime.timestamp(start_time))))
    end_time = int(datetime.timestamp(
        datetime.utcfromtimestamp(datetime.timestamp(end_time))))
    requests_mock.get(
        f'https://1.1.1.1:2/seg/api/console/array/stats?fromtime={start_time}&totime={end_time}',
        json=mock_response
    )
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_statistics_command(
        client, start_time='2021-04-04 07:35:58 PM', end_time='2021-05-05 07:35:58 PM')

    assert response.outputs_prefix == 'TrustwaveSEG.Statistics'
    assert response.raw_response['maliciousUrls'] == 0
    assert response.raw_response['pFolders'] is None
    assert response.raw_response['virusScanned'] == 0


def test_trustwave_seg_list_classifications_command(requests_mock):
    """Tests trustwave_seg_list_classifications_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_classifications_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_classifications_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_classifications_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/quarantine/classifications', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_classifications_command(client)

    assert response.outputs_prefix == 'TrustwaveSEG.Classification'
    assert response.raw_response[0]['code'] == 1022
    assert response.raw_response[0]['id'] == 53
    assert response.raw_response[0]['name'] == 'Policy Breaches - HIPAA'
    assert response.raw_response[0]['type'] == 1


def test_trustwave_seg_automatic_config_backup_list_command(requests_mock):
    """Tests trustwave_seg_automatic_config_backup_list_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_automatic_config_backup_list_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_automatic_config_backup_list_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_automatic_config_backup_list_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/services/config/autobackups', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_automatic_config_backup_list_command(client)

    tester = response.raw_response[0]

    assert response.outputs_prefix == 'TrustwaveSEG.AutomaticBackupConfig'
    assert tester['filename'] == 'MailMarshal-10.0.1-ManualBackup_11-Apr-2021-05-00-10'
    assert tester['fileSize'] == 69621136
    assert tester['lastModified'] == 1618142420


def test_trustwave_seg_automatic_config_backup_restore_command(requests_mock):
    """Tests trustwave_seg_automatic_config_backup_restore_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_automatic_config_backup_restore_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_automatic_config_backup_restore_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_automatic_config_backup_restore_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.put('https://1.1.1.1:2/seg/api/services/config/autobackups/restore',
                      json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_automatic_config_backup_restore_command(
        client, timeout=30, name='xxx', include_dkim=False)

    assert response.outputs_prefix == 'TrustwaveSEG.AutomaticBackupRestore'
    assert response.raw_response['errors'] == ''
    assert response.raw_response['reason'] == 'backup restored'
    assert response.raw_response['warnings'] == ''


def test_trustwave_seg_automatic_config_backup_run_command(requests_mock):
    """Tests trustwave_seg_automatic_config_backup_run_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_automatic_config_backup_run_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_automatic_config_backup_run_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_automatic_config_backup_run_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.put('https://1.1.1.1:2/seg/api/services/config/autobackups/backup',
                      json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_automatic_config_backup_run_command(
        client, timeout=30, include_dkim=False)

    raw_response = response.raw_response

    assert response.outputs_prefix == 'TrustwaveSEG.AutomaticBackupRun'
    assert raw_response['backupName'] == 'MailMarshal-10.0.1-ManualBackup_11-Apr-2021-05-03-58'
    assert raw_response['reason'] == 'backup successful'


def test_trustwave_seg_list_servers_command(requests_mock):
    """Tests trustwave_seg_list_servers_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_servers_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_servers_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_servers_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/services/servers/', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_servers_command(client)

    assert response.outputs_prefix == 'TrustwaveSEG.Server'
    assert response.outputs_key_field == 'serverId'
    assert response.raw_response[0]['serverId'] == 1
    assert response.raw_response[0]['serverName'] == 'DEV-TRUSTWAVE'


def test_trustwave_seg_get_server_command(requests_mock):
    """Tests trustwave_seg_get_server_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_get_server_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_get_server_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_get_server_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/services/servers/1', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_get_server_command(client, 1)

    assert response.outputs_prefix == 'TrustwaveSEG.Server'
    assert response.outputs_key_field == 'serverId'
    assert response.raw_response['serverId'] == 1
    assert response.raw_response['serverName'] == 'DEV-TRUSTWAVE'


def test_trustwave_seg_list_alerts_command(requests_mock):
    """Tests trustwave_seg_list_alerts_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_alerts_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_alerts_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_alerts_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/console/alerts?activeonly=False', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_alerts_command(client, False)

    assert response.outputs_prefix == 'TrustwaveSEG.Alert'
    assert response.outputs_key_field == ['triggered', 'source']
    assert not response.raw_response[0]['active']
    assert response.raw_response[0]['triggered'] == 1618122938


def test_trustwave_seg_list_quarantine_folders_command(requests_mock):
    """Tests trustwave_seg_list_quarantine_folders_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_quarantine_folders_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_quarantine_folders_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_quarantine_folders_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/quarantine/folders/', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_quarantine_folders_command(client)

    assert response.outputs_prefix == 'TrustwaveSEG.Folder'
    assert response.outputs_key_field == 'folderId'
    assert response.raw_response[0]['folderId'] == 1007


def test_trustwave_seg_list_quarantine_folders_with_day_info_command(requests_mock):
    """Tests trustwave_seg_list_quarantine_folders_with_day_info_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_quarantine_folders_with_day_info_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_quarantine_folders_with_day_info_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_quarantine_folders_with_day_info_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/quarantine/folderswithdayinfo/', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_quarantine_folders_with_day_info_command(
        client)

    assert response.outputs_prefix == 'TrustwaveSEG.Folder'
    assert response.outputs_key_field == 'folderId'
    assert response.raw_response[0]['folderId'] == 1007


def test_trustwave_seg_list_day_info_by_quarantine_folder_command(requests_mock):
    """Tests trustwave_seg_list_day_info_by_quarantine_folder_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_list_day_info_by_quarantine_folder_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_list_day_info_by_quarantine_folder_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_day_info_by_quarantine_folder_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.get(
        'https://1.1.1.1:2/seg/api/quarantine/folders/1007/dayinfo', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_list_day_info_by_quarantine_folder_command(
        client, '1007')

    assert response.outputs_prefix == 'TrustwaveSEG.DayInfo'
    assert response.outputs_key_field == ['startTime', 'endTime']
    assert response.raw_response[0]['numFiles'] == 1


def test_trustwave_seg_find_quarantine_message_command(requests_mock):
    """Tests trustwave_seg_find_quarantine_message_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_find_quarantine_message_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client, trustwave_seg_find_quarantine_message_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_find_quarantine_message_command.json')
    requests_mock.post('https://1.1.1.1:1/token',
                       json={'access_token': 'token', 'expires_in': 0})
    requests_mock.post(
        'https://1.1.1.1:2/seg/api/quarantine/findmessage/?maxRows=5', json=mock_response)
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_find_quarantine_message_command(
        client, max_rows="5", time_range="1 day ago")

    assert response.outputs_prefix == 'TrustwaveSEG.Message'
    assert response.outputs_key_field == ['edition', 'blockNumber']
    assert response.raw_response[0]['blockNumber'] == 106098471075840
    assert response.raw_response[0]['edition'] == '607ef9ae0000'


def test_trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command(requests_mock):
    """Tests trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command command

    Configures requests_mock instance to generate the appropriate
    trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command API response.
    Checks the output of the command function with the expected output.
    """
    from TrustwaveSEG import Client
    from TrustwaveSEG import trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command
    mock_response = util_load_json(
        'test_data/trustwave_seg_list_alerts_command.json')
    requests_mock.post(
        'https://1.1.1.1:1/token',
        json={'access_token': 'token', 'expires_in': 0}
    )
    requests_mock.post(
        'https://1.1.1.1:2/seg/api/quarantine/forwardspam/',
        json=mock_response
    )
    client = Client('1.1.1.1', '1', '2', 'username', 'password', False, False)
    response = trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command(
        client, "1", "1", "1", "xxx", "xxx",
        "1", "1", "xxx", "true"
    )

    assert 'forwarded' in response

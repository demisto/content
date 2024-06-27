import pytest
from freezegun import freeze_time

from CommonServerPython import *
from ZimperiumV2 import Client, users_search_command, devices_search_command, \
    report_get_command, threat_search_command, app_version_list_command, get_devices_by_cve_command, \
    devices_os_version_command, get_cves_by_device_command, policy_group_list_command, policy_privacy_get_command, \
    policy_threat_get_command, policy_phishing_get_command, policy_app_settings_get_command, \
    policy_device_inactivity_list_command, policy_device_inactivity_get_command, fetch_incidents, \
    vulnerability_get_command, main

SERVER_URL = 'https://test_url.com/api'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client(requests_mock):
    requests_mock.post(f'{SERVER_URL}/auth/v1/api_keys/login', json={'accessToken': 'token'})
    return Client(base_url=SERVER_URL, client_id='test', client_secret='test', verify=True, proxy=False)


def test_users_search_command(client, requests_mock):
    """
        When: Running zimperium-users-search
        Given: team_id and user_id
        Then: validate the command result returned.
        """
    args = {'team_id': '3', 'user_id': '01'}
    mock_response_users_search = util_load_json(
        './test_data/users_search.json')

    requests_mock.get(f'{SERVER_URL}/auth/public/v1/users/01', json=mock_response_users_search)
    results = users_search_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.User'
    assert results.outputs_key_field == 'id'
    assert results.raw_response == mock_response_users_search
    assert results.outputs.get('id') == '01'


def test_users_search_by_email_command(client, requests_mock):
    """
        When: Running zimperium-users-search
        Given: team_id and user_id
        Then: validate the command result returned.
        """
    args = {'team_id': '3', 'email': 'user1@email.com'}
    mock_response_users_search = util_load_json(
        './test_data/users_search_by_email.json')

    requests_mock.get(f'{SERVER_URL}/auth/public/v1/users', json=mock_response_users_search)
    results = users_search_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.User'
    assert results.outputs_key_field == 'id'
    assert results.raw_response == mock_response_users_search['content']
    assert results.outputs[0].get('id') == '01'


def test_devices_search_command(client, requests_mock):
    """
        When: running zimperium-devices-search
        Given: team_name
        Then: validate the command result returned.
        """
    args = {'team_name': 'Default'}
    mock_response_device_search = util_load_json(
        './test_data/device_search.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v2/devices/start-scroll', json=mock_response_device_search)
    results = devices_search_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.Device'
    assert results.outputs[0].get('id') == mock_response_device_search.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Device Search' in results.readable_output


def test_report_get_command(client, requests_mock):
    """
        When: running zimperium-report-get comand.
        Given: The app version id.
        Then: validate the command result returned.
        """
    args = {'app_version_id': '6', 'importance': 'All'}
    mock_response_report_get = util_load_json(
        './test_data/report_get.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v1/appVersions/6/json', json=mock_response_report_get)
    results = report_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.Report'
    assert results.outputs.get('platform') == 'android'
    assert 'Report' in results.readable_output
    assert results.raw_response == mock_response_report_get


def test_threat_search_command(client, requests_mock):
    """
        When: running zimperium-threat-search command
        Given: time to search threats after it, threats related to some team_id
        Then: validate the command result returned.
    """
    args = {'after': '3 month', 'team_id': '3'}
    mock_response_threat_search = util_load_json(
        './test_data/threat_search.json')

    requests_mock.get(f'{SERVER_URL}/threats/public/v1/threats', json=mock_response_threat_search)
    results = threat_search_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.Threat'
    assert results.outputs[0].get('id') == mock_response_threat_search.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Threat Search' in results.readable_output
    assert results.raw_response == mock_response_threat_search


def test_app_version_list_command(client, requests_mock):
    """
        When: running zimperium-app-version-list
        Given: bundle id to filter by.
        Then: validate the command result returned.
        """
    args = {'bundle_id': 'bundle.id'}
    mock_response_app_version_list = util_load_json(
        './test_data/app_version_list.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v1/appVersions', json=mock_response_app_version_list)
    results = app_version_list_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.AppVersion'
    assert results.outputs[0].get('id') == mock_response_app_version_list.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'App Version List' in results.readable_output
    assert results.raw_response == mock_response_app_version_list


def test_get_devices_by_cve_command(client, requests_mock):
    """
        When: running zimperium-get-devices-by-cve
        Given: bundle id to filter by.
        Then: validate the command result returned.
        """
    args = {'cve_id': 'cve_1'}
    mock_response_app_version_list = util_load_json(
        './test_data/device_cve_get.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v2/devices/data-cve-filter', json=mock_response_app_version_list)
    results = get_devices_by_cve_command(client=client, args=args)

    assert results.outputs.get('Zimperium.DeviceByCVE(val.id == obj.id && val.cveId == obj.cveId)')[0].get('id') == \
        mock_response_app_version_list.get('content', [''])[0].get('id')
    assert 'Devices Associated with' in results.readable_output
    assert results.raw_response == mock_response_app_version_list


def test_devices_os_version_command(client, requests_mock):
    """
        When: running zimperium-devices-os-version command.
        Given: os_vesrion of the device to filter by.
        Then: validate the command result returned.
        """
    args = {'os_version': '9'}
    mock_response_devices_os_version = util_load_json(
        './test_data/devices_os_version.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v2/devices/data-version-filter', json=mock_response_devices_os_version)
    results = devices_os_version_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.DeviceOsVersion'
    assert results.outputs[0].get('id') == mock_response_devices_os_version.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Device Os Version' in results.readable_output
    assert results.raw_response == mock_response_devices_os_version


def test_get_cves_by_device_command(client, requests_mock):
    """
        When: running zimperium-get-cves-by-device command.
        Given: device_id to filter by.
        Then: validate the command result returned.
        """
    args = {'device_id':
            '2a'}
    mock_response_cve_devices_get = util_load_json(
        './test_data/cve_devices_get.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v2/devices/2a/cves', json=mock_response_cve_devices_get)
    results = get_cves_by_device_command(client=client, args=args)

    assert results.outputs.get('Zimperium.CVEByDevice(val.id == obj.id && val.deviceId == obj.deviceId)')[0].get('id') == \
        mock_response_cve_devices_get.get('content', [''])[0].get('id')
    assert 'CVE on Device' in results.readable_output
    assert results.raw_response == mock_response_cve_devices_get


def test_vulnerability_get_command(client, requests_mock):
    """
        When: running zimperium-vulnerability-get command
        Given: no arguments
        Then: validate the command result returned.
        """
    args = {}
    mock_response_vulnerability_get = util_load_json(
        './test_data/vulnerability_get.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v1/os-versions', json=mock_response_vulnerability_get)
    results = vulnerability_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.Vulnerability'
    assert results.outputs[0].get('id') == mock_response_vulnerability_get.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Vulnerabilities List' in results.readable_output
    assert results.raw_response == mock_response_vulnerability_get


def test_policy_group_list_command(client, requests_mock):
    """
        When: running zimperium-policy-group-list command
        Given: no arguments
        Then: validate the command result returned.
        """
    args = {}
    mock_response_policy_group_list = util_load_json(
        './test_data/policy_group_list.json')

    requests_mock.get(f'{SERVER_URL}/mtd-policy/public/v1/groups/page', json=mock_response_policy_group_list)
    results = policy_group_list_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyGroup'
    assert results.outputs[0].get('id') == mock_response_policy_group_list.get('content', [''])[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Policy Group List' in results.readable_output
    assert results.raw_response == mock_response_policy_group_list


def test_policy_privacy_get_command(client, requests_mock):
    """
        When: running zimperium-policy-privacy-get command
        Given: no args
        Then: validate the command result returned.
        """
    args = {'policy_id': 'a2'}
    mock_response_policy_privacy = util_load_json(
        './test_data/policy_privacy.json')

    requests_mock.get(f'{SERVER_URL}/mtd-policy/public/v1/privacy/policies/a2', json=mock_response_policy_privacy)
    results = policy_privacy_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyPrivacy'
    assert results.outputs.get('id') == mock_response_policy_privacy.get('id')
    assert results.outputs_key_field == 'id'
    assert 'Privacy Policy' in results.readable_output
    assert results.raw_response == mock_response_policy_privacy


def test_policy_threat_get_command(client, requests_mock):
    """
        When: running zimperium-policy-threat-get command.
        Given: policy_id to get information about.
        Then: validate the command result returned.
        """
    args = {'policy_id': 'e2'}
    mock_response_policy_threat = util_load_json(
        './test_data/policy_threat.json')

    requests_mock.get(f'{SERVER_URL}/mtd-policy/public/v1/trm/policies/e2', json=mock_response_policy_threat)
    results = policy_threat_get_command(client=client, args=args)
    assert results.outputs_prefix == 'Zimperium.PolicyThreat'
    assert results.outputs.get('id') == mock_response_policy_threat.get('id')
    assert results.outputs_key_field == 'id'
    assert 'Threat Policy' in results.readable_output
    assert results.raw_response == mock_response_policy_threat


def test_policy_phishing_get_command(client, requests_mock):
    """
        When: running zimperium-policy-phishing-get command.
        Given: policy_id to get information about.
        Then: validate the command result returned.
        """
    args = {'policy_id': '25'}
    mock_response_policy_phishing = util_load_json(
        './test_data/policy_phishing.json')

    requests_mock.get(f'{SERVER_URL}/mtd-policy/public/v1/phishing/policies/25', json=mock_response_policy_phishing)
    results = policy_phishing_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyPhishing'
    assert results.outputs.get('id') == mock_response_policy_phishing.get('id')
    assert results.outputs_key_field == 'id'
    assert 'Phishing Policy' in results.readable_output
    assert results.raw_response == mock_response_policy_phishing


def test_policy_app_settings_get_command(client, requests_mock):
    """
        When: running zimperium-policy-app-settings-get command.
        Given: policy_id to get information about.
        Then: validate the command result returned.
        """
    args = {'app_settings_policy_id': '9e'}
    mock_response_policy_app_settings = util_load_json(
        './test_data/policy_app_settings.json')

    requests_mock.get(f'{SERVER_URL}/mtd-policy/public/v1/app-settings/policies/9e', json=mock_response_policy_app_settings)
    results = policy_app_settings_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyAppSetting'
    assert results.outputs.get('id') == mock_response_policy_app_settings.get('id')
    assert results.outputs_key_field == 'id'
    assert 'Policy App Settings' in results.readable_output
    assert results.raw_response == mock_response_policy_app_settings


def test_policy_device_inactivity_list_command(client, requests_mock):
    """
        When: running zimperium-policy-device-inactivity-list command.
        Given: team_id to filter by.
        Then: validate the command result returned.
        """
    args = {'team_id': '33'}
    mock_response_policy_device_inactivity_list = util_load_json(
        './test_data/policy_device_inactivity_list.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v1/dormancy/policies', json=mock_response_policy_device_inactivity_list)
    results = policy_device_inactivity_list_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyDeviceInactivity'
    assert results.outputs[0].get('id') == mock_response_policy_device_inactivity_list[0].get('id')
    assert results.outputs_key_field == 'id'
    assert 'Device Inactivity' in results.readable_output
    assert results.raw_response == mock_response_policy_device_inactivity_list


def test_policy_device_inactivity_get_command(client, requests_mock):
    """
        When: running zimperium-policy-device-inactivity-get command.
        Given: policy_id to get information about.
        Then: validate the command result returned.
        """
    args = {'policy_id': 'ff'}
    mock_response_policy_device_inactivity_get = util_load_json(
        './test_data/policy_device_inactivity_get.json')

    requests_mock.get(f'{SERVER_URL}/devices/public/v1/dormancy/policies/ff', json=mock_response_policy_device_inactivity_get)
    results = policy_device_inactivity_get_command(client=client, args=args)

    assert results.outputs_prefix == 'Zimperium.PolicyDeviceInactivity'
    assert results.outputs.get('id') == mock_response_policy_device_inactivity_get.get('id')
    assert results.outputs_key_field == 'id'
    assert 'Device Inactivity' in results.readable_output
    assert results.raw_response == mock_response_policy_device_inactivity_get


@freeze_time("2023-12-12 15:00:00 GTM")
def test_fetch_incidents_first_run(client, requests_mock):
    """
        When: running fetch-incidents command
        Given: fetch command, no last run - first time fetching
        Then: validate the 2 fetched incidents
    """
    last_run = {}
    first_fetch_time = '2023-12-12T14:59:00.000Z'
    mock_response_threat_search = util_load_json(
        './test_data/threat_search.json')

    requests_mock.get(f'{SERVER_URL}/threats/public/v1/threats', json=mock_response_threat_search)

    incidents, next_run = fetch_incidents(
        client=client,
        last_run=last_run,
        fetch_query=[],
        first_fetch_time=first_fetch_time,
        max_fetch=2,
        look_back=1,
    )

    assert len(incidents) == 2
    assert next_run['time'] == '2023-12-12T14:59:26.000Z'


@freeze_time("2023-12-12 15:00:00 GTM")
def test_fetch_incidents_last_run_not_empty(client, requests_mock):
    """
        When: running fetch-incidents command
        Given: fetch command, with last run.
        Then: validate the fetched incidents without duplicates
    """
    last_run = {'found_incident_ids': {'d6': 1702393200}, 'time': '2023-12-12T14:59:00.000Z'}
    first_fetch_time = '2023-12-12T14:59:00.000Z'
    mock_response_threat_search = util_load_json(
        './test_data/threat_search.json')

    requests_mock.get(f'{SERVER_URL}/threats/public/v1/threats', json=mock_response_threat_search)

    incidents, next_run = fetch_incidents(
        client=client,
        last_run=last_run,
        fetch_query=[],
        first_fetch_time=first_fetch_time,
        max_fetch=2,
        look_back=1,
    )

    assert len(incidents) == 1
    assert next_run['time'] == '2023-12-12T14:59:26.000Z'


@freeze_time("2023-12-12 15:00:00 GTM")
def test_fetch_incidents_no_new_incidents(client, requests_mock):
    """
        When: running fetch-incidents with last run contains ids
        Given: fetch command, no last run, with last run.
        Then: no new incidents
    """
    last_run = {'found_incident_ids': {'42': 1702393200, 'd6': 1702393200}, 'time': '2023-12-12T14:59:00.000Z'}
    first_fetch_time = '2023-12-12T14:59:00.000Z'
    mock_response_threat_search = util_load_json(
        './test_data/threat_search.json')

    requests_mock.get(f'{SERVER_URL}/threats/public/v1/threats', json=mock_response_threat_search)

    incidents, next_run = fetch_incidents(
        client=client,
        last_run=last_run,
        fetch_query=[],
        first_fetch_time=first_fetch_time,
        max_fetch=2,
        look_back=1,
    )

    assert len(incidents) == 0
    assert next_run['time'] == '2023-12-12T15:00:00.000Z'


@pytest.mark.parametrize('proxy, result', [('true', True), ('false', False)])
def test_proxy_parameter_setup(proxy, result, mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': proxy, 'url': 'fake_url.com'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch('ZimperiumV2.test_module', return_value=CommandResults(readable_output='test'))
    client = mocker.patch('ZimperiumV2.Client')
    main()
    assert client.call_args.kwargs.get('proxy') == result

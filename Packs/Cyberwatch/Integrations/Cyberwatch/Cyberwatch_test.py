import json
from Cyberwatch import Client
import requests_mock


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


BASE_URL = "http://fake_cyberwatch_url.local"

client = Client(
    base_url=BASE_URL,
    verify=False,
    auth=("fake_api_key", "fake_api_secret_key"),
    proxy=False
)

# Test Module and Ping


def test_test_module_ok(mocker):
    from Cyberwatch import test_module

    mock_response = util_load_json('test_data/test_module.json')

    # Case OK
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    response = test_module(client)
    assert response == "ok"


def test_test_module_error(mocker):
    from Cyberwatch import test_module

    # Case error
    mocker.patch.object(Client, '_http_request', return_value=None, status_code=401)
    try:
        test_module(client)
    except Exception as e:
        assert str(e) == "Authorization Error: please check your API Key and Secret Key"


def test_test_module_by_testing_ping(mocker):
    from Cyberwatch import test_module

    mock_response = util_load_json('test_data/test_module.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/ping', json=mock_response, status_code=200)

        response = test_module(client)
        assert response == "ok"

# Iso 8601 converter


def test_iso8601_to_human_when_zulu(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human("2019-09-10T14:59:23.000Z") == "2019-09-10T14:59:23"


def test_iso8601_to_human_when_iso8601(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human("2019-09-10T16:59:23.000+02:00") == "2019-09-10T14:59:23"


def test_iso8601_to_human_when_null(mocker):
    from Cyberwatch import iso8601_to_human

    assert iso8601_to_human(None) == ""

# CVEs


def test_list_cves_command_with_no_cves(mocker):
    from Cyberwatch import list_cves_command

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements',
              headers={'x-per-page': '100', 'x-total': '0'}, json={}, status_code=200)
        try:
            list_cves_command(client, {})
        except Exception as e:
            assert str(e) == 'No CVEs found'


def test_list_cves_command_with_cves_only_one_page(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json('test_data/test_list_cve_announcements.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_cves_command(client, {'page': '1'})

        assert len(response.raw_response) == 5


def test_list_cves_command_with_cves_all_pages(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json('test_data/test_list_cve_announcements.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements?page=2',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_cves_command(client, {})

        assert len(response.raw_response) == 10


def test_list_cves_command_with_cves_all_pages_with_hard_limit(mocker):
    from Cyberwatch import list_cves_command

    mock_response = util_load_json('test_data/test_list_cve_announcements.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements?page=2',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_cves_command(client, {'hard_limit': '5', 'per_page': '5'})

        assert len(response.raw_response) == 5


def test_fetch_cve_command_found(mocker):
    from Cyberwatch import fetch_cve_command

    mock_response = util_load_json('test_data/test_fetch_cve_CVE-2021-44228.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements/CVE-2021-44228', json=mock_response)

        response = fetch_cve_command(client, {'cve_code': 'CVE-2021-44228'})

        assert response.raw_response == mock_response


def test_fetch_cve_command_no_cve_code(mocker):
    from Cyberwatch import fetch_cve_command

    mock_response = util_load_json('test_data/test_list_cve_announcements.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/cve_announcements/', json=mock_response)

        try:
            fetch_cve_command(client, {})
        except Exception as e:
            assert str(e) == 'Please provide a CVE cve_code'

# Assets


def test_list_assets_command_with_no_assets(mocker):
    from Cyberwatch import list_assets_command

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers',
              headers={'x-per-page': '100', 'x-total': '0'}, json={}, status_code=200)
        try:
            list_assets_command(client, {})
        except Exception as e:
            assert str(e) == 'No assets found'


def test_list_assets_command_with_assets_only_one_page(mocker):
    from Cyberwatch import list_assets_command

    mock_response = util_load_json('test_data/test_list_servers.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_assets_command(client, {'page': '1'})

        assert len(response.raw_response) == 5


def test_list_assets_command_with_assets_all_pages(mocker):
    from Cyberwatch import list_assets_command

    mock_response = util_load_json('test_data/test_list_servers.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers?page=2',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_assets_command(client, {})

        assert len(response.raw_response) == 10


def test_fetch_asset_command_found(mocker):
    from Cyberwatch import fetch_asset_command

    mock_response = util_load_json('test_data/test_fetch_server.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers/0', json=mock_response)

        response = fetch_asset_command(client, {'id': '0'})

        assert response.raw_response == mock_response


def test_fetch_asset_full_command_found(mocker):
    from Cyberwatch import fetch_asset_full_command

    mock_response_part1 = util_load_json('test_data/test_fetch_server_full_part1.json')
    mock_response_part2 = util_load_json('test_data/test_fetch_server_full_part2.json')
    mock_response = util_load_json('test_data/test_fetch_server_full.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers/0', json=mock_response_part1)
        m.get(BASE_URL + '/api/v3/assets/servers/0', json=mock_response_part2)

        response = fetch_asset_full_command(client, {'id': '0'})

        assert response.raw_response == mock_response


def test_fetch_asset_command_no_id(mocker):
    from Cyberwatch import fetch_asset_command

    mock_response = util_load_json('test_data/test_list_servers.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/servers/', json=mock_response)

        try:
            fetch_asset_command(client, {})
        except Exception as e:
            assert str(e) == 'Please provide an asset ID'

# Security issues


def test_list_security_issues_command_with_no_security_issues(mocker):
    from Cyberwatch import list_security_issues_command

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/security_issues', headers={'x-per-page': '100', 'x-total': '0'}, json={}, status_code=200)
        try:
            list_security_issues_command(client, {})
        except Exception as e:
            assert str(e) == 'No security issues found'


def test_list_security_issues_command_with_security_issues_only_one_page(mocker):
    from Cyberwatch import list_security_issues_command

    mock_response = util_load_json('test_data/test_list_security_issues.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/security_issues?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_security_issues_command(client, {'page': '1'})

        assert len(response.raw_response) == 5


def test_list_security_issues_command_with_security_issues_all_pages(mocker):
    from Cyberwatch import list_security_issues_command

    mock_response = util_load_json('test_data/test_list_security_issues.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/security_issues?page=1',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)
        m.get(BASE_URL + '/api/v3/security_issues?page=2',
              headers={'x-per-page': '5', 'x-total': '10'}, json=mock_response, status_code=200)

        response = list_security_issues_command(client, {})

        assert len(response.raw_response) == 10


def test_fetch_security_issue_command_found(mocker):
    from Cyberwatch import fetch_security_issue_command

    mock_response = util_load_json('test_data/test_fetch_security_issue.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/security_issues/0', json=mock_response)

        response = fetch_security_issue_command(client, {'id': '0'})

        assert response.raw_response == mock_response


def test_fetch_security_issue_command_no_id(mocker):
    from Cyberwatch import fetch_security_issue_command

    mock_response = util_load_json('test_data/test_list_security_issues.json')

    with requests_mock.Mocker() as m:
        m.get(BASE_URL + '/api/v3/vulnerabilities/security_issues/', json=mock_response)

        try:
            fetch_security_issue_command(client, {})
        except Exception as e:
            assert str(e) == 'Please provide a Security Issues ID'

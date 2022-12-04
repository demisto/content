import demistomock as demisto

MOCK_PARAMS = {
    'access-key': 'fake_access_key',
    'secret-key': 'fake_access_key',
    'url': 'http://123-fake-api.com/',
    'unsecure': True,
    'proxy': True
}

MOCK_RAW_VULN_BY_ASSET = {
    'vulnerabilities': [
        {
            'count': 117,
            'plugin_family': 'General',
            'plugin_id': 51292,
            'plugin_name': 'Fake Plugin Name',
            'vulnerability_state': 'Resurfaced',
            'accepted_count': 0,
            'recasted_count': 0,
            'counts_by_severity': [
                {
                    'count': 117,
                    'value': 2
                }
            ],
            'severity': 2
        },
    ]
}

EXPECTED_VULN_BY_ASSET_RESULTS = [
    {
        'Id': 51292,
        'Name': 'Fake Plugin Name',
        'Severity': 'Medium',
        'Family': 'General',
        'VulnerabilityOccurences': 117,
        'VulnerabilityState': 'Resurfaced'
    }
]


def mock_demisto(mocker, mock_args):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'results')


def test_get_scan_status(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})

    from Tenable_io import get_scan_status_command
    results = get_scan_status_command()

    entry_context = results['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'Scan status for 25' in results['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'canceled'


def test_get_vuln_by_asset(mocker, requests_mock):
    mock_demisto(mocker, {'hostname': 'fake.hostname'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets', json={'assets': [{'id': 'fake_asset_id'}]})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets/fake_asset_id/vulnerabilities/',
                      json=MOCK_RAW_VULN_BY_ASSET)

    from Tenable_io import get_vulnerabilities_by_asset_command
    results = get_vulnerabilities_by_asset_command()

    actual_result = results['EntryContext']['TenableIO.Vulnerabilities']

    for k in actual_result[0].keys():
        assert EXPECTED_VULN_BY_ASSET_RESULTS[0][k] == actual_result[0][k]


def test_pause_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'running'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/pause', json={'info': {'status': 'running'}})

    from Tenable_io import pause_scan_command

    results = pause_scan_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'scan was paused successfully' in results[0]['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'Pausing'


def test_resume_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'paused'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/resume', json={'info': {'status': 'paused'}})
    from Tenable_io import resume_scan_command

    results = resume_scan_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'scan was resumed successfully' in results[0]['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'Resuming'


def test_get_vulnerability_details_command(mocker, requests_mock):
    mock_demisto(mocker, {'vulnerabilityId': '1', 'dateRange': '3'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/vulnerabilities/1/info',
                      json={'info': {'Id': '1'}})
    from Tenable_io import get_vulnerability_details_command

    results = get_vulnerability_details_command()
    entry_context = results['EntryContext']['TenableIO.Vulnerabilities']

    assert 'Vulnerability details' in results['HumanReadable']
    assert entry_context['Id'] == '1'


def test_get_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'folderId': '1'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/?folder_id=1',
                      json={'scans': [{'status': 'running', 'id': '1'}],
                            'info': {'id': '1'}})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/1', json={'info': {'status': 'paused'}})

    from Tenable_io import get_scans_command

    results = get_scans_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'Tenable.io - List of Scans' in results[0]['HumanReadable']
    assert entry_context[0]['Id'] == '1'


def test_launch_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '1', 'scanTargets': 'target1,target2'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/1', json={'info': {'status': 'paused'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/1/launch',
                       json={})

    from Tenable_io import launch_scan_command

    results = launch_scan_command()
    entry_context = results['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'The requested scan was launched successfully' in results['HumanReadable']
    assert entry_context['Id'] == '1'


def test_get_asset_details_command(mocker, requests_mock):
    from test_data.response_and_results import MOCK_RAW_ASSET_BY_IP
    from test_data.response_and_results import MOCK_RAW_ASSET_ATTRIBUTES
    from test_data.response_and_results import EXPECTED_ASSET_INFO_RESULTS

    mock_demisto(mocker, {'ip': '1.3.2.1'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets', json={'assets': [{'id': 'fake_asset_id'}]})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets/fake_asset_id/info',
                      json=MOCK_RAW_ASSET_BY_IP)
    requests_mock.get(MOCK_PARAMS['url'] + 'api/v3/assets/fake_asset_id/attributes',
                      json=MOCK_RAW_ASSET_ATTRIBUTES)

    from Tenable_io import get_asset_details_command

    response = get_asset_details_command()

    assert response.outputs == EXPECTED_ASSET_INFO_RESULTS
    assert response.outputs_prefix == 'TenableIO.AssetDetails'
    assert response.outputs_key_field == 'id'

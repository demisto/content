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

    entry_context = results['EntryContext']['TenableIO.Scan(val.Id === obj.Id)']

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

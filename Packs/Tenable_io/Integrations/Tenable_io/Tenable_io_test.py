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

MOCK_GET_SCANS_REQUEST = {
    "folders": [
        {
            "custom": 0,
            "default_tag": 0,
            "id": 27,
            "name": "Trash",
            "type": "trash",
            "unread_count": 0
        },
        {
            "custom": 0,
            "default_tag": 1,
            "id": 28,
            "name": "My Scans",
            "type": "main",
            "unread_count": 18
        }
    ],
    "scans": [],
    "timestamp": 1608316207
}

MOCK_VULN_DETAILS = {
    "info": {
        "accepted_count": 0,
        "count": 1496,
        "description": "The remote host answers to an ICMP timestamp request.  This allows an attacker to know the date that is set on the targeted machine, which may assist an unauthenticated, remote attacker in defeating time-based authentication protocols.\n\nTimestamps returned from machines running Windows Vista / 7 / 2008 / 2008 R2 are deliberately incorrect, but usually within 1000 seconds of the actual system time.",
        "discovery": {
            "seen_first": "2018-01-26T19:23:13.022Z",
            "seen_last": "2020-12-18T18:09:51.035Z"
        },
        "plugin_details": {
            "family": "General",
            "modification_date": "2012-06-18T00:00:00Z",
            "name": "ICMP Timestamp Request Remote Date Disclosure",
            "publication_date": "1999-08-01T00:00:00Z",
            "severity": 0,
            "type": "remote",
            "version": "$Revision: 1.45 $"
        },
        "recasted_count": 0,
        "reference_information": [
            {
                "name": "cve",
                "url": "http://web.nvd.nist.gov/view/vuln/detail?vulnId=",
                "values": [
                    "CVE-1999-0524"
                ]
            },
            {
                "name": "cwe",
                "url": "notaurl",
                "values": [
                    "200"
                ]
            },
            {
                "name": "osvdb",
                "values": [
                    "94"
                ]
            }
        ],
        "risk_information": {
            "cvss3_base_score": None,
            "cvss3_temporal_score": None,
            "cvss3_temporal_vector": None,
            "cvss3_vector": None,
            "cvss_base_score": None,
            "cvss_temporal_score": None,
            "cvss_temporal_vector": None,
            "cvss_vector": None,
            "risk_factor": "None",
            "stig_severity": None
        },
        "see_also": [],
        "severity": 0,
        "solution": "Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14).",
        "synopsis": "It is possible to determine the exact time set on the remote host.",
        "vuln_count": 20844,
        "vulnerability_information": {
            "asset_inventory": None,
            "cpe": None,
            "default_account": None,
            "exploit_available": None,
            "exploit_frameworks": [],
            "exploitability_ease": None,
            "exploited_by_malware": None,
            "exploited_by_nessus": None,
            "in_the_news": None,
            "malware": None,
            "patch_publication_date": None,
            "unsupported_by_vendor": None,
            "vulnerability_publication_date": "1995-01-01T00:00:00Z"
        }
    }
}

def mock_demisto(mocker, mock_args):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'results')

def test_get_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'folderId': '34', 'examplelastModificationDate': '2020-11-01' })
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/?folder_id=34', json=MOCK_GET_SCANS_REQUEST)
    from Tenable_io import get_scans_command
    get_scans_command()

def test_launch_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25', 'scanTargets': '10.0.0.1'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/launch?alt_targets=10.0.0.1', json={'info': {'status': 'canceled'}})
    from Tenable_io import launch_scan_command
    launch_scan_command()

def test_get_report_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25', })
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    from Tenable_io import get_report_command
    get_report_command()

def test_get_vulnerability_details_command(mocker, requests_mock):
    mock_demisto(mocker, {'vulnerabilityId': '10114'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/vulnerabilities/10114/info',
                      json=MOCK_VULN_DETAILS)
    from Tenable_io import get_vulnerability_details_command
    get_vulnerability_details_command()

def test_get_vulnerabilities_by_asset_command(mocker, requests_mock):
    mock_demisto(mocker, {'hostname': 'fake.hostname'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets', json={'assets': [{'id': 'fake_asset_id'}]})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets/fake_asset_id/vulnerabilities/',
                      json=MOCK_RAW_VULN_BY_ASSET)

    from Tenable_io import get_vulnerabilities_by_asset_command
    results = get_vulnerabilities_by_asset_command()

    actual_result = results['EntryContext']['TenableIO.Vulnerabilities']

    for k in actual_result[0].keys():
        assert EXPECTED_VULN_BY_ASSET_RESULTS[0][k] == actual_result[0][k]

def test_get_scan_status_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})

    from Tenable_io import get_scan_status_command
    results = get_scan_status_command()

    entry_context = results['EntryContext']['TenableIO.Scan(val.Id === obj.Id)']

    assert 'Scan status for 25' in results['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'canceled'

def test_pause_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    from Tenable_io import pause_scan_command
    pause_scan_command()

def test_resume_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    from Tenable_io import resume_scan_command
    resume_scan_command()

def test_add_tags_command(mocker, requests_mock):
    mock_demisto(mocker, {'payload': '25'})
    requests_mock.post(MOCK_PARAMS['url'] + 'tags/values', json={'info': {'status': 'canceled'}})
    from Tenable_io import add_tags
    add_tags()

def test_resume_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanIds': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    from Tenable_io import resume_scans_command
    resume_scans_command()

def test_pause_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanIds': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})
    from Tenable_io import pause_scans_command
    pause_scans_command()

def test_launch_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'scan_ids': '25'})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/launch', json={'info': {'status': 'canceled'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/launch?alt_targets=10.0.0.1', json={'info': {'status': 'canceled'}})
    from Tenable_io import launch_scans_command
    launch_scans_command()

def test_check_templates_command(mocker, requests_mock):
    mock_demisto(mocker, {})
    requests_mock.get(MOCK_PARAMS['url'] + 'editor/scan/templates', json={'info': {'status': 'canceled'}})
    from Tenable_io import get_scan_templates
    get_scan_templates()
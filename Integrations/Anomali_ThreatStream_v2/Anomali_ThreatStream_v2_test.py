import demistomock as demisto
from Anomali_ThreatStream_v2 import main


def http_request_mock(req_type, suffix, params, data, files):
    return {
        'success': True,
        'import_session_id': params,
        'data': data,
    }


package_500_error = {
    'import_type': 'url',
    'import_value': 'www.demisto.com',
    'ip_mapping': 'yes',
    'md5_mapping': 'no',
    'tags': '',
    'trustedcircles': ''
}

expected_output_500 = {
    'Contents': {
        'data': {
            'classification': 'Private',
            'confidence': '50',
            'domain_mapping': False,
            'email_mapping': False,
            'ip_mapping': True,
            'md5_mapping': False,
            'severity': 'low',
            'threat_type': 'exploit',
            'url_mapping': False,
            'tags': [],
            'trustedcircles': None
        },
        'import_session_id': {
            'api_key': None,
            'datatext': 'www.demisto.com',
            'username': None
        },
        'success': True
    },
    'ContentsFormat': 'json',
    'EntryContext': {
        'ThreatStream.Import.ImportID': {
            'api_key': None,
            'datatext': 'www.demisto.com',
            'username': None
        }
    },
    'HumanReadable': 'The data was imported successfully. The ID of imported job '
                     "is: {'datatext': 'www.demisto.com', 'username': None, "
                     "'api_key': None}",
    'Type': 1
}


def test_ioc_approval_500_error(mocker):
    mocker.patch('Anomali_ThreatStream_v2.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'args', return_value=package_500_error)
    mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-with-approval')
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0]

    assert results[0]['Contents']['data'] == expected_output_500['Contents']['data']
    assert 'datatext' in results[0]['Contents']['import_session_id']

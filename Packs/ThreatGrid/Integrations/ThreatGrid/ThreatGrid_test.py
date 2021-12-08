import demistomock as demisto
import requests_mock


def test_get_threat_summary_by_id(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'true', 'server': 'https://example.com'})
    mocker.patch.object(demisto, 'args', return_value={'id': '1234'})
    mocker.patch.object(demisto, 'command', return_value="threat-grid-get-threat-summary-by-id")
    mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        response_json = {
            'data': {
                'max-severity': 'fake_severity',
                'score': 95,
                'count': 'fake_count',
                'max-confidence': 'fake_confidence',
                'bis': 'fake_bis',
            },
            'sha256': '123456789012345678901234567890123456789012345678901234567890abcd',
            'sha1': '1234567890123456789012345678901234567890',
            'mkd5': '123456789012345678901234567890ab',
        }
        m.get('https://example.com/api/v2/samples/1234/threat', json=response_json)

        from ThreatGrid import get_threat_summary_by_id
        get_threat_summary_by_id()

    results = demisto.results.call_args[0]
    results[0]['EntryContext']['DBotScore']['Indicator'] == response_json['sha256']

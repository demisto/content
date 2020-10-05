import importlib
import json
import demistomock as demisto
queued_response = {u'response_code': -2,
                   u'resource': u'YES_THIS_IS_A_UID',
                   u'scan_id': u'YES_THIS_IS_A_UID',
                   u'verbose_msg': u'Your resource is queued for analysis'}


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_get_file_response_queued_response(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'resource': 'UID!'})
    requests_mock.get('https://www.virustotal.com/vtapi/v2/file/report', json=queued_response)
    vt = importlib.import_module("VirusTotal-Private_API")

    output = vt.get_file_report_command()
    assert output.get('HumanReadable') == 'The file is queued for analysis. Try again in a short while.'
    assert output.get('EntryContext', {}).get('VirusTotal(val.ID == obj.ID)', {}).get('Status') == 'Queued'


def test_get_url_multiple_results(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'resource': 'https://linkedin.com, https://twitter.com'})
    requests_mock.get('https://www.virustotal.com/vtapi/v2/url/report',
                      [
                          {'json': load_test_data('./test_data/get_url_report_linkedin.json'), 'status_code': 200},
                          {'json': load_test_data('./test_data/get_url_report_twitter.json'), 'status_code': 200},
                      ])

    vt = importlib.import_module("VirusTotal-Private_API")

    output = vt.get_url_report_command()
    assert len(output) == 2
    assert isinstance(output[0]['EntryContext']['DBotScore'], dict)
    assert isinstance(output[1]['EntryContext']['DBotScore'], dict)

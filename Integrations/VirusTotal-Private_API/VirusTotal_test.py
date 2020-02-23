import importlib
import demistomock as demisto
queued_response = {u'response_code': -2,
 u'resource': u'YES_THIS_IS_A_UID',
  u'scan_id': u'YES_THIS_IS_A_UID',
   u'verbose_msg': u'Your resource is queued for analysis'}


def test_get_file_response_queued_response(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'resource': 'UID!'})
    requests_mock.get('https://www.virustotal.com/vtapi/v2/file/report', json=queued_response)
    vt = importlib.import_module("VirusTotal-Private_API")

    output = vt.get_file_report_command()
    assert output == 'The file is queued for analysis. Try again in a short while.'

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


def test_create_url_report_output():
    vt = importlib.import_module("VirusTotal-Private_API")
    url = 'demisto.com'
    response = load_test_data('./test_data/get_url_report_demisto.json')
    threshold = 10
    max_len = 50
    short_format = False

    expected_md = "## VirusTotal URL report for: demisto.com\nScan ID: **someId**\nScan date: **2020-09-24 " \
                  "13:35:46**\nDetections / Total: **0/79**\nResource: demisto.com\nVT Link: [" \
                  "https://www.someurl.com/](https://www.someurl.com/)\nIP address resolution for this domain is: " \
                  "1.2.3.4\nResponse content SHA-256: someSHA\n### " \
                  "Scans\n|Details|Detected|Result|Source|Update|\n|---|---|---|---|---|\n|  | false | clean site | " \
                  "CLEAN MX |  |\n| http://www.someurl.com/?search=demisto.com | false | clean site | " \
                  "MalwareDomainList |  |\n|  | false | clean site | Trustwave |  |\n"

    expected_ec_url = {
        'Data': 'demisto.com',
        'VirusTotal': {
            'ResponseContentSHA256': 'someSHA',
            'Resolutions': '1.2.3.4',
            'ResponseHeaders': {
                'expires': 'Thu, 24 Sep 2020 13:50:50 GMT',
                'x-content-type-options': 'nosniff',
                'transfer-encoding': 'chunked',
                'set-cookie': 'AKA_A2=A; expires=Thu, '
                              '24-Sep-2020 14:35:50 GMT; path=/; domain=paloaltonetworks.com; secure; HttpOnly',
                'strict-transport-security': 'max-age=300',
                'vary': 'Accept-Encoding',
                'server': 'Apache',
                'cache-control': 'public, max-age=900',
                'server-timing': 'cdn-cache; desc=HIT, edge; dur=16',
                'connection': 'keep-alive, Transfer-Encoding',
                'link': 'somelink',
                'access-control-allow-credentials': 'true',
                'date': 'Thu, 24 Sep 2020 13:35:50 GMT',
                'x-frame-options': 'SAMEORIGIN',
                'content-type': 'text/html;charset=utf-8',
                'x-akamai-transformed': '9 81423 0 pmb=mRUM,2'
            }, 'Scans': [
                {
                    'Details': None,
                    'Source': 'CLEAN MX',
                    'Detected': False,
                    'Result': 'clean site',
                    'Update': None
                }, {
                    'Details': 'http://www.someurl.com/?search=demisto.com',
                    'Source': 'MalwareDomainList',
                    'Detected': False,
                    'Result': 'clean site',
                    'Update': None
                }, {
                    'Details': None,
                    'Source': 'Trustwave',
                    'Detected': False,
                    'Result': 'clean site',
                    'Update': None
                }
            ]
        }
    }

    expected_ec_dbot = {'Vendor': 'VirusTotal - Private API', 'Indicator': u'demisto.com', 'Score': 1, 'Type': 'url'}

    md, ec_url, ec_dbot = vt.create_url_report_output(url, response, threshold, max_len, short_format)
    assert md == expected_md
    assert ec_url == expected_ec_url
    assert ec_dbot == expected_ec_dbot


def test_empty_behavior_response(mocker):
    """

    Given:
        File hash which will return an empty report from the API
    When:
        Running vt-private-check-file-behaviour command
    Then:
        Return indicative response to the war room

    """
    vt = importlib.import_module("VirusTotal-Private_API")

    mocker.patch.object(vt, 'check_file_behaviour',
                        return_value={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
    mocker.patch.object(demisto, 'args',
                        return_value={'resource': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'})

    results = vt.check_file_behaviour_command()

    assert results['HumanReadable'] == 'No data were found for hash ' \
                                       'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def test_empty_hash_communication_response(mocker):
    """

    Given:
        File hash which will return an empty report from the API
    When:
        Running vt-private-hash-communication command
    Then:
        Return indicative response to the war room

    """
    vt = importlib.import_module("VirusTotal-Private_API")

    mocker.patch.object(vt, 'check_file_behaviour',
                        return_value={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
    mocker.patch.object(demisto, 'args',
                        return_value={'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'})

    results = vt.hash_communication_command()

    assert results['HumanReadable'] == 'No communication results were found for hash ' \
                                       'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

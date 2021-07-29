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


def test_create_url_report_output_no_resolution():
    """
    Given
    - command args with allInfo=true(implied, raw response is bigger)
    - command raw response
    When
    - mock the get_url_report response.
    Then
    - run the create_url_report_output command
    - validate the markdown, context and the DBotScore of the report generated.
    """
    vt = importlib.import_module("VirusTotal-Private_API")
    url = 'https://github.com/topics/spacevim'
    response = load_test_data('./test_data/get_url_report_no_resultion.json')
    threshold = 10
    max_len = 50
    short_format = False

    expected_md = """## VirusTotal URL report for: https://github.com/topics/spacevim
Scan ID: **856ec9887a4ffccbb8f5f4b559e6cb10751c9c411bd96464a47b50bc9c387b9c-1627397923**
Scan date: **2021-07-27 14:58:43**
Detections / Total: **0/89**
Resource: https://github.com/topics/spacevim
VT Link: [https://www.virustotal.com/gui/url/truncated](https://www.virustotal.com/gui/url/truncated)
Response content SHA-256: 0e1a3027e45f3971d9611b88be2b556a166b8e7dcbdbfd4b2de257fc22a86079
### Scans
|Details|Detected|Result|Source|Update|
|---|---|---|---|---|
|  | false | unrated site | 0xSI_f33d |  |
|  | false | clean site | ADMINUSLabs |  |
|  | false | clean site | AICC (MONITORAPP) |  |
|  | false | clean site | Abusix |  |
|  | false | clean site | AlienVault |  |
|  | false | clean site | Antiy-AVL |  |
|  | false | clean site | Armis |  |
|  | false | clean site | Artists Against 419 |  |
|  | false | unrated site | AutoShun |  |
|  | false | clean site | Avira |  |
|  | false | clean site | BADWARE.INFO |  |
|  | false | clean site | Baidu-International |  |
|  | false | clean site | Bfore.Ai PreCrime |  |
|  | false | clean site | BitDefender |  |
|  | false | clean site | BlockList |  |
|  | false | clean site | Blueliv |  |
|  | false | clean site | CINS Army |  |
|  | false | clean site | CMC Threat Intelligence |  |
|  | false | clean site | CRDF |  |
|  | false | clean site | Certego |  |
|  | false | clean site | Comodo Valkyrie Verdict |  |
|  | false | clean site | CyRadar |  |
|  | false | unrated site | Cyan |  |
|  | false | clean site | CyberCrime |  |
|  | false | clean site | Cyren |  |
|  | false | clean site | DNS8 |  |
|  | false | clean site | Dr.Web |  |
|  | false | clean site | ESET |  |
|  | false | clean site | EmergingThreats |  |
|  | false | clean site | Emsisoft |  |
|  | false | clean site | EonScope |  |
|  | false | clean site | Feodo Tracker |  |
|  | false | clean site | Forcepoint ThreatSeeker |  |
|  | false | clean site | Fortinet |  |
|  | false | clean site | FraudScore |  |
|  | false | clean site | G-Data |  |
|  | false | clean site | Google Safebrowsing |  |
|  | false | clean site | GreenSnow |  |
|  | false | clean site | Hoplite Industries |  |
|  | false | clean site | IPsum |  |
|  | false | clean site | K7AntiVirus |  |
|  | false | clean site | Kaspersky |  |
|  | false | clean site | Lionic |  |
|  | false | unrated site | Lumu |  |
|  | false | clean site | MalBeacon |  |
|  | false | clean site | MalSilo |  |
| http://www.malwaredomainlist.com/mdl.php?search=github.com | false | clean site | MalwareDomainList |  |
|  | false | clean site | MalwarePatrol |  |
|  | false | clean site | Malwared |  |
|  | false | unrated site | Netcraft |  |
|  | false | unrated site | NotMining |  |
|  | false | clean site | Nucleon |  |
|  | false | clean site | OpenPhish |  |
|  | false | clean site | PREBYTES |  |
|  | false | unrated site | PhishLabs |  |
|  | false | clean site | Phishing Database |  |
|  | false | clean site | Phishtank |  |
|  | false | clean site | Quick Heal |  |
|  | false | clean site | Quttera |  |
|  | false | clean site | Rising |  |
|  | false | clean site | SCUMWARE.org |  |
|  | false | unrated site | SafeToOpen |  |
|  | false | clean site | Sangfor |  |
|  | false | clean site | Scantitan |  |
|  | false | clean site | SecureBrain |  |
|  | false | clean site | Snort IP sample list |  |
|  | false | clean site | Sophos |  |
|  | false | clean site | Spam404 |  |
|  | false | clean site | Spamhaus |  |
|  | false | unrated site | StopBadware |  |
|  | false | clean site | StopForumSpam |  |
|  | false | clean site | Sucuri SiteCheck |  |
|  | false | clean site | Tencent |  |
|  | false | clean site | ThreatHive |  |
|  | false | clean site | Threatsourcing |  |
|  | false | clean site | Trustwave |  |
|  | false | clean site | URLhaus |  |
|  | false | clean site | VX Vault |  |
|  | false | clean site | Virusdie External Site Scan |  |
|  | false | clean site | Web Security Guard |  |
|  | false | clean site | Webroot |  |
| http://yandex.com/infected?l10n=en&url=https://github.com/topics/spacevim | false | clean site | Yandex Safebrowsing |  |
|  | false | clean site | ZeroCERT |  |
|  | false | clean site | alphaMountain.ai |  |
|  | false | clean site | benkow.cc |  |
|  | false | clean site | desenmascara.me |  |
|  | false | clean site | malwares.com URL checker |  |
|  | false | clean site | securolytics |  |
|  | false | clean site | zvelo |  |
"""

    expected_ec_url = {
        'Data': 'https://github.com/topics/spacevim',
        'VirusTotal': {
            'ResponseContentSHA256': '0e1a3027e45f3971d9611b88be2b556a166b8e7dcbdbfd4b2de257fc22a86079',
            'ResponseHeaders': {
                'accept-ranges': 'bytes',
                'cache-control': 'max-age=0, private, must-revalidate',
                'content-type': 'text/html; charset=utf-8',
                'date': 'Tue, 27 Jul 2021 14:58:50 GMT',
                'etag': 'W/"cc5749d30e85e6e4bbb2a0c8f8b85bb7"',
                'expect-ct': 'max-age=2592000, report-uri="https://api.github.com/_private/browser/errors"',
                'permissions-policy': 'interest-cohort=()',
                'referrer-policy': 'origin-when-cross-origin, strict-origin-when-cross-origin',
                'server': 'GitHub.com',
                'set-cookie': '_gh_sess=sD',
                'strict-transport-security': 'max-age=31536000; includeSubdomains; preload',
                'transfer-encoding': 'chunked',
                'vary': 'X-PJAX, Accept-Encoding, Accept, X-Requested-With',
                'x-content-type-options': 'nosniff', 'x-frame-options': 'deny',
                'x-github-request-id': '897E:5827:6536B6:93B410:61001F29',
                'x-xss-protection': '0'}, 'Scans': [
                {'Source': '0xSI_f33d', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'ADMINUSLabs', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'AICC (MONITORAPP)', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Abusix', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'AlienVault', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Antiy-AVL', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Armis', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Artists Against 419', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'AutoShun', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'Avira', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'BADWARE.INFO', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Baidu-International', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Bfore.Ai PreCrime', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'BitDefender', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'BlockList', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Blueliv', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'CINS Army', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'CMC Threat Intelligence', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'CRDF', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Certego', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Comodo Valkyrie Verdict', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'CyRadar', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Cyan', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'CyberCrime', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Cyren', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'DNS8', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Dr.Web', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'ESET', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'EmergingThreats', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Emsisoft', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'EonScope', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Feodo Tracker', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Forcepoint ThreatSeeker', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Fortinet', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'FraudScore', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'G-Data', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Google Safebrowsing', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'GreenSnow', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Hoplite Industries', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'IPsum', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'K7AntiVirus', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Kaspersky', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Lionic', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Lumu', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'MalBeacon', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'MalSilo', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'MalwareDomainList', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': 'http://www.malwaredomainlist.com/mdl.php?search=github.com'},
                {'Source': 'MalwarePatrol', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Malwared', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Netcraft', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'NotMining', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'Nucleon', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'OpenPhish', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'PREBYTES', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'PhishLabs', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'Phishing Database', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Phishtank', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Quick Heal', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Quttera', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Rising', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'SCUMWARE.org', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'SafeToOpen', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'Sangfor', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Scantitan', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'SecureBrain', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Snort IP sample list', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Sophos', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Spam404', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Spamhaus', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'StopBadware', 'Detected': False, 'Result': 'unrated site', 'Update': None, 'Details': None},
                {'Source': 'StopForumSpam', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Sucuri SiteCheck', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Tencent', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'ThreatHive', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Threatsourcing', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Trustwave', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'URLhaus', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'VX Vault', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Virusdie External Site Scan', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Web Security Guard', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'Webroot', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'Yandex Safebrowsing', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': 'http://yandex.com/infected?l10n=en&url=https://github.com/topics/spacevim'},
                {'Source': 'ZeroCERT', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'alphaMountain.ai', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'benkow.cc', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'desenmascara.me', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'malwares.com URL checker', 'Detected': False, 'Result': 'clean site', 'Update': None,
                 'Details': None},
                {'Source': 'securolytics', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None},
                {'Source': 'zvelo', 'Detected': False, 'Result': 'clean site', 'Update': None, 'Details': None}
            ]
        }
    }

    expected_ec_dbot = {'Vendor': 'VirusTotal - Private API', 'Indicator': u'https://github.com/topics/spacevim',
                        'Score': 1, 'Type': 'url'}

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


def test_get_url_report_invalid_url(mocker, requests_mock):
    """
    Given:
        - The get-url-report command.
    When:
        - Mocking a response for an invalid url.
    Then:
        - Validate that a message indicating an invalid url was queried is returned in the md message.
    """
    mocker.patch.object(demisto, 'args', return_value={'resource': 'hts://invalid_url.nfs.cv'})
    requests_mock.get('https://www.virustotal.com/vtapi/v2/url/report',
                      [{'json': load_test_data('./test_data/get_url_report_invalid_url.json'),
                        'status_code': 200}])

    vt = importlib.import_module("VirusTotal-Private_API")
    output = vt.get_url_report_command()
    assert 'Invalid URL' in output[0]['HumanReadable']

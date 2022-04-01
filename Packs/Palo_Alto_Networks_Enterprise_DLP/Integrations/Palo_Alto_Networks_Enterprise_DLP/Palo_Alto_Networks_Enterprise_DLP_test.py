import demistomock as demisto

import json

from Palo_Alto_Networks_Enterprise_DLP import Client, FeedbackStatus, fetch_incidents, \
    exemption_eligible, slack_bot_message, reset_last_run_command, parse_incident_details, parse_dlp_report

DLP_URL = 'https://api.dlp.paloaltonetworks.com'

REPORT_DATA = {
    'txn_id': '2573778324',
    'report_id': '2573778324',
    'data_profile_id': '11995149',
    'data_profile_version': 1,
    'data_profile_name': 'Credit Card Match 2',
    'type': 'advanced',
    'tenant_id': '1128505801991063552',
    'fileSha': '9093980f84a22659207d6a7194fc10e22416c833044a4d23f292b3a666ee66d9',
    'file_name': 'Test_file.txt',
    'file_type': 'txt',
    'file_size_in_bytes': 7640,
    'extracted_file_size_in_bytes': 7649,
    'detection_time': '04/01/2022 20:21:50 UTC',
    'action': 'block',
    'data_pattern_rule_1_verdict': 'MATCHED',
    'data_pattern_rule_2_verdict': None,
    'scanContentRawReport': {
        'data_pattern_rule_1_results': [{
            'data_pattern_id': '617b1867469e8924c80baeac',
            'version': 1,
            'name': 'Credit Card Number',
            'technique': 'regex',
            'type': 'predefined',
            'strict_detection_frequency': 2,
            'proximity_detection_frequency': 10,
            'detection_frequency': 42,
            'unique_strict_detection_frequency': 1,
            'unique_checksum_detection_frequency': 0,
            'unique_proximity_detection_frequency': 5,
            'unique_detection_frequency': 7,
            'weighted_frequency': 0,
            'score': 0.0,
            'high_confidence_frequency': 10,
            'medium_confidence_frequency': 42,
            'low_confidence_frequency': 42,
            'unique_high_confidence_frequency': 5,
            'unique_medium_confidence_frequency': 7,
            'unique_low_confidence_frequency': 7,
            'matched_confidence_level': 'low',
            'state': 'EVALUATED',
            'detections': [{
                'left': 'mastercard ************4444 \r\n************1881\r\n*********2222\r\n***********0005\r\n',
                'right': 'Cyprus CY17 0020 0128 0000 0012 0052 7600\r\nEs',
                'detection': '************1117',
                'origOffSet': 1484,
                'textLength': 0
            }]
        }],
        'data_pattern_rule_2_results': None,
        'mlResponse': {
            'sha_256_original': None,
            'sha_256_extracted': None,
            'tenant_id': None,
            'report_id': None,
            'features': None
        }
    }
}


def test_update_incident(requests_mock):
    incident_id = 'abcdefg12345'
    user_id = 'someone@somewhere.com'
    requests_mock.post(f'{DLP_URL}/public/incident-feedback/{incident_id}?feedback_type=CONFIRMED_SENSITIVE&region=us')
    client = Client(DLP_URL, "", "", False, None)
    result, status = client.update_dlp_incident(incident_id, FeedbackStatus.CONFIRMED_SENSITIVE, user_id, 'us',
                                                'A12345', 'ngfw')
    request = requests_mock.last_request
    assert status == 200
    assert result == {}
    assert request.text == json.dumps({"user_id": user_id, "report_id": "A12345", "service_name": 'ngfw'})


def test_get_dlp_report(requests_mock):
    report_id = 12345
    requests_mock.get(f'{DLP_URL}/public/report/{report_id}', json={'id': 'test'})
    client = Client(DLP_URL, "", "", False, None)
    result, status = client.get_dlp_report(report_id, fetch_snippets=True)
    assert result == {'id': 'test'}
    assert status == 200


def test_parse_dlp_report(mocker):
    mocker.patch.object(demisto, 'results')
    parse_dlp_report(REPORT_DATA)
    results = demisto.results.call_args_list[0][0]
    pattern_results = demisto.get(results[0]['Contents'], 'scanContentRawReport.data_pattern_rule_1_results', None)
    assert pattern_results is not None


def test_get_dlp_incidents(requests_mock):
    requests_mock.get(f'{DLP_URL}/public/incident-notifications?regions=us', json={'us': []})
    client = Client(DLP_URL, "", "", False, None)
    result = client.get_dlp_incidents(regions='us')
    assert result == {'us': []}


def test_fetch_incidents(requests_mock, mocker):
    requests_mock.get(f'{DLP_URL}/public/incident-notifications?regions=us', json={'us': []})
    client = Client(DLP_URL, "", "", False, None)
    incidents = fetch_incidents(client=client, regions='us')
    assert incidents == []


def test_exemption_eligible(mocker):
    args = {
        'data_profile': 'abc'
    }
    params = {
        'dlp_exemptible_list': 'abc,aaa,bbb'
    }
    mocker.patch.object(demisto, 'results')
    exemption_eligible(args, params)
    results = demisto.results.call_args_list[0][0]
    assert results[0]['Contents'] == {'eligible': True}


def test_slack_bot_message(mocker):
    params = {
        'dlp_slack_message': 'Hello $user, your file $file_name on $app_name violated $data_profile_name'
    }
    args = {
        'user': 'John Doe',
        'file_name': 'secrets.doc',
        'app_name': 'Google Drive',
        'data_profile_name': 'PCI'
    }
    mocker.patch.object(demisto, 'results')
    slack_bot_message(args, params)
    results = demisto.results.call_args_list[0][0]
    assert results[0]['Contents'] == {'message': 'Hello John Doe, your file secrets.doc on Google Drive violated PCI'}


def test_reset_last_run(mocker):
    mocker.patch.object(demisto, 'results')
    reset_last_run_command()
    results = demisto.results.call_args_list[0][0]
    assert results[0]['HumanReadable'] == 'fetch-incidents was reset successfully.'


def test_parse_incident_details():
    compressed_str = 'QlpoOTFBWSZTWVnl2RYAAKIfgFAFfBBEAoAKv+ffqjAA2CIpoZGjEDTIZBpgGGRpppkYTIwTQGBiSp/pTZGqe1T8qMQaaeo9Nqm3YdNAidgNoZcFEJmTIP+V1xQohhqNsWERYRnKAc3TlogFoteml94kUR+lVJzjB9uhEqOgfBMrQh34ox8qYCCQo2n9WoNceFBvtSCAfMeY7sIAvtXhGQZ7UToozWEQwedzu/MRtoFMK8+ucpSbK4O7zRnPU82E9etuWR5AtmDQF5muuAczVDMFREJd+AEsRAKqdBdyRThQkFnl2RY='  # noqa: E501
    details = parse_incident_details(compressed_str)
    assert details['app_details'] == {'name': 'Microsoft OneDrive'}

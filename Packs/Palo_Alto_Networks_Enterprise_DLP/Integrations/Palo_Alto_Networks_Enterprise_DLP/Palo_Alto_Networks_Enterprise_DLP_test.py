import demistomock as demisto
import pytest
import json

from Palo_Alto_Networks_Enterprise_DLP import Client, fetch_incidents, \
    exemption_eligible_command, slack_bot_message_command, parse_incident_details, \
    parse_dlp_report, update_incident_command, main, PAN_AUTH_URL, fetch_notifications

DLP_URL = 'https://api.dlp.paloaltonetworks.com/v1'

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

INCIDENT_JSON = {
    "incidentId": "1fd24b1e-05ff-46c1-b638-a79d284dc727",
    "userId": None,
    "tenantId": "1128505801991063552",
    "reportId": "2573778324",
    "dataProfileId": 11995149,
    "dataProfileVersion": 1,
    "action": "block",
    "channel": "ngfw",
    "filename": "Test_file.txt",
    "checksum": "9093980f84a22659207d6a7194fc10e22416c833044a4d23f292b3a666ee66d9",
    "source": "ngfw",
    "scanDate": "2022-Apr-01 20:21:50 UTC",
    "createdAt": "2022-Apr-01 20:21:50 UTC",
    "incidentDetails": "QlpoOTFBWSZTWVnl2RYAAKIfgFAFfBBEAoAKv+ffqjAA2CIpoZGjEDTIZBpgGGRpppkYTIwTQGBiSp/pTZGqe1T8qMQaaeo9Nqm3YdNAidgNoZcFEJmTIP+V1xQohhqNsWERYRnKAc3TlogFoteml94kUR+lVJzjB9uhEqOgfBMrQh34ox8qYCCQo2n9WoNceFBvtSCAfMeY7sIAvtXhGQZ7UToozWEQwedzu/MRtoFMK8+ucpSbK4O7zRnPU82E9etuWR5AtmDQF5muuAczVDMFREJd+AEsRAKqdBdyRThQkFnl2RY="  # noqa: E501
}

CREDENTIALS = {
    'credential': '',
    'credentials': {
        'id': '',
        'locked': False,
        'modified': '0001-01-01T00:00:00Z',
        'name': '',
        'password': '',
        'sortValues': None,
        'sshkey': '',
        'sshkeyPass': '',
        'user': '',
        'vaultInstanceId': '',
        'version': 0,
        'workgroup': ''
    },
    'identifier': '',
    'password': '',
    'passwordChanged': False
}


def test_update_incident(requests_mock, mocker):
    incident_id = 'abcdefg12345'
    user_id = 'someone@somewhere.com'
    args = {
        'incident_id': incident_id,
        'feedback': 'CONFIRMED_SENSITIVE',
        'user_id': user_id,
        'region': 'us',
        'report_id': 'A12345',
        'dlp_channel': 'ngfw'
    }

    requests_mock.post(f'{DLP_URL}/public/incident-feedback/{incident_id}?feedback_type=CONFIRMED_SENSITIVE&region=us')
    client = Client(DLP_URL, CREDENTIALS, False, None)
    mocker.patch.object(demisto, 'results')

    results = update_incident_command(client, args).to_context()

    request = requests_mock.last_request

    assert results['Contents'] == {'feedback': 'CONFIRMED_SENSITIVE', 'success': True}
    assert request.text == json.dumps({"user_id": user_id, "report_id": "A12345", "service_name": 'ngfw'})


def test_update_incident_with_error_details(requests_mock, mocker):
    incident_id = 'abcdefg12345'
    user_id = 'someone@somewhere.com'
    args = {
        'incident_id': incident_id,
        'feedback': 'SEND_NOTIFICATION_FAILURE',
        'user_id': user_id,
        'region': 'us',
        'report_id': 'A12345',
        'dlp_channel': 'ngfw',
        'error_details': 'Something went wrong'
    }

    requests_mock.post(f'{DLP_URL}/public/incident-feedback/{incident_id}?feedback_type=SEND_NOTIFICATION_FAILURE&region=us')
    client = Client(DLP_URL, CREDENTIALS, False, None)
    mocker.patch.object(demisto, 'results')

    results = update_incident_command(client, args).to_context()

    request = requests_mock.last_request

    assert results['Contents'] == {'feedback': 'SEND_NOTIFICATION_FAILURE', 'success': True}
    assert request.text == json.dumps({"user_id": user_id, "report_id": "A12345", "service_name": 'ngfw',
                                       'error_details': 'Something went wrong'})


def test_get_dlp_report(requests_mock, mocker):
    report_id = 12345
    requests_mock.get(f'{DLP_URL}/public/report/{report_id}?fetchSnippets=true', json={'id': 'test'})
    mocker.patch.object(demisto, 'command', return_value='pan-dlp-get-report')
    args = {
        'report_id': report_id,
        'fetch_snippets': 'true'
    }
    params = {
        'credentials': CREDENTIALS
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args_list[0][0]
    assert results[0]['Contents'] == {'id': 'test'}


def test_parse_dlp_report(mocker):
    mocker.patch.object(demisto, 'results')
    results = parse_dlp_report(REPORT_DATA).to_context()
    pattern_results = demisto.get(results['Contents'], 'scanContentRawReport.data_pattern_rule_1_results', None)
    assert pattern_results is not None


def test_get_dlp_incidents(requests_mock):
    requests_mock.get(f'{DLP_URL}/public/incident-notifications?regions=us', json={'us': []})
    client = Client(DLP_URL, CREDENTIALS, False, None)
    result = client.get_dlp_incidents(regions='us')
    assert result == {'us': []}


def test_fetch_notifications(requests_mock, mocker):
    requests_mock.get(f'{DLP_URL}/public/incident-notifications?regions=us', json={'us': []})
    incident_mock = mocker.patch.object(demisto, 'createIncidents')

    client = Client(DLP_URL, CREDENTIALS, False, None)
    fetch_notifications(client, 'us')
    assert incident_mock.call_args[0][0] == []


def test_refresh_token(requests_mock, mocker):
    with pytest.raises(Exception):
        report_id = 12345
        headers1 = {
            "Authorization": "Bearer 123",
            "Content-Type": "application/json"
        }
        requests_mock.get(f'{DLP_URL}/public/report/{report_id}?fetchSnippets=true', headers=headers1, status_code=403)

        requests_mock.post(f'{DLP_URL}/public/oauth/refreshToken', json={'access_token': 'abc'})
        credentials = {
            'credential': '',
            'credentials': {
                'id': '',
                'locked': False,
                'modified': '0001-01-01T00:00:00Z',
                'name': '',
                'password': '',
                'sortValues': None,
                'sshkey': '',
                'sshkeyPass': '',
                'user': '',
                'vaultInstanceId': '',
                'version': 0,
                'workgroup': ''
            },
            'identifier': '123',
            'password': '',
            'passwordChanged': False
        },
        client = Client(DLP_URL, credentials, False, None)

        client.get_dlp_report(report_id, True)

        assert client.access_token == 'abc'


def test_refresh_token_with_access_token(requests_mock, mocker):
    requests_mock.post(f'{DLP_URL}/public/oauth/refreshToken', json={'access_token': 'abc'})
    client = Client(DLP_URL, CREDENTIALS, False, None)
    client._refresh_token()
    assert client.access_token == 'abc'


def test_refresh_token_with_client_credentials(requests_mock, mocker):
    credentials = {
        'credential': 'test credentials',
        'credentials': {
            'id': 'test credentials',
            'locked': False,
            'name': 'test credentials',
            'password': 'test-pass',
            'sortValues': None,
            'sshkey': '',
            'sshkeyPass': '',
            'user': 'test-user',
            'vaultInstanceId': '',
            'version': 1,
            'workgroup': ''
        },
        'identifier': 'test-user',
        'password': 'test-pass',
        'passwordChanged': False
    }
    client = Client(DLP_URL, credentials, False, None)
    requests_mock.post(PAN_AUTH_URL, json={'access_token': 'abc'})
    client._refresh_token_with_client_credentials()
    assert client.access_token == 'abc'


def test_handle_403(requests_mock, mocker):
    credentials = {
        'credential': 'test credentials',
        'credentials': {
            'id': 'test credentials',
            'locked': False,
            'name': 'test credentials',
            'password': 'test-pass',
            'sortValues': None,
            'sshkey': '',
            'sshkeyPass': '',
            'user': 'test-user',
            'vaultInstanceId': '',
            'version': 1,
            'workgroup': ''
        },
        'identifier': 'test-user',
        'password': 'test-pass',
        'passwordChanged': False
    }
    client = Client(DLP_URL, credentials, False, None)
    credentials_mocker = mocker.patch.object(client, '_refresh_token_with_client_credentials')
    response_mock = mocker.MagicMock()
    type(response_mock).status_code = mocker.PropertyMock(return_value=403)
    client._handle_403_errors(response_mock)
    credentials_mocker.assert_called_with()

    client = Client(DLP_URL, CREDENTIALS, False, None)
    tokens_mocker = mocker.patch.object(client, '_refresh_token')
    client._handle_403_errors(response_mock)
    tokens_mocker.assert_called_with()


def test_fetch_incidents(requests_mock, mocker):
    requests_mock.get(f'{DLP_URL}/public/incident-notifications?regions=us', json={'us': [
        {
            'incident': INCIDENT_JSON,
            'previous_notifications': []
        }]})
    client = Client(DLP_URL, CREDENTIALS, False, None)
    incidents = fetch_incidents(client=client, regions='us')
    assert len(incidents) == 1


def test_exemption_eligible(mocker):
    args = {
        'data_profile': 'abc'
    }
    params = {
        'dlp_exemptible_list': 'abc,aaa,bbb'
    }
    mocker.patch.object(demisto, 'results')
    results = exemption_eligible_command(args, params).to_context()
    assert results['Contents'] == {'eligible': True}


def test_exemption_eligible_wildcard(mocker):
    args = {
        'data_profile': 'abc'
    }
    params = {
        'dlp_exemptible_list': '*'
    }
    mocker.patch.object(demisto, 'results')
    results = exemption_eligible_command(args, params).to_context()
    assert results['Contents'] == {'eligible': True}


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
    results = slack_bot_message_command(args, params).to_context()
    assert results['Contents'] == {'message': 'Hello John Doe, your file secrets.doc on Google Drive violated PCI'}


def test_parse_incident_details():
    compressed_str = 'QlpoOTFBWSZTWVnl2RYAAKIfgFAFfBBEAoAKv+ffqjAA2CIpoZGjEDTIZBpgGGRpppkYTIwTQGBiSp/pTZGqe1T8qMQaaeo9Nqm3YdNAidgNoZcFEJmTIP+V1xQohhqNsWERYRnKAc3TlogFoteml94kUR+lVJzjB9uhEqOgfBMrQh34ox8qYCCQo2n9WoNceFBvtSCAfMeY7sIAvtXhGQZ7UToozWEQwedzu/MRtoFMK8+ucpSbK4O7zRnPU82E9etuWR5AtmDQF5muuAczVDMFREJd+AEsRAKqdBdyRThQkFnl2RY='  # noqa: E501
    details = parse_incident_details(compressed_str)
    assert details['app_details'] == {'name': 'Microsoft OneDrive'}


def test_query_sleep_time(requests_mock):
    requests_mock.get(f'{DLP_URL}/public/seconds-between-incident-notifications-pull', json=10)
    client = Client(DLP_URL, CREDENTIALS, False, None)
    time = client.query_for_sleep_time()
    assert time == 10

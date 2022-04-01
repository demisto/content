import demistomock as demisto

import json

from Palo_Alto_Networks_Enterprise_DLP import Client, FeedbackStatus, fetch_incidents, \
    exemption_eligible, slack_bot_message
DLP_URL = 'https://api.dlp.paloaltonetworks.com'

def test_update_incident(requests_mock):
    incident_id = 'abcdefg12345'
    user_id = 'someone@somewhere.com'
    requests_mock.post(f'{DLP_URL}/public/incident-feedback/{incident_id}?feedback_type=CONFIRMED_SENSITIVE&region=us')
    client = Client(DLP_URL, "", "", False, None)
    result, status = client.update_dlp_incident(incident_id, FeedbackStatus.CONFIRMED_SENSITIVE, user_id, 'us', 'A12345', 'ngfw')
    request = requests_mock.last_request
    assert status == 200
    assert result == {}
    assert request.text == json.dumps({"user_id": user_id, "report_id": "A12345", "service_name": 'ngfw'})


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



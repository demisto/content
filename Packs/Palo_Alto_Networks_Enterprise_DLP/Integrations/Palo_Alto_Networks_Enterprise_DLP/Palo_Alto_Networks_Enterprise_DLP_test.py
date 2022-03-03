import json

import demistomock as demisto

from Palo_Alto_Networks_Enterprise_DLP import Client, FeedbackStatus
DLP_URL = 'https://api.dlp.paloaltonetworks.com'

def test_update_incident(requests_mock):
    incident_id = 'abcdefg12345'
    user_id = 'someone@somewhere.com'
    requests_mock.post(f'{DLP_URL}/public/incident-feedback/{incident_id}?feedback_type=CONFIRMED_SENSITIVE&region=us')
    client = Client(DLP_URL, "", "", False, None)
    result, status = client.update_dlp_incident(incident_id, FeedbackStatus.CONFIRMED_SENSITIVE, user_id, 'us')
    request = requests_mock.last_request
    assert status == 200
    assert result == {}
    assert request.text == json.dumps({"user_id": user_id})


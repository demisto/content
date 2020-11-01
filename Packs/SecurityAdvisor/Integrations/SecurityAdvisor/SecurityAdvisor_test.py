import SecurityAdvisor

URL_SUFFIX = 'apis/coachuser/'
BASE_URL = 'https://www.securityadvisor.io/'
CONTEXT_JSON = {
    "SecurityAdvisor.CoachUser": {
        "coaching_date": "2019-10-04T21:04:19.480425",
        "coaching_status": "Pending",
        "coaching_score": "",
        "user": "track@securityadvisor.io",
        "context": "phishing",
        "message": "Coaching Sent"
    }
}
RESPONSE_JSON = {
    "coaching_date": "2019-10-04T21:04:19.480425",
    "coaching_status": "Pending",
    "coaching_score": "",
    "user": "track@securityadvisor.io",
    "context": "phishing",
    "message": "Coaching Sent"
}
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Token ' + 'MOCKEY'
}


def test_coach_end_user_command(requests_mock):
    """Unit test for coach-end-user command
    Args:
        requests_mock ([type]): [description]
    """
    mock_reponse = RESPONSE_JSON
    requests_mock.post(BASE_URL + URL_SUFFIX, json=mock_reponse)
    client = SecurityAdvisor.Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        headers=HEADERS
    )
    args = {"user": "track@securityadvisor.io", "context": "phishing"}
    _, _, result = SecurityAdvisor.coach_end_user_command(client, args)
    assert result == RESPONSE_JSON


def test_module_command(requests_mock):
    """Unit test for test-module command
    Args:
        requests_mock ([type]): [description]
    """
    mock_reponse = RESPONSE_JSON
    requests_mock.post(BASE_URL + URL_SUFFIX, json=mock_reponse)
    client = SecurityAdvisor.Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        headers=HEADERS
    )
    response = SecurityAdvisor.test_module(client)
    assert response == "ok"

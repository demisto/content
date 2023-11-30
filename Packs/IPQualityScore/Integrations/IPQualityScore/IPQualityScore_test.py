import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_ip_command(requests_mock):
    from IPQualityScore import Client, ip_command
    mock_response = util_load_json('test_data/ip_response.json')
    requests_mock.get('https://ipqualityscore.com/api/json/ip/api_key_here/15.99.160.255', json=mock_response)
    client = Client(
        base_url='https://ipqualityscore.com/api/json/ip/api_key_here',
        verify=False)
    ip_suspicious_score_threshold = 75
    ip_malicious_score_threshold = 85
    reliability = "A - Completely reliable"
    args = {
        "ip": "15.99.160.255"
    }
    response = ip_command(client, args, ip_suspicious_score_threshold, ip_malicious_score_threshold, reliability)
    assert response[0].outputs_prefix == 'IPQualityScore.IP'


def test_email_command(requests_mock):
    from IPQualityScore import Client, email_command
    mock_response = util_load_json('test_data/email_response.json')
    requests_mock.get('https://ipqualityscore.com/api/json/email/api_key_here/someone%40gmail.com', json=mock_response)
    client = Client(
        base_url='https://ipqualityscore.com/api/json/email/api_key_here',
        verify=False)
    email_suspicious_score_threshold = 75
    email_malicious_score_threshold = 85
    reliability = "A - Completely reliable"
    args = {
        "email": "someone@gmail.com"
    }
    response = email_command(client, args, email_suspicious_score_threshold, email_malicious_score_threshold,
                             reliability)
    assert response[0].outputs_prefix == 'IPQualityScore.Email'


def test_url_command(requests_mock):
    from IPQualityScore import Client, url_command
    mock_response = util_load_json('test_data/url_response.json')
    requests_mock.get('https://ipqualityscore.com/api/json/url/api_key_here/https%3A%2F%2Fgoogle.com',
                      json=mock_response)
    client = Client(
        base_url='https://ipqualityscore.com/api/json/url/api_key_here',
        verify=False)
    url_suspicious_score_threshold = 75
    url_malicious_score_threshold = 85
    reliability = "A - Completely reliable"
    args = {
        "url": "https://google.com"
    }
    response = url_command(client, args, url_suspicious_score_threshold, url_malicious_score_threshold,
                           reliability)
    assert response[0].outputs_prefix == 'IPQualityScore.Url'

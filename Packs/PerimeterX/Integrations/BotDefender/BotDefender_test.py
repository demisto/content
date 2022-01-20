from BotDefender import Client, ip, perimeterx_get_investigate_details
from CommonServerPython import Common

HEADERS = {
    'Authorization': 'Bearer token',
    'Content-Type': 'application/json'
}
MOCK_BASE_URL = "https://api.perimeterx.com/v1/bot-defender/"


def _get_mock_url():
    return f'{MOCK_BASE_URL}/investigate/mock?search=ip:test&tops=user-agent,path,socket_ip_classification'


def _test_base_score(requests_mock, actual_score, expected_score):
    ip_addresses = ['5.79.76.181', '5.79.76.182']
    mock_response = {
        'max_risk_score': actual_score
    }

    mock_url = _get_mock_url()
    requests_mock.get(mock_url, json=mock_response)

    client = Client(base_url=mock_url, verify=False, headers=HEADERS)

    args = {
        'ip': ip_addresses
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = ip(client=client, args=args, thresholds=thresholds, api_key="test")

    for single_response in response:
        assert single_response.outputs_prefix == 'PerimeterX'
        assert isinstance(single_response.indicator, Common.IP)
        assert single_response.indicator.ip in ip_addresses
        assert single_response.indicator.dbot_score.score == expected_score


def test_ip_high_score(requests_mock):
    _test_base_score(requests_mock, actual_score=100, expected_score=3)


def test_ip_suspicious_score(requests_mock):
    _test_base_score(requests_mock, actual_score=60, expected_score=2)


def test_ip_good_score(requests_mock):
    _test_base_score(requests_mock, actual_score=10, expected_score=1)


def test_ip_unknown_score(requests_mock):
    _test_base_score(requests_mock, actual_score=1, expected_score=0)


def _test_perimeterx_get_investigate_details_base(requests_mock, search_type):
    mock_response = {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36',
             'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36',
             'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99',
             'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)',
             'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36',
             'count': 72}
        ],
        'topURLPaths': [
            {'urlPath': '/favicon.ico', 'count': 3315},
            {'urlPath': '/favicon.png', 'count': 3253},
            {'urlPath': '/', 'count': 3212},
            {'urlPath': '/loginok/light.cgi', 'count': 1228},
            {'urlPath': '/cgi-bin/way-board.cgi', 'count': 1222},
            {'urlPath': '/phpmyadmin/', 'count': 205},
            {'urlPath': '-', 'count': 139},
            {'urlPath': '/images/icons/favicon.ico', 'count': 82},
            {'urlPath': '/test.php', 'count': 48}
        ],
        'topBlockedURLPaths': [
            {'blockedURLPath': '/', 'count': 1404},
            {'blockedURLPath': '/cgi-bin/way-board.cgi', 'count': 702},
            {'blockedURLPath': '/loginok/light.cgi', 'count': 702}
        ],
        'topIncidentTypes': [
            {'incidentType': 'Spoof', 'count': 2106},
            {'incidentType': 'Bot Behavior', 'count': 702}
        ],
        'catpchaSolves': 200,
        'trafficOverTime': [
        ],
        'pageTypeDistributions': [
            {'pageType': 'Login', 'count': 1228},
            {'pageType': 'Scraping', 'count': 739},
            {'pageType': 'Checkout', 'count': 139}
        ],
        'max_risk_score': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }

    ip_address = ['5.79.76.181']
    mock_url = _get_mock_url()
    requests_mock.get(mock_url, json=mock_response)

    client = Client(base_url=mock_url, verify=False, headers=HEADERS)

    args = {
        'search_type': search_type,
        'search_term': ip_address
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = perimeterx_get_investigate_details(client=client, args=args, thresholds=thresholds, api_key="test_key")

    assert response.outputs_prefix == 'PerimeterX'
    assert response.outputs == {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36',
             'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36',
             'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99',
             'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)',
             'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2',
             'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36',
             'count': 72}
        ],
        'topURLPaths': [
            {'urlPath': '/favicon.ico', 'count': 3315},
            {'urlPath': '/favicon.png', 'count': 3253},
            {'urlPath': '/', 'count': 3212},
            {'urlPath': '/loginok/light.cgi', 'count': 1228},
            {'urlPath': '/cgi-bin/way-board.cgi', 'count': 1222},
            {'urlPath': '/phpmyadmin/', 'count': 205},
            {'urlPath': '-', 'count': 139},
            {'urlPath': '/images/icons/favicon.ico', 'count': 82},
            {'urlPath': '/test.php', 'count': 48}
        ],
        'topBlockedURLPaths': [
            {'blockedURLPath': '/', 'count': 1404},
            {'blockedURLPath': '/cgi-bin/way-board.cgi', 'count': 702},
            {'blockedURLPath': '/loginok/light.cgi', 'count': 702}
        ],
        'topIncidentTypes': [
            {'incidentType': 'Spoof', 'count': 2106},
            {'incidentType': 'Bot Behavior', 'count': 702}
        ],
        'catpchaSolves': 200,
        'trafficOverTime': [
        ],
        'pageTypeDistributions': [
            {'pageType': 'Login', 'count': 1228},
            {'pageType': 'Scraping', 'count': 739},
            {'pageType': 'Checkout', 'count': 139}
        ],
        'max_risk_score': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }


def test_perimeterx_get_investigate_details_by_socket_ip(requests_mock):
    return _test_perimeterx_get_investigate_details_base(requests_mock, search_type='socket_ip')


def test_perimeterx_get_investigate_details_by_true_ip(requests_mock):
    return _test_perimeterx_get_investigate_details_base(requests_mock, search_type='true_ip')

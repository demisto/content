from BotDefender import Client, perimeterx_get_investigate_details, ip


def test_ip_high_score(requests_mock):
    from CommonServerPython import Common

    ip_address = '5.79.76.181'
    mock_response = {
        'maxRiskScore': 100
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'ip': ip_address
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = ip(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert isinstance(response.indicators[0], Common.IP)
    assert response.indicators[0].ip == ip_address
    assert response.indicators[0].dbot_score.score == 3


def test_ip_suspicious_score(requests_mock):
    from CommonServerPython import Common

    ip_address = '5.79.76.181'
    mock_response = {
        'maxRiskScore': 60
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'ip': ip_address
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = ip(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert isinstance(response.indicators[0], Common.IP)
    assert response.indicators[0].ip == ip_address
    assert response.indicators[0].dbot_score.score == 2


def test_ip_good_score(requests_mock):
    from CommonServerPython import Common

    ip_address = '5.79.76.181'
    mock_response = {
        'maxRiskScore': 10
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'ip': ip_address
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = ip(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert isinstance(response.indicators[0], Common.IP)
    assert response.indicators[0].ip == ip_address
    assert response.indicators[0].dbot_score.score == 1


def test_ip_unknown_score(requests_mock):
    from CommonServerPython import Common

    ip_address = '5.79.76.181'
    mock_response = {
        'maxRiskScore': 1
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'ip': ip_address
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = ip(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert isinstance(response.indicators[0], Common.IP)
    assert response.indicators[0].ip == ip_address
    assert response.indicators[0].dbot_score.score == 0


def test_perimeterx_get_investigate_details_by_socket_ip(requests_mock):

    mock_response = {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36', 'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99', 'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)', 'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 72}
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
        'maxRiskScore': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'search_type': 'socket_ip',
        'search_term': '5.79.76.181'
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = perimeterx_get_investigate_details(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert response.outputs == {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36', 'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99', 'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)', 'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 72}
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
        'maxRiskScore': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }


def test_perimeterx_get_investigate_details_by_true_ip(requests_mock):

    mock_response = {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36', 'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99', 'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)', 'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 72}
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
        'maxRiskScore': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }

    requests_mock.post('https://k986g.mocklab.io/api/v0/investigate', json=mock_response)

    headers = {
        'Authorization': 'Bearer ebfb7ff0-b2f6-41c8-bef3-4fba17be410c',
        'Content-Type': 'application/json'
    }

    client = Client(base_url='https://k986g.mocklab.io/api/v0', verify=False, headers=headers)

    args = {
        'search_type': 'true_ip',
        'search_term': '5.79.76.181'
    }

    thresholds = {
        'good_threshold': 5,
        'suspicious_threshold': 50,
        'bad_threshold': 90,
        'unknown_threshold': 0
    }

    response = perimeterx_get_investigate_details(client=client, args=args, thresholds=thresholds)

    assert response.outputs_prefix == 'PerimeterX'
    assert response.outputs == {
        'topUserAgents': [
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 84},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/65.0.3325.181 Safari/537.36', 'count': 80},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64;x64 Gecko) Chrome/66.0.3359.170 OPR/53.0.2907.99', 'count': 78},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64 Gecko) Chrome/67.0.3396.87 (Edition Yx)', 'count': 76},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64;x64 Gecko) Chrome/67.0.3396.87 OPR/54.0.2952.51', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 Gecko) Chrome/68.0.3440.75 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1 Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1 Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2', 'count': 72},
            {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64 Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 72}
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
        'maxRiskScore': 100,
        'ipClassifications': [
            {'class': 'Bad Reputation', 'name': 'Bad Reputation'},
            {'class': 'SharedIPs', 'name': 'Shared IPs'},
            {'class': 'DataCenter', 'name': 'TAG DCIP'}
        ]
    }

"""CyberTotal Integration for Cortex XSOAR - Unit Tests file
This file contains the Unit Tests for the CyberTotal Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.
"""

import json


def util_load_json(path):
    with open(path, 'r') as f:
        return json.load(f)


def test_ip(requests_mock):
    """Tests the ip reputation command function.
    Configures requests_mock instance to generate the appropriate
    ip reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, ip_reputation_command
    from CommonServerPython import Common

    ip_to_check = '1.1.1.1'
    mock_response = util_load_json('test_data/reputation.json')
    requests_mock.get(f'http://test.com/_api/search/ip/basic/{ip_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'ip': ip_to_check,
        'threshold': 10,
    }

    response = ip_reputation_command(client, args, 10)[0]

    assert response.outputs_prefix == 'CyberTotal.IP'
    assert response.outputs_key_field == 'task_id'
    assert response.outputs['resource'] == ip_to_check
    assert response.outputs['severity'] == 9
    assert response.outputs['confidence'] == 3
    assert response.outputs['threat'] == "High"
    assert response.outputs['permalink'] == "https://test.com/app/intelligence/2e11509eb3034aabaf3c006425050247"
    assert response.outputs['detection_ratio'] == "1/2"

    # This command also returns Common.IP data
    assert isinstance(response.indicator, Common.IP)
    assert response.indicator.ip == ip_to_check
    assert type(response.indicator.detection_engines) is int
    assert type(response.indicator.positive_engines) is int


def test_url(requests_mock):
    """Tests the url reputation command function.
    Configures requests_mock instance to generate the appropriate
    url reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, url_reputation_command
    from CommonServerPython import Common

    url_to_check = 'http://abc.com'
    mock_response = util_load_json('test_data/reputation.json')
    requests_mock.get(f'http://test.com/_api/search/url/basic?q={url_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'url': url_to_check,
        'threshold': 10,
    }

    response = url_reputation_command(client, args, 10)[0]

    assert response.outputs_prefix == 'CyberTotal.URL'
    assert response.outputs_key_field == 'task_id'
    assert response.outputs['resource'] == url_to_check
    assert response.outputs['severity'] == 9
    assert response.outputs['confidence'] == 3
    assert response.outputs['threat'] == "High"
    assert response.outputs['permalink'] == "https://test.com/app/intelligence/2e11509eb3034aabaf3c006425050247"
    assert response.outputs['detection_ratio'] == "1/2"

    # This command also returns Common.URL data
    assert isinstance(response.indicator, Common.URL)
    assert response.indicator.url == url_to_check
    assert type(response.indicator.detection_engines) is int
    assert type(response.indicator.positive_detections) is int


def test_domain(requests_mock):
    """Tests the domain reputation command function.
    Configures requests_mock instance to generate the appropriate
    domain reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, domain_reputation_command
    from CommonServerPython import Common

    domain_to_check = 'abc.com'
    mock_response = util_load_json('test_data/reputation.json')
    requests_mock.get(f'http://test.com/_api/search/domain/basic/{domain_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'domain': domain_to_check,
        'threshold': 10,
    }

    response = domain_reputation_command(client, args, 10)[0]

    assert response.outputs_prefix == 'CyberTotal.Domain'
    assert response.outputs_key_field == 'task_id'
    assert response.outputs['resource'] == domain_to_check
    assert response.outputs['severity'] == 9
    assert response.outputs['confidence'] == 3
    assert response.outputs['threat'] == "High"
    assert response.outputs['permalink'] == "https://test.com/app/intelligence/2e11509eb3034aabaf3c006425050247"
    assert response.outputs['detection_ratio'] == "1/2"

    # This command also returns Common.Domain data
    assert isinstance(response.indicator, Common.Domain)
    assert response.indicator.domain == domain_to_check
    assert type(response.indicator.detection_engines) is int
    assert type(response.indicator.positive_detections) is int


def test_file(requests_mock):
    """Tests the file reputation command function.
    Configures requests_mock instance to generate the appropriate
    file reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, file_reputation_command
    from CommonServerPython import Common

    file_to_check = 'e594b31feb5f31c2bf611593f1651354'
    mock_response = util_load_json('test_data/reputation.json')
    requests_mock.get(f'http://test.com/_api/search/hash/basic/{file_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'file': file_to_check,
        'threshold': 10,
    }

    response = file_reputation_command(client, args, 10)[0]

    assert response.outputs_prefix == 'CyberTotal.File'
    assert response.outputs_key_field == 'task_id'
    assert response.outputs['resource'] == file_to_check
    assert response.outputs['severity'] == 9
    assert response.outputs['confidence'] == 3
    assert response.outputs['threat'] == "High"
    assert response.outputs['permalink'] == "https://test.com/app/intelligence/2e11509eb3034aabaf3c006425050247"
    assert response.outputs['detection_ratio'] == "1/2"

    # This command also returns Common.File data
    assert isinstance(response.indicator, Common.File)
    assert response.indicator.md5 == file_to_check


def test_ip_whois(requests_mock):
    """Tests the ip whois command function.
    Configures requests_mock instance to generate the appropriate
    ip whois API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, ip_whois_command

    ip_to_check = '1.1.1.1'
    mock_response = util_load_json('test_data/whois.json')
    requests_mock.get(f'http://test.com/_api/search/ip/whois/{ip_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'ip': ip_to_check
    }

    response = ip_whois_command(client, args)

    assert response.outputs_prefix == 'CyberTotal.WHOIS-IP'
    assert response.outputs_key_field == 'task_id'


def test_url_whois(requests_mock):
    """Tests the URL whois command function.
    Configures requests_mock instance to generate the appropriate
    url whois API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, url_whois_command

    url_to_check = 'http://abc.com'
    mock_response = util_load_json('test_data/whois.json')
    requests_mock.get(f'http://test.com/_api/search/url/whois?q={url_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'url': url_to_check
    }

    response = url_whois_command(client, args)

    assert response.outputs_prefix == 'CyberTotal.WHOIS-URL'
    assert response.outputs_key_field == 'task_id'


def test_domain_whois(requests_mock):
    """Tests the domain whois command function.
    Configures requests_mock instance to generate the appropriate
    domain whois API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyberTotal import Client, domain_whois_command

    domain_to_check = 'abc.com'
    mock_response = util_load_json('test_data/whois.json')
    requests_mock.get(f'http://test.com/_api/search/domain/whois/{domain_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authorization': 'Token cybertotal_api_key'
        }
    )

    args = {
        'domain': domain_to_check
    }

    response = domain_whois_command(client, args)

    assert response.outputs_prefix == 'CyberTotal.WHOIS-Domain'
    assert response.outputs_key_field == 'task_id'

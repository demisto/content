import requests_mock
from iDefense_v2 import Client, url_command, ip_command, _calculate_dbot_score
from CommonServerPython import DemistoException
from test_data.response_constants import URL_RES_JSON, IP_RES_JSON

API_URL = "https://test.com"

DBOT_KEY = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && ' \
           'val.Vendor == obj.Vendor && val.Type == obj.Type)'


def test_ip_command():
    """
    Given:
        - an IP

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    url = 'https://test.com/rest/threatindicator/v0/ip?key.values=0.0.0.0'
    status_code = 200
    json_data = IP_RES_JSON
    expected_output = {
        'IP': [{'Address': '0.0.0.0'}],
        'DBOTSCORE': [{'Indicator': '0.0.0.0', 'Type': 'ip', 'Vendor': 'iDefense', 'Score': 2}]}

    ip_to_check = {'ip': '0.0.0.0'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        client = Client(API_URL, 'api_token', True, False)
        results = ip_command(client, ip_to_check)
        output = results[0].to_context().get('EntryContext', {})
        assert output.get('IP(val.Address && val.Address == obj.Address)', []) == expected_output.get('IP')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')


def test_ip_not_found():
    """
    Given:
        - an IP

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results with context indicate that no results were found

    """

    url = 'https://test.com/rest/threatindicator/v0/ip?key.values=1.1.1.1'
    status_code = 200
    json_data = {'total_size': 0, 'page': 1, 'page_size': 25, 'more': False}
    expected_output = "No results were found for ip 1.1.1.1"

    ip_to_check = {'ip': '1.1.1.1'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        client = Client(API_URL, 'api_token', True, False)
        results = ip_command(client, ip_to_check)
        output = results[0].to_context().get('HumanReadable')
        assert expected_output in output


def test_wrong_ip():
    """
    Given:
        - an IP

    When:
        - running ip command validate at first to check if the given ip is a valid ip

    Then:
        - raise error before calling http request that indicates that the given argument is not valid

    """

    ip_to_check = {'ip': '1'}
    client = Client(API_URL, 'api_token', True, False)
    try:
        ip_command(client, ip_to_check)
    except DemistoException as err:
        assert "Received wrong IP value" in str(err)


def test_wrong_connection():
    """
    Given:
        - an api token

    When:
        - checking api access

    Then:
        - raise error if there is no access because of wrong api token

    """

    from iDefense_v2 import test_module
    with requests_mock.Mocker() as m:
        mock_address = 'https://test.com/rest/threatindicator/v0/'
        m.get(mock_address, status_code=401, json={})
        client = Client('bad_api_key', 'wrong_token', True, False)
        try:
            test_module(client)
        except DemistoException as err:
            assert 'Error in API call - check the input parameters' in str(err)


def test_connection():
    """
    Given:
        - an api token

    When:
        - checking api access

    Then:
        - ok if there is access

    """

    from iDefense_v2 import test_module
    with requests_mock.Mocker() as m:
        mock_address = 'https://test.com/rest/threatindicator/v0/'
        m.get(mock_address, status_code=200, json={})
        client = Client(API_URL, 'api_token', True, False)
        assert test_module(client) in "ok"


def test_url_command():
    """
    Given:
        - url

    When:
        - running url command and validate whether the url is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    url = 'https://test.com/rest/threatindicator/v0/url?key.values=http://www.malware.com'
    status_code = 200
    json_data = URL_RES_JSON
    expected_output = {
        'URL': [{'Data': 'http://www.malware.com'}],
        'DBOTSCORE': [{'Indicator': 'http://www.malware.com', 'Type': 'url', 'Vendor': 'iDefense',
                       'Score': 2}]}
    url_to_check = {'url': 'http://www.malware.com'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        client = Client(API_URL, 'api_token', True, False)
        results = url_command(client, url_to_check)
        output = results[0].to_context().get('EntryContext', {})
        assert output.get('URL(val.Data && val.Data == obj.Data)', []) == expected_output.get('URL')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')


def test_calculate_dbot_score():
    """
    Given:
        - number represents severity

    When:
        - api call with indicator returns response that includes them severity score

    Then:
        - returns dbotscore according to internal conversion

    """

    assert _calculate_dbot_score(2) == 1
    assert _calculate_dbot_score(0) == 0

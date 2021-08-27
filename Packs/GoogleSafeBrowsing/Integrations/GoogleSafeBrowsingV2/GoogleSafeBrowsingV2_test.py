import pytest
from GoogleSafeBrowsingV2 import Client

from CommonServerPython import DBotScoreReliability


CLIENT_BODY = {
    'clientId': 'Client ID',
    'clientVersion': 'Client Version'
}

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}


def create_client(proxy: bool = False, verify: bool = False, base_url='',
                  reliability: str = DBotScoreReliability.B):
    return Client(proxy=proxy, verify=verify, base_url=base_url, reliability=reliability, params={})


def test_build_request_body():
    """
    Given:
        - request body for the API request

    When:
        - we build the request according to the client body and the urls

    Then:
        - validating that the request body is as expected
    """
    urls = ['www.test.com', 'www.test1.com']

    client = create_client()

    request_body = client.build_request_body(CLIENT_BODY, urls)

    assert request_body == {'client': {'clientId': 'Client ID', 'clientVersion': 'Client Version'},
                            'threatInfo': {'platformTypes': ['ANY_PLATFORM', 'WINDOWS', 'LINUX', 'ALL_PLATFORMS', 'OSX',
                                           'CHROME', 'IOS', 'ANDROID'],
                                           'threatEntries': [{'url': 'www.test.com'}, {'url': 'www.test1.com'}],
                                           'threatEntryTypes': ['URL'],
                                           'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING',
                                                           'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE']
                                           }
                            }


def test_arrange_results_to_urls():
    """
    Given:
        - response data to arrange

    When:
        - we arrange the response according to the urls

    Then:
        - validating that the results is as expected
    """
    from GoogleSafeBrowsingV2 import arrange_results_to_urls

    urls = ['www.test.com', 'www.test1.com']
    result = [{'threatType': 'MALWARE', 'platformType': 'ANY_PLATFORM', 'threat': {'url': 'www.test.com'},
               'cacheDuration': '300s', 'threatEntryType': 'URL'}]

    results_urls_data = arrange_results_to_urls(result, urls)

    assert results_urls_data == {'www.test.com': [{'cacheDuration': '300s', 'platformType': 'ANY_PLATFORM', 'threat':
                                                  {'url': 'www.test.com'}, 'threatEntryType': 'URL',
                                                   'threatType': 'MALWARE'}],
                                 'www.test1.com': []}


def test_handle_errors():
    """
    Given:
        - Handle errors function to return understandable error massage

    When:
        - the response contain error

    Then:
        - validating that the error massage is as expected
    """
    from GoogleSafeBrowsingV2 import handle_errors

    with pytest.raises(Exception) as e:
        handle_errors({'StatusCode': 250})
    assert str(e.value) == 'Failed to perform request, request status code: 250.'

    with pytest.raises(Exception) as e:
        handle_errors({'StatusCode': 204, 'Body': ''})
    assert str(e.value) == 'No content received. Possible API rate limit reached.'

    with pytest.raises(Exception) as e:
        handle_errors({'Body': ''})
    assert str(e.value) == 'No content received. Maybe you tried a private API?.'

    with pytest.raises(Exception) as e:
        handle_errors({'error': {'message': 'massage', 'code': 'code'}})
    assert str(e.value) == 'Failed accessing Google Safe Browsing APIs. Error: massage. Error code: code'


URL_RESPONSE = {
    'matches': [
        {'threatType': 'MALWARE', 'platformType': 'ANY_PLATFORM', 'threat': {'url': 'benign.com'}, 'cacheDuration':
            '300s', 'threatEntryType': 'URL'},
        {'threatType': 'MALWARE', 'platformType': 'WINDOWS', 'threat': {'url': 'malicious.com'},
         'cacheDuration': '300s', 'threatEntryType': 'URL'}]}

URL_CONTENTS = [
    {'cacheDuration': '300s',
     'platformType': 'ANY_PLATFORM',
     'threat': {'url': 'benign.com'},
     'threatEntryType': 'URL',
     'threatType': 'MALWARE'}
]


def test_command_url(mocker):
    """
    Given:
        - A url to check

    When:
        - Running the url_command and mocking a malicious response

    Then:
        - validating that the IOC score is as expected
        - validating the the Reliability is as expected
        - validating the the Contents is as expected
    """
    from GoogleSafeBrowsingV2 import url_command
    client = create_client(base_url="https://safebrowsing.googleapis.com/v4/threatMatches:find")
    mocker.patch.object(client, '_http_request', return_value=URL_RESPONSE)

    url_command = url_command(client, {'url': ['benign.com', 'malicious.com']})

    # validate score
    output = url_command[0].to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    assert output.get(dbot_key, [])[0].get('Score') == 3
    assert output.get(dbot_key, [])[0].get('Reliability') == DBotScoreReliability.B
    assert url_command[0].to_context().get('Contents') == URL_CONTENTS


def test_url_not_found(mocker):
    """
        Given:
        - A url to check with no results

    When:
        - Running the url_command and mocking no results

    Then:
        - validating that the IOC score is as expected
        - validating the the Reliability is as expected
        - validating the the Contents is as expected
    """
    from GoogleSafeBrowsingV2 import url_command
    client = create_client(base_url="https://safebrowsing.googleapis.com/v4/threatMatches:find")
    mocker.patch.object(client, '_http_request', return_value={})

    url_command = url_command(client, {'url': ['test.com']})
    # print(url_command.to_context())
    output = url_command.to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && ' \
               'val.Vendor == obj.Vendor && val.Type == obj.Type)'
    assert output.get(dbot_key, [])[0].get('Score') == 0
    assert output.get(dbot_key, [])[0].get('Reliability') == DBotScoreReliability.B
    assert url_command.readable_output == "No information was found for url ['test.com']"

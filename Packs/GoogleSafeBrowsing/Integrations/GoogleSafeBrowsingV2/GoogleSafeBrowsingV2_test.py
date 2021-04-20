import pytest


def test_build_request_body():
    from GoogleSafeBrowsingV2 import build_request_body

    client_body = {
        'clientId': 'Client ID',
        'clientVersion': 'Client Version'
    }
    urls = ['www.test.com', 'www.test1.com']

    request_body = build_request_body(client_body, urls)

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

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_module(client):
    result = client._http_request('GET', '/')
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def find_type_and_value(indicatordata):
    if len(indicatordata.get('sha256')) > 0:
        return 'File SHA-256', indicatordata.get('sha256')
    elif len(indicatordata.get('md5')) > 0:
        return 'File MD5', indicatordata.get('md5')
    elif len(indicatordata.get('sha1')) > 0:
        return 'File SHA-1', indicatordata.get('sha1')
    elif len(indicatordata.get('mail')) > 0:
        return 'Email', indicatordata.get('mail')
    elif len(indicatordata.get('ip')) > 0:
        return 'IP', indicatordata.get('ip')
    elif len(indicatordata.get('domain')) > 0:
        return 'Domain', indicatordata.get('domain')
    elif len(indicatordata.get('url')) > 0:
        return 'URL', indicatordata.get('url')
    else:
        return 'Error', ''


def get_indicators_command(client):
    listofindicators = []
    result = client._http_request('GET', '/')
    for item in result:
        typeofindicator, valueofindicator = find_type_and_value(item)
        for newitem in valueofindicator:
            data = {'type': typeofindicator,
                    'value': newitem,
                    'service': 'Twitter IOC Hunter',
                    'rawJSON': {'reference': item.get('reference'), 'tweet': item.get('tweet')},
                    'score': 3
                    }
        listofindicators.append(data)
    return listofindicators


def main():
    base_url = 'http://www.tweettioc.com/v1/tweets/daily/full'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-indicators':
            indicators = get_indicators_command(client)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif demisto.command() == 'twitteriochunter-get-indicators':
            return_results({'Indicators': get_indicators_command(client)})
    except Exception as e:
        raise Exception(f'Error in Integration [{e}]')


if __name__ in ('__main__', '__bui {SOURCE_NAME}ltin__', 'builtins'):
    main()

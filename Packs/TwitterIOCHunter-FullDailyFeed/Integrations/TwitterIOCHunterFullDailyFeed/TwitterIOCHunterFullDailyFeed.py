import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_module(client, url):
    result = client._http_request('GET', full_url=url)
    if isinstance(result, list):
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def find_type_and_value(indicatordata):
    if len(indicatordata.get('sha256')) > 0:
        return 'File', indicatordata.get('sha256')
    elif len(indicatordata.get('md5')) > 0:
        return 'File', indicatordata.get('md5')
    elif len(indicatordata.get('sha1')) > 0:
        return 'File', indicatordata.get('sha1')
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


def get_indicators_command(client, url, feed_tags=None, tlp_color=None):
    listofindicators = []
    result = client._http_request('GET', full_url=url)
    for item in result:
        typeofindicator, valueofindicator = find_type_and_value(item)
        for newitem in valueofindicator:
            data = {'type': typeofindicator,
                    'value': newitem,
                    'service': 'Twitter IOC Hunter',
                    'fields': {
                        'firstseenbysource': item.get('tweet').get('timestamp'),
                        'tags': feed_tags,
                        'reportedby': item.get('tweet').get('user')},
                    'rawJSON': item,
                    'score': 3
                    }
        if tlp_color:
            data['fields']['trafficlightprotocol'] = tlp_color
        listofindicators.append(data)
    return listofindicators


def main():
    type_of_feed = demisto.params().get('typeoffeed')
    base_url = 'http://www.tweettioc.com/v1/tweets/daily/full'
    user_url = 'http://www.tweettioc.com/v1/tweets/daily/full/user/'
    tags_url = 'http://www.tweettioc.com/v1/tweets/daily/ioc/hashtags/'
    feed_tags = demisto.params().get('feedTags')
    tlp_color = demisto.params().get('tlp_color')
    filter_to_use = demisto.params().get('filtertouse')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    demisto.info(f'Command being called is {demisto.command()}')
    if type_of_feed == 'Username':
        url = f'{user_url}{filter_to_use}'
    elif type_of_feed == 'Hashtag':
        url = f'{tags_url}{filter_to_use}'
    else:
        url = base_url
    try:
        client = BaseClient(
            base_url=url,
            verify=verify_certificate,
            proxy=proxy)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, url)
            demisto.results(result)
        elif demisto.command() == 'fetch-indicators':
            indicators = get_indicators_command(client, url, feed_tags, tlp_color)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif demisto.command() == 'twitteriochunter-get-indicators':
            return_results({'Indicators': get_indicators_command(client, url, feed_tags, tlp_color)})
    except Exception as e:
        raise Exception(f'Error in Integration [{e}]')


if __name__ in ('__main__', '__bui {SOURCE_NAME}ltin__', 'builtins'):
    main()

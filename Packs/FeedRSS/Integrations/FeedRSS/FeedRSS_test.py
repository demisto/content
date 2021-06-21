from unittest import mock

import pytest
from FeedRSS import *
from requests.models import Response

FEED_DATA = [({'bozo': False,
             'entries': [feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                          'link': 'https://test-article.com/',
                          'authors': [{'name': 'Example'}],
                          'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                          'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                          'id': 'https://kasperskycontenthub.com/threatpost-global/?p=167040',
                          'guidislink': False,
                          'summary': "this is summary"})]
               }, [{
        "type": 'Report',
        "value": "Test Article with comma",
        "rawJSON": {'value': {'authors': [{'name': 'Example'}],
                        'guidislink': False,
                        'id': 'https://kasperskycontenthub.com/threatpost-global/?p=167040',
                        'link': 'https://test-article.com/',
                        'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                        'summary': 'this is summary',
                        'tags': [{'label': None,
                                  'scheme': None,
                                  'term': 'Malware'}],
                        'title': 'Test Article, with comma'},
                    'type': 'Report', "firstseenbysource": '2021-06-18T15:35:41'},
        "fields": {
            'publications': [{
                'timestamp': 'Fri, 18 Jun 2021 15:35:41 +0000',
                'link': 'https://test-article.com/',
                'source': 'test.com',
                'title': 'Test Article, with comma'
            }],
            'description': 'test description',
            'tags': [],
        }}])]


# def test_get_url_content():


@pytest.mark.parametrize('parse_response,expected_output', FEED_DATA)
def test_parsed_indicators_from_response(mocker, parse_response, expected_output):

    feed_content_res = Response()
    type(feed_content_res).text = mocker.PropertyMock(return_value='text_to_parse')

    mocker.patch.object(Client, 'feed_content', return_value=feed_content_res)
    mocker.patch.object(Client, 'get_url_content', return_value='test description')
    mocker.patch.object(feedparser, 'parse', return_value=feedparser.util.FeedParserDict(parse_response))

    feedparser.util.FeedParserDict(parse_response)

    client = Client(server_url='test.com',
                    use_ssl=False,
                    proxy=False,
                    feed_tags=[],
                    tlp_color=None,
                    content_max_size=45)

    client.create_indicators_from_response()
    assert client.parsed_indicators == expected_output





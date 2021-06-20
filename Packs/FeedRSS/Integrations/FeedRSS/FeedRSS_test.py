import pytest
from FeedRSS import *
from requests.models import Response

FEED_DATA = ([{'title': 'Test Article, with comma',
             'title_detail': {'type': 'text/plain', 'language': None, 'base': '', 'value': 'Test Article, with comma'},
             'links': [{'rel': 'alternate', 'type': 'text/html', 'href': 'https://test-article.com/'}],
             'link': 'https://test-article.com/',
             'authors': [{'name': 'Name'}],
             'author': 'Name',
             'author_detail': {'name': 'Name'},
             'published': 'Thu, 17 Jun 2021 13:00:14 +0000',
             'id': 'https://kasperskycontenthub.com/threatpost-global/?p=166998',
             'guidislink': False,
             'summary': 'test summary.',
             'summary_detail': {'type': 'text/html', 'language': None, 'base': '', 'value': 'test summary.'},
             'wfw_commentrss': 'https://test.com/feed/',
             'slash_comments': '1'}])

# def test_get_url_content():


@pytest.mark.parametrize('feed_data', FEED_DATA)
def test_parsed_indicators_from_response(mocker, feed_data):
    # res = Response()
    # res.text = ''
    mocked_client = mocker.Mock()

    mocked_client._http_request.return_value = Response()
    mocked_client._http_request.return_value.text = ''
    # mocker.patch.object(Client, '_http_request', return_value=res)
    mocker.patch.object(feedparser, 'parse', feed_data)
    expected_output = [{
        "type": 'Report',
        "value": "Test Article with comma",
        "rawJSON": {'value': feed_data, 'type': 'Report', "firstseenbysource": '2021-06-17T13:00:14'},
        "fields": {
            'publications': [{
                'timestamp': 'Thu, 17 Jun 2021 13:00:14 +0000',
                'link': 'https://test-article.com/',
                'source': 'test.com',
                'title': 'Test Article, with comma'
            }],
            'description': 'the content of the article',
            'tags': [],
        }}]
    client = Client(server_url='test.com',
                    use_ssl=False,
                    proxy=False,
                    feed_tags=[],
                    tlp_color=None,
                    content_max_size=45)
    client.parsed_indicators == expected_output





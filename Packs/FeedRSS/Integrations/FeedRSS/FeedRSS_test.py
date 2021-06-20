import pytest
from FeedRSS import *
from requests.models import Response

FEED_DATA = ([{'title': 'Test Article, with comma',
             'title_detail': {'type': 'text/plain', 'language': None, 'base': '', 'value': 'Threat Actors Use Google Docs to Host Phishing Attacks'},
             'links': [{'rel': 'alternate', 'type': 'text/html', 'href': 'https://threatpost.com/google-docs-host-attack/166998/'}],
             'link': 'https://test-article.com/',
             'comments': 'https://threatpost.com/google-docs-host-attack/166998/#comments',
             'authors': [{'name': 'Elizabeth Montalbano'}],
             'author': 'Elizabeth Montalbano',
             'author_detail': {'name': 'Elizabeth Montalbano'},
             'published': 'Thu, 17 Jun 2021 13:00:14 +0000',
             'tags': [{'term': 'Hacks', 'scheme': None, 'label': None}, {'term': 'Web Security', 'scheme': None, 'label': None}, {'term': 'full', 'scheme': None, 'label': None}, {'term': 'large', 'scheme': None, 'label': None}, {'term': 'medium', 'scheme': None, 'label': None}, {'term': 'thumbnail', 'scheme': None, 'label': None}],
             'id': 'https://kasperskycontenthub.com/threatpost-global/?p=166998',
             'guidislink': False,
             'summary': 'Exploit in the widely used document service leveraged to send malicious links that appear legitimate but actually steal victims credentials.',
             'summary_detail': {'type': 'text/html', 'language': None, 'base': '', 'value': 'Exploit in the widely used document service leveraged to send malicious links that appear legitimate but actually steal victims credentials.'},
             'wfw_commentrss': 'https://threatpost.com/google-docs-host-attack/166998/feed/',
             'slash_comments': '1',
             'media_content': [{'url': 'https://media.threatpost.com/wp-content/uploads/sites/103/2021/06/17063701/Google_Docs.jpg', 'width': '800', 'height': '506'}, {'url': 'https://media.threatpost.com/wp-content/uploads/sites/103/2021/06/17063701/Google_Docs.jpg', 'width': '800', 'height': '506'}, {'url': 'https://media.threatpost.com/wp-content/uploads/sites/103/2021/06/17063701/Google_Docs-300x190.jpg', 'width': '300', 'height': '190'}, {'url': 'https://media.threatpost.com/wp-content/uploads/sites/103/2021/06/17063701/Google_Docs-150x150.jpg', 'width': '150', 'height': '150'}],
             'media_keywords': 'thumbnail'}])

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






from CommonServerPython import DemistoException
import pytest
from FeedRSS import *
from requests.models import Response
from test_data.test_variables import HTML_CONTENT, FEED_DATA, TEST_DATA_MAX_SIZE, FEED_DATA_NO_PUBLISH_FIELD


def side_effect_feed_url(mocker, client):
    feed_content_res = Response()
    type(feed_content_res).status_code = mocker.PropertyMock(return_value=200)
    type(feed_content_res).content = mocker.PropertyMock(return_value='text_to_parse')

    client.feed_response = feed_content_res


def mock_client(mocker, dict_to_parse: dict, content_max_size: int = 45, enrichment_excluded: bool = False) -> Client:
    """ Create a mock client"""

    client = Client(server_url='test.com',
                    use_ssl=False,
                    proxy=False,
                    reliability='F - Reliability cannot be judged',
                    feed_tags=[],
                    tlp_color=None,
                    content_max_size=content_max_size,
                    enrichment_excluded=enrichment_excluded)

    mocker.patch.object(feedparser, 'parse', return_value=feedparser.util.FeedParserDict(dict_to_parse))
    mocker.patch.object(Client, 'request_feed_url', side_effect=side_effect_feed_url(mocker=mocker, client=client))

    return client


@pytest.mark.parametrize('parse_response,expected_output', FEED_DATA)
def test_parsed_indicators_from_response(mocker, parse_response, expected_output):
    """
    Given:
    - RSS feed url

    When:
    - After parsing the feed content, we hold a list of items and create a Report indicator from each one of them

    Then:
    - Ensure all indicator fields extracted properly
    """

    client = mock_client(mocker, parse_response)

    mocker.patch.object(Client, 'get_url_content', return_value='test description')
    indicators = fetch_indicators(client)
    assert indicators == expected_output


def test_get_url_content(mocker):
    """
    Given:
    - Content of article in html format

    When:
    - when creating Report indicators from each item on the rss feed, we want to extract the article content.

    Then:
    - Ensure only the relevant html tags are extracted
    """

    client = mock_client(mocker=mocker, dict_to_parse={})
    article_content_res = Response()
    type(article_content_res).content = HTML_CONTENT
    mocker.patch.object(Client, '_http_request', return_value=article_content_res)
    assert client.get_url_content('test-link.com') == \
        "This is a dumped content of the article. Use the link under Publications field to read the full article. " \
        "\n\n p in div p li inside ul li inside ul Coffee Tea Milk Month Savings January $100 This is h1"


def test_get_url_content_invalid_link(mocker):
    """
    Given:
    - Invalid URL link to get the content from

    When:
    - when creating Report indicators from each item on the rss feed, we want to extract the article content.

    Then:
    - Ensure it returns an empty value
    """
    client = mock_client(mocker=mocker, dict_to_parse={})
    article_content_res = Response()
    article_content_res.status_code = 403
    mocker.patch.object(Client, '_http_request', side_effect=DemistoException(article_content_res))
    assert client.get_url_content('test-link.com') == ""


@pytest.mark.parametrize("article_content, expected_output", TEST_DATA_MAX_SIZE)
def test_content_max_size(mocker, article_content, expected_output):
    """Check if the content of an article exceed "content_max_size", if so we cut him as expected"""

    client = mock_client(mocker=mocker, dict_to_parse={}, content_max_size=1)
    article_content_res = Response()
    type(article_content_res).content = article_content
    mocker.patch.object(Client, '_http_request', return_value=article_content_res)
    assert client.get_url_content('test-link.com') == expected_output


@pytest.mark.parametrize('parse_response,expected_output', FEED_DATA_NO_PUBLISH_FIELD)
def test_parsed_indicators_from_response_no_publish_field(mocker, parse_response, expected_output):
    """
    Given:
    - RSS feed url with indicators without publish filed

    When:
    - After parsing the feed content, we hold a list of items and create a Report indicator from each one of them

    Then:
    - Ensure all indicator fields extracted properly
    """

    client = mock_client(mocker, parse_response)

    mocker.patch.object(Client, 'get_url_content', return_value='test description')
    indicators = fetch_indicators(client)
    assert indicators == expected_output


def test_parsed_indicators_from_response_with_links_field(mocker):
    """
    Given:
    - RSS feed url

    When:
    - After parsing the feed content, we hold a list of items and create a Report indicator from each one of them

    Then:
    - Ensure all the links extracted properly to the publications field
    """

    from unittest.mock import MagicMock
    example_link = MagicMock()
    example_link.href = "https://example.com"

    FEED_DATA[0][0]['entries'][0]['links'] = [example_link]

    client = mock_client(mocker, FEED_DATA[0][0])

    mocker.patch.object(Client, 'get_url_content', return_value='test description')
    indicators = fetch_indicators(client)

    expected_output = [{
        "timestamp": "2021-06-18T15:35:41",
        "link": "https://test-article.com/",
        "source": "test.com",
        "title": "Test Article, with comma"
    }, {
        "timestamp": "2021-06-18T15:35:41",
        "link": "https://example.com",
        "source": "test.com",
        "title": "Test Article, with comma"
    }]

    assert indicators[0]['fields']['publications'] == expected_output


def test_feed_main_enrichment_excluded(mocker):
    """
        Given: params with tlp_color set to RED and enrichmentExcluded set to False
        When: Calling feed_main
        Then: validate enrichment_excluded is set to True
    """
    from FeedRSS import main

    params = {
        'tlp_color': 'RED',
        'enrichmentExcluded': False,
        'server_url': 'test.test.com'
    }

    client_mocker = mocker.patch('FeedRSS.Client')

    mocker.patch('FeedRSS.is_xsiam_or_xsoar_saas', return_value=True)
    mocker.patch('FeedRSS.fetch_indicators', return_value=[])
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')

    # Call the function under test
    main()

    # Assertion - verify that enrichment_excluded is set to True
    assert client_mocker.call_args.kwargs.get('enrichment_excluded') is True

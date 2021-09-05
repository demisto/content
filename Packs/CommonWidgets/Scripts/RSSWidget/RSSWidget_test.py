import pytest
from test_data.test_variables import NO_ARTICLE, NO_ARTICLE_RES, ONE_ARTICLE, ONE_ARTICLE_RES, ONE_ARTICLE_STRING, \
    TWO_ARTICLES, TWO_ARTICLES_RES, TWO_ARTICLES_STRING,\
    ONE_ARTICLE_NOT_PUBLISHED, ONE_ARTICLE_NOT_PUBLISHED_RES, TWO_ARTICLES_STRING_REVERSED
from RSSWidget import collect_entries_data_from_response, create_widget_content, main
import demistomock as demisto


@pytest.mark.parametrize('parsed_response, expected_result', [
    (NO_ARTICLE, NO_ARTICLE_RES),
    (ONE_ARTICLE, ONE_ARTICLE_RES),
    (TWO_ARTICLES, TWO_ARTICLES_RES),
    (ONE_ARTICLE_NOT_PUBLISHED, ONE_ARTICLE_NOT_PUBLISHED_RES)
])
def test_no_entries_collect_entries_data_from_response(parsed_response, expected_result):
    """
    Given: Parsed response from feed.

    When: Collecting relevant data from entries.

    Then: Verify the collected data.
    """
    result = collect_entries_data_from_response(parsed_response)

    assert len(result) == len(expected_result)
    for entry in expected_result:
        assert entry in result


@pytest.mark.parametrize('data, text_output', [
    (NO_ARTICLE_RES, '## No entries were found.'),
    (ONE_ARTICLE_RES, ONE_ARTICLE_STRING),
    (TWO_ARTICLES_RES, TWO_ARTICLES_STRING)
])
def test_create_widget_content(data, text_output):
    """
    Given: Data about entries to show.

    When: Creating the markdown output for the widget.

    Then: Verify the markdown string.
    """
    res = create_widget_content(data)

    assert res == text_output


def test_full_flow(mocker, requests_mock):
    import RSSWidget as rssw
    requests_mock.get('https://test.com')
    mocker.patch.object(rssw, 'parse_feed_data', return_value=TWO_ARTICLES)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://test.com'})

    main()

    res = demisto.results.call_args[0][0]
    assert res['ContentsFormat'] == 'markdown'
    assert res['Contents'] == TWO_ARTICLES_STRING_REVERSED

import sys
import pytest
from test_data.test_variables import NO_ARTICLE, NO_ARTICLE_RES, ONE_ARTICLE, ONE_ARTICLE_RES, ONE_ARTICLE_STRING, \
    ONE_ARTICLE_STRING_FORMATTED, TWO_ARTICLES, TWO_ARTICLES_RES, TWO_ARTICLES_STRING,\
    ONE_ARTICLE_NOT_PUBLISHED, ONE_ARTICLE_NOT_PUBLISHED_RES, ONE_ARTICLE_HTML, ONE_ARTICLE_HTML_RES
from RSSWidget import collect_entries_data_from_response, create_widget_content, main
import demistomock as demisto


@pytest.mark.parametrize('parsed_response, limit, expected_result', [
    (NO_ARTICLE, sys.maxsize, NO_ARTICLE_RES),
    (ONE_ARTICLE_HTML, True, ONE_ARTICLE_HTML_RES),
    (ONE_ARTICLE, sys.maxsize, ONE_ARTICLE_RES),
    (TWO_ARTICLES, sys.maxsize, TWO_ARTICLES_RES),
    (ONE_ARTICLE_NOT_PUBLISHED, sys.maxsize, ONE_ARTICLE_NOT_PUBLISHED_RES),
    (TWO_ARTICLES, 1, ONE_ARTICLE_RES),
])
def test_collect_entries_data_from_response(parsed_response, limit, expected_result):
    """
    Given: Parsed response from feed.

    When: Collecting relevant data from entries.

    Then: Verify the collected data.
    """
    result = collect_entries_data_from_response(parsed_response, limit=limit)

    assert len(result) == len(expected_result)
    for entry in expected_result:
        assert entry in result


@pytest.mark.parametrize('data, is_version_ge_65, text_output', [
    (NO_ARTICLE_RES, False, '## No entries were found.'),
    (ONE_ARTICLE_RES, False, ONE_ARTICLE_STRING),
    (ONE_ARTICLE_RES, True, ONE_ARTICLE_STRING_FORMATTED),
    (TWO_ARTICLES_RES, False, TWO_ARTICLES_STRING)
])
def test_create_widget_content(mocker, data, is_version_ge_65, text_output):
    """
    Given: Data about entries to show.

    When: Creating the markdown output for the widget.

    Then: Verify the markdown string.
    """
    import RSSWidget as rssw
    mocker.patch.object(rssw, 'is_demisto_version_ge', return_value=is_version_ge_65)

    res = create_widget_content(data)

    assert res == text_output


@pytest.mark.parametrize('limit, exepcted_result', [
    ('', TWO_ARTICLES_STRING),
    ('1', ONE_ARTICLE_STRING),
]
)
def test_full_flow(mocker, requests_mock, limit, exepcted_result):
    import RSSWidget as rssw
    requests_mock.get('https://test.com')
    mocker.patch.object(rssw, 'parse_feed_data', return_value=TWO_ARTICLES)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://test.com', 'limit': limit})

    main()

    res = demisto.results.call_args[0][0]
    assert res['ContentsFormat'] == 'markdown'
    assert res['Contents'] == exepcted_result

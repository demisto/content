import pytest
from test_data.test_variables import NO_ARTICLE, NO_ARTICLE_RES, ONE_ARTICLE, ONE_ARTICLE_RES, ONE_ARTICLE_STRING, \
    TWO_ARTICLES, TWO_ARTICLES_RES, TWO_ARTICLES_STRING,\
    ONE_ARTICLE_NOT_PUBLISHED, ONE_ARTICLE_NOT_PUBLISHED_RES
from RSSWidget import collect_entries_data_from_response, create_widget_content


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
    (NO_ARTICLE_RES, ''),
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

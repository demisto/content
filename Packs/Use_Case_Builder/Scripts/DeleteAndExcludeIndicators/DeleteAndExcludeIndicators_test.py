import pytest
from DeleteAndExcludeIndicators import build_search_query, is_unscoped_query

MENLO_URL_WITH_BARE_WILDCARD = "https://isolate.menlosecurity.com/9/11/https://test.com/a?x=1,y=2&p=,*"


class TestValuesAreTreatedAsLiterals:
    def test_wraps_a_single_value_in_double_quotes(self):
        assert build_search_query("example.com") == 'value:("example.com")'

    def test_splits_a_comma_separated_list_into_quoted_terms(self):
        assert build_search_query("a.com,b.com") == 'value:("a.com" "b.com")'

    def test_ignores_surrounding_whitespace_between_entries(self):
        assert build_search_query(" a.com , b.com ") == 'value:("a.com" "b.com")'

    def test_escapes_double_quotes_embedded_in_a_value(self):
        assert build_search_query('https://x.com/a?q="test"') == r'value:("https://x.com/a?q=\"test\"")'

    def test_accepts_a_list_of_values(self):
        assert build_search_query(["a.com", "b.com"]) == 'value:("a.com" "b.com")'


class TestWildcardsCannotEscapeIntoQuerySyntax:
    def test_neutralises_a_value_that_is_only_a_wildcard(self):
        query = build_search_query("*")

        assert query == 'value:("*")'
        assert not is_unscoped_query(query)

    def test_neutralises_the_url_that_purged_the_production_tenant(self):
        # Splitting on the comma used to leave a bare
        # '*' term, which matched -- and deleted -- every indicator.
        query = build_search_query(MENLO_URL_WITH_BARE_WILDCARD)

        assert query == 'value:("https://isolate.menlosecurity.com/9/11/https://test.com/a?x=1" "y=2&p=" "*")'
        assert " * " not in query, "a standalone '*' term makes the query match every indicator"
        assert not is_unscoped_query(query)

    def test_does_not_turn_commas_into_or_operators(self):
        query = build_search_query("a.com,b.com")

        assert " or " not in query


class TestUnscopedQueryDetection:
    @pytest.mark.parametrize(
        "query",
        ["*", "  *  ", "*:*", "value:*", "value:(*)"],
        ids=["bare", "padded", "all-fields", "unparenthesised", "parenthesised"],
    )
    def test_flags_queries_that_match_every_indicator(self, query):
        assert is_unscoped_query(query)

    @pytest.mark.parametrize(
        "query",
        ['value:("example.com")', 'value:("*")', 'value:("a.com" "*")'],
        ids=["literal", "quoted-wildcard", "quoted-wildcard-among-values"],
    )
    def test_allows_queries_that_are_properly_scoped(self, query):
        assert not is_unscoped_query(query)

    @pytest.mark.parametrize("query", ["", "   "], ids=["empty", "whitespace"])
    def test_flags_an_empty_query(self, query):
        assert is_unscoped_query(query)


class TestInputValidation:
    @pytest.mark.parametrize("value", ["", "   ", None, [], ","], ids=["empty", "whitespace", "none", "list", "comma"])
    def test_rejects_input_that_names_no_indicator(self, value):
        with pytest.raises(ValueError, match="No indicator values"):
            build_search_query(value)

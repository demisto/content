import pytest
from DeleteIndicators import build_search_query, is_unscoped_query

# An isolated URL embeds the whole original URL, query string included, so
# it readily carries commas and wildcard characters. This is the shape of value
# that triggered the production incident.
URL_WITH_BARE_WILDCARD = "https://isolate.security.com/9/11/https://test.com/a?x=1,y=2&p=,*"


class TestValuesAreTreatedAsLiterals:
    """Every supplied value must reach the query as quoted literal text."""

    def test_wraps_a_single_value_in_double_quotes(self):
        query = build_search_query(indicator_values=["example.com"])

        assert query == 'value:("example.com")'

    def test_keeps_a_value_containing_a_comma_as_one_term(self):
        # argToList splits on commas, so a value carrying its own comma used to
        # be torn into several independent search terms.
        query = build_search_query(indicator_values=["https://x.com/q?tags=a,b"])

        assert query == 'value:("https://x.com/q?tags=a,b")'

    def test_escapes_double_quotes_embedded_in_a_value(self):
        # URLs scraped out of HTML email bodies (href="...") carry stray quotes,
        # which previously broke out of the quoted term.
        query = build_search_query(indicator_values=['https://x.com/a?q="test"'])

        assert query == r'value:("https://x.com/a?q=\"test\"")'

    def test_quotes_every_value_when_several_are_supplied(self):
        query = build_search_query(indicator_values=["a.com", "b.com"])

        assert query == 'value:("a.com" "b.com")'


class TestWildcardsCannotEscapeIntoQuerySyntax:
    """A ``*`` inside a value is data, never the match-all operator."""

    def test_neutralises_a_value_that_is_only_a_wildcard(self):
        query = build_search_query(indicator_values=["*"])

        assert query == 'value:("*")'
        assert not is_unscoped_query(query)

    def test_neutralises_the_url_that_purged_the_production_tenant(self):
        # This exact input deleted every indicator.
        query = build_search_query(indicator_values=[URL_WITH_BARE_WILDCARD])

        assert query == f'value:("{URL_WITH_BARE_WILDCARD}")'
        assert " * " not in query, "a standalone '*' term makes the query match every indicator"
        assert not is_unscoped_query(query)

    def test_keeps_a_trailing_wildcard_value_scoped(self):
        query = build_search_query(indicator_values=["foo.com", "*"])

        assert query == 'value:("foo.com" "*")'
        assert not is_unscoped_query(query)


class TestIdsAreTreatedAsLiterals:
    def test_wraps_each_id_in_double_quotes(self):
        query = build_search_query(indicator_ids=["123", "456"])

        assert query == 'id:("123" "456")'


class TestRawQueriesArePassedThrough:
    """``indicator_query`` is a deliberate query, so it is not quoted."""

    def test_forwards_a_caller_supplied_query_unchanged(self):
        query = build_search_query(indicator_query="type:URL and expirationStatus:expired")

        assert query == "type:URL and expirationStatus:expired"


class TestUnscopedQueryDetection:
    """The guard that stops a delete from matching the whole indicator store."""

    @pytest.mark.parametrize(
        "query",
        [
            "*",
            "  *  ",
            "*:*",
            "value:*",
            "value:(*)",
            "id:(*)",
        ],
        ids=["bare", "padded", "all-fields", "unparenthesised", "parenthesised", "id-field"],
    )
    def test_flags_queries_that_match_every_indicator(self, query):
        assert is_unscoped_query(query)

    @pytest.mark.parametrize(
        "query",
        [
            'value:("example.com")',
            'value:("*")',
            'value:("a.com" "*")',
            "type:URL and expirationStatus:expired",
        ],
        ids=["literal", "quoted-wildcard", "quoted-wildcard-among-values", "scoped-expression"],
    )
    def test_allows_queries_that_are_properly_scoped(self, query):
        assert not is_unscoped_query(query)

    @pytest.mark.parametrize("query", ["", "   "], ids=["empty", "whitespace"])
    def test_flags_an_empty_query(self, query):
        # An empty query must never reach deleteIndicators.
        assert is_unscoped_query(query)


class TestBuildSearchQueryInputValidation:
    def test_rejects_being_given_no_input_at_all(self):
        with pytest.raises(ValueError, match="Exactly ONE"):
            build_search_query()

    def test_rejects_being_given_more_than_one_input(self):
        with pytest.raises(ValueError, match="Exactly ONE"):
            build_search_query(indicator_query="type:URL", indicator_values=["a.com"])

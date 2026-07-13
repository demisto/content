import pytest

from CommonServerPython import *
from FeedDomainTools import (
    DomainToolsClient,
    fetch_indicators,
    fetch_indicators_command,
    get_indicators_command,
    get_dbot_score,
    main,
)


from test_data import feed_mock_response


@pytest.fixture()
def dt_feeds_client():
    return DomainToolsClient(api_username="test", api_key="test", verify_ssl=False)


class TestDTClient:
    def test_nod_build_iterator(self, mocker, dt_feeds_client):
        """
        Given:
            - Output of the NOD feed API
        When:
            - When calling fetch_indicators or get_indicators
        Then:
            - Returns a iterator of the indicators parsed from the API's response

        """
        mocker.patch.object(
            dt_feeds_client,
            "_get_dt_feeds",
            return_value=feed_mock_response.NOD_FEED_RESPONSE,
        )
        indicators = list(dt_feeds_client.build_iterator(feed_type="nod"))
        domains = [indicator.get("value") for indicator in indicators]

        assert "solarwinds.com.kz" in domains
        assert len(indicators) == 10

    def test_nad_build_iterator(self, mocker, dt_feeds_client):
        """
        Given:
            - Output of the NAD feed API
        When:
            - When calling fetch_indicators or get_indicators
        Then:
            - Returns a iterator of the indicators parsed from the API's response

        """
        mocker.patch.object(
            dt_feeds_client,
            "_get_dt_feeds",
            return_value=feed_mock_response.NAD_FEED_RESPONSE,
        )
        indicators = list(dt_feeds_client.build_iterator(feed_type="nad"))
        domains = [indicator.get("value") for indicator in indicators]

        assert "image163.blogspot.sn" in domains
        assert len(indicators) == 10

    def test_build_iterator_with_limit(self, mocker, dt_feeds_client):
        """
        Given:
            - Output of the NOD feed API with limit
        When:
            - When calling fetch_indicators or get_indicators
        Then:
            - Returns a iterator of the indicators parsed from the API's response with limit param given

        """
        mocker.patch.object(
            dt_feeds_client,
            "_get_dt_feeds",
            return_value=feed_mock_response.NOD_FEED_RESPONSE,
        )

        indicators = list(dt_feeds_client.build_iterator(feed_type="nod", dt_feed_kwargs={"top": 5}))
        [indicator.get("value") for indicator in indicators]

        assert len(indicators) == 5


def test_conversion_feed_to_indicato_obj(mocker, dt_feeds_client):
    """
    Given:
        - Output of the feeds and convert to an indicator object
    When:
        - Fetching indicators from the API and calling the build_iterator
    Then:
        - Create list of indicator objects
    """
    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=feed_mock_response.NOD_FEED_RESPONSE,
    )

    mock_dt_feeds_kwargs = {
        "session_id": "test-session-1",
        "before": "-60",
    }

    indicators = fetch_indicators(dt_feeds_client, feed_type="nod", dt_feed_kwargs=mock_dt_feeds_kwargs)

    assert len(indicators) == 10
    assert indicators == feed_mock_response.NOD_PARSED_INDICATOR_RESPONSE


@pytest.mark.parametrize(
    "overall_riskscore,expected_dbot_score",
    [
        (99, 3),
        (63, 2),
        (21, 1),
        (0, 1),
        (None, 0),
    ],
)
def test_get_dbot_score(overall_riskscore, expected_dbot_score):
    """
    Given:
        - Output of the feed API as list Overall risk score of a domain
    When:
        - Getting a feed of indicators from the `domainrisk, domainhotlist` API endpoint
    Then:
        - Returns the DbotScore
    """
    actual_dbot_score = get_dbot_score(overall_riskscore)
    assert actual_dbot_score == expected_dbot_score


@pytest.mark.parametrize(
    "feed_type",
    ["nod", "nad", "noh", "domaindiscovery", "domainrdap", "domainrisk", "domainhotlist"],
)
def test_get_indicators_command(mocker, dt_feeds_client, feed_type):
    """
    Given:
        - Output of the feed API as list
    When:
        - Getting a limited number of indicators from the API
    Then:
        - Return results as war-room entry

    """

    mock_feed_response = {
        "nod": feed_mock_response.NOD_FEED_RESPONSE,
        "nad": feed_mock_response.NAD_FEED_RESPONSE,
        "noh": feed_mock_response.NOH_FEED_RESPONSE,
        "domaindiscovery": feed_mock_response.DOMAINDISCOVERY_RESPONSE,
        "domainrdap": feed_mock_response.DOMAINRDAP_RESPONSE,
        "domainrisk": feed_mock_response.DOMAINRISK_RESPONSE,
        "domainhotlist": feed_mock_response.DOMAINHOTLIST_RESPONSE,
    }

    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=mock_feed_response[feed_type],
    )
    results = get_indicators_command(dt_feeds_client, args={"feed_type": feed_type, "top": "10"}, params={})

    expected_indicator_results = {
        "nod": feed_mock_response.NOD_PARSED_INDICATOR_RESPONSE,
        "nad": feed_mock_response.NAD_PARSED_INDICATOR_RESPONSE,
        "noh": feed_mock_response.NOH_PARSED_INDICATOR_RESPONSE,
        "domaindiscovery": feed_mock_response.DOMAINDISCOVERY_PARSED_INDICATOR_RESPONSE,
        "domainrdap": feed_mock_response.DOMAINRDAP_PARSED_INDICATOR_RESPONSE,
        "domainrisk": feed_mock_response.DOMAINRISK_PARSED_INDICATOR_RESPONSE,
        "domainhotlist": feed_mock_response.DOMAINHOTLIST_PARSED_INDICATOR_RESPONSE,
    }

    human_readable = tableToMarkdown(
        f"Indicators from DomainTools {feed_type.upper()} Feed:",
        expected_indicator_results[feed_type],
        headers=["value", "type", "fields", "rawJSON"],
        removeNull=True,
    )

    assert results.readable_output == human_readable


def test_fetch_indicators_command(mocker, dt_feeds_client):
    """
    Given:
        - Output of the feed API calling the fetch indicator command
    When:
        - Fetching indicators from the API
    Then:
        - Create indicator objects list

    """

    mock_return_value = (
        feed_mock_response.NAD_FEED_RESPONSE + feed_mock_response.NOD_FEED_RESPONSE + feed_mock_response.DOMAINDISCOVERY_RESPONSE
    )
    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=mock_return_value,
    )
    results = fetch_indicators_command(dt_feeds_client, params={"top": "2"})

    assert len(results) == 14


def test_calling_command_using_main(mocker, dt_feeds_client):
    """
    Given:
        - A command
    When:
        - test-module is called
    Then:
        - should have the "ok" result
    """

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={"credentials": {"identifier": "test_username", "password": "test_key"}},
    )
    mocker.patch(
        "FeedDomainTools.DomainToolsClient._get_dt_feeds",
        return_value=feed_mock_response.NAD_FEED_RESPONSE,
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0] == "ok"


class TestGetDtFeeds:
    def test_dispatches_correct_api_method(self, mocker, dt_feeds_client):
        """_get_dt_feeds calls the correct domaintools API method via FEED_METHOD_MAP."""
        mock_response = mocker.MagicMock()
        mock_response.response.return_value = iter([])
        mock_method = mocker.MagicMock(return_value=mock_response)
        mocker.patch.object(dt_feeds_client._api, "realtime_domain_risk", mock_method, create=True)

        dt_feeds_client._get_dt_feeds(feed_type="domainrisk", top=10)

        mock_method.assert_called_once_with(top=10)

    def test_filters_none_kwargs(self, mocker, dt_feeds_client):
        """None values are not passed as kwargs to the API method."""
        mock_response = mocker.MagicMock()
        mock_response.response.return_value = iter([])
        mock_method = mocker.MagicMock(return_value=mock_response)
        mocker.patch.object(dt_feeds_client._api, "nod", mock_method, create=True)

        dt_feeds_client._get_dt_feeds(feed_type="nod", session_id="s1", domain=None, top=5)

        call_kwargs = mock_method.call_args.kwargs
        assert "domain" not in call_kwargs
        assert call_kwargs == {"sessionID": "s1", "top": 5}

    def test_returns_list_of_lines(self, mocker, dt_feeds_client):
        """Returns list of NDJSON lines from FeedsResults.response()."""
        lines = ['{"domain":"example.com"}', '{"domain":"test.com"}']
        mock_response = mocker.MagicMock()
        mock_response.response.return_value = iter(lines)
        mocker.patch.object(dt_feeds_client._api, "nod", return_value=mock_response, create=True)

        result = dt_feeds_client._get_dt_feeds(feed_type="nod")

        assert result == lines


def test_missing_credentials():
    """DomainToolsClient raises DemistoException when credentials are empty."""
    with pytest.raises(DemistoException):
        DomainToolsClient(api_username="", api_key="")


def test_format_parameter_prepends_dash(dt_feeds_client):
    """_format_parameter prepends '-' to after/before values that lack it."""
    assert dt_feeds_client._format_parameter("after", "60") == "-60"
    assert dt_feeds_client._format_parameter("after", "-60") == "-60"
    assert dt_feeds_client._format_parameter("before", "120") == "-120"


def test_test_module_all_feed_type_falls_back_to_nod(mocker, dt_feeds_client):
    """test_module falls back to 'nod' when feed_type param is 'ALL'."""
    from FeedDomainTools import test_module

    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=feed_mock_response.NOD_FEED_RESPONSE,
    )
    result = test_module(dt_feeds_client, args={}, params={"feed_type": "ALL"})
    assert result == "ok"

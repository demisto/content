import pytest

from CommonServerPython import *
from FeedDomainTools import (
    DomainToolsClient,
    fetch_indicators,
    fetch_indicators_command,
    get_indicators_command,
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

    indicators = fetch_indicators(
        dt_feeds_client, feed_type="nod", dt_feed_kwargs=mock_dt_feeds_kwargs
    )

    assert len(indicators) == 10
    assert indicators == feed_mock_response.NOD_PARSED_INDICATOR_RESPONSE


@pytest.mark.parametrize(
    "feed_type",
    [
        "nod",
        "nad",
    ],
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
    }

    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=mock_feed_response[feed_type],
    )
    results = get_indicators_command(
        dt_feeds_client, args={"feed_type": feed_type, "top": "10"}, params={}
    )

    expected_indicator_results = {
        "nod": feed_mock_response.NOD_PARSED_INDICATOR_RESPONSE,
        "nad": feed_mock_response.NAD_PARSED_INDICATOR_RESPONSE,
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
    mocker.patch.object(
        dt_feeds_client,
        "_get_dt_feeds",
        return_value=feed_mock_response.NAD_FEED_RESPONSE
        + feed_mock_response.NOD_FEED_RESPONSE,
    )
    results = fetch_indicators_command(dt_feeds_client, params={"top": "20"})

    assert len(results) == 40


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

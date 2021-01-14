import json
import pytest
from FeedTAXII2 import *

with open('test_data/results.json', 'r') as f:
    RESULTS_JSON = json.load(f)
with open('test_data/cortex_indicators_1.json', 'r') as f:
    CORTEX_IOCS_1 = json.load(f)
with open('test_data/cortex_indicators_1.json', 'r') as f:
    CORTEX_IOCS_2 = json.load(f)


class MockCollection:
    def __init__(self, id_, title):
        self.id = id_
        self.title = title


class TestFetchIndicators:
    """
    Scenario: Test fetch_indicators_command
    """
    def test_single_no_context(self, mocker):
        """
        Scenario: Test single collection fetch with no last run

        Given:
        - collection to fetch is available and set to 'default'
        - there is no integration context
        - limit is -1
        - initial interval is `1 day`

        When:
        - fetch_indicators_command is called

        Then:
        - update last run with latest collection fetch time
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False)
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        mocker.patch.object(mock_client, 'build_iterator', return_value=RESULTS_JSON)
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, {})
        assert indicators == RESULTS_JSON
        assert mock_client.collection_to_fetch.id in last_run

    def test_single_with_context(self, mocker):
        """
        Scenario: Test single collection fetch with no last run context

        Given:
        - collection to fetch is available and set to 'default'
        - there is an integration context, with 2 collections
        - limit is -1
        - initial interval is `1 day`

        When:
        - fetch_indicators_command is called

        Then:
        - update last run with latest collection fetch time
        - don't update collection that wasn't fetched from
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False)
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        last_run = {mock_client.collections[1]: 'test'}
        mocker.patch.object(mock_client, 'build_iterator', return_value=RESULTS_JSON)
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, last_run)
        assert indicators == RESULTS_JSON
        assert mock_client.collection_to_fetch.id in last_run
        assert last_run.get(mock_client.collections[1]) == 'test'

    def test_multi_no_context(self, mocker):
        """
        Scenario: Test multi collection fetch with no last run

        Given:
        - collection to fetch is set to None
        - there is no integration context
        - limit is -1
        - initial interval is `1 day`

        When:
        - fetch_indicators_command is called

        Then:
        - fetch 14 indicators
        - update last run with latest collection fetch time
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, {})
        assert len(indicators) == 14
        assert mock_client.collection_to_fetch.id in last_run

    def test_multi_with_context(self, mocker):
        """
        Scenario: Test multi collection fetch with no last run

        Given:
        - collection to fetch is set to None
        - there is no integration context
        - limit is len(CORTEX_IOCS_1)
        - initial interval is `1 day`

        When:
        - fetch_indicators_command is called

        Then:
        - fetch 7 indicators
        - update last run with latest collection fetch time
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
        id_1 = 1
        id_2 = 2
        mock_client.collections = [MockCollection(id_1, 'a'), MockCollection(id_2, 'b')]

        last_run = {mock_client.collections[1]: 'test'}
        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', len(CORTEX_IOCS_1), last_run)
        assert len(indicators) == len(CORTEX_IOCS_1)
        assert last_run.get(mock_client.collections[1]) == 'test'


class TestHelperFunctions:
    def test_try_parse_integer(self):
        assert try_parse_integer(None, '') is None
        assert try_parse_integer('8', '') == 8
        assert try_parse_integer(8, '') == 8
        with pytest.raises(DemistoException, match='parse failure'):
            try_parse_integer('a', 'parse failure')

    class TestGetAddedAfter:
        """Scenario: Test get_added_after"""

        def test_get_last_fetch_time(self):
            """
            Scenario: Incremental feed and last fetch is set

            Given:
            - fetch_full_feed is false
            - last fetch time is set

            When:
            - calling get_added_after

            Then:
            - return last fetch time
            """
            fetch_full_feed = False
            last_fetch_time = 'last_fetch_mock'
            initial_interval = 'initial_mock'

            assert get_added_after(fetch_full_feed, initial_interval, last_fetch_time) == last_fetch_time

        def test_get_initial_interval__fetch_full_feed_true(self):
            """
            Scenario: Full feed and last fetch is set

            Given:
            - fetch_full_feed is true
            - initial interval is set
            - last fetch time is set

            When:
            - calling get_added_after

            Then:
            - return initial interval
            """
            fetch_full_feed = True
            last_fetch_time = 'last_fetch_mock'
            initial_interval = 'initial_mock'

            assert get_added_after(fetch_full_feed, initial_interval, last_fetch_time) == initial_interval

        def test_get_initial_interval__fetch_full_feed_false(self):
            """
            Scenario: Incremental feed and last fetch is not set

            Given:
            - fetch_full_feed is true
            - initial interval is set
            - last fetch time is not set

            When:
            - calling get_added_after

            Then:
            - return initial interval
            """
            fetch_full_feed = False
            last_fetch_time = None
            initial_interval = 'initial_mock'

            assert get_added_after(fetch_full_feed, initial_interval, last_fetch_time) == initial_interval

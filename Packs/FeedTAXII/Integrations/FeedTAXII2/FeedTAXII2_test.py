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

    def test_get_last_run_in_6_2_when_get_last_run_has_results(self, mocker):
        """
        Given: 6.2.0 environment
        When: Fetch indicators when getLastRun returns results
        Then: Returning all indicators from demisto.getLastRun object
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getLastRun', return_value={1: "first indicator"})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}

    def test_get_last_run_in_6_1_when_get_integration_context_has_results(self, mocker):
        """
        Given: 6.1.0 environment
        When: Fetch indicators when getIntegrationContext return results:
                This can happen when updating XSOAR version to 6.2.0 while a feed instance is already set.
        Then: Returning all indicators from demisto.getIntegrationContext object
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.1.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={1: "first indicator"})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}

    def test_get_last_run_in_6_2_when_get_last_run_has_no_results(self, mocker):
        """
        Given: 6.2.0 environment
        When: Fetch indicators when getLastRun and getIntegrationContext are empty
        Then: {}
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        result = get_feed_last_run()
        assert result == {}

    def test_get_last_run_in_6_2_when_get_last_is_empty_and_get_integration_is_not(self, mocker):
        """
        Given: 6.2.0 environment
        When: Fetch indicators when getLastRun is empty and getIntegrationContext has results.
        Then: {}
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={1: "first indicator"})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}
        assert set_last_run.call_args.args[0] == {1: "first indicator"}
        assert set_integration_context.call_args.args[0] == {}

    def test_set_last_run_in_6_2(self, mocker):
        """
        Given: 6.2.0 environment
        When: Fetch indicators
        Then: Using demisto.setLastRun to save results
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        set_feed_last_run({1: "first indicator"})
        assert set_last_run.call_args.args[0] == {1: "first indicator"}
        assert set_integration_context.called is False

    def test_set_last_run_in_6_1(self, mocker):
        """
        Given: 6.1.0 environment
        When: Fetch indicators
        Then: Using demisto.setIntegrationContext to save results
        """
        import demistomock as demisto
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.1.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        set_feed_last_run({1: "first indicator"})
        assert set_integration_context.call_args.args[0] == {1: "first indicator"}
        assert set_last_run.called is False


class TestHelperFunctions:
    def test_try_parse_integer(self):
        assert try_parse_integer(None, '') is None
        assert try_parse_integer('8', '') == 8
        assert try_parse_integer(8, '') == 8
        with pytest.raises(DemistoException, match='parse failure'):
            try_parse_integer('a', 'parse failure')

    class TestAssertIncrementalFeedParams:
        """Scenario: Test assert_incremental_feed_params raises appropriate errors"""

        def test_both_params_are_false(self):
            """
            Scenario: Both params are False

            Given:
            - fetch_full_feed is false
            - feedIncremental is false

            When:
            - calling assert_incremental_feed_params

            Then:
            - raise appropriate error
            """
            fetch_full_feed = is_incremental_feed = False
            with pytest.raises(DemistoException) as e:
                assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)
                assert "'Full Feed Fetch' cannot be disabled when 'Incremental Feed' is disabled." in str(e)

        def test_both_params_are_true(self):
            """
            Scenario: Both params are True

            Given:
            - fetch_full_feed is true
            - feedIncremental is true

            When:
            - calling assert_incremental_feed_params

            Then:
            - raise appropriate error
            """
            fetch_full_feed = is_incremental_feed = True
            with pytest.raises(DemistoException) as e:
                assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)
                assert "'Full Feed Fetch' cannot be enabled when 'Incremental Feed' is enabled." in str(e)

        def test_params_have_different_values(self):
            """
            Scenario: Both params are False

            Given:
            - fetch_full_feed is false / true
            - feedIncremental is true / false

            When:
            - calling assert_incremental_feed_params

            Then:
            - don't raise any error
            """
            fetch_full_feed = False
            is_incremental_feed = True
            assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)

            fetch_full_feed = True
            is_incremental_feed = False
            assert_incremental_feed_params(fetch_full_feed, is_incremental_feed)

    class TestGetAddedAfter:
        """Scenario: Test get_added_after"""

        def test_get_last_fetch_time(self):
            """
            Scenario: fetch_full_feed and last fetch is set

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

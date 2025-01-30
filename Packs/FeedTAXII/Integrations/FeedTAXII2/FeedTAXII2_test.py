import json

import pytest
from FeedTAXII2 import *

with open('test_data/results.json') as f:
    RESULTS_JSON = json.load(f)
with open('test_data/cortex_indicators_1.json') as f:
    CORTEX_IOCS_1 = json.load(f)
with open('test_data/cortex_indicators_1.json') as f:
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        result = RESULTS_JSON.get("Contents")
        mocker.patch.object(mock_client, 'build_iterator', return_value=result)
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, {})
        assert indicators == result
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        last_run = {mock_client.collections[1]: 'test'}
        result = RESULTS_JSON.get("Contents")
        mocker.patch.object(mock_client, 'build_iterator', return_value=result)
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, last_run)
        assert indicators == result
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', -1, {})
        assert len(indicators) == 14
        assert mock_client.collection_to_fetch.id in last_run

    @pytest.mark.parametrize('empty_collection_type', [None, ""])
    def test_multi_with_context(self, mocker, empty_collection_type):
        """
        Scenario: Test multi collection fetch with no last run, testing both types of empty collection

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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=empty_collection_type, proxies=[],
                                       verify=False, objects_to_fetch=[])
        id_1 = 1
        id_2 = 2
        mock_client.collections = [MockCollection(id_1, 'a'), MockCollection(id_2, 'b')]

        last_run = {mock_client.collections[1]: 'test'}
        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, '1 day', len(CORTEX_IOCS_1), last_run)
        assert len(indicators) == len(CORTEX_IOCS_1)
        assert last_run.get(mock_client.collections[1]) == 'test'


def test_get_collections_function():
    mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
    mock_client.collections = [MockCollection("first id", 'first name'), MockCollection("second id", 'second name')]

    result = get_collections_command(mock_client)

    assert len(result.outputs) == 2
    assert result.outputs[0] == {"Name": "first name", "ID": "first id"}
    assert result.outputs[1] == {"Name": "second name", "ID": "second id"}


@pytest.mark.parametrize('response, expected_md_results',
                         [([{'value': '1.1.1.1', 'type': 'IP'}, {'value': 'google.com', 'type': 'Domain'}],
                          'Found 2 results:\n|value|type|\n|---|---|\n| 1.1.1.1 | IP |\n| google.com | Domain |\n'),
                          ([{'value': '1.1.1.1', 'type': 'IP'}, {'value': 'google.com', 'type': 'Domain'},
                            {'value': '$$DummyIndicator$$',
                             'relationships': [{'name': 'related-to', 'reverseName': 'related-to',
                                                'type': 'IndicatorToIndicator', 'entityA': '1.1.1.1',
                                                'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'google.com',
                                                'entityBFamily': 'Indicator', 'entityBType': 'Domain',
                                                'fields': {'lastseenbysource': '2023-03-26T12:45:55.068670Z',
                                                           'firstseenbysource': '2023-03-26T12:45:55.068662Z'}}]}],
                          'Found 2 results:\n|value|type|\n|---|---|\n| 1.1.1.1 | IP |\n| google.com | Domain |\n\n\n\nRelations'
                           ' ships:\n|entityA|entityAFamily|entityAType|entityB|entityBFamily|entityBType|fields|name|'
                           'reverseName|type|\n|---|---|---|---|---|---|---|---|---|---|\n| 1.1.1.1 | Indicator | IP | '
                           'google.com | Indicator | Domain | lastseenbysource: 2023-03-26T12:45:55.068670Z<br>'
                           'firstseenbysource: 2023-03-26T12:45:55.068662Z | related-to | related-to | IndicatorToIndicator |\n')]
                         )
def test_get_indicators_command(mocker, response, expected_md_results):
    """
    Given:
    - A mock response
    - Case 1: response with 2 indicators and no relationship between them.
    - Case 2: response with 2 indicators and a relationship between them.

    When:
    - calling test_get_indicators_command

    Then:
    - Ensure the information was parsed correctly.
    - Case 1: No relationships section is mentioned in the readable output.
    - Case 2: Relationships section is mentioned in the readable output,
    and both the indicators and the relationship are in the outputs section.
    """
    mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
    mock_client.collection_to_fetch = [1]
    mocker.patch.object(Taxii2FeedClient, "build_iterator", return_value=response)
    results = get_indicators_command(mock_client)
    md = results.readable_output
    outputs = results.outputs
    assert md == expected_md_results
    assert outputs == response


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

    @pytest.mark.parametrize("indicators, last_run, new_indicators", [
        (
            [{'value': 'one', 'type': 'IP', "rawJSON": {'id': 'test_one', "modified": '2023-06-14T13:18:21.598591Z'}},
             {'value': 'two', 'type': 'IP', "rawJSON": {'id': 'test_two', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': 'three', 'type': 'Domain', "rawJSON": {'id': 'test_three', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': '$$DummyIndicator$$', 'relationships': [{}, {}, {}]}],
            {},
            [{'value': 'one', 'type': 'IP', "rawJSON": {'id': 'test_one', "modified": '2023-06-14T13:18:21.598591Z'}},
             {'value': 'two', 'type': 'IP', "rawJSON": {'id': 'test_two', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': 'three', 'type': 'Domain', "rawJSON": {'id': 'test_three', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': '$$DummyIndicator$$', 'relationships': [{}, {}, {}]}]
        ),
        (
            [{'value': 'two', 'type': 'IP', "rawJSON": {'id': 'test_two', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': 'three', 'type': 'Domain', "rawJSON": {'id': 'test_three', "modified": '2023-07-06T08:59:57.339606Z'}}],
            {"latest_indicators":
             [{'test_one': '2023-06-14T13:18:21.598591Z'},
              {'test_two': '2023-07-06T08:59:57.339606Z'},
              {'test_three': '2023-07-06T08:59:57.339606Z'}
              ]},
            []
        ),
        (
            [{'value': 'two', 'type': 'IP', "rawJSON": {'id': 'test_two', "modified": '2023-10-02T05:34:45.339145Z'}},
             {'value': 'three', 'type': 'Domain', "rawJSON": {'id': 'test_three', "modified": '2023-07-06T08:59:57.339606Z'}},
             {'value': 'four', 'type': 'Domain', "rawJSON": {'id': 'test_four', "modified": '2023-10-02T05:34:28.339145Z'}},
             {'value': '$$DummyIndicator$$', 'relationships': [{}, {}, {}]}],
            {"latest_indicators":
             [{'test_two': '2023-07-06T08:59:57.339606Z'},
              {'test_three': '2023-07-06T08:59:57.339606Z'},
              {'value': '$$DummyIndicator$$', 'relationships': [{}, {}, {}]}
              ]},
            [{'value': 'two', 'type': 'IP', "rawJSON": {'id': 'test_two', "modified": '2023-10-02T05:34:45.339145Z'}},
             {'value': 'four', 'type': 'Domain', "rawJSON": {'id': 'test_four', "modified": '2023-10-02T05:34:28.339145Z'}},
             {'value': '$$DummyIndicator$$', 'relationships': [{}, {}, {}]}]
        )

    ])
    def test_filter_previously_fetched_indicators(self, indicators, last_run, new_indicators):
        """
        Scenario: Test filtering indicators received from the fetch call before sending indicators to server

        Given:
        - list of indicators returned from the fetch call with empty lastrun object.
        - list of indicators returned from the fetch call with lastrun containing the same indicators (they were fetched
         in the previous fetch call).
        - list of indicators returned from the fetch call, and lastrun containing an indicator that was
         modified in the fetch call.

        When:
        - running filter_indicators command.

        Then:
        - all fetched indicators are returned, lastrun is updated with all fetched indicators ids and modified date.
        - non of the fetched indicators returned, lastrun is updated with all fetched indicators ids and modified date.
        - only the new and modified indicators are returned, lastrun is updated with all
         fetched indicators ids and modified dates.
        """

        from FeedTAXII2 import filter_previously_fetched_indicators

        next_latest_indicators = [{obj.get('rawJSON', {}).get("id"): obj.get('rawJSON', {}).get("modified")}
                                  if obj.get("value") != "$$DummyIndicator$$" else obj
                                  for obj in indicators]

        result = filter_previously_fetched_indicators(indicators, last_run)

        assert result == new_indicators
        assert last_run.get("latest_indicators") == next_latest_indicators


@pytest.mark.parametrize("url, expected_result",
                         [("https://test.com/taxii/", True),
                          ("https://test.com/taxii2/", True),
                          ("https://test.com/test/", False),
                          ("domain.com/taxii2/bad_path/", False)])
def test_is_valid_url(url, expected_result):
    """
    Scenario: Test validation of the is_valid_url method.

    Given:
    - A url

    When:
    - running is_valid_url command.

    Then:
    - Ensure the function evaluates correctly the correctness of the URL.
    """
    from FeedTAXII2 import is_valid_taxii_url
    assert is_valid_taxii_url(url) == expected_result


def test_feed_main_enrichment_excluded(mocker):
    """
        Given: params with tlp_color set to RED and enrichmentExcluded set to False
        When: Calling feed_main
        Then: validate enrichment_excluded is set to True
    """
    from FeedTAXII2 import main

    params = {
        'tlp_color': 'RED',
        'enrichmentExcluded': False,
        'server_url': 'test.test.com'
    }

    client_mocker = mocker.patch('FeedTAXII2.Taxii2FeedClient')

    mocker.patch('FeedTAXII2.is_xsiam_or_xsoar_saas', return_value=True)
    mocker.patch('FeedTAXII2.assert_incremental_feed_params')
    mocker.patch('FeedTAXII2.fetch_indicators_command', return_value=([], []))
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')

    # Call the function under test
    main()

    # Assertion - verify that enrichment_excluded is set to True
    assert client_mocker.call_args.kwargs.get('enrichment_excluded') is True

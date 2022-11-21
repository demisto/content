import pytest

from DHSFeedV2 import *

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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        mocker.patch.object(mock_client, 'build_iterator', return_value=RESULTS_JSON)
        indicators, last_run = fetch_indicators_command(mock_client, -1, {}, '1 day')
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mock_client.collection_to_fetch = mock_client.collections[0]
        last_run = {mock_client.collections[1]: 'test'}
        mocker.patch.object(mock_client, 'build_iterator', return_value=RESULTS_JSON)
        indicators, last_run = fetch_indicators_command(mock_client, -1, last_run, '1 day')
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        default_id = 1
        nondefault_id = 2
        mock_client.collections = [MockCollection(default_id, 'default'), MockCollection(nondefault_id, 'not_default')]

        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, -1, {}, '1 day')
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        id_1 = 1
        id_2 = 2
        mock_client.collections = [MockCollection(id_1, 'a'), MockCollection(id_2, 'b')]

        last_run = {mock_client.collections[1]: 'test'}
        mocker.patch.object(mock_client, 'build_iterator', side_effect=[CORTEX_IOCS_1, CORTEX_IOCS_2])
        indicators, last_run = fetch_indicators_command(mock_client, len(CORTEX_IOCS_1), last_run, '1 day')
        assert len(indicators) == len(CORTEX_IOCS_1)
        assert last_run.get(mock_client.collections[1]) == 'test'


def test_get_collections_function():
    mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
    mock_client.collections = [MockCollection("first id", 'first name'), MockCollection("second id", 'second name')]

    result = get_collections_command(mock_client)

    assert result.outputs == [{"Name": "first name", "ID": "first id"}, {"Name": "second name", "ID": "second id"}]


less_then_max = ('24 hours', None, '24 hours')
a_bit_less_then_max = ('44 hours', None, '44 hours')
more_then_max = ('57 hours', None, MAX_FETCH_INTERVAL)
take_min_second_value = ('2 hours', '1 hour', '1 hour')
take_min_first_value = ('1 hour', '2 hours', '1 hour')
take_min_sent_with_value = (get_limited_interval('3 days' or DEFAULT_FETCH_INTERVAL), '50 hours', MAX_FETCH_INTERVAL)
take_min_sent_without_value = (get_limited_interval(None or DEFAULT_FETCH_INTERVAL), '50 hours', DEFAULT_FETCH_INTERVAL)


@pytest.mark.parametrize('given_interval, fetch_interval, expected_min_interval', [less_then_max,
                                                                                   a_bit_less_then_max,
                                                                                   more_then_max,
                                                                                   take_min_second_value,
                                                                                   take_min_first_value,
                                                                                   take_min_sent_with_value,
                                                                                   take_min_sent_without_value])
def test_get_limited_interval(given_interval, fetch_interval, expected_min_interval):
    returned_min_interval = get_limited_interval(given_interval, fetch_interval)
    expected_min_interval = dateparser.parse(expected_min_interval, date_formats=[TAXII_TIME_FORMAT])
    assert returned_min_interval.replace(microsecond=0) == expected_min_interval.replace(microsecond=0)

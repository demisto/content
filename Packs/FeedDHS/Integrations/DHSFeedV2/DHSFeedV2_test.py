import pytest
from freezegun import freeze_time

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


def test_get_collections_command():
    """
    Given:
        - A taxii2 feed with collections
    When:
        - Running 'dhs-get-collections' command
    Then:
        - Returns the collections that the feed has
    """
    mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
    mock_client.collections = [MockCollection("first id", 'first name'), MockCollection("second id", 'second name')]

    result = get_collections_command(mock_client)

    assert result.outputs == [{"Name": "first name", "ID": "first id"}, {"Name": "second name", "ID": "second id"}]


less_then_max = ('24 hours', None, '24 hours')
a_bit_less_then_max = ('44 hours', None, '44 hours')
more_then_max = ('57 hours', None, MAX_FETCH_INTERVAL)
take_closer_second_value = ('2 hours', '1 hour', '1 hour')
take_closer_first_value = ('1 hour', '2 hours', '1 hour')


@freeze_time("2022-11-23 11:00:00 UTC")
@pytest.mark.parametrize('given_interval, fetch_interval, expected_min_interval', [less_then_max,
                                                                                   a_bit_less_then_max,
                                                                                   more_then_max,
                                                                                   take_closer_second_value,
                                                                                   take_closer_first_value])
def test_get_limited_interval(given_interval, fetch_interval, expected_min_interval):
    """
    Given:
        - Two time intervals
    When:
        - Running fetch indicators
    Then:
        - Returns the closer time
    """
    returned_min_interval = get_limited_interval(given_interval, fetch_interval)
    expected_min_interval = dateparser.parse(expected_min_interval, date_formats=[TAXII_TIME_FORMAT])
    assert returned_min_interval.replace(microsecond=0) == expected_min_interval.replace(microsecond=0, tzinfo=utc)


take_min_sent_with_value = ('3 days', '50 hours', MAX_FETCH_INTERVAL)
take_min_sent_without_value = (None, '50 hours', DEFAULT_FETCH_INTERVAL)


@freeze_time("2022-11-23 11:00:00 UTC")
@pytest.mark.parametrize('given_interval, fetch_interval, expected_min_interval', [take_min_sent_with_value,
                                                                                   take_min_sent_without_value])
def test_get_limited_interval_twice(given_interval, fetch_interval, expected_min_interval):
    """
    Given:
        - Two time intervals, one which passes get_limited_interval twice
    When:
        - Running fetch indicators with initial_interval value
    Then:
        - Returns the closer time
    """
    returned_min_interval = get_limited_interval(get_limited_interval(given_interval or DEFAULT_FETCH_INTERVAL), fetch_interval)
    expected_min_interval = dateparser.parse(expected_min_interval, date_formats=[TAXII_TIME_FORMAT])
    assert returned_min_interval.replace(microsecond=0) == expected_min_interval.replace(microsecond=0, tzinfo=utc)


human_to_datetime = ('24 hours', datetime(2022, 11, 22, 11, 00, 00, tzinfo=utc))
timestamp_to_datetime = ('2022-11-30T00:28:24Z', datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc))
datetime_to_datetime = (datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc), datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc))
none_or_human_to_datetime = (None or MAX_FETCH_INTERVAL, datetime(2022, 11, 21, 11, 00, 00, tzinfo=utc))
timestamp_or_none_to_datetime = ('2022-11-30T00:28:24Z' or None, datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc))
datetime_or_human_to_datetime = (datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc) or '24 hours',
                                 datetime(2022, 11, 30, 00, 28, 24, tzinfo=utc))


@freeze_time("2022-11-23 11:00:00 UTC")  # works only with lint
@pytest.mark.parametrize('given_interval, expected_datetime', [human_to_datetime,
                                                               timestamp_to_datetime,
                                                               datetime_to_datetime,
                                                               none_or_human_to_datetime,
                                                               timestamp_or_none_to_datetime,
                                                               datetime_or_human_to_datetime,
                                                               ])
def test_get_datetime(given_interval, expected_datetime):
    """
    Given:
        - Time interval
    When:
        - Turning it into datetime
    Then:
        - Returns the corresponding datetime
    """
    assert get_datetime(given_interval) == expected_datetime

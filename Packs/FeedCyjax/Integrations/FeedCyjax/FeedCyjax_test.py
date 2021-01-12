import pytest
import dateparser
from datetime import datetime, timedelta, timezone

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from FeedCyjax import INDICATORS_LAST_FETCH_KEY, DATE_FORMAT, Client, main, cyjax_sdk, test_module as module_test, \
     get_indicators_last_fetch_date, map_indicator_type, map_reputation_to_score, convert_cyjax_indicator, \
     fetch_indicators_command, get_indicators_command, indicator_sighting_command
from test_data.indicators import mocked_indicators


client_for_testing = Client(None, 'test-xsoar-api-token')
default_reputation = 'Suspicious'


def test_constants():
    assert 'last_fetch' == INDICATORS_LAST_FETCH_KEY
    assert '%Y-%m-%dT%H:%M:%SZ' == DATE_FORMAT


def test_map_reputation_to_score():
    assert 0 == map_reputation_to_score('Unknown')
    assert 0 == map_reputation_to_score('None')
    assert 1 == map_reputation_to_score('Good')
    assert 2 == map_reputation_to_score('Suspicious')
    assert 3 == map_reputation_to_score('Bad')


def test_map_indicator_type():
    assert FeedIndicatorType.IP == map_indicator_type('IPv4')
    assert FeedIndicatorType.IPv6 == map_indicator_type('IPv6')
    assert FeedIndicatorType.URL == map_indicator_type('URL')
    assert FeedIndicatorType.Email == map_indicator_type('Email')
    assert FeedIndicatorType.Domain == map_indicator_type('Domain')
    assert FeedIndicatorType.Domain == map_indicator_type('Hostname')
    assert FeedIndicatorType.File == map_indicator_type('FileHash-SHA1')
    assert FeedIndicatorType.File == map_indicator_type('FileHash-SHA256')
    assert FeedIndicatorType.File == map_indicator_type('FileHash-MD5')
    assert FeedIndicatorType.SSDeep == map_indicator_type('FileHash-SSDEEP')
    assert None is map_indicator_type('IP')
    assert None is map_indicator_type('invalid')


def test_get_incidents_last_fetch_date(mocker):
    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)
    timestamp = int(date.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={
        INDICATORS_LAST_FETCH_KEY: str(timestamp)
    })

    last_fetch_date = get_indicators_last_fetch_date()
    assert isinstance(last_fetch_date, datetime)
    last_timestamp = int(last_fetch_date.timestamp())
    assert timestamp == last_timestamp


def test_get_incidents_last_fetch_timestamp_on_fist_fetch(mocker):
    three_days_ago = datetime.now() - timedelta(days=3)
    three_days_ago_timestamp = int(three_days_ago.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={})

    last_fetch_date = get_indicators_last_fetch_date()
    assert isinstance(last_fetch_date, datetime)
    last_timestamp = int(last_fetch_date.timestamp())
    assert three_days_ago_timestamp <= last_timestamp

def test_convert_cyjax_indicator_with_default_score():
    cyjax_indicator = mocked_indicators[0]
    indicator_date = dateparser.parse(cyjax_indicator.get('discovered_at'))

    xsoar_indicator = convert_cyjax_indicator(cyjax_indicator)

    assert xsoar_indicator.get('value') == cyjax_indicator.get('value')
    assert xsoar_indicator.get('rawJSON') == json.dumps(cyjax_indicator)
    assert FeedIndicatorType.URL == xsoar_indicator.get('type')
    assert 2 == xsoar_indicator.get('score')
    assert indicator_date.strftime(DATE_FORMAT) == xsoar_indicator['fields']['firstseenbysource']
    assert cyjax_indicator['geoip']['country_name'] == xsoar_indicator['fields']['geocountry']
    assert cyjax_indicator['geoip']['city_name'] == xsoar_indicator['fields']['city']
    assert "Lon: 37.7759, Lat: 47.9917" == xsoar_indicator['fields']['geolocation']
    assert cyjax_indicator['ttp'] == xsoar_indicator['fields']['techniquestacticsprocedures']
    assert cyjax_indicator['industry_type'] == xsoar_indicator['fields']['industrytypes']
    assert cyjax_indicator['source'] == xsoar_indicator['fields']['source']
    assert cyjax_indicator['description'] == xsoar_indicator['fields']['description']
    assert cyjax_indicator['handling_condition'] == xsoar_indicator['fields']['trafficlightprotocol']

def test_convert_cyjax_indicator_with_set_score():
    cyjax_indicator = mocked_indicators[1]

    xsoar_indicator = convert_cyjax_indicator(cyjax_indicator, map_reputation_to_score('Bad'))

    assert xsoar_indicator.get('value') == cyjax_indicator.get('value')
    assert xsoar_indicator.get('rawJSON') == json.dumps(cyjax_indicator)
    assert FeedIndicatorType.File == xsoar_indicator.get('type')
    assert 3 == xsoar_indicator.get('score')


def test_test_module(mocker):
    ioc_mock = mocker.MagicMock()
    ioc_mock.list.return_value = []

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', return_value=ioc_mock)
    assert 'ok' == module_test(client_for_testing)
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', side_effect=Exception('Invalid Api Key'))
    assert 'Could not connect to Cyjax API (Invalid Api Key)' == module_test(client_for_testing)


def test_fetch_indicators_command(mocker):
    cyjax_indicator = mocked_indicators
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert {'last_fetch': last_fetch_timestamp} != next_run
    assert {'last_fetch': '1640988032'} != next_run

    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]
    assert isinstance(incidents, list)
    assert expected_indicators == incidents
    assert 4 == len(incidents)


def test_fetch_indicators_no_new_indicators(mocker):
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[])

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert {'last_fetch': last_fetch_timestamp} == next_run

    assert isinstance(incidents, list)
    assert [] == incidents
    assert 0 == len(incidents)


def test_fetch_indicators_when_skd_throws_error(mocker):
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', side_effect=Exception('Not found'))

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert {'last_fetch': last_fetch_timestamp} == next_run

    assert isinstance(incidents, list)
    assert [] == incidents
    assert 0 == len(incidents)


def test_get_indicators_command_arguments_specified(mocker):
    client = client_for_testing
    list_call_spy = mocker.spy(client, 'fetch_indicators')

    cyjax_indicator = mocked_indicators
    list_mock = mocker.MagicMock()
    list_mock.list.return_value = cyjax_indicator

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', return_value=list_mock)
    mocker.patch.object(demisto, 'args', return_value={
        'since': '2020-10-10',
        'until': '2021-01-15',
        'type': 'URL',
        'source_type': 'incident-report',
        'source_id': '50000'
    })

    result = get_indicators_command(client_for_testing, demisto.args())
    list_call_spy.assert_called_with(since='2020-10-10T00:00:00',
                                     until='2021-01-15T00:00:00',
                                     indicator_type='URL',
                                     source_type='incident-report',
                                     source_id=50000)


def test_get_indicators_command_without_arguments_specified(mocker):
    client = client_for_testing
    list_call_spy = mocker.spy(client, 'fetch_indicators')

    cyjax_indicator = mocked_indicators
    list_mock = mocker.MagicMock()
    list_mock.list.return_value = cyjax_indicator

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', return_value=list_mock)

    result = get_indicators_command(client_for_testing, demisto.args())
    list_call_spy.assert_called_with(since=None,
                                     until=None,
                                     indicator_type=None,
                                     source_type=None,
                                     source_id=None)


def test_get_indicators_command_response(mocker):
    cyjax_indicator = mocked_indicators
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)

    result = get_indicators_command(client_for_testing, demisto.args())
    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' in result
    assert EntryType.NOTE == result.get('Type')
    assert EntryFormat.JSON == result.get('ContentsFormat')
    assert EntryFormat.MARKDOWN == result.get('ReadableContentsFormat')

    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]
    assert expected_indicators == result.get('Contents')


''' MAIN COMMAND FUNCTIONS TEST'''


def test_fetch_indicators_main_command_call(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setLastRun')

    main()

    assert demisto.createIndicators.call_count == 1
    assert demisto.setLastRun.call_count == 1

    demisto.createIndicators.assert_called_with(expected_indicators)
    demisto.setLastRun.assert_called_with({'last_fetch': 1640988032})


def test_fetch_indicators_main_command_call_no_new_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setLastRun')

    main()

    assert demisto.createIndicators.call_count == 0
    assert demisto.setLastRun.call_count == 0

    demisto.createIndicators.assert_not_called()
    demisto.setLastRun.assert_not_called()


def test_get_indicators_main_command_call_with_one_new_indicator(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0])
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[cyjax_indicator[0]])
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-indicators')
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_count == 1
    result = demisto.results.call_args[0][0]

    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' in result
    assert EntryType.NOTE == result.get('Type')
    assert EntryFormat.JSON == result.get('ContentsFormat')
    assert EntryFormat.MARKDOWN == result.get('ReadableContentsFormat')
    assert expected_indicators == result.get('Contents')


def test_get_indicators_main_command_call_no_new_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-indicators')
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_count == 1
    result = demisto.results.call_args[0][0]

    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' in result
    assert EntryType.NOTE == result.get('Type')
    assert EntryFormat.JSON == result.get('ContentsFormat')
    assert EntryFormat.MARKDOWN == result.get('ReadableContentsFormat')
    assert expected_indicators == result.get('Contents')


def test_test_module_main_command_call(mocker):
    ioc_mock = mocker.MagicMock()
    ioc_mock.list.return_value = []

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', return_value=ioc_mock)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', side_effect=Exception('Server not responding'))

    main()
    assert demisto.results.call_count == 2
    assert demisto.results.call_args[0][0] == 'Could not connect to Cyjax API (Server not responding)'

import dateparser
from datetime import datetime, timedelta, timezone

import demistomock as demisto
from CommonServerPython import *

from FeedCyjax import INDICATORS_LAST_FETCH_KEY, DATE_FORMAT, INDICATORS_LIMIT, Client, main, \
    test_module as module_test, get_indicators_last_fetch_date, set_indicators_last_fetch_date, map_indicator_type, \
    map_reputation_to_score, convert_cyjax_indicator, fetch_indicators_command, get_indicators_command, \
    indicator_sighting_command, UnauthorizedException
from test_data.indicators import mocked_indicators
from test_data.enrichment import mocked_enrichment


client_for_testing = Client(None, 'test-xsoar-api-token')
default_reputation = 'Suspicious'


def test_constants():
    assert 'last_fetch' == INDICATORS_LAST_FETCH_KEY
    assert '%Y-%m-%dT%H:%M:%SZ' == DATE_FORMAT
    assert 50 == INDICATORS_LIMIT


def test_map_reputation_to_score():
    assert map_reputation_to_score('Unknown') == 0
    assert map_reputation_to_score('None') == 0
    assert map_reputation_to_score('Good') == 1
    assert map_reputation_to_score('Suspicious') == 2
    assert map_reputation_to_score('Bad') == 3


def test_map_indicator_type():
    assert map_indicator_type('IPv4') == FeedIndicatorType.IP
    assert FeedIndicatorType.IPv6 == map_indicator_type('IPv6')
    assert map_indicator_type('URL') == FeedIndicatorType.URL
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
    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)  # noqa: UP017
    timestamp = int(date.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: str(timestamp)
    })

    last_fetch_date = get_indicators_last_fetch_date()
    assert isinstance(last_fetch_date, datetime)
    last_timestamp = int(last_fetch_date.timestamp())
    assert timestamp == last_timestamp


def test_get_incidents_last_fetch_timestamp_on_fist_fetch(mocker):
    three_days_ago = datetime.now() - timedelta(days=3)
    three_days_ago_timestamp = int(three_days_ago.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})

    last_fetch_date = get_indicators_last_fetch_date()
    assert isinstance(last_fetch_date, datetime)
    last_timestamp = int(last_fetch_date.timestamp())
    assert three_days_ago_timestamp <= last_timestamp


def test_set_indicators_last_fetch_date(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})

    assert demisto.getIntegrationContext() == {}

    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)  # noqa: UP017
    timestamp = int(date.timestamp())

    set_indicators_last_fetch_date(timestamp)

    assert demisto.getIntegrationContext() == {INDICATORS_LAST_FETCH_KEY: timestamp}


def test_set_indicators_last_fetch_date_does_not_break_existing_context(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'Test': True, 'Value': 12345})

    assert demisto.getIntegrationContext() == {'Test': True, 'Value': 12345}

    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)  # noqa: UP017
    timestamp = int(date.timestamp())

    set_indicators_last_fetch_date(timestamp)

    context = demisto.getIntegrationContext()
    assert context.get(INDICATORS_LAST_FETCH_KEY) == timestamp
    assert context.get('Test') is True
    assert context.get('Value') == 12345


def test_convert_cyjax_indicator_with_default_score():
    cyjax_indicator = mocked_indicators[0]
    indicator_date = dateparser.parse(cyjax_indicator.get('discovered_at'))

    xsoar_indicator = convert_cyjax_indicator(cyjax_indicator)

    assert xsoar_indicator.get('value') == cyjax_indicator.get('value')
    assert xsoar_indicator.get('rawJSON') == cyjax_indicator
    assert xsoar_indicator.get('type') == FeedIndicatorType.URL
    assert xsoar_indicator.get('score') == 2
    assert indicator_date.strftime(DATE_FORMAT) == xsoar_indicator['fields']['firstseenbysource']
    assert cyjax_indicator['geoip']['country_name'] == xsoar_indicator['fields']['geocountry']
    assert cyjax_indicator['geoip']['city_name'] == xsoar_indicator['fields']['city']
    assert xsoar_indicator['fields']['geolocation'] == "Lon: 37.7759, Lat: 47.9917"
    assert cyjax_indicator['ttp'] == xsoar_indicator['fields']['cyjaxtechniquestacticsprocedures']
    assert cyjax_indicator['industry_type'] == xsoar_indicator['fields']['cyjaxindustrytypes']
    assert cyjax_indicator['source'] == xsoar_indicator['fields']['source']
    assert cyjax_indicator['description'] == xsoar_indicator['fields']['description']
    assert cyjax_indicator['handling_condition'] == xsoar_indicator['fields']['trafficlightprotocol']


def test_convert_cyjax_indicator_with_set_score():
    cyjax_indicator = mocked_indicators[1]

    xsoar_indicator = convert_cyjax_indicator(cyjax_indicator, map_reputation_to_score('Bad'))

    assert xsoar_indicator.get('value') == cyjax_indicator.get('value')
    assert xsoar_indicator.get('rawJSON') == cyjax_indicator
    assert FeedIndicatorType.File == xsoar_indicator.get('type')
    assert xsoar_indicator.get('score') == 3


def test_test_module(mocker):
    ioc_mock = mocker.MagicMock()
    ioc_mock.list.return_value = []

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', return_value=ioc_mock)
    assert module_test(client_for_testing) == 'ok'
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', side_effect=Exception('Invalid Api Key'))
    assert module_test(client_for_testing) == 'Could not connect to Cyjax API (Invalid Api Key)'


def test_fetch_indicators_command(mocker):
    cyjax_indicator = mocked_indicators
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert last_fetch_timestamp != next_run
    assert next_run != '1640988032'
    assert next_run == 1640988032

    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]
    assert isinstance(incidents, list)
    assert expected_indicators == incidents
    assert len(incidents) == 4


def test_fetch_indicators_no_new_indicators(mocker):
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[])

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert last_fetch_timestamp == next_run

    assert isinstance(incidents, list)
    assert [] == incidents
    assert len(incidents) == 0


def test_fetch_indicators_when_skd_throws_error(mocker):
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', side_effect=Exception('Not found'))

    last_fetch = datetime(2020, 12, 30, 15, 38)
    last_fetch_timestamp = int(last_fetch.timestamp())

    result = fetch_indicators_command(client_for_testing, last_fetch, default_reputation)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert last_fetch_timestamp == next_run

    assert isinstance(incidents, list)
    assert [] == incidents
    assert len(incidents) == 0


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
        'source_id': '50000',
        'limit': '12'
    })

    result = get_indicators_command(client_for_testing, demisto.args())
    list_call_spy.assert_called_with(since='2020-10-10T00:00:00Z',
                                     until='2021-01-15T00:00:00Z',
                                     indicator_type='URL',
                                     source_type='incident-report',
                                     source_id=50000,
                                     limit=12)
    assert isinstance(result, dict)


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
                                     source_id=None,
                                     limit=50)
    assert isinstance(result, dict)


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
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN

    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[0]),
        convert_cyjax_indicator(cyjax_indicator[1]),
        convert_cyjax_indicator(cyjax_indicator[2]),
        convert_cyjax_indicator(cyjax_indicator[3])
    ]
    assert expected_indicators == result.get('Contents')


def test_indicator_sighting_command_response(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'value': '236.516.247.352',
    })

    mocked_response = mocked_enrichment
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.enrichment', return_value=mocked_response)

    result = indicator_sighting_command(client_for_testing, demisto.args())

    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' in result
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN

    expected_contents = mocked_response.get('sightings')
    assert expected_contents == result.get('Contents')


def test_indicator_sighting_command_response_not_found(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'value': '236.516.247.352',
    })

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.enrichment', side_effect=Exception('Invalid indicator'))

    result = indicator_sighting_command(client_for_testing, demisto.args())

    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' not in result
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN
    assert result.get('Contents') == []


''' MAIN COMMAND FUNCTIONS TEST'''


def test_fetch_indicators_main_command_call(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com',
        'use_cyjax_tlp': True
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
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
    mocker.patch.object(demisto, 'setIntegrationContext')

    main()

    assert demisto.createIndicators.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1

    demisto.createIndicators.assert_called_with(expected_indicators)
    demisto.setIntegrationContext.assert_called_with({'last_fetch': 1640988032})


def test_fetch_indicators_main_command_call_no_new_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setIntegrationContext')

    main()

    assert demisto.createIndicators.call_count == 0
    assert demisto.setIntegrationContext.call_count == 0

    demisto.createIndicators.assert_not_called()
    demisto.setIntegrationContext.assert_not_called()


def test_fetch_indicators_main_command_call_use_cyjax_tlp(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com',
        'use_cyjax_tlp': True,
        'tlp_color': 'AMBER'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[1])
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[cyjax_indicator[1]])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setIntegrationContext')

    main()

    assert demisto.createIndicators.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1

    demisto.createIndicators.assert_called_with(expected_indicators)
    assert expected_indicators[0]['fields']['trafficlightprotocol'] == 'GREEN'


def test_fetch_indicators_main_command_call_use_set_tlp(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com',
        'use_cyjax_tlp': False,
        'tlp_color': 'AMBER'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[1], None, 'AMBER')
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[cyjax_indicator[1]])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setIntegrationContext')

    main()

    assert demisto.createIndicators.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1

    demisto.createIndicators.assert_called_with(expected_indicators)
    assert expected_indicators[0]['fields']['trafficlightprotocol'] == 'AMBER'


def test_fetch_indicators_main_command_call_use_tags(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com',
        'use_cyjax_tlp': True,
        'feedTags': 'TestTag, YellowTag'
    })

    last_fetch = datetime(2020, 12, 27, 15, 45)
    last_fetch_timestamp = int(last_fetch.timestamp())

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: last_fetch_timestamp
    })

    cyjax_indicator = mocked_indicators
    expected_indicators = [
        convert_cyjax_indicator(cyjax_indicator[1], None, None, 'TestTag, YellowTag')
    ]

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[cyjax_indicator[1]])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setIntegrationContext')

    main()

    assert demisto.createIndicators.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1

    demisto.createIndicators.assert_called_with(expected_indicators)
    assert expected_indicators[0]['fields']['tags'] == 'TestTag, YellowTag'


def test_get_indicators_main_command_call_with_one_new_indicator(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: int(datetime(2020, 12, 27, 15, 45).timestamp())
    })

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
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN
    assert expected_indicators == result.get('Contents')


def test_since_date_in_get_indicators_command_no_new_indicators_found(mocker):
    client = client_for_testing
    fetch_indicators_spy = mocker.spy(client, 'fetch_indicators')

    last_fetch = datetime(2020, 12, 27, 15, 0, 0, 0)
    last_fetch_timestamp = int(last_fetch.timestamp())
    expected_since = datetime(2020, 12, 27, 15, 0, 1, 0)

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=[])

    next_run, indicators = fetch_indicators_command(client_for_testing, last_fetch, 'good')

    fetch_indicators_spy.assert_called_with(since=expected_since.isoformat())
    assert [] == indicators
    assert last_fetch_timestamp == next_run


def test_since_date_in_get_indicators_command_new_indicators_found(mocker):
    client = client_for_testing
    fetch_indicators_spy = mocker.spy(client, 'fetch_indicators')

    last_fetch = datetime(2020, 12, 31, 15, 0, 0, 0)
    expected_since = datetime(2020, 12, 31, 15, 0, 1, 0)

    cyjax_indicator = mocked_indicators

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.list', return_value=cyjax_indicator)

    next_run, indicators = fetch_indicators_command(client_for_testing, last_fetch, 'good')

    fetch_indicators_spy.assert_called_with(since=expected_since.isoformat())
    assert next_run == 1640988032


def test_get_indicators_main_command_call_no_new_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: int(datetime(2020, 12, 27, 15, 45).timestamp())
    })

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
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN
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


def test_test_module_main_command_call_invalid_api_key(mocker):
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise', side_effect=UnauthorizedException())

    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'Could not connect to Cyjax API (Unauthorized)'


def test_unset_indicators_last_fetch_date_main_command_call(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        INDICATORS_LAST_FETCH_KEY: 1640988032,
        'Something': 'Else'
    })

    assert demisto.getIntegrationContext() == {
        INDICATORS_LAST_FETCH_KEY: 1640988032,
        'Something': 'Else'
    }

    mocker.patch.object(demisto, 'command', return_value='cyjax-unset-indicators-last-fetch-date')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    assert demisto.getIntegrationContext() == {
        'Something': 'Else'
    }


def test_indicators_sigthing_main_command_call(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'test-api-key',
        'url': 'https://cyjax-api-for-testing.com'
    })
    mocker.patch.object(demisto, 'args', return_value={
        'value': '236.516.247.352',
    })

    mocked_response = mocked_enrichment
    mocker.patch('FeedCyjax.cyjax_sdk.IndicatorOfCompromise.enrichment', return_value=mocked_response)
    mocker.patch.object(demisto, 'command', return_value='cyjax-indicator-sighting')
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
    assert result.get('Type') == EntryType.NOTE
    assert result.get('ContentsFormat') == EntryFormat.JSON
    assert result.get('ReadableContentsFormat') == EntryFormat.MARKDOWN

    expected_sightings = mocked_response.get('sightings')

    assert expected_sightings == result.get('Contents')

import io
import json
import pytest
import demistomock as demisto
import dateparser
from datetime import datetime, timedelta

server_url = 'https://vigilant.alienvault.cloud/api/2.0/alarms?page=0&size=1' \
             '&sort=timestamp_occured%2Casc&timestamp_occured_gte=1547567249000'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


alarms_data = util_load_json("./test_data/alarms_data.json")


def approximate_compare(time1, time2):
    if isinstance(time1, int):
        time1 = datetime.fromtimestamp(time1 / 1000)
    if isinstance(time2, int):
        time2 = datetime.fromtimestamp(time2 / 1000)

    return timedelta(seconds=-30) <= time1 - time2 <= timedelta(seconds=3)


@pytest.mark.parametrize('alarm, expected_incident', [
    (
        {
            '_embedded': {
                'alarms': [
                    {
                        'uuid': '4444444444',
                        'timestamp_occured_iso8601': '2019-07-12T06:00:38.000Z',
                    }
                ]
            },
            'page': {
                'totalElements': 1861
            }
        },
        {
            'name': 'Alarm: 4444444444',
            'occurred': '2019-07-12T06:00:38.000Z',
        }
    ),
    (
        {
            '_embedded': {
                'alarms': [
                    {
                        'uuid': '75d464ef-2834-k73a-5af0-7967369de3a1',
                        'timestamp_occured': '1629187949000',
                    }
                ]
            },
            'page': {
                'totalElements': 1861
            }
        },
        {
            'name': 'Alarm: 75d464ef-2834-k73a-5af0-7967369de3a1',
            'occurred': '2021-08-17T08:12:29.000Z',
        }
    )
])
def test_fetch_incidents(mocker, requests_mock, alarm, expected_incident):
    mocker.patch.object(demisto, 'params', return_value={
        'fetch_limit': '1',
        'url': 'https://vigilant.alienvault.cloud/'
    })
    mocker.patch.object(demisto, 'getLastRun', return_value={'timestamp': '1547567249000'})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    from AlienVault_USM_Anywhere import fetch_incidents
    requests_mock.get(
        server_url,
        json=alarm,
    )
    fetch_incidents()
    incident = demisto.incidents.call_args[0][0][0]
    assert incident['name'] == expected_incident['name']
    assert incident['occurred'] == expected_incident['occurred']


def test_get_time_range():
    from AlienVault_USM_Anywhere import get_time_range
    from CommonServerPython import date_to_timestamp

    assert get_time_range(None, None, None) == (None, None)

    dt = datetime.now()
    start, end = get_time_range('Today', None, None)
    assert datetime.fromtimestamp(start / 1000).date() == dt.date() and approximate_compare(dt, end)

    dt = datetime.now()
    # should ignore the start/end time values
    start, end = get_time_range('Today', 'asfd', 'asdf')
    assert datetime.fromtimestamp(start / 1000).date() == dt.date() and approximate_compare(dt, end)

    dt = datetime.now()
    start, end = get_time_range('Yesterday', None, None)
    assert datetime.fromtimestamp(start / 1000).date() == (dt.date() - timedelta(days=1)) and approximate_compare(dt, end)

    start, end = get_time_range('Custom', '2019-12-30T01:02:03Z', '2019-12-30T04:05:06Z')
    assert ((start, end) == (date_to_timestamp(dateparser.parse('2019-12-30T01:02:03Z')),
                             date_to_timestamp(dateparser.parse('2019-12-30T04:05:06Z'))))

    start, end = get_time_range('Custom', '2019-12-30T01:02:03Z', None)
    assert (start == date_to_timestamp(dateparser.parse('2019-12-30T01:02:03Z'))
            and approximate_compare(end, datetime.now()))


parsed_regular_alarm = {'ID': 'some_uuid',
                        'Priority': 'low',
                        'OccurredTime': '2021-08-17T08:15:57.000Z',
                        'ReceivedTime': '2021-08-17T08:17:03.106Z',
                        'RuleAttackID': 'T1110',
                        'RuleAttackTactic': ['Credential Access'],
                        'RuleAttackTechnique': 'Brute Force',
                        'RuleDictionary': 'WindowsRules-Dict',
                        'RuleID': 'MultipleAccountPasswordResetAttempts',
                        'RuleIntent': 'Delivery & Attack',
                        'RuleMethod': 'Multiple Account Password Reset Attempts',
                        'RuleStrategy': 'Anomalous User Behavior',
                        'Source': {'IPAddress': 'some_destination_name', 'Organization': None, 'Country': None},
                        'Destination': {'IPAddress': 'some_destination_name'},
                        'Event': [{'ID': 'some_specific_packet_data3',
                                   'OccurredTime': '2021-08-17T08:12:28.000Z',
                                   'ReceivedTime': '2021-08-17T08:13:22.233Z'},
                                  {'ID': 'some_specific_packet_data2',
                                   'OccurredTime': '2021-08-17T08:13:41.000Z',
                                   'ReceivedTime': '2021-08-17T08:14:57.783Z'},
                                  {'ID': 'some_specific_packet_data1',
                                   'OccurredTime': '2021-08-17T08:15:57.000Z',
                                   'ReceivedTime': '2021-08-17T08:17:01.325Z'}],
                        'Status': 'open'}


@pytest.mark.parametrize('alarms_raw_data, parsed_alarms', [(alarms_data.get("event_timestamp_occured_iso86_missing"),
                                                             [parsed_regular_alarm]),
                                                            (alarms_data.get("alarm_timestamp_occured_iso86_missing"),
                                                             [parsed_regular_alarm]),
                                                            (alarms_data.get("regular_alarm"), [parsed_regular_alarm]),
                                                            (alarms_data.get("event_timestamp_received_iso86_missing"),
                                                             [parsed_regular_alarm]),
                                                            (alarms_data.get("alarm_timestamp_received_iso86_missing"),
                                                             [parsed_regular_alarm]),
                                                            ])
def test_parse_alarms(alarms_raw_data, parsed_alarms):
    """Test Parsing of alarms from AlienVault

    Given: Alarms raw data to parse

    When: Getting alarms from AlienVault

    Then: Assert they are parsed correctly

    """
    from AlienVault_USM_Anywhere import parse_alarms
    assert parse_alarms(alarms_raw_data) == parsed_alarms

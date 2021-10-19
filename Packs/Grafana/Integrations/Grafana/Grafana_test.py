import dateparser
import pytest
import json
from pytz import utc

from Grafana import Client, change_key, keys_to_lowercase, decapitalize, calculate_fetch_start_time, parse_alerts, \
    alert_to_incident, filter_alerts_by_time, filter_alerts_by_id, reduce_incidents_to_limit, set_state, \
    set_time_to_epoch_millisecond
from freezegun import freeze_time
from CommonServerPython import urljoin


def create_client(url: str = 'url', verify_certificate: bool = True, proxy: bool = False):
    return Client(urljoin(url, ''), verify_certificate, proxy)


with open("TestData/change_key_values.json") as change_key_values_file:
    change_key_values_data = json.load(change_key_values_file)

alertId_to_id = change_key_values_data["alertId_to_id"]
teamID_to_id = change_key_values_data["teamID_to_id"]
orgID_to_id = change_key_values_data["orgID_to_id"]
CHANGE_KEY_VALUES = [alertId_to_id, teamID_to_id, orgID_to_id]


@pytest.mark.parametrize('dict_input, prev_key, new_key, expected_result', CHANGE_KEY_VALUES)
def test_change_key(dict_input, prev_key, new_key, expected_result):
    """

    Given:
        - Dictionary we want to change one of it's keys

    When:
        - Getting response from Grafana API, which has a different key than desired

    Then:
        - Returns the dictionary with the wanted key changed

    """
    assert change_key(dict_input, prev_key, new_key) == expected_result


def test_keys_to_lowercase():
    """

    Given:
        - Dictionary we want to change it's keys to decapitalized

    When:
        - Getting response about an alert, that has it's keys capitalized

    Then:
        - Returns the dictionary with it's keys decapitalized

    """
    with open("TestData/keys_to_lowercase.json") as keys_to_lowercase_file:
        keys_to_lowercase_data = json.load(keys_to_lowercase_file)
    dict_input = keys_to_lowercase_data["dict_input"]
    expected_result = keys_to_lowercase_data["expected_result"]
    assert keys_to_lowercase(dict_input) == expected_result


first_capitalized = ('Id', 'id')
decapitalize_only_first = ('NewStateDate', 'newStateDate')
empty_string = ('', '')
DECAPITALIZE_VALUES = [first_capitalized, decapitalize_only_first, empty_string]


@pytest.mark.parametrize('str_input, expected_output', DECAPITALIZE_VALUES)
def test_decapitalize(str_input, expected_output):
    """

    Given:
        - A string we want to decapitalize

    When:
        - Getting response about an alert, that has it's keys capitalized, this is executed to lower the keys in the dictionary

    Then:
        - Returns the string decapitalized

    """
    assert decapitalize(str_input) == expected_output


first_fetch_hour_ago = (None,
                        '1 hour',  # equals to 2020-07-29 10:00:00 UTC
                        dateparser.parse('2020-07-29 10:00:00 UTC').replace(tzinfo=utc, microsecond=0))
first_fetch_day_ago = (None,
                       '3 days',  # equals to 2020-07-26 11:00:00 UTC
                       dateparser.parse('2020-07-26 11:00:00 UTC').replace(tzinfo=utc, microsecond=0))
fetch_from_closer_time_last_fetched = ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
                                       '3 days',  # equals to 2020-07-26 11:00:00 UTC
                                       dateparser.parse('2020-07-27 11:00:00 UTC').replace(tzinfo=utc, microsecond=0))
fetch_from_closer_time_given_human = ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
                                      '2 hours',  # equals to 2020-07-29 09:00:00 UTC
                                      dateparser.parse('2020-07-29 9:00:00 UTC').replace(tzinfo=utc, microsecond=0))
fetch_from_closer_time_given_epoch = ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
                                      '1596013200',  # epoch time for 2020-07-29 9:00:00 UTC
                                      dateparser.parse('2020-07-29 9:00:00 UTC').replace(tzinfo=utc, microsecond=0))
FETCH_START_TIME_VALUES = [first_fetch_hour_ago, first_fetch_day_ago, fetch_from_closer_time_last_fetched,
                           fetch_from_closer_time_given_human, fetch_from_closer_time_given_epoch]


@pytest.mark.parametrize('last_fetch, first_fetch, expected_output', FETCH_START_TIME_VALUES)
@freeze_time("2020-07-29 11:00:00 UTC")
def test_calculate_fetch_start_time(last_fetch, first_fetch, expected_output):
    """

    Given:
        - Fetch incidents runs

    When:
        - Needs to calculate the time to start fetching from

    Then:
        - Returns the time to fetch from - the latter of the 2 given

    """
    # works only with lint due to freeze_time
    assert calculate_fetch_start_time(last_fetch, first_fetch) == expected_output


with open("TestData/parse_alerts_values.json") as parse_alerts_values_file:
    parse_alerts_values_data = json.load(parse_alerts_values_file)

no_alerts_to_fetch = ([],
                      5,
                      dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                      2,
                      dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                      2,
                      [])
after_one_alert_was_fetched_high_limit = (parse_alerts_values_data["after_one_alert_was_fetched_high_limit"],
                                          10,
                                          dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                                          1,
                                          dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
                                          2,
                                          ["TryAlert", "Adi's Alert"])
after_one_alert_was_fetched_low_limit = (parse_alerts_values_data["after_one_alert_was_fetched_low_limit"],
                                         1,
                                         dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                                         1,
                                         dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                                         3,
                                         ["TryAlert"])
keep_all_alerts = (parse_alerts_values_data["keep_all_alerts"],
                   2,
                   dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                   -1,
                   dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                   3,
                   ["Arseny's Alert", "TryAlert"])
limit_to_one = (parse_alerts_values_data["limit_to_one"],
                1,
                dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                -1,
                dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                1,
                ["Arseny's Alert"])
same_time_at_fetch = (parse_alerts_values_data["same_time_at_fetch"],
                      100,
                      dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                      2,
                      dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                      3,
                      ["TryAlert"])
PARSE_ALERTS_VALUES = [limit_to_one, keep_all_alerts, after_one_alert_was_fetched_low_limit,
                       after_one_alert_was_fetched_high_limit, no_alerts_to_fetch, same_time_at_fetch]


@pytest.mark.parametrize('alerts, max_fetch, last_fetch, last_id_fetched, '
                         'expected_output_time, expected_output_id, expected_incidents_names',
                         PARSE_ALERTS_VALUES)
def test_parse_alerts(alerts, max_fetch, last_fetch, last_id_fetched,
                      expected_output_time, expected_output_id, expected_incidents_names):
    """

    Given:
        - Fetch incidents runs and got all alerts, that some of them will become fetched incidents

    When:
        - Needs to choose only the relevant incidents to fetch

    Then:
        - Returns the incidents fetched, the new time to fetch from next time and the last id fetched

    """
    output_time, output_id, output_incidents = parse_alerts(alerts, max_fetch, last_fetch, last_id_fetched)
    assert output_time == expected_output_time
    assert output_id == expected_output_id
    for i in range(len(expected_incidents_names)):
        assert output_incidents[i]['name'] == expected_incidents_names[i]


def test_alert_to_incident():
    """

    Given:
        - Fetch incidents runs

    When:
        - Needs to turn the alert given into an incident to return

    Then:
        - Returns the incident

    """
    alert = {
        "id": 2,
        "dashboardId": 2,
        "dashboardUid": "yzDQUOR7z",
        "dashboardSlug": "simple-streaming-example-adis-copy",
        "panelId": 5,
        "name": "Adi's Alert",
        "state": "no_data",
        "newStateDate": "2021-07-29T14:03:20Z",
        "evalDate": "0001-01-01T00:00:00Z",
        "evalData": {
            "noData": True
        }}
    expected_incident = {
        'name': "Adi's Alert",
        'occurred': "2021-07-29T14:03:20Z",
        'type': 'Grafana Alert'
    }
    incident = alert_to_incident(alert)
    if incident:
        incident.pop('rawJSON')
    assert incident == expected_incident


with open("TestData/concatenate_url_values.json") as concatenate_url_values_file:
    concatenate_url_values_data = json.load(concatenate_url_values_file)

url_with_nothing_at_the_end = ('https://base_url',
                               concatenate_url_values_data['url_with_nothing_at_the_end'][0],
                               concatenate_url_values_data['url_with_nothing_at_the_end'][1])
url_with_end_characters = ('https://00.000.000.000:0000/',
                           concatenate_url_values_data['url_with_end_characters'][0],
                           concatenate_url_values_data['url_with_end_characters'][1])
no_url_field_at_given_list = ('https://base_url',
                              concatenate_url_values_data['no_url_field_at_given_list'][0],
                              concatenate_url_values_data['no_url_field_at_given_list'][1])
CONCATENATE_URL_VALUES = [url_with_nothing_at_the_end, url_with_end_characters, no_url_field_at_given_list]


@pytest.mark.parametrize('base_url, dict_input, expected_result', CONCATENATE_URL_VALUES)
def test_concatenate_url(base_url, dict_input, expected_result):
    """

    Given:
        - A url entry in a dictionary, with the suffix only as value

    When:
        - A dashboard url is given

    Then:
        - Returns the dictionary with the url value as base and suffix

    """
    client = create_client(url=base_url)
    assert client._concatenate_urls(dict_input) == expected_result


with open("TestData/alerts_to_filter_by_time.json") as alerts_to_filter_by_time_file:
    alerts_to_filter_by_time_data = json.load(alerts_to_filter_by_time_file)

keep_all_alerts = (alerts_to_filter_by_time_data['keep_all_alerts'][0],
                   dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                   alerts_to_filter_by_time_data['keep_all_alerts'][1])
keep_one_alert_same_time = (alerts_to_filter_by_time_data['keep_one_alert_same_time'][0],
                            dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
                            alerts_to_filter_by_time_data['keep_one_alert_same_time'][1])
keep_two_alerts = (alerts_to_filter_by_time_data['keep_two_alerts'][0],
                   dateparser.parse('2021-06-10 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                   alerts_to_filter_by_time_data['keep_two_alerts'][1])

ALERTS_TO_FILTER_BY_TIME = [keep_all_alerts, keep_one_alert_same_time, keep_two_alerts]


@pytest.mark.parametrize('alerts, last_fetch, expected_alerts', ALERTS_TO_FILTER_BY_TIME)
def test_filter_alerts_by_time(alerts, last_fetch, expected_alerts):
    """

    Given:
        - Fetch incidents runs

    When:
        - Needs to filter alerts so only recent ones will return

    Then:
        - Returns the recent alerts

    """
    assert filter_alerts_by_time(alerts, last_fetch) == expected_alerts


with open("TestData/alerts_to_filter_by_date.json") as alerts_to_filter_by_date_file:
    alerts_to_filter_by_date_data = json.load(alerts_to_filter_by_date_file)

keep_all_alerts_first_fetch = (alerts_to_filter_by_date_data['keep_all_alerts_first_fetch'][0],
                               dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                               0,
                               alerts_to_filter_by_date_data['keep_all_alerts_first_fetch'][1])
keep_all_alerts_not_first = (alerts_to_filter_by_date_data['keep_all_alerts_not_first'][0],
                             dateparser.parse('2021-05-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                             2,
                             alerts_to_filter_by_date_data['keep_all_alerts_not_first'][1])
keep_one_alert_greater_id_same_time = (alerts_to_filter_by_date_data['keep_one_alert_greater_id_same_time'][0],
                                       dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                                       2,
                                       alerts_to_filter_by_date_data['keep_one_alert_greater_id_same_time'][1])
ALERTS_TO_FILTER_BY_DATE = [keep_all_alerts_first_fetch, keep_all_alerts_not_first, keep_one_alert_greater_id_same_time]


@pytest.mark.parametrize('alerts, last_fetch, last_id_fetched, expected_alerts', ALERTS_TO_FILTER_BY_DATE)
def test_filter_alerts_by_id(alerts, last_fetch, last_id_fetched, expected_alerts):
    """

    Given:
        - Fetch incidents runs

    When:
        - Needs to filter alerts so if more then one lert happened at the same time as the last fetched alert, only those that
        were not fetched will be fetched now

    Then:
        - Returns the alerts that need to be fetched

    """
    assert filter_alerts_by_id(alerts, last_fetch, last_id_fetched) == expected_alerts


with open("TestData/incidents_to_reduce.json") as incidents_to_reduce_file:
    incidents_to_reduce_data = json.load(incidents_to_reduce_file)

keep_all_incidents = (incidents_to_reduce_data["keep_all_incidents"][0],
                      100,
                      dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                      0,
                      dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
                      2,
                      incidents_to_reduce_data["keep_all_incidents"][1])
limit_to_two = (incidents_to_reduce_data["limit_to_two"][0],
                2,
                dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                5,
                dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                3,
                incidents_to_reduce_data["limit_to_two"][1])
no_alerts = ([],
             150,
             dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
             5,
             dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
             5,
             [])
INCIDENTS_TO_REDUCE = [keep_all_incidents, limit_to_two, no_alerts]


@pytest.mark.parametrize('alerts, limit, last_fetch, last_id_fetched, expected_last_fetch, expected_last_id, expected_incidents',
                         INCIDENTS_TO_REDUCE)
def test_reduce_incidents_to_limit(alerts, limit, last_fetch, last_id_fetched,
                                   expected_last_fetch, expected_last_id, expected_incidents):
    """

    Given:
        - Fetch incidents runs, after filtering alerts by date and by id, and after sorting it by date and then by id

    When:
        - Needs to return only up to the limit of alerts wanted

    Then:
        - Returns the alert and the new time and id fetched

    """
    output_last_fetch, output_last_id, output_incidents = reduce_incidents_to_limit(alerts, limit, last_fetch, last_id_fetched)
    assert output_last_fetch == expected_last_fetch
    assert output_last_id == expected_last_id
    assert output_incidents == expected_incidents


STATES = ((None, []), ('', []), ('all', []), ('no_data,all', []), ('no_data,alerting', ['no_data', 'alerting']))


@pytest.mark.parametrize('state_input, state_output', STATES)
def test_set_state(state_input, state_output):
    """

    Given:
        - alerts-list command is executed

    When:
        - 'state' argument is or isn't given

    Then:
        - Returns the right states to get

    """
    assert set_state(state_input) == state_output


TIME_TO_EPOCH = ((None, None), ('now', 1596020400000), ('2021-10-04T15:21:57Z', 1633360917000))


@freeze_time("2020-07-29 11:00:00 UTC")
@pytest.mark.parametrize('time_input, time_output', TIME_TO_EPOCH)
def test_set_time_for_annotation(time_input, time_output):
    """

    Given:
        - annotation-create command is executed

    When:
        - 'time' and 'time_end' arguments are or aren't given

    Then:
        - Returns the right epoch time in millisecond resolution

    """
    assert set_time_to_epoch_millisecond(time_input) == time_output

import json

import dateparser
import pytest
from freezegun import freeze_time
from pytz import utc

from Grafana import Client, alert_get_by_id_command, alert_pause_command, alert_to_incident, alert_unpause_command, \
    alerts_list_command, annotation_create_command, calculate_fetch_start_time, change_key, dashboards_search_command, \
    decapitalize, filter_alerts_by_id, filter_alerts_by_time, keys_to_lowercase, org_create_command, org_get_by_id_command, \
    org_get_by_name_command, org_list_command, paging_heading, parse_alerts, reduce_incidents_to_limit, set_state, \
    set_time_to_epoch_millisecond, team_add_command, team_delete_command, team_get_by_id_command, team_members_command, \
    teams_search_command, user_add_to_team_command, user_get_by_id_command, user_remove_from_team_command, user_update_command, \
    users_organization_command, users_search_command, users_teams_command


def create_client(url: str = 'url', verify_certificate: bool = True, proxy: bool = False):
    return Client(url, verify_certificate, proxy)


''' HELPER FUNCTIONS TESTS '''

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
first_fetch_high_limit = (parse_alerts_values_data["first_fetch_high_limit"],
                          100,
                          dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                          -1,
                          dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
                          2,
                          ["Arseny's Alert", "TryAlert", "Adi's Alert"])
first_fetch_low_limit = (parse_alerts_values_data["first_fetch_low_limit"],
                         2,
                         dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                         -1,
                         dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                         3,
                         ["Arseny's Alert", "TryAlert"])
limit_to_one_first_fetch = (parse_alerts_values_data["limit_to_one_first_fetch"],
                            1,
                            dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                            -1,
                            dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                            1,
                            ["Arseny's Alert"])
limit_to_one_second_fetch = (parse_alerts_values_data["limit_to_one_second_fetch"],
                             1,
                             dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
                             1,
                             dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                             3,
                             ["TryAlert"])
same_time_at_fetch_bigger_id = (parse_alerts_values_data["same_time_at_fetch_bigger_id"],
                                100,
                                dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                                2,
                                dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                                3,
                                ["TryAlert"])
PARSE_ALERTS_VALUES = [limit_to_one_first_fetch, first_fetch_high_limit, after_one_alert_was_fetched_low_limit,
                       after_one_alert_was_fetched_high_limit, no_alerts_to_fetch, same_time_at_fetch_bigger_id,
                       first_fetch_low_limit, no_alerts_to_fetch, limit_to_one_second_fetch]


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
        - An alert fetched in fetch incidents

    When:
        - Fetch incidents runs and needs to turn the alert given into an incident to return

    Then:
        - Returns the incident created

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
url_with_end_character = ('https://00.000.000.000:0000/',
                          concatenate_url_values_data['url_with_end_character'][0],
                          concatenate_url_values_data['url_with_end_character'][1])
no_url_field_at_given_list = ('https://base_url',
                              concatenate_url_values_data['no_url_field_at_given_list'][0],
                              concatenate_url_values_data['no_url_field_at_given_list'][1])
CONCATENATE_URL_VALUES = [url_with_nothing_at_the_end, url_with_end_character, no_url_field_at_given_list]


@pytest.mark.parametrize('base_url, dict_input, expected_result', CONCATENATE_URL_VALUES)
def test_concatenate_url(base_url, dict_input, expected_result):
    """

    Given:
        - A url entry in a dictionary, with the value of the suffix only

    When:
        - The url is about to be shown to the user

    Then:
        - Returns the dictionary with the url value as base and suffix

    """
    client = create_client(url=base_url)
    assert client._concatenate_urls(dict_input) == expected_result


with open("TestData/alerts_to_filter_by_time.json") as alerts_to_filter_by_time_file:
    alerts_to_filter_by_time_data = json.load(alerts_to_filter_by_time_file)

first_fetch_high_limit = (alerts_to_filter_by_time_data['keep_all_alerts'][0],
                          dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                          alerts_to_filter_by_time_data['keep_all_alerts'][1])
keep_two_alerts = (alerts_to_filter_by_time_data['keep_two_alerts'][0],
                   dateparser.parse('2021-06-10 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
                   alerts_to_filter_by_time_data['keep_two_alerts'][1])
keep_one_alert_same_time = (alerts_to_filter_by_time_data['keep_one_alert_same_time'][0],
                            dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
                            alerts_to_filter_by_time_data['keep_one_alert_same_time'][1])

ALERTS_TO_FILTER_BY_TIME = [first_fetch_high_limit, keep_two_alerts, keep_one_alert_same_time]


@pytest.mark.parametrize('alerts, last_fetch, expected_alerts', ALERTS_TO_FILTER_BY_TIME)
def test_filter_alerts_by_time(alerts, last_fetch, expected_alerts):
    """

    Given:
        - All alerts got from Grafana

    When:
        - Fetch incidents runs needs to filter alerts so only recent ones will be returned

    Then:
        - Returns the alerts that happened after the last fetch

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
# all alerts have the same time, last ID fetched is 2, so we want to get only ID 3 and not ID 1
keep_one_alert_greater_id_same_time = (alerts_to_filter_by_date_data['keep_one_alert_greater_id_same_time'][0],
                                       dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
                                       2,
                                       alerts_to_filter_by_date_data['keep_one_alert_greater_id_same_time'][1])
ALERTS_TO_FILTER_BY_DATE = [keep_all_alerts_first_fetch, keep_all_alerts_not_first, keep_one_alert_greater_id_same_time]


@pytest.mark.parametrize('alerts, last_fetch, last_id_fetched, expected_alerts', ALERTS_TO_FILTER_BY_DATE)
def test_filter_alerts_by_id(alerts, last_fetch, last_id_fetched, expected_alerts):
    """

    Given:
        - Alerts got from Grafana

    When:
        - Fetch incidents runs and needs to filter alerts so if more then one alert happened at the same time as the last fetched
        alert, only those that were not fetched will be fetched now

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
        - Alerts got from Grafana

    When:
        - Fetch incidents runs, after filtering alerts by date and by id, and after sorting it by date and then by id

    Then:
        - Returns new time and id fetched, and the alerts only up to the limit wanted

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
        - 'state' argument is or isn't given to the `alerts-list` command

    When:
        - `alerts-list` command is executed

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
        - 'time' and 'time_end' arguments are or aren't given to the `annotation-create` command

    When:
        - `annotation-create` command is executed

    Then:
        - Returns the right epoch time in millisecond resolution

    """
    # works only with lint due to freeze_time
    assert set_time_to_epoch_millisecond(time_input) == time_output


no_page_number = (None, '100', 'Showing 100 results:\n')
no_page_size = ('50', None, 'Showing results from page 50:\n')
no_page_number_size = (None, None, '')
page_number_size = ('1', '20', 'Showing 20 results from page 1:\n')
PAGING_HEADING = (no_page_number, no_page_size, no_page_number_size, page_number_size)


@pytest.mark.parametrize('page_number, page_size, expected_output', PAGING_HEADING)
def test_paging_heading(page_number, page_size, expected_output):
    """

    Given:
        - 'page_number' and 'page_size' arguments are or aren't given to commands that have paging

    When:
        - A command that has paging is executed

    Then:
        - Returns the right sentence to write in the beginning of the readable output

    """
    assert paging_heading(page_number, page_size) == expected_output


''' COMMAND FUNCTIONS TESTS '''


@pytest.fixture
def grafana_client():
    return Client('url')


def test_alerts_list_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - alerts-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'dashboard_id': "1", 'panel_id': "2", 'name': "ADash", 'state': "no_data,paused", 'limit': "50", 'folder_id': "1",
            'dashboard_name': "Dash", 'dashboard_tag': "tag"}
    alerts_list_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/alerts', params={'dashboardId': ['1'], 'panelId': '2', 'query': 'ADash',
                                                                 'state': ['no_data', 'paused'], 'limit': '50', 'folderId': ['1'],
                                                                 'dashboardQuery': 'Dash', 'dashboardTag': ['tag']}, headers=None)


def test_alert_pause_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - alert-pause command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'alert_id': "4"}
    alert_pause_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/alerts/4/pause', json_data={'paused': True}, headers=None)


def test_alert_unpause_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - alert-unpause command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'alert_id': "4"}
    alert_unpause_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/alerts/4/pause', json_data={'paused': False}, headers=None)


def test_users_search_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - users-search command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'page_size': "1000", 'page_number': "1", 'query': "admin"}
    users_search_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/users', params={'perpage': '1000', 'page': '1', 'query': 'admin'}, headers=None)


def test_users_teams_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-teams-get command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'user_id': "4"}
    users_teams_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/users/4/teams', headers=None)


def test_users_organization_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-orgs-get command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'user_id': "4"}
    users_organization_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/users/4/orgs', headers=None)


def test_user_update_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-update command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'email': "e@mail", 'name': "Name", 'login': "login", 'theme': "dark", 'user_id': "2"}
    user_update_command(grafana_client, args)
    http_request.assert_called_with('PUT', 'api/users/2',
                                    json_data={'email': 'e@mail', 'login': 'login', 'name': 'Name', 'theme': 'dark'},
                                    headers=None)


def test_annotation_create_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - annotation-create command is executed

    Then:
        - The http request is called with the right arguments
    """
    # to pass this test you must run it using lint due to time conflicts
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'dashboard_id': "3", 'panel_id': "2", 'time': "2019-10-21T23:45:00", 'time_end': "2019-10-21T23:45:01",
            'tags': "tag1", 'text': "Text"}
    annotation_create_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/annotations',
                                    json_data={'dashboardId': 3, 'panelId': 2, 'tags': ['tag1'], 'text': 'Text',
                                               'time': 1571701500000, 'timeEnd': 1571701501000}, headers=None)


def test_teams_search_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - teams-search command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'page_size': "60", 'page_number': "2", 'query': "team", 'name': "team_name"}
    teams_search_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/teams/search',
                                    params={'perpage': '60', 'page': '2', 'query': 'team', 'name': 'team_name'}, headers=None)


def test_team_members_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - team-members-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'team_id': "16"}
    team_members_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/teams/16/members', headers=None)


def test_user_add_to_team_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-add-to-team command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'user_id': "2", 'team_id': "15"}
    user_add_to_team_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/teams/15/members', json_data={'userId': 2}, headers=None, ok_codes=(200, 400))


def test_user_remove_from_team_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-remove-from-team command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'user_id': "3", 'team_id': "17"}
    user_remove_from_team_command(grafana_client, args)
    http_request.assert_called_with('DELETE', 'api/teams/17/members/3', headers=None)


def test_team_add_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - team-add command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'name': "New Team", 'email': "new@email", 'org_id': "2"}
    team_add_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/teams', json_data={'email': 'new@email', 'name': 'New Team', 'orgId': '2'},
                                    headers=None)


def test_team_delete_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - team-delete command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'team_id': "4"}
    team_delete_command(grafana_client, args)
    http_request.assert_called_with('DELETE', 'api/teams/4', headers=None)


def test_org_create_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - org-create command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'name': 'NewOrg'}
    org_create_command(grafana_client, args)
    http_request.assert_called_with('POST', 'api/orgs', json_data={'name': 'NewOrg'}, headers=None)


def test_dashboards_search_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - dashboards-search command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'query': "dash", 'tag': "tag1,tag2", 'type': "dash-db", 'dashboard_ids': "2,1", 'folder_ids': "1,3",
            'starred': "false", 'limit': "30", 'page_number': "2"}
    dashboards_search_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/search', params={'query': 'dash', 'tag': ['tag1', 'tag2'], 'type': 'dash-db',
                                                                 'dashboardIds': ['2', '1'], 'folderIds': ['1', '3'],
                                                                 'starred': 'false', 'limit': '30', 'page': '2'}, headers=None)


def test_user_get_by_id_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - user-get-by-id command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'user_id': "6"}
    user_get_by_id_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/users/6', headers=None)


def test_team_get_by_id_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - team-get-by-id command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'team_id': "7"}
    team_get_by_id_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/teams/7', headers=None)


def test_alert_get_by_id_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - alert-get-by-id command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'alert_id': "4"}
    alert_get_by_id_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/alerts/4', headers=None)


def test_org_list_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - org-list command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'page_size': "40", 'page_number': "0"}
    org_list_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/orgs', params={'perpage': '40', 'page': '0'}, headers=None)


def test_org_get_by_name_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - org-get-by-name command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'name': "OrgName"}
    org_get_by_name_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/orgs/name/OrgName', headers=None)


def test_org_get_by_id_command(mocker, grafana_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - org-get-by-id command is executed

    Then:
        - The http request is called with the right arguments
    """
    http_request = mocker.patch.object(grafana_client, '_http_request')
    args = {'org_id': "114"}
    org_get_by_id_command(grafana_client, args)
    http_request.assert_called_with('GET', 'api/orgs/114', headers=None)

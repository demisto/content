"""
    QRadar v3 integration for Cortex XSOAR - Unit Tests file
"""
import json
from datetime import datetime
from collections.abc import Callable
import copy

import requests
from requests.exceptions import ReadTimeout

import QRadar_v3  # import module separately for mocker
import pytest
import pytz
from QRadar_v3 import LAST_FETCH_KEY, USECS_ENTRIES, OFFENSE_OLD_NEW_NAMES_MAP, MINIMUM_API_VERSION, \
    Client, ASSET_PROPERTIES_NAME_MAP, REFERENCE_SETS_RAW_FORMATTED, \
    FULL_ASSET_PROPERTIES_NAMES_MAP, EntryType, EntryFormat, MIRROR_OFFENSE_AND_EVENTS, \
    MIRRORED_OFFENSES_QUERIED_CTX_KEY, MIRRORED_OFFENSES_FINISHED_CTX_KEY, LAST_MIRROR_KEY, QueryStatus, LAST_MIRROR_CLOSED_KEY
from QRadar_v3 import get_time_parameter, add_iso_entries_to_dict, build_final_outputs, build_headers, \
    get_offense_types, get_offense_closing_reasons, get_domain_names, get_rules_names, enrich_assets_results, \
    get_offense_addresses, get_minimum_id_to_fetch, poll_offense_events, sanitize_outputs, \
    create_search_with_retry, enrich_offense_with_assets, get_offense_enrichment, \
    add_iso_entries_to_asset, create_single_asset_for_offense_enrichment, create_incidents_from_offenses, \
    qradar_offenses_list_command, qradar_offense_update_command, qradar_closing_reasons_list_command, \
    qradar_offense_notes_list_command, qradar_offense_notes_create_command, qradar_rules_list_command, \
    qradar_rule_groups_list_command, qradar_assets_list_command, qradar_saved_searches_list_command, \
    qradar_searches_list_command, qradar_search_create_command, qradar_search_status_get_command, \
    qradar_search_results_get_command, qradar_reference_sets_list_command, qradar_reference_set_create_command, \
    qradar_reference_set_delete_command, qradar_reference_set_value_upsert_command, \
    qradar_reference_set_value_delete_command, qradar_domains_list_command, qradar_geolocations_for_ip_command, \
    qradar_log_sources_list_command, qradar_get_custom_properties_command, enrich_asset_properties, \
    flatten_nested_geolocation_values, get_modified_remote_data_command, get_remote_data_command, is_valid_ip, \
    qradar_ips_source_get_command, qradar_ips_local_destination_get_command, \
    qradar_remote_network_cidr_create_command, get_cidrs_indicators, verify_args_for_remote_network_cidr, \
    qradar_remote_network_cidr_list_command, verify_args_for_remote_network_cidr_list, is_positive, \
    qradar_remote_network_cidr_delete_command, qradar_remote_network_cidr_update_command, \
    qradar_remote_network_deploy_execution_command, qradar_indicators_upload_command, migrate_integration_ctx, \
    qradar_event_collectors_list_command, qradar_wincollect_destinations_list_command, \
    qradar_disconnected_log_collectors_list_command, qradar_log_source_types_list_command, \
    qradar_log_source_protocol_types_list_command, qradar_log_source_extensions_list_command, \
    qradar_log_source_languages_list_command, qradar_log_source_groups_list_command, qradar_log_source_create_command, \
    qradar_log_source_delete_command, qradar_log_source_update_command, convert_dict_to_actual_values, \
    enrich_offense_with_events, perform_long_running_loop, validate_integration_context, convert_list_to_actual_values, \
    qradar_search_cancel_command, \
    MIRRORED_OFFENSES_FETCHED_CTX_KEY, FetchMode, IndicatorsSearcher

from CommonServerPython import DemistoException, set_integration_context, CommandResults, \
    GetModifiedRemoteDataResponse, GetRemoteDataResponse, get_integration_context
import demistomock as demisto

QRadar_v3.FAILURE_SLEEP = 0
QRadar_v3.SLEEP_FETCH_EVENT_RETRIES = 0

client = Client(
    server='https://192.168.0.1',
    verify=False,
    proxy=False,
    api_version=str(MINIMUM_API_VERSION),
    credentials={
        'identifier': 'admin',
        'password': '1234'
    }
)

QRadar_v3.EVENTS_SEARCH_RETRY_SECONDS = 0


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


asset_enrich_data = util_load_json("./test_data/asset_enrich_test.json")

command_test_data = util_load_json('./test_data/command_test_data.json')
ip_command_test_data = util_load_json('./test_data/ips_commands_data.json')
ctx_test_data = util_load_json('./test_data/integration_context_tests.json')

event_columns_default_value = \
    'QIDNAME(qid), LOGSOURCENAME(logsourceid), CATEGORYNAME(highlevelcategory), ' \
    'CATEGORYNAME(category), PROTOCOLNAME(protocolid), sourceip, sourceport, destinationip, ' \
    'destinationport, QIDDESCRIPTION(qid), username, PROTOCOLNAME(protocolid), ' \
    'RULENAME("creEventList"), sourcegeographiclocation, sourceMAC, sourcev6, ' \
    'destinationgeographiclocation, destinationv6, LOGSOURCETYPENAME(devicetype), ' \
    'credibility, severity, magnitude, eventcount, eventDirection, postNatDestinationIP, ' \
    'postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationPort, ' \
    'preNatSourceIP, preNatSourcePort, UTF8(payload), starttime, devicetime '


@pytest.mark.parametrize('arg, iso_format, epoch_format, expected',
                         [('2020-11-22T16:31:14-02:00', False, False,
                           datetime(2020, 11, 22, 18, 31, 14, tzinfo=pytz.utc)),
                          (None, False, False, None),
                          (None, True, False, None),
                          ('2020-12-12', True, False, '2020-12-12T00:00:00+00:00'),
                          ('2020-12-12T10:11:22', True, False, '2020-12-12T10:11:22+00:00'),
                          ('2020-12-12T22:11:22-03:00', True, False, '2020-12-13T01:11:22+00:00'),
                          ('2020-12-12', False, True, 1607731200000),
                          ('2020-12-12T10:11:22', False, True, 1607767882000),
                          ('2020-12-12T22:11:22-03:00', False, True, 1607821882000)
                          ])
def test_get_optional_time_parameter_valid_time_argument(arg, iso_format, epoch_format, expected):
    """
    Given:
     - Demisto arguments.
     - Argument of type time to extract from Demisto arguments as epoch time.

    When:
     - Case a: Argument exists, has expected date format, parse format was not asked,.
     - Case b: Argument does not exist, parse format was not asked.
     - Case c: Argument does not exist, parse format was asked.
     - Case d: Argument exist and has ISO format, parse format was asked.
     - Case e: Argument exist and has ISO format, parse format was asked.

    Then:
     - Case a: Ensure that the corresponding epoch time is returned.
     - Case b: Ensure that None is returned.
     - Case c: Ensure that None is returned.
     - Case d: Ensure that correct FraudWatch format is returned.
     - Case e: Ensure that correct FraudWatch format is returned.
    """
    assert (get_time_parameter(arg, iso_format=iso_format, epoch_format=epoch_format)) == expected


def test_connection_errors_recovers(mocker):
    """
    Given:
     - Connection Error, ReadTimeout error and a success response

    When:
     - running the http_request method

    Then:
     - Ensure that success message is printed and recovery for http request happens.
    """
    mocker.patch.object(demisto, "error")
    mocker.patch("QRadar_v3.time.sleep")
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=[
            DemistoException(message="error", exception=requests.ConnectionError("error")),
            requests.ReadTimeout("error"),
            "success"
        ]
    )
    assert client.http_request(method="GET", url_suffix="url") == "success"


@pytest.mark.parametrize('dict_key, inner_keys, expected',
                         [('continent', ['name'], {'ContinentName': 'NorthAmerica'}),
                          ('city', ['name'], {'CityName': 'Mukilteo'}),
                          ('represented_country', ['unknown', 'confidence'],
                           {'RepresentedCountryUnknown': None, 'RepresentedCountryConfidence': None}),
                          ('registered_country', ['iso_code', 'name'],
                           {'RegisteredCountryIsoCode': 'US', 'RegisteredCountryName': 'United States'}),
                          ('location', ['accuracy_radius', 'timezone', 'latitude', 'metro_code', 'average_income',
                                        'population_density', 'longitude'],
                           {'LocationAccuracyRadius': 1000, 'LocationTimezone': 'America/Los_Angeles',
                            'LocationLatitude': 47.913,
                            'LocationMetroCode': 819, 'LocationAverageIncome': None, 'LocationPopulationDensity': None,
                            'LocationLongitude': -122.3042})])
def test_flatten_nested_geolocation_values(dict_key, inner_keys, expected):
    """
    Given:
     - Dict of IP details returned by QRadar service for geolocations for ip command.
     - Dict key to flatten its inner values.
     - Inner values to be flattened

    When:
     - Creating outputs to Demisto form geolocations for ip command.

    Then:
     Ensure values are flattened as expected
    """
    assert flatten_nested_geolocation_values(command_test_data['geolocations_for_ip']['response'][0], dict_key,
                                             inner_keys) == expected


@pytest.mark.parametrize('properties, properties_to_enrich_dict, expected',
                         [(asset_enrich_data['assets'][0]['properties'], ASSET_PROPERTIES_NAME_MAP,
                           {'Name': {'Value': '192.168.0.1', 'LastUser': 'admin'}}),
                          (asset_enrich_data['assets'][0]['properties'], FULL_ASSET_PROPERTIES_NAMES_MAP,
                           {'ComplianceNotes': {'Value': 'note', 'LastUser': 'Adam'}}),
                          ([], FULL_ASSET_PROPERTIES_NAMES_MAP, {})
                          ])
def test_enrich_asset_properties(properties, properties_to_enrich_dict: dict, expected):
    """
    Given:
     - Properties of an asset.
     - Dict containing properties keys to enrich, and the new names of the enrichment as corresponding values.

    When:
     - Case a: Basic enrichment of properties have been asked.
     - Case b: Full enrichment of properties have been asked.
     - Case c: Full enrichment of properties have been asked, properties are empty.

    Then:
     - Case a: Ensure that only properties keys that are contained in basic enrichment are enriched.
     - Case b: Ensure that only properties keys that are contained in full enrichment are enriched.
     - Case c: Ensure that empty dict is returned
    """
    assert enrich_asset_properties(properties, properties_to_enrich_dict) == expected


@pytest.mark.parametrize('enrichment, expected',
                         [('None', (False, False)), ('IPs', (True, False)), ('IPs And Assets', (True, True))])
def test_get_offense_enrichment(enrichment, expected):
    """
    Given:
     - Enrichment asked by the user.

    When:
     - Case a: Enrichment was not asked (None).
     - Case b: Enrichment asked was for IPs only.
     - Case c: Enrichment asked was for IPs and assets.

    Then:
     - Case a: Ensure False, False is returned.
     - Case b: Ensure True, False is returned.
     - Case c: Ensure True, True is returned.
    """
    assert get_offense_enrichment(enrichment) == expected


def test_add_iso_entries_to_dict():
    """
    Given:
     - Dict containing entries with epoch time.

    When:
     - Adding to entries with epoch time entries with iso time.

    Then:
     - All 'usecs' keys in the dict are replaced with 'iso time' entries with correct iso values.
     - The dict is cloned and its values are not changed, and a new one is created
    """
    tested_dict = {usec_entry: 1600000000000 for usec_entry in USECS_ENTRIES}
    tested_dict['host_name'] = 'QRadar Host'
    output_dict = add_iso_entries_to_dict([tested_dict])[0]
    assert tested_dict['host_name'] == 'QRadar Host'
    assert output_dict['host_name'] == 'QRadar Host'
    assert all(
        tested_dict.get(iso_entry) == 1600000000000 for iso_entry in USECS_ENTRIES)
    assert all(
        output_dict.get(iso_entry) == '2020-09-13T12:26:40+00:00' for iso_entry in USECS_ENTRIES)
    assert len(tested_dict) == (1 + len(USECS_ENTRIES))
    assert len(output_dict) == (1 + len(USECS_ENTRIES))


def test_add_iso_entries_to_asset():
    """
    Given:
     - Asset.

    When:
     - Replacing epoch values with ISO values

    Then:
     - Ensure epoch values are replaced with the expected ISO values.
    """
    assets = asset_enrich_data['assets']
    assert [add_iso_entries_to_asset(asset) for asset in assets] == asset_enrich_data['iso_transform']


@pytest.mark.parametrize('output, old_new_dict, expected',
                         [([{'a': 2, 'c': 3}], {'a': 'b'}, [{'b': 2}]),
                          ([OFFENSE_OLD_NEW_NAMES_MAP], OFFENSE_OLD_NEW_NAMES_MAP,
                           [{v: v for v in OFFENSE_OLD_NEW_NAMES_MAP.values()}]),
                          ([{'description': 'bla'}], {'name': 'Adam'}, [{}]),
                          ([{'a': 1, 'b': 2, 'c': 3}, {'a': 4, 'd': 5, 'e': 6}],
                           {'a': 'A', 'b': 'B', 'd': 'D'}, [{'A': 1, 'B': 2}, {'A': 4, 'D': 5}])])
def test_build_final_outputs(output, old_new_dict, expected):
    """
    Given:
     - Output.
     - Dict mapping old key names to be replaced with new key names

    When:
     - Case a: Part of the keys of the output intersects with 'old_new' dictionary and some are not
     - Case b: All of the keys of the output intersects in 'old_new' dictionary.
     - Case c: No key of the output intersects with 'old_new' dictionary

    Then:
     - Case a: Correct keys are replaced (only those who intersects).
     - Case b: All of the keys are replaced (because all keys intersects).
     - Case c: No key is replaced (no intersect).
    """
    assert (build_final_outputs(output, old_new_dict)) == expected


@pytest.mark.parametrize('first_headers, all_headers',
                         [(['ID', 'Description'], {'A', 'B', 'C', 'ID', 'Description'}),
                          (['A'], {'A', 'B'})])
def test_build_headers(first_headers, all_headers):
    """
    Given:
     - List of first headers to be shown in entry room.
     - Set of all of the headers to be shown in the entry room.

    When:
     - Case a: Building headers for human readable.
     - Case b: Building headers for human readable.

    Then:
     - Case a: First headers are first in the list.
     - Case b: First headers are first in the list.
    """
    assert (build_headers(first_headers, all_headers))[:len(first_headers)] == first_headers


@pytest.mark.parametrize('last_run_offense_id, user_query, expected',
                         [(1, None, 1),
                          (2, 'status=open or id > 4', 4),
                          (6, 'username_count > 2 and id > 3 or event_count < 6', 6),
                          (4, 'id >= 4', 4),
                          (2, 'id >= 4', 3),
                          (32, 'as4ll a4as ll5ajs 352lk aklj id     >           35 zjfzlkfj selkj', 35),
                          (32, 'as4ll a4as ll5ajs 352lk aklj id     >=           35 zjfzlkfj selkj', 34),
                          (32, 'a id     >=           35001 ', 35000),
                          (1523, 'closing_reason_id > 5000', 1523),
                          (0, 'id > 4', 4),
                          (0, 'id > 1', 2)])
def test_get_minimum_id_to_fetch(last_run_offense_id, user_query, expected, mocker):
    """
    Given:
     - The highest fetched offense ID from last run.
     - The user query for fetch.

    When:
     - Fetching incidents in long time execution.

    Then:
     - Ensure that returned value is the lowest ID to fetch from.
    """
    mocker.patch.object(client, 'offenses_list', return_value=[{'id': '3'}])
    assert get_minimum_id_to_fetch(last_run_offense_id, user_query, '3 days', client) == expected


@pytest.mark.parametrize('outputs, key_replace_dict, expected',
                         [({'a': 2, 'number_of_elements': 3, 'creation_time': 1600000000000},
                           REFERENCE_SETS_RAW_FORMATTED,
                           [{'NumberOfElements': 3, 'CreationTime': '2020-09-13T12:26:40+00:00'}]),
                          ({'a': 2, 'number_of_elements': 3, 'creation_time': 1600000000000},
                           None,
                           [{'a': 2, 'number_of_elements': 3, 'creation_time': '2020-09-13T12:26:40+00:00'}])
                          ])
def test_sanitize_outputs(outputs, key_replace_dict, expected):
    """
    Given:
     - Outputs.
     - Dict, containing old names as keys, and new names as values.

    When:
     - Case a: Sanitizing outputs, 'key_replace_dict' exists.
     - Case b: Sanitizng outputs, 'key_replace_dict' does not exist.

    Then:
     - Case a: Ensure that outputs keys not included in 'key_replace_dict' are dismissed, and key names are changed.
     - Case b: Ensure that outputs are sanitized, but keys remains the same.
    """
    assert sanitize_outputs(outputs, key_replace_dict) == expected


def test_create_single_asset_for_offense_enrichment():
    """
    Given:
     - Asset to enrich

    When:
     - Enriching offense with asset values.

    Then:
     - Ensure enrichment asset object returned is as expected.
    """
    assets = asset_enrich_data['assets']
    enriched_assets = [create_single_asset_for_offense_enrichment(asset) for asset in assets]
    assert enriched_assets == asset_enrich_data['offense_enrich']


@pytest.mark.parametrize('status_exception, status_response, results_response, search_id, expected',
                         [(None,
                           command_test_data['search_status_get']['response'],
                           command_test_data['search_results_get']['response'],
                           '19e90792-1a17-403b-ae5b-d0e60740b95e',
                           (sanitize_outputs(command_test_data['search_results_get']['response']['events']),
                            QueryStatus.SUCCESS.value)),
                          (DemistoException('error occurred'),
                           None,
                           None,
                           None,
                           ([], QueryStatus.ERROR.value))
                          ])
def test_poll_offense_events_with_retry(mocker, requests_mock, status_exception, status_response, results_response, search_id,
                                        expected):
    """
    Given:
     - Client to perform API calls.
     - Search ID of the query to enrich events.

    When:
     - Case a: QRadar returns a valid and terminated results to the search.
     - Case b: Error occurred in request to QRadar during poll.

    Then:
     - Case a: Ensure that expected events are returned.
     - Case b: Ensure that None is returned.
    """
    mocker.patch.object(demisto, "error")
    context_data = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                    MIRRORED_OFFENSES_FINISHED_CTX_KEY: {}}
    set_integration_context(context_data)
    if status_exception:
        requests_mock.get(
            f'{client.server}/api/ariel/searches/{search_id}',
            exc=status_exception
        )
    else:
        requests_mock.get(
            f'{client.server}/api/ariel/searches/{search_id}',
            json=status_response
        )
    requests_mock.get(
        f'{client.server}/api/ariel/searches/{search_id}/results',
        json=results_response
    )
    assert poll_offense_events(client, search_id, True, 16) == expected


@pytest.mark.parametrize('search_exception, fetch_mode, search_response',
                         [(None, 'Fetch With All Events',
                           command_test_data['search_create']['response']),
                          (DemistoException('error occurred'),
                           'Fetch With All Events',
                           None),
                          (None, 'Fetch Correlation Events Only',
                           command_test_data['search_create']['response']),
                          (DemistoException('error occurred'),
                           'Fetch Correlation Events Only',
                           None)
                          ])
def test_create_search_with_retry(mocker, search_exception, fetch_mode, search_response):
    """
    Given:
     - Client to perform API calls.
     - Query for creating search in QRadar service.
    When:
     - Case a: QRadar manages to create search, fetch_mode is all events.
     - Case b: Error occurred in request to QRadar search creation, fetch_mode is all events.
     - Case c: QRadar manages to create search, fetch_mode is correlation events only.
     - Case d: Error occurred in request to QRadar search creation, fetch_mode is correlation events only.

    Then:
     - Case a: Ensure that QRadar service response is returned.
     - Case b: Ensure that None is returned.
     - Case c: Ensure that QRadar service response is returned.
     - Case d: Ensure that None is returned.
    """
    context_data = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                    MIRRORED_OFFENSES_FINISHED_CTX_KEY: {}}
    set_integration_context(context_data)
    offense = command_test_data['offenses_list']['response'][0]
    if search_exception:
        mocker.patch.object(client, "search_create", side_effect=[search_exception])
    else:
        mocker.patch.object(client, "search_create", return_value=search_response)
    expected_search_id = search_response['search_id'] if search_response else QueryStatus.ERROR.value
    assert create_search_with_retry(client, fetch_mode=fetch_mode,
                                    offense=offense,
                                    event_columns=event_columns_default_value, events_limit=20,
                                    max_retries=1) == expected_search_id


@pytest.mark.parametrize(
    'offense, fetch_mode, mock_search_response, poll_events_response, events_limit',
    [
        # success cases
        (command_test_data['offenses_list']['response'][0],
         FetchMode.correlations_events_only.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events']), ''),
         3,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.correlations_events_only.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         2,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.all_events.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events']), ''),
         3,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.all_events.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         1,
         ),

        # failure cases
        (command_test_data['offenses_list']['response'][0],
         FetchMode.correlations_events_only.value,
         None,
         None,
         3,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.correlations_events_only.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         3,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.all_events.value,
         None,
         None,
         3,
         ),
        (command_test_data['offenses_list']['response'][0],
         FetchMode.all_events.value,
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         3,
         ),
    ])
def test_enrich_offense_with_events(mocker, offense: dict, fetch_mode: FetchMode, mock_search_response: dict,
                                    poll_events_response, events_limit):
    """
    Given:
     - Offense to enrich with events.
     - Fetch modes of the events.

    When:
    Success cases:
     - Case a: Fetch mode is 'correlations_events_only', number of events returned equals to event count, lower than
               'events_limit'.
     - Case b: Fetch mode is 'correlations_events_only', number of events returned is lower than event count, but equals
               to 'events_limit'.
     - Case c: Fetch mode is 'all_events', number of events returned equals to event count, lower than 'events_limit'.
     - Case d: Fetch mode is 'all_events', number of events returned is lower than event count, but equals
               to 'events_limit'.
     Failure cases:
     - Case a: Fetch mode is 'correlations_events_only', fails to enrich offense (fails to create search).
     - Case b: Fetch mode is 'correlations_events_only', fails to enrich offense (not enough events).
     - Case c: Fetch mode is 'all_events', fails to enrich offense (fails to create search).
     - Case d: Fetch mode is 'all_events', fails to enrich offense (not enough events).


    Then:
        For success cases:
        - Ensure additional where clause is added to the query if fetch mode is 'correlations_events_only'.
        - Ensure expected events are returned.
        - Ensure expected count of events are returned.
        - Ensure poll events is queried with the expected search ID.
        For failure cases:
        - Ensure additional where clause is added to the query if fetch mode is 'correlations_events_only'.
        - Ensure empty list of events are returned.
        - Ensure poll events is queried with the expected search ID, if search ID succeeded.
    """
    offense = offense.copy()
    context_data = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                    MIRRORED_OFFENSES_FINISHED_CTX_KEY: {}}
    set_integration_context(context_data)
    poll_events = poll_events_response[0] if poll_events_response else []
    num_events = sum(event.get('eventcount', 1) for event in poll_events)
    if poll_events and num_events >= min(events_limit, offense.get('event_count')):
        events = poll_events[:min(events_limit, len(poll_events))] if poll_events else []
        num_events = sum(event.get('eventcount', 1) for event in poll_events)
        expected_offense: dict[str, list | int] = dict(offense, events=events,
                                                       events_fetched=num_events,
                                                       )
    else:
        expected_offense = dict(offense,
                                events_fetched=num_events,
                                )
        if poll_events:
            expected_offense = dict(expected_offense, events=poll_events)
    expected_id = mock_search_response['search_id'] if mock_search_response else QueryStatus.ERROR.value
    mocker.patch.object(QRadar_v3, "create_search_with_retry", return_value=expected_id)
    poll_events_mock = mocker.patch.object(QRadar_v3, "poll_offense_events_with_retry",
                                           return_value=poll_events_response)
    is_all_events_fetched = mock_search_response and ((num_events >= min(offense['event_count'], events_limit))
                                                      or (fetch_mode == FetchMode.correlations_events_only.value))
    mocker.patch.object(QRadar_v3, 'is_all_events_fetched', return_value=is_all_events_fetched)
    enriched_offense, is_success = enrich_offense_with_events(client, offense, fetch_mode, event_columns_default_value,
                                                              events_limit=events_limit)
    assert 'mirroring_events_message' in enriched_offense
    del enriched_offense['mirroring_events_message']
    if mock_search_response:
        assert is_success == is_all_events_fetched
        assert poll_events_mock.call_args[0][1] == mock_search_response['search_id']
    else:
        assert not is_success
    if not expected_offense.get('events'):
        expected_offense['events'] = []
    assert enriched_offense == expected_offense


def test_create_incidents_from_offenses():
    """
    Given:
     - List of offenses.
     - Incident type.

    When:
     - Creating incidents by the offenses with the corresponding incident type.

    Then:
     - Ensure expected incidents are created.
    """
    offenses = command_test_data['offenses_list']['enrich_offenses_result']
    assert create_incidents_from_offenses(offenses, 'QRadar Incident') == [{
        'name': f'''{offense.get('id')} {offense.get('description', '')}''',
        'rawJSON': json.dumps(offense),
        'occurred': get_time_parameter(offense.get('start_time'), iso_format=True),
        'type': 'QRadar Incident',
        'haIntegrationEventID': str(offense.get('id'))
    } for offense in offenses]


@pytest.mark.parametrize('enrich_func, mock_func_name, args, mock_response, expected',
                         [
                             (get_offense_types,
                              'offense_types',
                              {
                                  'client': client,
                                  'offenses': [{'offense_type': 1, 'offense_name': 'offense1'},
                                               {'offense_type': 2, 'offense_name': 'offense2'}]
                              },
                              [{'id': 1, 'name': 'Scheduled Search'},
                               {'id': 2, 'name': 'Destination IP Identity'}],
                              {1: 'Scheduled Search', 2: 'Destination IP Identity'}
                              ),
                             (get_offense_closing_reasons,
                              'closing_reasons_list',
                              {
                                  'client': client,
                                  'offenses': [{'closing_reason_id': 3, 'offense_name': 'offense1'},
                                               {'closing_reason_id': 4, 'offense_name': 'offense2'}]
                              },
                              [{'id': 3, 'text': 'Non-Issue'},
                               {'id': 4, 'text': 'Policy Violation'}],
                              {3: 'Non-Issue', 4: 'Policy Violation'}
                              ),
                             (get_domain_names,
                              'domains_list',
                              {
                                  'client': client,
                                  'outputs': [{'domain_id': 5, 'offense_name': 'offense1'},
                                              {'domain_id': 6, 'offense_name': 'offense2'}]
                              },
                              [{'id': 5, 'name': 'domain1'},
                               {'id': 6, 'name': 'domain2'}],
                              {5: 'domain1', 6: 'domain2'}
                              ),
                             (get_rules_names,
                              'rules_list',
                              {
                                  'client': client,
                                  'offenses': [{'rules': [{'id': 7}, {'id': 8}], 'offense_name': 'offense1'},
                                               {'rules': [{'id': 9}], 'offense_name': 'offense2'}]
                              },
                              [{'id': 7, 'name': 'Devices with High Event Rates'},
                               {'id': 8, 'name': 'Excessive Database Connections'},
                               {'id': 9, 'name': 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}],
                              {7: 'Devices with High Event Rates',
                               8: 'Excessive Database Connections',
                               9: 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}
                              ),
                             (get_offense_addresses,
                              'get_addresses',
                              {
                                  'client': client,
                                  'offenses': [{'source_address_ids': [1, 2], 'offense_name': 'offense1'},
                                               {'source_address_ids': [3, 4], 'offense_name': 'offense2'}],
                                  'is_destination_addresses': False
                              },
                              [{'id': 1, 'source_ip': '1.2.3.4'},
                               {'id': 2, 'source_ip': '1.2.3.5'},
                               {'id': 3, 'source_ip': '192.168.1.3'},
                               {'id': 4, 'source_ip': '192.168.0.2'}],
                              {1: '1.2.3.4',
                               2: '1.2.3.5',
                               3: '192.168.1.3',
                               4: '192.168.0.2'}
                              ),
                             (get_offense_addresses,
                              'get_addresses',
                              {
                                  'client': client,
                                  'offenses': [
                                      {'local_destination_address_ids': [1, 2], 'offense_name': 'offense1'},
                                      {'local_destination_address_ids': [3, 4], 'offense_name': 'offense2'}],
                                  'is_destination_addresses': True
                              },
                              [{'id': 1, 'local_destination_ip': '1.2.3.4'},
                               {'id': 2, 'local_destination_ip': '1.2.3.5'},
                               {'id': 3, 'local_destination_ip': '192.168.1.3'},
                               {'id': 4, 'local_destination_ip': '192.168.0.2'}],
                              {1: '1.2.3.4',
                               2: '1.2.3.5',
                               3: '192.168.1.3',
                               4: '192.168.0.2'}
                              ),
                             (enrich_offense_with_assets,
                              'assets_list',
                              {
                                  'client': client,
                                  'offense_ips': ['8.8.8.8', '1.1.1.1', '2.2.2.2']
                              },
                              asset_enrich_data['assets'],
                              asset_enrich_data['offense_enrich']
                              ),
                             (enrich_assets_results,
                              'domains_list',
                              {
                                  'client': client,
                                  'assets': asset_enrich_data['assets'],
                                  'full_enrichment': asset_enrich_data['case_one']['full_enrichment']
                              },
                              asset_enrich_data['domain_mock_response'],
                              asset_enrich_data['case_one']['expected']
                              ),
                             (enrich_assets_results,
                              'domains_list',
                              {
                                  'client': client,
                                  'assets': asset_enrich_data['assets'],
                                  'full_enrichment': asset_enrich_data['case_two']['full_enrichment']
                              },
                              asset_enrich_data['domain_mock_response'],
                              asset_enrich_data['case_two']['expected']
                              ),

                             # Empty cases
                             (get_offense_types,
                              'offense_types',
                              {
                                  'client': client,
                                  'offenses': [{'offense_name': 'offense1'},
                                               {'offense_name': 'offense2'}],
                              },
                              None,
                              {}
                              ),
                             (get_offense_closing_reasons,
                              'closing_reasons_list',
                              {
                                  'client': client,
                                  'offenses': [{'offense_name': 'offense1'},
                                               {'offense_name': 'offense2'}],
                              },
                              None,
                              {}
                              ),
                             (get_domain_names,
                              'domains_list',
                              {
                                  'client': client,
                                  'outputs': [{'offense_name': 'offense1'},
                                              {'offense_name': 'offense2'}],
                              },
                              None,
                              {}
                              ),
                             (get_rules_names,
                              'rules_list',
                              {
                                  'client': client,
                                  'offenses': [{'offense_name': 'offense1'},
                                               {'offense_name': 'offense2'}],
                              },
                              None,
                              {}
                              ),
                             (get_offense_addresses,
                              'get_addresses',
                              {
                                  'client': client,
                                  'offenses': [{'source_address_ids': [], 'offense_name': 'offense1'},
                                               {'source_address_ids': [], 'offense_name': 'offense2'}],
                                  'is_destination_addresses': False
                              },
                              None,
                              {}
                              ),
                             (get_offense_addresses,
                              'get_addresses',
                              {
                                  'client': client,
                                  'offenses': [{'local_destination_address_ids': [], 'offense_name': 'offense1'},
                                               {'local_destination_address_ids': [], 'offense_name': 'offense2'}],
                                  'is_destination_addresses': True
                              },
                              None,
                              {}
                              ),
                             (enrich_assets_results,
                              'domains_list',
                              {
                                  'client': client,
                                  'assets': asset_enrich_data['empty_case']['assets'],
                                  'full_enrichment': False
                              },
                              asset_enrich_data['domain_mock_response'],
                              asset_enrich_data['empty_case']['expected_basic_enrichment']
                              ),
                             (enrich_assets_results,
                              'domains_list',
                              {
                                  'client': client,
                                  'assets': asset_enrich_data['empty_case']['assets'],
                                  'full_enrichment': True
                              },
                              asset_enrich_data['domain_mock_response'],
                              asset_enrich_data['empty_case']['expected_full_enrichment']
                              )
                         ])
def test_outputs_enriches(mocker, enrich_func, mock_func_name, args, mock_response, expected):
    """
    Given:
     - Function to do enrichment.
     - List of outputs.

    When:
     - Calling function to return the dict containing values of the enrichment.

    Then:
     - Ensure dict containing the enrichment is as expected.
    """
    mocker.patch.object(client, mock_func_name, return_value=mock_response)
    res = enrich_func(**args)
    assert res == expected


@pytest.mark.parametrize('command_func, command_name',
                         [
                             (qradar_closing_reasons_list_command, 'closing_reasons_list'),
                             (qradar_offense_notes_list_command, 'offense_notes_list'),
                             (qradar_offense_notes_create_command, 'offense_notes_create'),
                             (qradar_rules_list_command, 'rules_list'),
                             (qradar_rule_groups_list_command, 'rule_groups_list'),
                             (qradar_saved_searches_list_command, 'saved_searches_list'),
                             (qradar_searches_list_command, 'searches_list'),
                             (qradar_search_create_command, 'search_create'),
                             (qradar_search_status_get_command, 'search_status_get'),
                             (qradar_search_results_get_command, 'search_results_get'),
                             (qradar_search_cancel_command, 'search_cancel'),
                             (qradar_reference_sets_list_command, 'reference_sets_list'),
                             (qradar_reference_set_create_command, 'reference_set_create'),
                             (qradar_reference_set_delete_command, 'reference_set_delete'),
                             (qradar_reference_set_value_delete_command, 'reference_set_value_delete'),
                             (qradar_reference_set_value_upsert_command, 'reference_set_bulk_load'),
                             (qradar_domains_list_command, 'domains_list'),
                             (qradar_geolocations_for_ip_command, 'geolocations_for_ip'),
                             (qradar_get_custom_properties_command, 'custom_properties'),
                             (qradar_remote_network_cidr_list_command, 'get_remote_network_cidr'),
                             (qradar_remote_network_cidr_update_command, 'create_and_update_remote_network_cidr'),
                             (qradar_remote_network_deploy_execution_command, 'remote_network_deploy_execution'),
                             (qradar_indicators_upload_command, 'reference_set_bulk_load')
                         ])
def test_commands(mocker, command_func: Callable[[Client, dict], CommandResults], command_name: str):
    """
    Given:
     - Command function.
     - Demisto arguments.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    mocker.patch.object(QRadar_v3.ScheduledCommand, "raise_error_if_not_supported")
    args = command_test_data[command_name].get('args', {})
    response = command_test_data[command_name]['response']
    expected = command_test_data[command_name]['expected']
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs'),
        raw_response=response
    )
    mocker.patch.object(client, command_name, return_value=response)
    if command_func == qradar_search_create_command:
        results = command_func(client, {}, args)
    elif command_func == qradar_reference_set_value_upsert_command:
        results = command_func(args, client, {"api_version": "14"})
    elif command_func == qradar_indicators_upload_command:
        mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={
            "iocs": [{"value": "test1", "indicator_type": "ip"},
                     {"value": "test2", "indicator_type": "ip"},
                     {"value": "test3", "indicator_type": "ip"}]})
        mocker.patch.object(client, "reference_sets_list")
        results = command_func(args, client, {"api_version": "14"})

    else:
        results = command_func(client, args)

    assert results.outputs_prefix == expected_command_results.outputs_prefix
    assert results.outputs_key_field == expected_command_results.outputs_key_field
    assert results.outputs == expected_command_results.outputs
    assert results.raw_response == expected_command_results.raw_response


@pytest.mark.parametrize('command_func, command_name, enrichment_func_name',
                         [(qradar_offenses_list_command, 'offenses_list', 'enrich_offenses_result'),
                          (qradar_offense_update_command, 'offense_update', 'enrich_offenses_result'),
                          (qradar_assets_list_command, 'assets_list', 'enrich_assets_results')
                          ])
def test_commands_with_enrichment(mocker, command_func: Callable[[Client, dict], CommandResults], command_name: str,
                                  enrichment_func_name: str):
    """
    Given:
     - Command function that requires another API calls for enrichment.
     - Demisto arguments.

    When:
     - Executing a command.

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    response = command_test_data[command_name]['response']
    expected = command_test_data[command_name]['expected']
    args = command_test_data[command_name].get('args', {})
    enriched_response = command_test_data[command_name][enrichment_func_name]
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs'),
        raw_response=response
    )
    mocker.patch.object(client, command_name, return_value=response)
    mocked_enrich = mocker.patch.object(QRadar_v3, enrichment_func_name, return_value=enriched_response)

    results = command_func(client, args)

    assert mocked_enrich.call_args[0][1] == response

    assert results.outputs_prefix == expected_command_results.outputs_prefix
    assert results.outputs_key_field == expected_command_results.outputs_key_field
    assert results.outputs == expected_command_results.outputs
    assert results.raw_response == expected_command_results.raw_response


def mock_mirroring_response(filter_, **kwargs):
    if "status=closed" in filter_:
        return list(filter(lambda x: x['status'] == 'CLOSED', command_test_data['get_modified_remote_data']['response']))
    else:
        return list(filter(lambda x: x['status'] != 'CLOSED', command_test_data['get_modified_remote_data']['response']))


def test_get_modified_remote_data_command(mocker):
    """
    Given:
     - QRadar client.
     - Demisto arguments.

    When:
     - Command 'get-modified-remote-data' is being called.

    Then:
     - Ensure that command outputs the IDs of the offenses to update.
    """
    set_integration_context({MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                             MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                             'last_update': 1})
    expected = GetModifiedRemoteDataResponse(list(map(str, command_test_data['get_modified_remote_data']['outputs'])))
    mocker.patch.object(client, 'offenses_list', side_effect=mock_mirroring_response)
    result = get_modified_remote_data_command(client, {}, command_test_data['get_modified_remote_data']['args'])
    assert {int(id_) for id_ in expected.modified_incident_ids} == {int(id_) for id_ in result.modified_incident_ids}


@pytest.mark.parametrize('params, offense, enriched_offense, note_response, expected',
                         [
                             ({}, command_test_data['get_remote_data']['response'],
                              command_test_data['get_remote_data']['enrich_offenses_result'],
                              None,
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_offenses_result'])[0],
                                  [])),

                             ({}, command_test_data['get_remote_data']['closed'],
                              command_test_data['get_remote_data']['enrich_closed_offense'],
                              None,
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_closed_offense'])[0],
                                  [])),

                             ({'close_incident': True}, command_test_data['get_remote_data']['closed'],
                              command_test_data['get_remote_data']['enrich_closed_offense'],
                              [],
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_closed_offense'])[0],
                                  [{
                                      'Type': EntryType.NOTE,
                                      'Contents': {
                                          'dbotIncidentClose': True,
                                          'closeReason': 'False-Positive, Tuned',
                                          'closeNotes': 'From QRadar: False-Positive, Tuned'
                                      },
                                      'ContentsFormat': EntryFormat.JSON
                                  }])),

                             ({'close_incident': True}, command_test_data['get_remote_data']['closed'],
                              command_test_data['get_remote_data']['enrich_closed_offense'],
                              [{'note_text': 'This offense was closed with reason: False-Positive, Tuned.'}],
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_closed_offense'])[0],
                                  [{
                                      'Type': EntryType.NOTE,
                                      'Contents': {
                                          'dbotIncidentClose': True,
                                          'closeReason': 'False-Positive, Tuned',
                                          'closeNotes': 'From QRadar: This offense was closed with reason: '
                                                         'False-Positive, Tuned.',
                                      },
                                      'ContentsFormat': EntryFormat.JSON
                                  }])),

                             ({'close_incident': True}, command_test_data['get_remote_data']['closed'],
                              command_test_data['get_remote_data']['enrich_closed_offense'],
                              [{'note_text': 'This offense was closed with reason: False-Positive, Tuned. Notes: '
                                             'Closed because it is on our white list.'}],
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_closed_offense'])[0],
                                  [{
                                      'Type': EntryType.NOTE,
                                      'Contents': {
                                          'dbotIncidentClose': True,
                                          'closeReason': 'False-Positive, Tuned',
                                          'closeNotes': 'From QRadar: This offense was closed with reason: '
                                                         'False-Positive, Tuned. Notes: Closed because it is on our '
                                                         'white list.',
                                      },
                                      'ContentsFormat': EntryFormat.JSON
                                  }]))
                         ])
def test_get_remote_data_command(mocker, params, offense: dict, enriched_offense, note_response,
                                 expected: GetRemoteDataResponse):
    """
    Given:
     - QRadar client.
     - Demisto params.
     - Demisto arguments.

    When:
     - Case a: Offense updated, not closed, no events.
     - Case b: Offense updated, closed, no events, close_incident is false.
     - Case c: Offense updated, closed, no events, close_incident is true, close was made through API call (no note).
     - Case d: Offense updated, closed, no events, close_incident is true, close was made through QRadar UI, empty note.
     - Case e: Offense updated, closed, no events, close_incident is true, close was made through QRadar UI, with note.

    Then:
     - Case a: Ensure that offense is returned as is.
     - Case b: Ensure that offense is returned as is.
     - Case c: Ensure that offense is returned, along with expected entries.
     - Case d: Ensure that offense is returned, along with expected entries.
     - Case e: Ensure that offense is returned, along with expected entries.
    """
    set_integration_context({MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                             MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                             'last_update': 1})
    mocker.patch.object(client, 'offenses_list', return_value=offense)
    mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=enriched_offense)
    if 'close_incident' in params:
        mocker.patch.object(client, 'closing_reasons_list',
                            return_value=command_test_data['closing_reasons_list']['response'][0])
    if note_response is not None:
        mocker.patch.object(client, 'offense_notes_list', return_value=note_response)
    result = get_remote_data_command(client, params, {'id': offense.get('id'), 'lastUpdate': 1})
    expected.mirrored_object['last_mirror_in_time'] = result.mirrored_object['last_mirror_in_time']
    expected.mirrored_object['events_fetched'] = 0
    assert result.mirrored_object == expected.mirrored_object
    assert result.entries == expected.entries


@pytest.mark.parametrize('ip_address, expected', [('1.2.3.4', True), ('1.2.3.4.765', False), ('', False),
                                                  ('192.0.0.1', True), ('::1', True),
                                                  ('2001:0db8:0a0b:12f0:0000:0000:0000:0001', True), ('1', False)])
def test_is_valid_ip(ip_address: str, expected: bool):
    """
    Given:
     - IP address returned by QRadar, could be valid and could be invalid.

    When:
     - Checking whether IP is valid or not.

    Then:
     - Ensure expected bool is returned indicating whether IP is valid.
    """
    assert is_valid_ip(ip_address) == expected


def test_validate_long_running_params():
    """
    Given:
     - Cortex XSOAR params.

    When:
     - Running long running execution.

    Then:
     - Ensure that error is thrown.
    """
    from QRadar_v3 import validate_long_running_params, LONG_RUNNING_REQUIRED_PARAMS
    for param_name, _param_value in LONG_RUNNING_REQUIRED_PARAMS.items():
        params_without_required_param = {k: v for k, v in LONG_RUNNING_REQUIRED_PARAMS.items() if k is not param_name}
        with pytest.raises(DemistoException):
            validate_long_running_params(params_without_required_param)


@pytest.mark.parametrize('command_func, command_name',
                         [
                             (qradar_ips_source_get_command, 'source_ip'),
                             (qradar_ips_local_destination_get_command, 'local_destination')
                         ])
def test_ip_commands(mocker, command_func: Callable[[Client, dict], CommandResults], command_name: str):
    """
    Given:
     - Command function.
     - Demisto arguments.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    args = {}
    response = ip_command_test_data[command_name]['response']
    expected = ip_command_test_data[command_name]['expected']
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs'),
        raw_response=response
    )
    mocker.patch.object(client, 'get_addresses', return_value=response)

    results = command_func(client, args)

    assert results.outputs_prefix == expected_command_results.outputs_prefix
    assert results.outputs_key_field == expected_command_results.outputs_key_field
    assert results.outputs == expected_command_results.outputs
    assert results.raw_response == expected_command_results.raw_response


class MockResults:
    def __init__(self, value):
        self.value = value

    def result(self, timeout=None):
        return self.value


def test_get_modified_with_events(mocker):
    """
    Given:
        Context data with mirrored offenses, queried and finished.

    When:
        Calling get_modified_with_events.

    Then:
        Ensure that finished queries goes to finished queue,
        and modified incidents returns the modified offenses and the finished queries.
    """
    context_data = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {'1': '123', '2': '456', '10': QueryStatus.WAIT.value},
                    MIRRORED_OFFENSES_FINISHED_CTX_KEY: {'3': '789', '4': '012'}, MIRRORED_OFFENSES_FETCHED_CTX_KEY: {}}
    expected_updated_context = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {'2': '456', '10': '555'},
                                MIRRORED_OFFENSES_FINISHED_CTX_KEY: {'3': '789', '4': '012', '1': '123'},
                                LAST_MIRROR_KEY: 3444, MIRRORED_OFFENSES_FETCHED_CTX_KEY: {}, LAST_MIRROR_CLOSED_KEY: 3444}
    set_integration_context(context_data)
    status = {'123': {'status': 'COMPLETED'},
              '456': {'status': 'WAIT'},
              '555': {'status': 'PENDING'}}

    mocker.patch.object(client, 'offenses_list', return_value=[{'id': 6, 'last_persisted_time': "3444", 'close_time': '3444'}])
    mocker.patch.object(QRadar_v3, 'create_events_search', return_value='555')
    mocker.patch.object(client, 'search_status_get', side_effect=lambda offense_id: status[offense_id])
    modified = get_modified_remote_data_command(client,
                                                {'mirror_options': MIRROR_OFFENSE_AND_EVENTS},
                                                {'lastUpdate': '0'})
    assert set(modified.modified_incident_ids) == {'1', '6'}
    assert get_integration_context() == expected_updated_context


@pytest.mark.parametrize('offense_id', ['1', '2', '3', '4', '5', '10'])
def test_remote_data_with_events(mocker, offense_id):
    """
    Given:
        - Offense ID.

    When:
        - Calling get_remote_data_command with offense ID after `get-modified`

    Then:
        - Ensure that the offense data is returned and context_data is updated.
    """
    context_data = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {'1': '123', '2': '456', '10': QueryStatus.WAIT.value},
                    MIRRORED_OFFENSES_FINISHED_CTX_KEY: {'3': '789', '4': '012'}, MIRRORED_OFFENSES_FETCHED_CTX_KEY: {}}
    set_integration_context(copy.deepcopy(context_data))

    mocker.patch.object(QRadar_v3, 'create_events_search', return_value='555')

    # we expect the total events fetched to be the sum of `eventcount`, meaning 5 + int(offense_id)
    events = {'events':
              [{'eventcount': int(offense_id)},
               {'eventcount': 2},
               {'eventcount': 3}]}
    mocker.patch.object(client, 'search_results_get', return_value=events)
    mocker.patch.object(client, 'search_status_get', return_value={'status': 'EXECUTE'})
    offense = {'id': offense_id}
    mocker.patch.object(client, 'offenses_list', return_value=offense)
    if offense_id in context_data[MIRRORED_OFFENSES_FINISHED_CTX_KEY]:
        offense_data = get_remote_data_command(client,
                                               {'mirror_options': MIRROR_OFFENSE_AND_EVENTS},
                                               {'id': offense_id,
                                                'lastUpdate': '0'}).mirrored_object

    else:
        # if not finished we expect to get an exception
        with pytest.raises(DemistoException):
            get_remote_data_command(client,
                                    {'mirror_options': MIRROR_OFFENSE_AND_EVENTS},
                                    {'id': offense_id,
                                     'lastUpdate': '0'})

    updated_context = get_integration_context()
    if offense_id in context_data[MIRRORED_OFFENSES_FINISHED_CTX_KEY]:
        # offense is already finished, so we expect it to being deleted from the context
        assert offense_id not in updated_context[MIRRORED_OFFENSES_FINISHED_CTX_KEY]
        assert offense_data.get('events') == events['events']
        expected_events_fetched = 5 + int(offense_id)
        assert offense_data.get('events_fetched') == expected_events_fetched
        assert updated_context[MIRRORED_OFFENSES_FETCHED_CTX_KEY][offense_id] == expected_events_fetched

    elif offense_id not in context_data[MIRRORED_OFFENSES_QUERIED_CTX_KEY] or \
            (offense_id in context_data[MIRRORED_OFFENSES_QUERIED_CTX_KEY]
             and context_data[MIRRORED_OFFENSES_QUERIED_CTX_KEY][offense_id] == QueryStatus.WAIT.value):
        # offense is not yet queried, so we expect it to be added to the context
        assert updated_context[MIRRORED_OFFENSES_QUERIED_CTX_KEY][offense_id] == '555'
    else:
        # offense is unchanged, so we expect it to be unchanged in the context
        assert offense_id in updated_context[MIRRORED_OFFENSES_QUERIED_CTX_KEY]


def test_qradar_remote_network_cidr_create_command(mocker):
    """
    Given:
        - A network CIDR to create.

    When:
        - Calling qradar_remote_network_cidr_create_command.

    Then:
        - Ensure the correct request was called and the correct response is returned.
    """
    expected_response_from_api = {'name': 'test_name',
                                  'description': 'description',
                                  'cidrs': ['1.2.3.4/32', '8.8.8.8/24'],
                                  'id': 12,
                                  'group': 'test_group'}

    mocker.patch.object(client, 'create_and_update_remote_network_cidr', return_value=expected_response_from_api)

    res = qradar_remote_network_cidr_create_command(client, {'name': 'test_name',
                                                             'description': 'description',
                                                             'cidrs': '1.2.3.4/32,8.8.8.8/24',
                                                             'group': 'test_group'})

    assert expected_response_from_api == res.raw_response
    assert '| description | test_group | 12 | test_name |' in res.readable_output


def test_qradar_remote_network_cidr_delete_command(mocker):
    expected_command_result = command_test_data['remote_network_cidr_delete']['readable_output']

    mocker.patch.object(client, 'delete_remote_network_cidr', return_value=b'')
    result = qradar_remote_network_cidr_delete_command(client, {'id': '46'})

    assert result.readable_output == expected_command_result


@pytest.mark.parametrize('mirror_options', [MIRROR_OFFENSE_AND_EVENTS, ""])
@pytest.mark.parametrize('test_case_data',
                         [(ctx_test_data['ctx_compatible']['empty_ctx_no_mirroring_two_loops_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offense_two_loops_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offense_and_events_two_loops_offenses']),
                          (ctx_test_data['ctx_compatible']['no_mirroring_two_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_two_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_and_events_two_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_no_mirroring_first_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offense_first_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offense_and_events_first_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['no_mirroring_first_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_first_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_and_events_first_offenses_loop']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_no_mirroring_second_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offenses_second_loop_offenses']),
                          (
                          ctx_test_data['ctx_compatible']['empty_ctx_mirror_offenses_and_events_second_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['no_mirroring_second_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['mirror_offenses_second_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['mirror_offenses_and_events_second_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_no_mirroring_no_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offenses_no_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['empty_ctx_mirror_offenses_and_events_no_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['no_mirroring_no_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_no_loop_offenses']),
                          (ctx_test_data['ctx_compatible']['mirror_offense_and_events_no_loop_offenses']),
                          ])
def test_integration_context_during_run(mirror_options, test_case_data, mocker):
    """
    Given:
    - Cortex XSOAR parameters.

    When:
    - Performing `long-running-execution` command

    Then:
    - Assure the whole flow of managing the context is as expected.
    1) Call to change_ctx_to_be_compatible_with_retry is performed.
    2) Resetting the mirroring events variables.
    3) Performing long-running loop.
    4) Assuring context is as expected after first loop.
    5) Performing another long-running loop.
    6) Assure context is as expected after the second loop.

    Cases:
    a) Integration ctx is empty (first instance run), no mirroring.
    b) Integration ctx is empty (first instance run), mirroring of offense only.
    c) Integration ctx is empty (first instance run), mirroring offense with events.
    a, b, c are only relevant for cases where the integration context is compatible with retries, as empty integration
    context is always compatible with retries.
    d) Integration context is not empty, no mirroring.
    e) Integration context is not empty, mirroring of offense only.
    f) Integration context is not empty, mirroring offense with events.

    All those cases will be tested where:
    A) With init integration context not compatible with retry.
    B) With init integration context compatible with retry.
    And for one of A, B, checks the following:
        1) In both loop runs, offenses were fetched.
        2) Only in first loop run offenses were fetched.
        3) Only in second loop run offenses were fetched.
        4) In both loop runs no offenses were fetched.
    """
    mirror_direction = test_case_data['mirror_direction']

    init_context = test_case_data['init_context'].copy()
    init_context |= {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                     MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                     MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
                     LAST_FETCH_KEY: init_context.get(LAST_FETCH_KEY, 0),
                     'samples': init_context.get('samples', [])}

    set_integration_context(init_context)
    if is_offenses_first_loop := test_case_data['offenses_first_loop']:
        first_loop_offenses_with_success = ctx_test_data['offenses_first_loop']
        first_loop_offenses_with_events = [(dict(offense, events=ctx_test_data['events']), is_success) for offense, is_success in
                                           first_loop_offenses_with_success]
        first_loop_offenses = [offense for offense, _ in first_loop_offenses_with_success]
        mocker.patch.object(client, 'offenses_list', return_value=first_loop_offenses)
        mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=first_loop_offenses)
        enrich_mock = mocker.patch.object(QRadar_v3, 'enrich_offense_with_events')
        enrich_mock.side_effect = first_loop_offenses_with_events
        expected_ctx_first_loop = ctx_test_data['context_data_first_loop_default'].copy()
    else:
        mocker.patch.object(client, 'offenses_list', return_value=[])
        expected_ctx_first_loop = ctx_test_data['context_data_after_retry_compatible'].copy()

    first_loop_ctx_not_default_values = test_case_data.get('first_loop_ctx_not_default_values', {})
    for k, v in first_loop_ctx_not_default_values.items():
        expected_ctx_first_loop[k] = v

    perform_long_running_loop(
        client=client,
        offenses_per_fetch=2,
        fetch_mode='Fetch With All Events',
        user_query='id > 5',
        events_columns='QIDNAME(qid), LOGSOURCENAME(logsourceid)',
        events_limit=3,
        ip_enrich=False,
        asset_enrich=False,
        incident_type=None,
        mirror_direction=mirror_direction,
        first_fetch='3 days',
        mirror_options=mirror_options,
        assets_limit=100,
        long_running_container_id="12345"
    )
    expected_ctx_first_loop |= {MIRRORED_OFFENSES_QUERIED_CTX_KEY:
                                {'15': QueryStatus.WAIT.value} if mirror_options and is_offenses_first_loop else {},
                                MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                                MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
                                LAST_FETCH_KEY: expected_ctx_first_loop.get(LAST_FETCH_KEY, 0),
                                'samples': expected_ctx_first_loop.get('samples', [])}

    current_context = get_integration_context()

    assert current_context == expected_ctx_first_loop

    if test_case_data['offenses_second_loop']:
        second_loop_offenses_with_success = ctx_test_data['offenses_second_loop']
        second_loop_offenses_with_events = [(dict(offense, events=ctx_test_data['events']), is_success) for offense, is_success in
                                            second_loop_offenses_with_success]
        second_loop_offenses = [offense for offense, _ in second_loop_offenses_with_success]
        mocker.patch.object(client, 'offenses_list', return_value=second_loop_offenses)
        mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=second_loop_offenses)
        enrich_mock = mocker.patch.object(QRadar_v3, 'enrich_offense_with_events')
        enrich_mock.side_effect = second_loop_offenses_with_events
        expected_ctx_second_loop = ctx_test_data['context_data_second_loop_default'].copy()
    else:
        mocker.patch.object(client, 'offenses_list', return_value=[])
        expected_ctx_second_loop = expected_ctx_first_loop
    perform_long_running_loop(
        client=client,
        offenses_per_fetch=2,
        fetch_mode='Fetch With All Events',
        user_query='id > 15',
        events_columns='QIDNAME(qid), LOGSOURCENAME(logsourceid)',
        events_limit=3,
        ip_enrich=False,
        asset_enrich=False,
        incident_type=None,
        mirror_direction=mirror_direction,
        first_fetch='3 days',
        mirror_options=mirror_options,
        assets_limit=100,
        long_running_container_id="12345"
    )
    second_loop_ctx_not_default_values = test_case_data.get('second_loop_ctx_not_default_values', {})
    for k, v in second_loop_ctx_not_default_values.items():
        expected_ctx_second_loop[k] = v

    expected_ctx_second_loop |= {MIRRORED_OFFENSES_QUERIED_CTX_KEY:
                                 {'15': QueryStatus.WAIT.value} if mirror_options and is_offenses_first_loop else {},
                                 MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                                 MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
                                 LAST_FETCH_KEY: expected_ctx_second_loop.get(LAST_FETCH_KEY, 0),
                                 'samples': expected_ctx_second_loop.get('samples', [])}

    current_context = get_integration_context()
    assert current_context == expected_ctx_second_loop
    set_integration_context({})


def test_convert_ctx():
    """
    Given: Old context structure

    When: Calling to update structure

    Then: New structure is returned
    """
    new_context = migrate_integration_ctx(ctx_test_data.get('old_ctxs')[0])
    expected = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
                LAST_FETCH_KEY: 15,
                LAST_MIRROR_KEY: 0,
                'samples': [],
                }
    assert new_context == expected


def test_convert_ctx_to_new_structure():
    context = {LAST_FETCH_KEY: '15',
               LAST_MIRROR_KEY: '0',
               'samples': '[]'}
    set_integration_context(context)
    validate_integration_context()
    assert get_integration_context() == {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                                         MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                                         MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
                                         LAST_FETCH_KEY: 15,
                                         LAST_MIRROR_KEY: 0,
                                         'samples': []}


@pytest.mark.parametrize('query, expected', [
    ('', []),
    ('cidr', ['1.2.3.4/32', '5.6.7.8/2'])
])
def test_get_cidrs_indicators(query, expected, mocker):
    """
    Given: A query to get cidr indicators

    When: Calling the function

    Then: Extract and return a clean list of cidrs only
    """
    mocker.patch.object(demisto, 'searchIndicators', return_value={'iocs': [
        {'id': '14', 'version': 1, 'indicator_type': 'CIDR', 'value': '1.2.3.4/32'},
        {'id': '12', 'version': 1, 'indicator_type': 'CIDR', 'value': '5.6.7.8/2'},
    ]})

    assert get_cidrs_indicators(query) == expected


VERIFY_MESSAGES_ERRORS = [
    'Cannot specify both cidrs and query arguments.',
    'Must specify either cidrs or query arguments.',
    '1.2.3.4 is not a valid CIDR.',
    'Name and group arguments only allow letters, numbers, \'_\' and \'-\'.',
    "cidr is not a valid field. Possible fields are: ['id', 'name', 'group', 'cidrs', 'description']."
]


@pytest.mark.parametrize('cidrs_list, cidrs_from_query, name, group, fields, expected', [
    (['1.2.3.4/32', '5.6.7.8/2'], ['8.8.8.8/12'], 'test1', 'test_group1', '', VERIFY_MESSAGES_ERRORS[0]),
    ([], [], 'test2', 'test_group2', '', VERIFY_MESSAGES_ERRORS[1]),
    (['1.2.3.4'], [], 'test3', 'test_group3', '', VERIFY_MESSAGES_ERRORS[2]),
    (['1.2.3.4/32'], [], 'test4!', 'test_group4', '', VERIFY_MESSAGES_ERRORS[3]),
    (['1.2.3.4/32'], [], 'test5', 'test_group5!', '', VERIFY_MESSAGES_ERRORS[3]),
    (['1.2.3.4/32'], [], 'test9', 'test_group9', 'id,cidr', VERIFY_MESSAGES_ERRORS[4]),
])
def test_verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields, expected):
    """
    Given: Command arguments

    When: Calling to verify arguments

    Then: Verify that the correct error message is returned
    """
    error_message = verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields)

    assert error_message == expected


@pytest.mark.parametrize('values, expected', [
    ([50, 2, 25], True),
    ([None, 2, None], True),
    ([None, None, 0], False),
    ([4, -5], False),
    ([None], True)
])
def test_is_positive(values, expected):
    assert is_positive(*values) == expected


VERIFY_LIST_MESSAGES_ERRORS = [
    'Please provide either limit argument or page and page_size arguments.',
    'Please provide both page and page_size arguments.',
    'Limit, page and page_size arguments must be positive numbers.',
    'You can not use filter argument with group, id or name arguments.'
]


@pytest.mark.parametrize('limit, page, page_size, filter_, group, id_, name, expected', [
    (50, 2, 25, None, None, None, None, VERIFY_LIST_MESSAGES_ERRORS[0]),
    (None, 2, None, None, None, None, None, VERIFY_LIST_MESSAGES_ERRORS[1]),
    (None, None, 25, None, None, None, None, VERIFY_LIST_MESSAGES_ERRORS[1]),
    (-1, None, None, None, None, None, None, VERIFY_LIST_MESSAGES_ERRORS[2]),
    (None, -1, -1, None, None, None, None, VERIFY_LIST_MESSAGES_ERRORS[2]),
    (None, None, None, 'test', 'test', 'test', 'test', VERIFY_LIST_MESSAGES_ERRORS[3])
])
def test_verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name, expected):
    """
    Given: Command arguments

    When: Calling to verify arguments

    Then: Verify that the correct error message is returned
    """
    error_message = verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name)

    assert error_message == expected


@pytest.mark.parametrize("api_version", ("16.2", "17.0"))
@pytest.mark.parametrize("status", ("COMPLETED", "IN_PROGRESS"))
@pytest.mark.parametrize("func", (qradar_reference_set_value_upsert_command, qradar_indicators_upload_command))
def test_reference_set_upsert_commands_new_api(mocker, api_version, status, func):
    """
    Given:
        - A reference set name and data to upload

    When:
        - Calling the reference set upsert command or the indicators upload command

    Then:
        - Verify that the correct API is used.
        - Verify that the data is returned if the status is COMPLETED.
        - Verify that the task id is returned if the status is IN_PROGRESS.
    """
    if func == qradar_indicators_upload_command:
        mocker.patch.object(client, "reference_sets_list")
        mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={
                            "iocs": [{"value": "test1", "indicator_type": "ip"},
                                     {"value": "test2", "indicator_type": "ip"},
                                     {"value": "test3", "indicator_type": "ip"}]})

    mocker.patch.object(QRadar_v3.ScheduledCommand, "raise_error_if_not_supported")
    mocker.patch.object(client, "reference_set_entries", return_value={"id": 1234})
    mocker.patch.object(client, "get_reference_data_bulk_task_status", return_value={"status": status})
    response = command_test_data["reference_set_bulk_load"]['response']
    mocker.patch.object(client, "reference_sets_list", return_value=response)
    args = {"ref_name": "test_ref"}
    if func == qradar_reference_set_value_upsert_command:
        args["value"] = "test1,test2,test3"
    results = func(
        args, client, {"api_version": api_version}
    )
    if status == "COMPLETED":

        expected = command_test_data["reference_set_bulk_load"]['expected']
        expected_command_results = CommandResults(
            outputs_prefix=expected.get('outputs_prefix'),
            outputs_key_field=expected.get('outputs_key_field'),
            outputs=expected.get('outputs'),
            raw_response=response
        )

        assert results.outputs_prefix == expected_command_results.outputs_prefix
        assert results.outputs_key_field == expected_command_results.outputs_key_field
        assert results.outputs == expected_command_results.outputs
        assert results.raw_response == expected_command_results.raw_response

    else:
        assert results.readable_output == 'Reference set test_ref is still being updated in task 1234'
        assert results.scheduled_command._args.get('task_id') == 1234


def test_qradar_reference_set_value_upsert_command_continue_polling_with_connection_issues(mocker):
    """
    Given:
        - get_reference_data_bulk_task_status that returns ReadTimeout exception, IN_PROGRESS and COMPLETED statuses

    When:
        - qradar_reference_set_value_upsert_command function

    Then:
        - Verify the command would keep polling when there are temporary connection issues.
    """
    mocker.patch.object(QRadar_v3.ScheduledCommand, "raise_error_if_not_supported")
    mocker.patch.object(client, "reference_set_entries", return_value={"id": 1234})
    mocker.patch.object(client, "get_reference_data_bulk_task_status", side_effect=[
                        ReadTimeout, {"status": "IN_PROGRESS"}, {"status": "COMPLETED"}])
    args = {"ref_name": "test_ref", "value": "value1"}
    api_version = {"api_version": "17.0"}
    mocker.patch.object(client, "reference_sets_list", return_value=command_test_data["reference_set_bulk_load"]['response'])

    result = qradar_reference_set_value_upsert_command(args, client=client, params=api_version)
    # make sure in ReadTimeout that no outputs are returned
    assert not result.outputs
    result = qradar_reference_set_value_upsert_command(args, client=client, params=api_version)
    # make sure when status is IN_PROGRESS no outputs are returned
    assert not result.outputs
    result = qradar_reference_set_value_upsert_command(args, client=client, params=api_version)
    # make sure when status is COMPLETED that outputs are returned
    assert result.outputs


@pytest.mark.parametrize('command_func, endpoint, resource_id', [
    (qradar_event_collectors_list_command, '/config/event_sources/event_collectors', 0),
    (qradar_wincollect_destinations_list_command, '/config/event_sources/wincollect/wincollect_destinations', 0),
    (qradar_disconnected_log_collectors_list_command, '/config/event_sources/disconnected_log_collectors', 0),
    (qradar_log_source_types_list_command, '/config/event_sources/log_source_management/log_source_types', 0),
    (qradar_log_source_protocol_types_list_command, '/config/event_sources/log_source_management/protocol_types', 0),
    (qradar_log_source_extensions_list_command, '/config/event_sources/log_source_management/log_source_extensions', 0),
    (qradar_log_source_languages_list_command, '/config/event_sources/log_source_management/log_source_languages', 0),
    (qradar_log_source_groups_list_command, '/config/event_sources/log_source_management/log_source_groups', 0)
])
def test_id_commands(mocker, command_func: Callable[[Client, dict], CommandResults], endpoint: str, resource_id: int):
    """
    Given:
        - A command an endpoint and an ID.
    When:
        - Running the command with the corresponding endpoint and ID packed in an args object.
    Then:
        - Verify that the correct GET function is called with the ID and the endpoint.
    """
    args = {"id": resource_id}
    get_by_id_mock = mocker.patch.object(client, 'get_resource_by_id', return_value={})
    try:
        command_func(client, args)
    except KeyError:
        demisto.log(f'command {command_func.__name__} raised key error')
    get_by_id_mock.assert_called_with(resource_id, endpoint, None, None)


@pytest.mark.parametrize('command_func, endpoint', [
    (qradar_event_collectors_list_command, '/config/event_sources/event_collectors'),
    (qradar_wincollect_destinations_list_command, '/config/event_sources/wincollect/wincollect_destinations'),
    (qradar_disconnected_log_collectors_list_command, '/config/event_sources/disconnected_log_collectors'),
    (qradar_log_source_types_list_command, '/config/event_sources/log_source_management/log_source_types'),
    (qradar_log_source_protocol_types_list_command, '/config/event_sources/log_source_management/protocol_types'),
    (qradar_log_source_extensions_list_command, '/config/event_sources/log_source_management/log_source_extensions'),
    (qradar_log_source_languages_list_command, '/config/event_sources/log_source_management/log_source_languages'),
    (qradar_log_source_groups_list_command, '/config/event_sources/log_source_management/log_source_groups',)
])
def test_list_commands(mocker, command_func: Callable[[Client, dict], CommandResults], endpoint: str):
    """
    Given:
        - A command and an endpoint.
    When:
        - Running the command with the corresponding endpoint.
    Then:
        - Verify that the correct GET function is called with the correct endpoint
    """
    args = {'range': '0-49'}
    get_list_mock = mocker.patch.object(client, 'get_resource_list', return_value=[{}])
    try:
        command_func(client, args)
    except KeyError:
        demisto.log(f'command {command_func.__name__} raised key error')
    get_list_mock.assert_called_with(f"items={args['range']}", endpoint, None, None, None)


@pytest.mark.parametrize('id', [(0), (None)])
def test_get_resource(mocker, id: int | None):
    """
    Given:
        - An existing ID or None.
    When:
        - Running the get_resource function with the int or None value.
    Then:
        - Verify that the correct GET function is called.
    """
    endpoint = 'example.com'
    range = 'items=0-49'
    get_resource_by_id_mock = mocker.patch.object(client, 'get_resource_by_id')
    get_resource_list_mock = mocker.patch.object(client, 'get_resource_list')

    client.get_resource(id, range, endpoint)
    if id is not None:
        get_resource_by_id_mock.assert_called()
    else:
        get_resource_list_mock.assert_called()


def test_get_log_sources_list(mocker):
    """
    Given:
        - An endpoint, a range, an algorithm and a password.
    When:
        - Running the qradar_log_sources_list command with the corresponding arguments.
    Then:
        - Verify that the get_resource_list function is called with the correct parameters.
    """
    qrd_encryption_details = {
        'qrd_encryption_algorithm': 'algorithm',
        'qrd_encryption_password': 'password'
    }
    args = {'range': '0-49', **qrd_encryption_details}
    get_list_mock = mocker.patch.object(client, 'get_resource_list', return_value=[{}])
    endpoint = '/config/event_sources/log_source_management/log_sources'
    expected_additional_headers = {'x-qrd-encryption-algorithm': 'algorithm', 'x-qrd-encryption-password': 'password'}
    try:
        qradar_log_sources_list_command(client, args)
    except KeyError:
        demisto.log('command log_sources_list_command raised key error')
    get_list_mock.assert_called_with(f"items={args['range']}", endpoint, None, None, expected_additional_headers)


def test_get_log_source_by_id(mocker):
    """
    Given:
        - An endpoint, a range, an algorithm a password and an id.
    When:
        - Running the qradar_log_sources_list command with the corresponding arguments and an id.
    Then:
        - Verify that the get_resource_by_id function is called with the correct parameters.
    """
    mock_id = 1880
    qrd_encryption_details = {
        'qrd_encryption_algorithm': 'algorithm',
        'qrd_encryption_password': 'password'
    }
    args = {'id': mock_id, **qrd_encryption_details}
    get_by_id_mock = mocker.patch.object(client, 'get_resource_by_id', return_value={})
    endpoint = '/config/event_sources/log_source_management/log_sources'
    expected_additional_headers = {'x-qrd-encryption-algorithm': 'algorithm', 'x-qrd-encryption-password': 'password'}
    try:
        qradar_log_sources_list_command(client, args)
    except KeyError:
        demisto.log('command log_sources_list_command raised key error')
    get_by_id_mock.assert_called_with(mock_id, endpoint, None, expected_additional_headers)


def test_create_log_source(mocker):
    """
    Given:
        - The required arguments for creating a log source.
    When:
        - Running the qradar_log_source_create command with the required arguments.
    Then:
        - Verify that the create_log_source function is called with the body correctly parsed and formatted.
    """
    args = command_test_data['create_log_source']['args']
    expected_body = command_test_data['create_log_source']['expected_body']
    return_value = command_test_data['create_log_source']['response']
    create_log_source_mock = mocker.patch.object(client, 'create_log_source', return_value=return_value)
    qradar_log_source_create_command(client, args)
    create_log_source_mock.assert_called_with(expected_body)


def test_update_log_source(mocker):
    """
    Given:
        - The required arguments for updating a log source.
    When:
        - Running the qradar_log_source_update command with the required arguments.
    Then:
        - Verify that the update_log_source function is called with nothing but the correct fields.
    """
    args = command_test_data['update_log_source']['args']
    expected_body = command_test_data['update_log_source']['expected_body']
    update_log_source_mock = mocker.patch.object(client, 'update_log_source', return_value={})
    qradar_log_source_update_command(client, args)
    update_log_source_mock.assert_called_with(expected_body)


def test_delete_log_source(mocker):
    """
    Given:
        - An id.
    When:
        - Running the qradar_log_source_delete command with the id.
    Then:
        - Verify that the delete_log_source function is called with the correct id.
    """
    id = 0
    args = {"id": id}
    update_log_source_mock = mocker.patch.object(client, 'delete_log_source')

    qradar_log_source_delete_command(client, args)
    update_log_source_mock.assert_called_with(id)


def test_dict_converter():
    """
    Given:
        - A dictionary with string represented values.
    When:
        - Converting the dictionary to actual values using the conversion function.
    Then:
        - Verify that the outputted dictionary contains the expected values.
    """
    input_dict = {'enabled': 'true', 'year': '2024', 'name': 'Moshe'}
    expected_output = {'enabled': True, 'year': 2024, 'name': 'Moshe'}
    assert convert_dict_to_actual_values(input_dict) == expected_output

    input_nested_dict = {'enabled': 'true', 'year': '2024', 'name': 'Moshe', 'details': {'age': '30', 'score': '95.5'}}
    expected_nested_output = {'enabled': True, 'year': 2024, 'name': 'Moshe', 'details': {'age': 30, 'score': 95.5}}
    assert convert_dict_to_actual_values(input_nested_dict) == expected_nested_output

    input_dict_with_list = {'enabled': 'true', 'year': '2024', 'name': 'Moshe', 'lst': ['true', '22', 'str']}
    expected_output_with_list = {'enabled': True, 'year': 2024, 'name': 'Moshe', 'lst': [True, 22, 'str']}
    assert convert_dict_to_actual_values(input_dict_with_list) == expected_output_with_list

    input_nested_with_list_dict = {
        'enabled': 'true',
        'year': '2024',
        'name': 'Moshe',
        'details': {'age': '30', 'score': '95.5'},
        'lst': [{'age': '30', 'score': '95'}, {'name': 'Moshe'}]
    }
    expected_nested_with_list_output = {
        'enabled': True,
        'year': 2024,
        'name': 'Moshe',
        'details': {'age': 30, 'score': 95.5},
        'lst': [{'age': 30, 'score': 95}, {'name': 'Moshe'}],
    }
    assert convert_dict_to_actual_values(input_nested_with_list_dict) == expected_nested_with_list_output


def test_list_converter():
    """
    Given:
        - A list with string represented values.
    When:
        - Converting the list to actual values using the conversion function.
    Then:
        - Verify that the outputted list contains the expected values.
    """
    simple_input_list = ['true', '2024', 'moshe']
    expected_output = [True, 2024, 'moshe']
    assert convert_list_to_actual_values(simple_input_list) == expected_output

    expected_nested_output = [True, 2024, 'Moshe', [30, 95.5, False, 'string']]
    input_nested_list = ['true', '2024', 'Moshe', ['30', '95.5', 'false', 'string']]
    assert convert_list_to_actual_values(input_nested_list) == expected_nested_output

    input_list_with_dict = ['true', '2024', 'Moshe', {'enabled': 'true', 'year': '2024', 'name': 'Moshe'}]
    expected_output_with_dict = [True, 2024, 'Moshe', {'enabled': True, 'year': 2024, 'name': 'Moshe'}]
    assert convert_list_to_actual_values(input_list_with_dict) == expected_output_with_dict


def test_recovery_lastrun(mocker):
    """
    Given:
        - Last run is more up-to-date than the integration context.
        - Last run is the same as the integration context.

    When:
        - The container starts and the recovery method is called

    Then:
        - Ensure that the integration context is updated to the last run.
        - If there are not changes, make sure that the context is not updated
    """
    set_integration_context({LAST_FETCH_KEY: 2, MIRRORED_OFFENSES_QUERIED_CTX_KEY: {
                            0: 0}, MIRRORED_OFFENSES_FINISHED_CTX_KEY: {0: 0}})
    mocker.patch.object(QRadar_v3.demisto, "getLastRun", return_value={LAST_FETCH_KEY: 4})
    QRadar_v3.recover_from_last_run()
    context_data = get_integration_context()
    assert context_data[LAST_FETCH_KEY] == 4

    # now the last run and the integration context are the same, make sure that update context is not called
    update_context_mock = mocker.patch.object(QRadar_v3, "safely_update_context_data")
    set_integration_context({LAST_FETCH_KEY: 2, MIRRORED_OFFENSES_QUERIED_CTX_KEY: {
                            0: 0}, MIRRORED_OFFENSES_FINISHED_CTX_KEY: {0: 0}})
    mocker.patch.object(QRadar_v3.demisto, "getLastRun", return_value={LAST_FETCH_KEY: 2})
    QRadar_v3.recover_from_last_run()
    context_data = get_integration_context()
    assert context_data[LAST_FETCH_KEY] == 2
    assert not update_context_mock.called


@pytest.mark.parametrize('quiet_mode', [False, True])
def test_qradar_reference_set_value_upsert_command_quiet_mode(mocker, quiet_mode):
    """
    Given:
        - A reference set with data
    When:
        - Running qradar-reference-set-value-upsert with quiet_mode, once set to true and once to false
        - The polling status is "completed" (i.e. the results should be returned in the current interval)
    Then:
        - Ensure the command does not output the reference set data iff quiet_mode=true
        - Ensure the data is always in the raw response
    """
    args = {"ref_name": "test_ref", "value": "value1", "task_id": "test", "quiet_mode": quiet_mode}

    mocker.patch.object(QRadar_v3.ScheduledCommand, "raise_error_if_not_supported")
    mocker.patch.object(client, "get_reference_data_bulk_task_status", return_value={"status": "COMPLETED"})
    mock_response = command_test_data["reference_set_bulk_load"]['response'] | {"data": ["some_data"]}
    mocker.patch.object(client, "reference_sets_list", return_value=mock_response)

    result = qradar_reference_set_value_upsert_command(args, client=client, params={"api_version": "17.0"})

    assert all("Name" in i for i in result.outputs)
    assert all("Data" not in i for i in result.outputs) or not quiet_mode
    assert "data" in result.raw_response


@pytest.mark.parametrize('quiet_mode', [False, True])
def test_qradar_indicators_upload_command_quiet_mode(mocker, quiet_mode):
    """
    Given:
        - A reference set with data
    When:
        - Running qradar-indicators-upload with quiet_mode, once set to true and once to false
        - The polling status is "completed" (i.e. the results should be returned in the current interval)
    Then:
        - Ensure the command does not output the reference set data iff quiet_mode=true
        - Ensure the data is always in the raw response
    """
    args = {"ref_name": "test_ref", "quiet_mode": quiet_mode, "task_id": "test"}

    mocker.patch.object(QRadar_v3.ScheduledCommand, "raise_error_if_not_supported")
    mocker.patch.object(client, "get_reference_data_bulk_task_status", return_value={"status": "COMPLETED"})
    mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version",
                        return_value={"iocs": [{"value": "test", "indicator_type": "ip"}]})
    mock_response = command_test_data["reference_set_bulk_load"]['response'] | {"data": ["some_data"]}
    mocker.patch.object(client, "reference_sets_list", return_value=mock_response)

    result = qradar_indicators_upload_command(args, client=client, params={"api_version": "17.0"})

    assert all("Name" in i for i in result.outputs)
    assert all("Data" not in i for i in result.outputs) or not quiet_mode
    assert "data" in result.raw_response

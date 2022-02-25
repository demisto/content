"""
    QRadar v3 integration for Cortex XSOAR - Unit Tests file
"""
import concurrent.futures
import io
import json
from datetime import datetime
from typing import Dict, Callable

import QRadar_v3  # import module separately for mocker
import pytest
import pytz
from QRadar_v3 import USECS_ENTRIES, OFFENSE_OLD_NEW_NAMES_MAP, MINIMUM_API_VERSION, REFERENCE_SETS_OLD_NEW_MAP, \
    Client, ASSET_PROPERTIES_NAME_MAP, FetchMode, \
    FULL_ASSET_PROPERTIES_NAMES_MAP, EntryType, EntryFormat, MIRROR_OFFENSE_AND_EVENTS, LAST_FETCH_KEY, \
    MIRRORED_OFFENSES_CTX_KEY, UPDATED_MIRRORED_OFFENSES_CTX_KEY, RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY
from QRadar_v3 import get_time_parameter, add_iso_entries_to_dict, build_final_outputs, build_headers, \
    get_offense_types, get_offense_closing_reasons, get_domain_names, get_rules_names, enrich_assets_results, \
    get_offense_addresses, get_minimum_id_to_fetch, poll_offense_events_with_retry, sanitize_outputs, \
    create_search_with_retry, enrich_offense_with_events, enrich_offense_with_assets, get_offense_enrichment, \
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
    qradar_ips_source_get_command, qradar_ips_local_destination_get_command, update_mirrored_events, \
    encode_context_data, extract_context_data, change_ctx_to_be_compatible_with_retry, clear_integration_ctx, \
    reset_mirroring_events_variables, perform_long_running_loop

from CommonServerPython import DemistoException, set_integration_context, CommandResults, \
    GetModifiedRemoteDataResponse, GetRemoteDataResponse, get_integration_context
from CommonServerPython import set_to_integration_context_with_retries

QRadar_v3.FAILURE_SLEEP = 0
QRadar_v3.SLEEP_FETCH_EVENT_RETIRES = 0

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


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
                          ([], FULL_ASSET_PROPERTIES_NAMES_MAP, dict())
                          ])
def test_enrich_asset_properties(properties, properties_to_enrich_dict: Dict, expected):
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
    return get_offense_enrichment(enrichment) == expected


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
                          (1523, 'closing_reason_id > 5000', 1523)])
def test_get_minimum_id_to_fetch(last_run_offense_id, user_query, expected):
    """
    Given:
     - The highest fetched offense ID from last run.
     - The user query for fetch.

    When:
     - Fetching incidents in long time execution.

    Then:
     - Ensure that returned value is the lowest ID to fetch from.
    """
    assert get_minimum_id_to_fetch(last_run_offense_id, user_query) == expected


@pytest.mark.parametrize('outputs, key_replace_dict, expected',
                         [({'a': 2, 'number_of_elements': 3, 'creation_time': 1600000000000},
                           REFERENCE_SETS_OLD_NEW_MAP,
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
                           (sanitize_outputs(command_test_data['search_results_get']['response']['events']), '')),
                          (DemistoException('error occurred'),
                           None,
                           None,
                           None,
                           ([], "DemistoException('error occurred', None) \nSee logs for further details."))
                          ])
def test_poll_offense_events_with_retry(requests_mock, status_exception, status_response, results_response, search_id,
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
    assert poll_offense_events_with_retry(client, search_id, 1, 1) == expected


@pytest.mark.parametrize('search_exception, fetch_mode, query_expression, search_response',
                         [(None, 'Fetch With All Events', command_test_data['all_events_query'],
                           command_test_data['search_create']['response']),
                          (DemistoException('error occurred'),
                           'Fetch With All Events', command_test_data['all_events_query'],
                           None),
                          (None, 'Fetch Correlation Events Only', command_test_data['correlation_events_query'],
                           command_test_data['search_create']['response']),
                          (DemistoException('error occurred'),
                           'Fetch Correlation Events Only', command_test_data['correlation_events_query'],
                           None)
                          ])
def test_create_search_with_retry(mocker, search_exception, fetch_mode, query_expression, search_response):
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
    set_to_integration_context_with_retries(dict())
    if search_exception:
        mocker.patch.object(client, "search_create", side_effect=[search_exception])
    else:
        mocker.patch.object(client, "search_create", return_value=search_response)
    assert create_search_with_retry(client, fetch_mode=fetch_mode,
                                    offense=command_test_data['offenses_list']['response'][0],
                                    event_columns=event_columns_default_value, events_limit=20,
                                    max_retries=1) == search_response


@pytest.mark.parametrize(
    'offense, fetch_mode, mock_search_response, poll_events_response, events_limit',
    [
        # success cases
        (command_test_data['offenses_list']['response'][0],
         'correlations_events_only',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events']), ''),
         3
         ),
        (command_test_data['offenses_list']['response'][0],
         'correlations_events_only',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         1
         ),
        (command_test_data['offenses_list']['response'][0],
         'all_events',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events']), ''),
         3
         ),
        (command_test_data['offenses_list']['response'][0],
         'all_events',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         1
         ),

        # failure cases
        (command_test_data['offenses_list']['response'][0],
         'correlations_events_only',
         None,
         None,
         3
         ),
        (command_test_data['offenses_list']['response'][0],
         'correlations_events_only',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         3
         ),
        (command_test_data['offenses_list']['response'][0],
         'all_events',
         None,
         None,
         3
         ),
        (command_test_data['offenses_list']['response'][0],
         'all_events',
         command_test_data['search_create']['response'],
         (sanitize_outputs(command_test_data['search_results_get']['response']['events'][:1]), ''),
         3
         ),
    ])
def test_enrich_offense_with_events(mocker, offense: Dict, fetch_mode, mock_search_response: Dict,
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
    poll_events = poll_events_response[0] if poll_events_response else None
    if poll_events and len(poll_events) >= min(events_limit, offense.get('event_count')):
        events = poll_events[:min(events_limit, len(poll_events))] if poll_events else []
        expected_offense = dict(offense, events=events,
                                mirroring_events_message='')
    else:
        expected_offense = dict(offense,
                                mirroring_events_message='Events were probably not indexed in QRadar at the time '
                                                         'of the mirror.')

    mocker.patch.object(QRadar_v3, "create_search_with_retry", return_value=mock_search_response)
    poll_events_mock = mocker.patch.object(QRadar_v3, "poll_offense_events_with_retry",
                                           return_value=poll_events_response)

    enriched_offense = enrich_offense_with_events(client, offense, fetch_mode, event_columns_default_value,
                                                  events_limit=events_limit, max_retries=1)

    if mock_search_response:
        assert poll_events_mock.call_args[0][1] == mock_search_response['search_id']
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
        'type': 'QRadar Incident'
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
                              dict()
                              ),
                             (get_offense_closing_reasons,
                              'closing_reasons_list',
                              {
                                  'client': client,
                                  'offenses': [{'offense_name': 'offense1'},
                                               {'offense_name': 'offense2'}],
                              },
                              None,
                              dict()
                              ),
                             (get_domain_names,
                              'domains_list',
                              {
                                  'client': client,
                                  'outputs': [{'offense_name': 'offense1'},
                                              {'offense_name': 'offense2'}],
                              },
                              None,
                              dict()
                              ),
                             (get_rules_names,
                              'rules_list',
                              {
                                  'client': client,
                                  'offenses': [{'offense_name': 'offense1'},
                                               {'offense_name': 'offense2'}],
                              },
                              None,
                              dict()
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
                              dict()
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
                              dict()
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
                             (qradar_reference_sets_list_command, 'reference_sets_list'),
                             (qradar_reference_set_create_command, 'reference_set_create'),
                             (qradar_reference_set_delete_command, 'reference_set_delete'),
                             (qradar_reference_set_value_upsert_command, 'reference_set_value_upsert'),
                             (qradar_reference_set_value_delete_command, 'reference_set_value_delete'),
                             (qradar_domains_list_command, 'domains_list'),
                             (qradar_geolocations_for_ip_command, 'geolocations_for_ip'),
                             (qradar_log_sources_list_command, 'log_sources_list'),
                             (qradar_get_custom_properties_command, 'custom_properties')
                         ])
def test_commands(mocker, command_func: Callable[[Client, Dict], CommandResults], command_name: str):
    """
    Given:
     - Command function.
     - Demisto arguments.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    args = command_test_data[command_name].get('args', dict())
    response = command_test_data[command_name]['response']
    expected = command_test_data[command_name]['expected']
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs'),
        raw_response=response
    )
    mocker.patch.object(client, command_name, return_value=response)

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
def test_commands_with_enrichment(mocker, command_func: Callable[[Client, Dict], CommandResults], command_name: str,
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
    args = command_test_data[command_name].get('args', dict())
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
    set_to_integration_context_with_retries(dict())
    expected = GetModifiedRemoteDataResponse(list(map(str, command_test_data['get_modified_remote_data']['outputs'])))
    mocker.patch.object(client, 'offenses_list', return_value=command_test_data['get_modified_remote_data']['response'])
    result = get_modified_remote_data_command(client, dict(), command_test_data['get_modified_remote_data']['args'])
    assert expected.modified_incident_ids == result.modified_incident_ids


@pytest.mark.parametrize('params, args, expected',
                         [
                             (dict(), {'lastUpdate': 1613399051537,
                                       'id': command_test_data['get_remote_data']['response']['id']},
                              GetRemoteDataResponse(
                                  {'id': command_test_data['get_remote_data']['response']['id'],
                                   'mirroring_events_message': 'Nothing new in the ticket.'},
                                  [])),
                             (dict(), {'lastUpdate': 1613399051535,
                                       'id': command_test_data['get_remote_data']['response']['id']},
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_offenses_result'])[0],
                                  []))
                         ])
def test_get_remote_data_command_pre_6_1(mocker, params, args, expected: GetRemoteDataResponse):
    """
    Given:
     - QRadar client.
     - Demisto arguments.

    When:
     - Command 'get-get-remote-data' is being called.

    Then:
     - Ensure that command outputs the IDs of the offenses to update.
    """
    set_to_integration_context_with_retries(dict())
    enriched_response = command_test_data['get_remote_data']['enrich_offenses_result']
    mocker.patch.object(client, 'offenses_list', return_value=command_test_data['get_remote_data']['response'])
    mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=enriched_response)
    result = get_remote_data_command(client, params, args)
    if expected.mirrored_object.get('last_mirror_in_time'):
        expected.mirrored_object['last_mirror_in_time'] = result.mirrored_object['last_mirror_in_time']
    assert result.mirrored_object == expected.mirrored_object
    assert result.entries == expected.entries


@pytest.mark.parametrize('params, offense, enriched_offense, note_response, expected',
                         [
                             (dict(), command_test_data['get_remote_data']['response'],
                              command_test_data['get_remote_data']['enrich_offenses_result'],
                              None,
                              GetRemoteDataResponse(
                                  sanitize_outputs(command_test_data['get_remote_data']['enrich_offenses_result'])[0],
                                  [])),

                             (dict(), command_test_data['get_remote_data']['closed'],
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
                                          'closeReason': 'From QRadar: False-Positive, Tuned'
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
                                          'closeReason': 'From QRadar: This offense was closed with reason: '
                                                         'False-Positive, Tuned.'
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
                                          'closeReason': 'From QRadar: This offense was closed with reason: '
                                                         'False-Positive, Tuned. Notes: Closed because it is on our '
                                                         'white list.'
                                      },
                                      'ContentsFormat': EntryFormat.JSON
                                  }]))
                         ])
def test_get_remote_data_command_6_1_and_higher(mocker, params, offense: Dict, enriched_offense, note_response,
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
    set_to_integration_context_with_retries({'last_update': 1})
    mocker.patch.object(client, 'offenses_list', return_value=offense)
    mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=enriched_offense)
    if 'close_incident' in params:
        mocker.patch.object(client, 'closing_reasons_list',
                            return_value=command_test_data['closing_reasons_list']['response'][0])
    if note_response is not None:
        mocker.patch.object(client, 'offense_notes_list', return_value=note_response)
    result = get_remote_data_command(client, params, {'id': offense.get('id'), 'lastUpdate': 1})
    expected.mirrored_object['last_mirror_in_time'] = result.mirrored_object['last_mirror_in_time']
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
    for param_name, param_value in LONG_RUNNING_REQUIRED_PARAMS.items():
        params_without_required_param = {k: v for k, v in LONG_RUNNING_REQUIRED_PARAMS.items() if k is not param_name}
        with pytest.raises(DemistoException):
            validate_long_running_params(params_without_required_param)


@pytest.mark.parametrize('command_func, command_name',
                         [
                             (qradar_ips_source_get_command, 'source_ip'),
                             (qradar_ips_local_destination_get_command, 'local_destination')
                         ])
def test_ip_commands(mocker, command_func: Callable[[Client, Dict], CommandResults], command_name: str):
    """
    Given:
     - Command function.
     - Demisto arguments.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    args = dict()
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


@pytest.mark.parametrize('offenses, context_data',
                         # One offense with one event.
                         [({'ids': [{'id': '1', 'last_persisted_time': 2}],
                            'as_results': [MockResults({'id': '1', 'last_persisted_time': 2,
                                                        'events': [{'event_id': '2'}]})],
                            'with_events': [{'id': '1', 'last_persisted_time': 2,
                                             'events': [{'event_id': '2'}]}]},
                           {'before_offenses_ids': {LAST_FETCH_KEY: 0},
                            'with_offenses_ids': {'samples': [], 'last_mirror_update': '2',
                                                  MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                               'last_persisted_time': 2}]},
                            'with_events': [{'samples': [], 'last_mirror_update': '2', LAST_FETCH_KEY: 0,
                                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                  'last_persisted_time': 2,
                                                                                  'events': [{'event_id': '2'}]}],
                                             MIRRORED_OFFENSES_CTX_KEY: []}],
                            'with_updated_removed': [{'samples': [], 'last_mirror_update': '2',
                                                      LAST_FETCH_KEY: 0,
                                                      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                      MIRRORED_OFFENSES_CTX_KEY: []}]}),
                          # One offense with two events.
                          ({'ids': [{'id': '1', 'last_persisted_time': 2}],
                            'as_results': [MockResults({'id': '1', 'last_persisted_time': 2,
                                                        'events': [{'event_id': '2'}, {'event_id': '3'}]})],
                            'with_events': [{'id': '1', 'last_persisted_time': 2,
                                             'events': [{'event_id': '2'}, {'event_id': '3'}]}]},
                           {'before_offenses_ids': {LAST_FETCH_KEY: 0},
                            'with_offenses_ids': {'samples': [], 'last_mirror_update': '2',
                                                  MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                               'last_persisted_time': 2}]},
                            'with_events': [{'samples': [], 'last_mirror_update': '2', LAST_FETCH_KEY: 0,
                                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                  'last_persisted_time': 2,
                                                                                  'events': [{'event_id': '2'},
                                                                                             {'event_id': '3'}]}],
                                             MIRRORED_OFFENSES_CTX_KEY: []}],
                            'with_updated_removed': [{'samples': [], 'last_mirror_update': '2',
                                                      LAST_FETCH_KEY: 0,
                                                      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                      MIRRORED_OFFENSES_CTX_KEY: []}]}),
                          # Two offenses with one event.
                          ({'ids': [{'id': '1', 'last_persisted_time': 2},
                                    {'id': '11', 'last_persisted_time': 3}],
                            'as_results': [MockResults({'id': '1', 'last_persisted_time': 2,
                                                        'events': [{'event_id': '2'}, {'event_id': '3'}]}),
                                           MockResults({'id': '11', 'last_persisted_time': 3,
                                                        'events': [{'event_id': '22'}, {'event_id': '33'}]})],
                            'with_events': [{'id': '1', 'last_persisted_time': 2,
                                             'events': [{'event_id': '2'}, {'event_id': '3'}]},
                                            {'id': '11', 'last_persisted_time': 3,
                                             'events': [{'event_id': '22'}, {'event_id': '33'}]}]},
                           {'before_offenses_ids': {LAST_FETCH_KEY: 0},
                            'with_offenses_ids': {'samples': [], 'last_mirror_update': '3',
                                                  MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                               'last_persisted_time': 2},
                                                                              {'id': '11',
                                                                               'last_persisted_time': 3}]},
                            'with_events': [{'samples': [], 'last_mirror_update': '2', LAST_FETCH_KEY: 0,
                                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1', 'last_persisted_time': 2,
                                                                                  'events': [{'event_id': '2'},
                                                                                             {'event_id': '3'}]},
                                                                                 {'id': '11', 'last_persisted_time': 3,
                                                                                  'events': [{'event_id': '22'},
                                                                                             {'event_id': '33'}]}],
                                             MIRRORED_OFFENSES_CTX_KEY: []},
                                            {'samples': [], 'last_mirror_update': '2',
                                             LAST_FETCH_KEY: 0,
                                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '11',
                                                                                  'last_persisted_time': 3,
                                                                                  'events': [{'event_id': '22'},
                                                                                             {'event_id': '33'}]
                                                                                  }],
                                             MIRRORED_OFFENSES_CTX_KEY: []}],
                            'with_updated_removed': [{'samples': [], 'last_mirror_update': '2',
                                                      LAST_FETCH_KEY: 0,
                                                      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '11',
                                                                                           'last_persisted_time': 3,
                                                                                           'events': [
                                                                                               {'event_id': '22'},
                                                                                               {'event_id': '33'}]
                                                                                           }],
                                                      MIRRORED_OFFENSES_CTX_KEY: []},
                                                     {'samples': [], 'last_mirror_update': '2',
                                                      LAST_FETCH_KEY: 0,
                                                      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                      MIRRORED_OFFENSES_CTX_KEY: []}]})
                          ])
def test_mirroring_offenses_with_events(mocker, offenses, context_data):
    """Test mirroring with events: happy flow

    Given:
        offenses ids to mirror.
        Context data.

    When:
        Mirroring offenses with events.

    Then:
        Ensure the communication between the mirroring commands and the long running container works as expected.
        Ensure offenses are updated with events.
    """
    # Get a list of offenses to update their events
    mocker.patch.object(client, 'offenses_list', return_value=offenses.get('ids'))
    mocker.patch.object(QRadar_v3, 'get_integration_context_with_version', return_value=(set_context_data_as_json(
        context_data.get('before_offenses_ids')), 666))
    mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
    get_modified_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS}, {"lastUpdate": "0"})
    QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(encode_context_data(
        context_data.get('with_offenses_ids')), max_retry_times=1)

    # Transfer that list to the long running docker and update the events.
    mocker.patch.object(concurrent.futures.ThreadPoolExecutor, 'submit', side_effect=offenses.get('as_results'))
    updated_mirrored_offenses = update_mirrored_events(client=client,
                                                       fetch_mode=FetchMode.correlations_events_only.value,
                                                       events_columns='',
                                                       events_limit=5,
                                                       context_data=context_data.get('with_offenses_ids'),
                                                       offenses_per_fetch=15)
    # Make sure all the mirrored offenses were updated.
    assert updated_mirrored_offenses == offenses.get('with_events')

    # Update an incident's events accordingly.
    for offense_index, offense in enumerate(offenses.get('ids')):
        mocker.patch.object(QRadar_v3, 'get_integration_context_with_version', return_value=(set_context_data_as_json(
            context_data.get('with_events')[offense_index]), 666))
        mocker.patch.object(client, 'offenses_list', return_value=offense)
        mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=offense)
        mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
        result = get_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS},
                                         {'id': offense.get('id'), 'lastUpdate': 1})

        # Make sure the final offense has it's updated events
        QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(
            encode_context_data(context_data.get('with_updated_removed')[offense_index]), max_retry_times=1)
        assert result.mirrored_object.get('events', '')

        updated_result_events = result.mirrored_object.get('events')
        for event in offenses.get('with_events')[offense_index].get('events'):
            assert event in updated_result_events


def set_context_data_as_json(context_data, include_id=False):
    new_context_data = encode_context_data(context_data, include_id=include_id)
    for key in new_context_data.keys():
        new_context_data[key] = json.dumps(new_context_data[key])

    return new_context_data


@pytest.mark.parametrize('offenses, context_data',
                         # No new offenses, just one exhausted offense
                         [({'new_offenses': [], 'to_update': ['1']},
                           {'get_modified_input': {LAST_FETCH_KEY: 0,
                                                   UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                        'last_persisted_time': 2,
                                                                                        'events': [{'event_id': '2'},
                                                                                                   {'event_id': '3'}]}],
                                                   MIRRORED_OFFENSES_CTX_KEY: []},
                            'get_modified_output': {'samples': [], 'last_mirror_update': '0',
                                                    LAST_FETCH_KEY: 0,
                                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                         'last_persisted_time': 2,
                                                                                         'events': [{'event_id': '2'},
                                                                                                    {
                                                                                                        'event_id': '3'}]}],
                                                    MIRRORED_OFFENSES_CTX_KEY: [],
                                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1']},
                            'after_get_remote_data': [{'samples': [], 'last_mirror_update': '0',
                                                       LAST_FETCH_KEY: 0,
                                                       UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                       MIRRORED_OFFENSES_CTX_KEY: [],
                                                       RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}]}),
                          # No new offenses, 2 exhausted offenses
                          ({'new_offenses': [], 'to_update': ['1', '11']},
                           {'get_modified_input': {LAST_FETCH_KEY: 0,
                                                   UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                        'last_persisted_time': 2,
                                                                                        'events': [{'event_id': '2'},
                                                                                                   {'event_id': '3'}]},
                                                                                       {'id': '11',
                                                                                        'last_persisted_time': 3,
                                                                                        'events': [{'event_id': '22'},
                                                                                                   {'event_id': '33'}]}
                                                                                       ],
                                                   MIRRORED_OFFENSES_CTX_KEY: []},
                            'get_modified_output': {'samples': [], 'last_mirror_update': '0',
                                                    LAST_FETCH_KEY: 0,
                                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                         'last_persisted_time': 2,
                                                                                         'events': [{'event_id': '2'},
                                                                                                    {'event_id': '3'}]},
                                                                                        {'id': '11',
                                                                                         'last_persisted_time': 3,
                                                                                         'events': [{'event_id': '22'},
                                                                                                    {'event_id': '33'}]}
                                                                                        ],
                                                    MIRRORED_OFFENSES_CTX_KEY: [],
                                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11']},
                            'after_get_remote_data': [{'samples': [], 'last_mirror_update': '0',
                                                       LAST_FETCH_KEY: 0,
                                                       UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '11',
                                                                                            'last_persisted_time': 3,
                                                                                            'events': [
                                                                                                {'event_id': '22'},
                                                                                                {'event_id': '33'}]}],
                                                       MIRRORED_OFFENSES_CTX_KEY: [],
                                                       RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['11']},
                                                      {'samples': [], 'last_mirror_update': '0',
                                                       LAST_FETCH_KEY: 0,
                                                       UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                       MIRRORED_OFFENSES_CTX_KEY: [],
                                                       RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}
                                                      ]}),
                          # 2 new offenses, 2 old offenses
                          ({'new_offenses': [{'id': '100', 'last_persisted_time': 2},
                                             {'id': '200', 'last_persisted_time': 3}],
                            'to_update': ['1', '11', '100', '200']},
                           {'get_modified_input': {LAST_FETCH_KEY: 0,
                                                   UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                        'last_persisted_time': 2,
                                                                                        'events': [{'event_id': '2'},
                                                                                                   {'event_id': '3'}]},
                                                                                       {'id': '11',
                                                                                        'last_persisted_time': 3,
                                                                                        'events': [{'event_id': '22'},
                                                                                                   {'event_id': '33'}]}
                                                                                       ],
                                                   MIRRORED_OFFENSES_CTX_KEY: []},
                            'get_modified_output': {'samples': [], 'last_mirror_update': '3',
                                                    LAST_FETCH_KEY: 0,
                                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                                         'last_persisted_time': 2,
                                                                                         'events': [{'event_id': '2'},
                                                                                                    {'event_id': '3'}]},
                                                                                        {'id': '11',
                                                                                         'last_persisted_time': 3,
                                                                                         'events': [{'event_id': '22'},
                                                                                                    {'event_id': '33'}]}
                                                                                        ],
                                                    MIRRORED_OFFENSES_CTX_KEY: [{'id': '100', 'last_persisted_time': 2},
                                                                                {'id': '200',
                                                                                 'last_persisted_time': 3}],
                                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11']},
                            'after_get_remote_data': [{'samples': [], 'last_mirror_update': '3',
                                                       LAST_FETCH_KEY: 0,
                                                       UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '11',
                                                                                            'last_persisted_time': 3,
                                                                                            'events': [
                                                                                                {'event_id': '22'},
                                                                                                {'event_id': '33'}]}],
                                                       MIRRORED_OFFENSES_CTX_KEY: [
                                                           {'id': '100', 'last_persisted_time': 2},
                                                           {'id': '200', 'last_persisted_time': 3}],
                                                       RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['11']},
                                                      {'samples': [], 'last_mirror_update': '3',
                                                       LAST_FETCH_KEY: 0,
                                                       UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                                       MIRRORED_OFFENSES_CTX_KEY: [
                                                           {'id': '100', 'last_persisted_time': 2},
                                                           {'id': '200', 'last_persisted_time': 3}],
                                                       RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}
                                                      ]})
                          ])
def test_mirroring_with_events_resubmit_exhausted_offenses(mocker, offenses, context_data):
    """Test mirroring with events: long running container updated offense after get_remote_data reached timeout

    Given:
        Context data with an updated offense.

    When:
        Getting remote modified data.

    Then:
        Ensure get_modified_remote_data resubmitted offense id for get_remote_data.
        Ensure get_remote_data updated incident and updated the context data accordingly.
    """
    mocker.patch.object(client, 'offenses_list', return_value=offenses.get('new_offenses'))
    mocker.patch.object(QRadar_v3, 'get_integration_context_with_version', return_value=(set_context_data_as_json(
        context_data.get('get_modified_input')), 666))
    mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
    mocker.patch.object(QRadar_v3, 'GetModifiedRemoteDataResponse')

    get_modified_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS}, {"lastUpdate": "0"})

    QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(encode_context_data(
        context_data.get('get_modified_output')), max_retry_times=1)
    assert set(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == set(offenses.get('to_update'))
    assert len(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == len(offenses.get('to_update'))

    context_input_for_get_remote_data = context_data.get('get_modified_output')
    updated_offenses = context_input_for_get_remote_data.get(UPDATED_MIRRORED_OFFENSES_CTX_KEY)

    # Update an incident's events accordingly.
    for offense_index, offense in enumerate(updated_offenses):
        mocker.patch.object(QRadar_v3, 'get_integration_context_with_version', return_value=(set_context_data_as_json(
            context_input_for_get_remote_data), 666))
        mocker.patch.object(client, 'offenses_list', return_value=offense)
        mocker.patch.object(QRadar_v3, 'enrich_offenses_result', return_value=offense)
        mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
        get_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS},
                                {'id': offense.get('id'), 'lastUpdate': 1})

        # Make sure the final offense has it's updated events
        QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(
            encode_context_data(context_data.get('after_get_remote_data')[offense_index]), max_retry_times=1)

        context_input_for_get_remote_data = context_data.get('after_get_remote_data')[offense_index]


@pytest.mark.parametrize('offenses, context_data', [
    # One offense to resubmit and clean, no new, no newer.
    ({'new_offenses': [],
      'newer_offenses': [],
      'to_update': ['1'],
      'clean_to_update': []},
     {'get_modified_input': {LAST_FETCH_KEY: 0,
                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                  'last_persisted_time': 2,
                                                                  'events': [{'event_id': '2'},
                                                                             {'event_id': '3'}]}],
                             MIRRORED_OFFENSES_CTX_KEY: []},
      'get_modified_output': {'samples': [], 'last_mirror_update': '0',
                              LAST_FETCH_KEY: 0,
                              UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                   'last_persisted_time': 2,
                                                                   'events': [{'event_id': '2'},
                                                                              {'event_id': '3'}]}],
                              MIRRORED_OFFENSES_CTX_KEY: [],
                              RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1']},
      'clean_get_modified_output': {'samples': [], 'last_mirror_update': '0',
                                    LAST_FETCH_KEY: 0,
                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                    MIRRORED_OFFENSES_CTX_KEY: [],
                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}}),
    # 2 offenses to resubmit and clean, no new, no newer.
    ({'new_offenses': [],
      'newer_offenses': [],
      'to_update': ['1', '11'],
      'clean_to_update': []},
     {'get_modified_input': {LAST_FETCH_KEY: 0,
                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                  'last_persisted_time': 2,
                                                                  'events': [{'event_id': '2'},
                                                                             {'event_id': '3'}]},
                                                                 {'id': '11',
                                                                  'last_persisted_time': 3,
                                                                  'events': [{'event_id': '22'},
                                                                             {'event_id': '33'}]}
                                                                 ],
                             MIRRORED_OFFENSES_CTX_KEY: []},
      'get_modified_output': {'samples': [], 'last_mirror_update': '0',
                              LAST_FETCH_KEY: 0,
                              UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                   'last_persisted_time': 2,
                                                                   'events': [{'event_id': '2'},
                                                                              {'event_id': '3'}]},
                                                                  {'id': '11',
                                                                   'last_persisted_time': 3,
                                                                   'events': [{'event_id': '22'},
                                                                              {'event_id': '33'}]}],
                              MIRRORED_OFFENSES_CTX_KEY: [],
                              RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11']},
      'clean_get_modified_output': {'samples': [], 'last_mirror_update': '0',
                                    LAST_FETCH_KEY: 0,
                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                    MIRRORED_OFFENSES_CTX_KEY: [],
                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}}),
    # 2 offenses to resubmit and clean, 2 new, 2 newer.
    ({'new_offenses': [{'id': '100', 'last_persisted_time': 2},
                       {'id': '200', 'last_persisted_time': 3}],
      'newer_offenses': [{'id': '300', 'last_persisted_time': 4},
                         {'id': '400', 'last_persisted_time': 5}],
      'to_update': ['1', '11', '100', '200'],
      'clean_to_update': ['300', '400']},
     {'get_modified_input': {LAST_FETCH_KEY: 0,
                             UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                  'last_persisted_time': 2,
                                                                  'events': [{'event_id': '2'},
                                                                             {'event_id': '3'}]},
                                                                 {'id': '11',
                                                                  'last_persisted_time': 3,
                                                                  'events': [{'event_id': '22'},
                                                                             {'event_id': '33'}]}],
                             MIRRORED_OFFENSES_CTX_KEY: []},
      'get_modified_output': {'samples': [], 'last_mirror_update': '3',
                              LAST_FETCH_KEY: 0,
                              UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                                                   'last_persisted_time': 2,
                                                                   'events': [{'event_id': '2'},
                                                                              {'event_id': '3'}]},
                                                                  {'id': '11',
                                                                   'last_persisted_time': 3,
                                                                   'events': [{'event_id': '22'},
                                                                              {'event_id': '33'}]}],
                              MIRRORED_OFFENSES_CTX_KEY: [{'id': '100', 'last_persisted_time': 2},
                                                          {'id': '200', 'last_persisted_time': 3}],
                              RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11']},
      'clean_get_modified_output': {'samples': [], 'last_mirror_update': '5',
                                    LAST_FETCH_KEY: 0,
                                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: [],
                                    MIRRORED_OFFENSES_CTX_KEY: [{'id': '100', 'last_persisted_time': 2},
                                                                {'id': '200', 'last_persisted_time': 3},
                                                                {'id': '300', 'last_persisted_time': 4},
                                                                {'id': '400', 'last_persisted_time': 5}],
                                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: []}})
])
def test_mirroring_with_events_remove_resubmitted_offenses(mocker, offenses, context_data):
    """Test mirroring with events: resubmitted offenses are not being updated

    Given:
        Context data with an updated offense and a leftover resubmitted offense.

    When:
        Getting remote modified data.

    Then:
        Ensure get_modified_remote_data deletes relevant offense from mirror processing.
    """
    mocker.patch.object(client, 'offenses_list', return_value=offenses.get('new_offenses'))
    mocker.patch.object(QRadar_v3, 'get_integration_context_with_version',
                        return_value=(set_context_data_as_json(context_data.get('get_modified_input')), 666))
    mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
    mocker.patch.object(QRadar_v3, 'GetModifiedRemoteDataResponse')

    get_modified_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS}, {"lastUpdate": "0"})

    QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(encode_context_data(
        context_data.get('get_modified_output')), max_retry_times=1)
    assert set(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == set(offenses.get('to_update'))
    assert len(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == len(offenses.get('to_update'))

    mocker.patch.object(client, 'offenses_list', return_value=offenses.get('newer_offenses'))
    mocker.patch.object(QRadar_v3, 'get_integration_context_with_version', return_value=(set_context_data_as_json(
        context_data.get('get_modified_output')), 666))
    mocker.patch.object(QRadar_v3, 'set_to_integration_context_with_retries')
    mocker.patch.object(QRadar_v3, 'GetModifiedRemoteDataResponse')

    get_modified_remote_data_command(client, {'mirror_options': MIRROR_OFFENSE_AND_EVENTS}, {"lastUpdate": "0"})

    QRadar_v3.set_to_integration_context_with_retries.assert_called_once_with(encode_context_data(
        context_data.get('clean_get_modified_output')), max_retry_times=1)
    assert set(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == set(offenses.get('clean_to_update'))
    assert len(QRadar_v3.GetModifiedRemoteDataResponse.call_args.args[0]) == len(offenses.get('clean_to_update'))


@pytest.mark.parametrize('context_data', [
    {'samples': [], 'last_mirror_update': '0',
     LAST_FETCH_KEY: 5,
     UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                          'last_persisted_time': 2,
                                          'events': [{'event_id': '2'},
                                                     {'event_id': '3'}]},
                                         {'id': '11',
                                          'last_persisted_time': 3,
                                          'events': [{'event_id': '22'},
                                                     {'event_id': '33'}]}],
     MIRRORED_OFFENSES_CTX_KEY: [],
     RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11']}])
def test_extract_decode_encode(context_data):
    assert extract_context_data(set_context_data_as_json(context_data, include_id=True),
                                include_id=True) == context_data


@pytest.mark.parametrize('context_data, retry_compatible', [
    # Happy flow: configuration matches retry_compatible
    ({'samples': [{'id': '1', 'last_persisted_time': 2,
                   'events': [{'event_id': '2'}, {'event_id': '3'}]}],
      'last_mirror_update': '10',
      LAST_FETCH_KEY: 5,
      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                           'last_persisted_time': 2,
                                           'events': [{'event_id': '2'},
                                                      {'event_id': '3'}]},
                                          {'id': '11',
                                           'last_persisted_time': 3,
                                           'events': [{'event_id': '22'},
                                                      {'event_id': '33'}]}],
      MIRRORED_OFFENSES_CTX_KEY: [],
      RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11'],
      'retry_compatible': False},
     False),
    # Happy flow: configuration matches retry_compatible
    ({'samples': '["{\\"id\\": \\"1\\", '
                 '\\"last_persisted_time\\": 2, '
                 '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}"]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'updated_mirrored_offenses': '["{\\"id\\": \\"1\\", '
                                   '\\"last_persisted_time\\": 2, '
                                   '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}", '
                                   '"{\\"id\\": \\"11\\", '
                                   '\\"last_persisted_time\\": 3, '
                                   '\\"events\\": [{\\"event_id\\": \\"22\\"}, {\\"event_id\\": \\"33\\"}]}"]',
      'mirrored_offenses': '[]',
      'resubmitted_mirrored_offenses': '["\\"1\\"", "\\"11\\""]',
      'retry_compatible': True},
     True),
    # Configuration doesn't match retry_compatible
    ({'samples': [{'id': '1', 'last_persisted_time': 2,
                   'events': [{'event_id': '2'}, {'event_id': '3'}]}],
      'last_mirror_update': '10',
      LAST_FETCH_KEY: 5,
      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                           'last_persisted_time': 2,
                                           'events': [{'event_id': '2'},
                                                      {'event_id': '3'}]},
                                          {'id': '11',
                                           'last_persisted_time': 3,
                                           'events': [{'event_id': '22'},
                                                      {'event_id': '33'}]}],
      MIRRORED_OFFENSES_CTX_KEY: [],
      RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11'],
      'retry_compatible': True},
     False),
    # Configuration doesn't match retry_compatible
    ({'samples': '["{\\"id\\": \\"1\\", '
                 '\\"last_persisted_time\\": 2, '
                 '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}"]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'updated_mirrored_offenses': '["{\\"id\\": \\"1\\", '
                                   '\\"last_persisted_time\\": 2, '
                                   '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}", '
                                   '"{\\"id\\": \\"11\\", '
                                   '\\"last_persisted_time\\": 3, '
                                   '\\"events\\": [{\\"event_id\\": \\"22\\"}, {\\"event_id\\": \\"33\\"}]}"]',
      'mirrored_offenses': '[]',
      'resubmitted_mirrored_offenses': '["\\"1\\"", "\\"11\\""]',
      'retry_compatible': False},
     True),
    # No retry_compatible
    ({'samples': [{'id': '1', 'last_persisted_time': 2,
                   'events': [{'event_id': '2'}, {'event_id': '3'}]}],
      'last_mirror_update': '10',
      LAST_FETCH_KEY: 5,
      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                           'last_persisted_time': 2,
                                           'events': [{'event_id': '2'},
                                                      {'event_id': '3'}]},
                                          {'id': '11',
                                           'last_persisted_time': 3,
                                           'events': [{'event_id': '22'},
                                                      {'event_id': '33'}]}],
      MIRRORED_OFFENSES_CTX_KEY: [],
      RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11'],
      'retry_compatible': False},
     False),
    ({'samples': [{'id': '1', 'last_persisted_time': 2,
                   'events': [{'event_id': '2'}, {'event_id': '3'}]}],
      'last_mirror_update': '10',
      LAST_FETCH_KEY: 5,
      UPDATED_MIRRORED_OFFENSES_CTX_KEY: [{'id': '1',
                                           'last_persisted_time': 2,
                                           'events': [{'event_id': '2'},
                                                      {'event_id': '3'}]},
                                          {'id': '11',
                                           'last_persisted_time': 3,
                                           'events': [{'event_id': '22'},
                                                      {'event_id': '33'}]}],
      MIRRORED_OFFENSES_CTX_KEY: [],
      RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: ['1', '11'],
      'retry_compatible': False, 'reset': True},
     False),
    ({'samples': '["{\\"id\\": \\"1\\", '
                 '\\"last_persisted_time\\": 2, '
                 '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}"]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'updated_mirrored_offenses': '["{\\"id\\": \\"1\\", '
                                   '\\"last_persisted_time\\": 2, '
                                   '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}", '
                                   '"{\\"id\\": \\"11\\", '
                                   '\\"last_persisted_time\\": 3, '
                                   '\\"events\\": [{\\"event_id\\": \\"22\\"}, {\\"event_id\\": \\"33\\"}]}"]',
      'mirrored_offenses': '[]',
      'resubmitted_mirrored_offenses': '["\\"1\\"", "\\"11\\""]',
      'retry_compatible': False},
     True),
    ({'samples': '["{\\"id\\": \\"1\\", '
                 '\\"last_persisted_time\\": 2, '
                 '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}"]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'updated_mirrored_offenses': '["{\\"id\\": \\"1\\", '
                                   '\\"last_persisted_time\\": 2, '
                                   '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}", '
                                   '"{\\"id\\": \\"11\\", '
                                   '\\"last_persisted_time\\": 3, '
                                   '\\"events\\": [{\\"event_id\\": \\"22\\"}, {\\"event_id\\": \\"33\\"}]}"]',
      'mirrored_offenses': '[]',
      'resubmitted_mirrored_offenses': '["\\"1\\"", "\\"11\\""]',
      'retry_compatible': False},
     True),
    ({'samples': '["{\\"id\\": \\"1\\", '
                 '\\"last_persisted_time\\": 2, '
                 '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}"]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'updated_mirrored_offenses': '["{\\"id\\": \\"1\\", '
                                   '\\"last_persisted_time\\": 2, '
                                   '\\"events\\": [{\\"event_id\\": \\"2\\"}, {\\"event_id\\": \\"3\\"}]}", '
                                   '"{\\"id\\": \\"11\\", '
                                   '\\"last_persisted_time\\": 3, '
                                   '\\"events\\": [{\\"event_id\\": \\"22\\"}, {\\"event_id\\": \\"33\\"}]}"]',
      'mirrored_offenses': '[]',
      'resubmitted_mirrored_offenses': '["\\"1\\"", "\\"11\\""]',
      'retry_compatible': False,
      'reset': True},
     True),
    ({'samples': '[{"id": "1", "last_persisted_time": 2, "events": [{"event_id": "2"}, {"event_id": "3"}]}]',
      'id': '"5"',
      'last_mirror_update': '"10"',
      'retry_compatible': True},
     False)
])
def test_change_ctx_to_be_compatible(mocker, context_data, retry_compatible):
    """Test changing the context data to be compatible with set_to_integration_context_with_retries.

    Given:
        Context data in the old or new format.

    When:
        Executing any command.

    Then:
        Ensure the context_data is transformed to the new format if needed.
    """
    mocker.patch.object(QRadar_v3, 'get_integration_context', return_value=context_data)
    mocker.patch.object(QRadar_v3, 'set_integration_context')
    mocker.patch.object(QRadar_v3.demisto, 'error')

    change_ctx_to_be_compatible_with_retry()

    extracted_ctx = {'last_mirror_update': '10', LAST_FETCH_KEY: 5}

    if not retry_compatible:
        QRadar_v3.set_integration_context.assert_called_once_with(clear_integration_ctx(extracted_ctx))
    else:
        assert not QRadar_v3.set_integration_context.called


@pytest.mark.parametrize('context_data', [
    # Expected after previous bug fix
    {'samples': '[{"id": "1", "last_persisted_time": 2, "events": [{"event_id": "2"}, {"event_id": "3"}]}]',
     'id': '"5"',
     'last_mirror_update': '"1000"',
     'retry_compatible': True,
     'reset': True},
    {'samples': [{"id": "1", "last_persisted_time": 2, "events": [{"event_id": "2"}, {"event_id": "3"}]}],
     'id': '5',
     'last_mirror_update': '"1000"',
     'retry_compatible': True},
    {'samples': "",
     'id': 5,
     'last_mirror_update': '1000'},
    {'samples': "",
     'id': 5,
     'last_mirror_update': 1000},
])
def test_clearing_of_ctx(context_data):
    """Test clearing context data works for all supported cases

    Given:
        Context data in the old or new format.

    When:
        Clearing the context data.

    Then:
        Ensure the context_data is cleared as expected.
    """
    expected_ctx = {LAST_FETCH_KEY: '5',
                    'last_mirror_update': '"1000"',
                    UPDATED_MIRRORED_OFFENSES_CTX_KEY: '[]',
                    MIRRORED_OFFENSES_CTX_KEY: '[]',
                    RESUBMITTED_MIRRORED_OFFENSES_CTX_KEY: '[]',
                    'samples': '[]'}

    assert clear_integration_ctx(context_data) == expected_ctx


def test_cleared_ctx_is_compatible_with_retries():
    """Make sure the cleared context data is compatoble with
    set_to_integration_context_with_retries as promised.

    This is needed since set_to_integration_context_with_retries
    runs update_integration_context which in turn assumes a certain
    context_data format.

    Given:
        Cleared context data in the set_to_integration_context_with_retries.

    When:
        Running set_to_integration_context_with_retries.

    Then:
        Ensure no error is raised.
    """
    cleared_ctx = clear_integration_ctx({'id': 5, 'last_mirror_update': '1000'})
    QRadar_v3.set_to_integration_context_with_retries(cleared_ctx)
    QRadar_v3.set_to_integration_context_with_retries({'id': 7})


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

                          (ctx_test_data['ctx_not_compatible']['no_mirroring_two_loops_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_two_loops_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_and_events_two_loops_offenses']),
                          (ctx_test_data['ctx_not_compatible']['no_mirroring_first_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_first_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_and_events_first_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['no_mirroring_second_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_second_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_and_events_second_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['no_mirroring_no_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_no_loop_offenses']),
                          (ctx_test_data['ctx_not_compatible']['mirror_offense_and_events_no_loop_offenses'])
                          ])
def test_integration_context_during_run(test_case_data, mocker):
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
    mirror_options = test_case_data['mirror_options']
    mirror_direction = test_case_data['mirror_direction']

    init_context = test_case_data['init_context']
    set_integration_context(init_context)
    if test_case_data['offenses_first_loop']:
        first_loop_offenses = ctx_test_data['offenses_first_loop']
        first_loop_offenses_with_events = [dict(offense, events=ctx_test_data['events']) for offense in
                                           first_loop_offenses]
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

    change_ctx_to_be_compatible_with_retry()
    reset_mirroring_events_variables(mirror_options)
    perform_long_running_loop(
        client=client,
        offenses_per_fetch=2,
        fetch_mode='Fetch With All Events',
        mirror_options=mirror_options,
        user_query='id > 5',
        events_columns='QIDNAME(qid), LOGSOURCENAME(logsourceid)',
        events_limit=3,
        ip_enrich=False,
        asset_enrich=False,
        incident_type=None,
        mirror_direction=mirror_direction
    )
    assert get_integration_context() == expected_ctx_first_loop

    if test_case_data['offenses_second_loop']:
        second_loop_offenses = ctx_test_data['offenses_second_loop']
        second_loop_offenses_with_events = [dict(offense, events=ctx_test_data['events']) for offense in
                                            second_loop_offenses]
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
        mirror_options=mirror_options,
        user_query='id > 15',
        events_columns='QIDNAME(qid), LOGSOURCENAME(logsourceid)',
        events_limit=3,
        ip_enrich=False,
        asset_enrich=False,
        incident_type=None,
        mirror_direction=mirror_direction
    )
    second_loop_ctx_not_default_values = test_case_data.get('second_loop_ctx_not_default_values', {})
    for k, v in second_loop_ctx_not_default_values.items():
        expected_ctx_second_loop[k] = v
    assert get_integration_context() == expected_ctx_second_loop
    set_integration_context({})


def test_update_missing_offenses_from_raw_offenses():
    """
    Assert missing offenses are copied from raw offenses
    Given:
        - enriched_offenses is missing some offenses
        - raw_offenses has the offenses missing from enriched_offenses
    When:
        - Calling update_missing_offenses_from_raw_offenses
    Then:
        - Assert missing offenses are copied from raw_offenses
        - Assert enriched offenses are not copied from raw_offenses
    """
    raw_offenses = [
        {'id': 1},
        {'id': 2},
        {'id': 3}
    ]
    enriched_offenses = [{'id': 2, 'events': []}]
    QRadar_v3.update_missing_offenses_from_raw_offenses(raw_offenses, enriched_offenses)
    assert len(enriched_offenses) == 3
    assert enriched_offenses[0]['id'] == 2
    assert 'events' in enriched_offenses[0]
    assert enriched_offenses[1]['id'] == 1
    assert 'events' not in enriched_offenses[1]
    assert enriched_offenses[2]['id'] == 3
    assert 'events' not in enriched_offenses[2]

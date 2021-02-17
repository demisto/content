"""
    QRadar_V3 integration for Cortex XSOAR - Unit Tests file
"""
import io
import json

import pytest

from QRadar_v3 import USECS_ENTRIES_MAPPING, OFFENSE_OLD_NEW_NAMES_MAP, MINIMUM_API_VERSION, Client
from QRadar_v3 import convert_epoch_time_to_datetime, add_iso_entries_to_dict, replace_keys, build_headers, \
    get_offense_types, get_offense_closing_reasons, get_domain_names, get_rules_names, enrich_assets_results

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


@pytest.mark.parametrize('epoch_time, expected',
                         [(0, None),
                          (None, None),
                          (1600000000000000, '2020-09-13T12:26:40+00:00')
                          ])
def test_convert_epoch_time_to_datetime_valid_cases(epoch_time, expected):
    """
    Given:
     - Time to be converted to date time in UTC timezone.

    When:
     - Case a: Epoch time is 0.
     - Case b: Epoch time is not given.
     - Case c: Valid epoch time is given.

    Then:
     - Case a: Ensure None is returned.
     - Case b: Ensure None is returned.
     - Case c: Ensure the corresponding date time string is returned.
    """
    assert convert_epoch_time_to_datetime(epoch_time) == expected


def test_add_iso_entries_to_dict():
    """
    Given:
     - Dict containing entries with epoch time.

    When:
     - Adding to entries with epoch time entries with iso time.

    Then:
     - All 'usecs' keys in the dict are replaced with 'iso time' entries with correct iso values.
    """
    tested_dict = {usec_entry: 1600000000000000 for usec_entry in USECS_ENTRIES_MAPPING.keys()}
    tested_dict['host_name'] = 'Nutanix Host'
    add_iso_entries_to_dict([tested_dict])
    assert tested_dict['host_name'] == 'Nutanix Host'
    assert all(
        tested_dict.get(iso_entry) == '2020-09-13T12:26:40+00:00' for iso_entry in USECS_ENTRIES_MAPPING.keys())
    assert all(
        tested_dict.get(iso_entry) == 1600000000000000 for iso_entry in USECS_ENTRIES_MAPPING.values())
    assert len(tested_dict) == (1 + (len(USECS_ENTRIES_MAPPING) * 2))


@pytest.mark.parametrize('output, old_new_dict, expected',
                         [([{'a': 2, 'c': 3}], {'a': 'b'}, [{'b': 2, 'c': 3}]),
                          ([OFFENSE_OLD_NEW_NAMES_MAP], OFFENSE_OLD_NEW_NAMES_MAP,
                           [{v: v for v in OFFENSE_OLD_NEW_NAMES_MAP.values()}]),
                          ([{'description': 'bla'}], {'name': 'Adam'}, [{'description': 'bla'}]),
                          ([{'a': 1, 'b': 2, 'c': 3}, {'a': 4, 'd': 5, 'e': 6}],
                           {'a': 'A', 'b': 'B', 'd': 'D'}, [{'A': 1, 'B': 2, 'c': 3}, {'A': 4, 'D': 5, 'e': 6}])])
def test_replace_keys(output, old_new_dict, expected):
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
    assert (replace_keys(output, old_new_dict)) == expected


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


@pytest.mark.parametrize('enrich_func, mock_func_name, outputs, mock_response, expected',
                         [
                             (get_offense_types,
                              'qradar_offense_types',
                              [{'offense_type': 1, 'offense_name': 'offense1'},
                               {'offense_type': 2, 'offense_name': 'offense2'}],
                              [{'id': 1, 'name': 'Scheduled Search'},
                               {'id': 2, 'name': 'Destination IP Identity'}],
                              {1: 'Scheduled Search', 2: 'Destination IP Identity'}
                              ),
                             (get_offense_closing_reasons,
                              'qradar_closing_reasons_list',
                              [{'closing_reason_id': 3, 'offense_name': 'offense1'},
                               {'closing_reason_id': 4, 'offense_name': 'offense2'}],
                              [{'id': 3, 'text': 'Non-Issue'},
                               {'id': 4, 'text': 'Policy Violation'}],
                              {3: 'Non-Issue', 4: 'Policy Violation'}
                              ),
                             (get_domain_names,
                              'qradar_domains_list',
                              [{'domain_id': 5, 'offense_name': 'offense1'},
                               {'domain_id': 6, 'offense_name': 'offense2'}],
                              [{'id': 5, 'name': 'domain1'},
                               {'id': 6, 'name': 'domain2'}],
                              {5: 'domain1', 6: 'domain2'}
                              ),
                             (get_rules_names,
                              'qradar_rules_list',
                              [{'rules': [{'id': 7}, {'id': 8}], 'offense_name': 'offense1'},
                               {'rules': [{'id': 9}], 'offense_name': 'offense2'}],
                              [{'id': 7, 'name': 'Devices with High Event Rates'},
                               {'id': 8, 'name': 'Excessive Database Connections'},
                               {'id': 9, 'name': 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}],
                              {7: 'Devices with High Event Rates',
                               8: 'Excessive Database Connections',
                               9: 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}
                              ),

                             # Empty cases
                             (get_offense_types,
                              'qradar_offense_types',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_offense_closing_reasons,
                              'qradar_closing_reasons_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_domain_names,
                              'qradar_domains_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_rules_names,
                              'qradar_rules_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              )
                         ])
def test_outputs_enriches(mocker, enrich_func, mock_func_name, outputs, mock_response, expected):
    mocker.patch.object(client, mock_func_name, return_value=mock_response)
    assert (enrich_func(client, outputs)) == expected


@pytest.mark.parametrize('assets, domain_mock_response, full_enrichment, expected', [
    (asset_enrich_data['assets'],
     asset_enrich_data['domain_mock_response'],
     asset_enrich_data['case_one']['full_enrichment'],
     asset_enrich_data['case_one']['expected']
     ),
    (asset_enrich_data['assets'],
     asset_enrich_data['domain_mock_response'],
     asset_enrich_data['case_two']['full_enrichment'],
     asset_enrich_data['case_two']['expected']
     )])
def test_assets_enriches(mocker, assets, domain_mock_response, full_enrichment, expected):
    mocker.patch.object(client, 'qradar_domains_list', return_value=domain_mock_response)

    assert (enrich_assets_results(client, assets, full_enrichment)) == expected

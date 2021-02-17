"""
    QRadar_V3 integration for Cortex XSOAR - Unit Tests file
"""
import io
import json
from datetime import datetime

import pytest
import pytz

from QRadar_v3 import USECS_ENTRIES, OFFENSE_OLD_NEW_NAMES_MAP, MINIMUM_API_VERSION, Client
from QRadar_v3 import get_time_parameter, add_iso_entries_to_dict, replace_keys, build_headers, \
    get_offense_types, get_offense_closing_reasons, get_domain_names, get_rules_names, enrich_assets_results, \
    get_offense_source_addresses, get_offense_destination_addresses

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
    tested_dict['host_name'] = 'Nutanix Host'
    output_dict = add_iso_entries_to_dict([tested_dict])[0]
    assert tested_dict['host_name'] == 'Nutanix Host'
    assert output_dict['host_name'] == 'Nutanix Host'
    assert all(
        tested_dict.get(iso_entry) == 1600000000000 for iso_entry in USECS_ENTRIES)
    assert all(
        output_dict.get(iso_entry) == '2020-09-13T12:26:40+00:00' for iso_entry in USECS_ENTRIES)
    assert len(tested_dict) == (1 + len(USECS_ENTRIES))
    assert len(output_dict) == (1 + len(USECS_ENTRIES))


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
                              'offense_types',
                              [{'offense_type': 1, 'offense_name': 'offense1'},
                               {'offense_type': 2, 'offense_name': 'offense2'}],
                              [{'id': 1, 'name': 'Scheduled Search'},
                               {'id': 2, 'name': 'Destination IP Identity'}],
                              {1: 'Scheduled Search', 2: 'Destination IP Identity'}
                              ),
                             (get_offense_closing_reasons,
                              'closing_reasons_list',
                              [{'closing_reason_id': 3, 'offense_name': 'offense1'},
                               {'closing_reason_id': 4, 'offense_name': 'offense2'}],
                              [{'id': 3, 'text': 'Non-Issue'},
                               {'id': 4, 'text': 'Policy Violation'}],
                              {3: 'Non-Issue', 4: 'Policy Violation'}
                              ),
                             (get_domain_names,
                              'domains_list',
                              [{'domain_id': 5, 'offense_name': 'offense1'},
                               {'domain_id': 6, 'offense_name': 'offense2'}],
                              [{'id': 5, 'name': 'domain1'},
                               {'id': 6, 'name': 'domain2'}],
                              {5: 'domain1', 6: 'domain2'}
                              ),
                             (get_rules_names,
                              'rules_list',
                              [{'rules': [{'id': 7}, {'id': 8}], 'offense_name': 'offense1'},
                               {'rules': [{'id': 9}], 'offense_name': 'offense2'}],
                              [{'id': 7, 'name': 'Devices with High Event Rates'},
                               {'id': 8, 'name': 'Excessive Database Connections'},
                               {'id': 9, 'name': 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}],
                              {7: 'Devices with High Event Rates',
                               8: 'Excessive Database Connections',
                               9: 'Anomaly: Excessive Firewall Accepts Across Multiple Hosts'}
                              ),
                             (get_offense_source_addresses,
                              'source_addresses',
                              [{'source_address_ids': [1, 2], 'offense_name': 'offense1'},
                               {'source_address_ids': [3, 4], 'offense_name': 'offense2'}],
                              [{'id': 1, 'source_ip': '1.2.3.4'},
                               {'id': 2, 'source_ip': '1.2.3.5'},
                               {'id': 3, 'source_ip': '1.2.3.6'},
                               {'id': 4, 'source_ip': '192.168.0.2'}],
                              {1: '1.2.3.4',
                               2: '1.2.3.5',
                               3: '1.2.3.6',
                               4: '192.168.0.2'}
                              ),
                             (get_offense_destination_addresses,
                              'destination_addresses',
                              [{'local_destination_address_ids': [1, 2], 'offense_name': 'offense1'},
                               {'local_destination_address_ids': [3, 4], 'offense_name': 'offense2'}],
                              [{'id': 1, 'local_destination_ip': '1.2.3.4'},
                               {'id': 2, 'local_destination_ip': '1.2.3.5'},
                               {'id': 3, 'local_destination_ip': '1.2.3.6'},
                               {'id': 4, 'local_destination_ip': '192.168.0.2'}],
                              {1: '1.2.3.4',
                               2: '1.2.3.5',
                               3: '1.2.3.6',
                               4: '192.168.0.2'}
                              ),

                             # Empty cases
                             (get_offense_types,
                              'offense_types',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_offense_closing_reasons,
                              'closing_reasons_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_domain_names,
                              'domains_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_rules_names,
                              'rules_list',
                              [{'offense_name': 'offense1'},
                               {'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_offense_source_addresses,
                              'source_addresses',
                              [{'source_address_ids': [], 'offense_name': 'offense1'},
                               {'source_address_ids': [], 'offense_name': 'offense2'}],
                              None,
                              dict()
                              ),
                             (get_offense_destination_addresses,
                              'destination_addresses',
                              [{'local_destination_address_ids': [], 'offense_name': 'offense1'},
                               {'local_destination_address_ids': [], 'offense_name': 'offense2'}],
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
    mocker.patch.object(client, 'domains_list', return_value=domain_mock_response)

    assert (enrich_assets_results(client, assets, full_enrichment)) == expected

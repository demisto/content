"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import os
import pytest
from contextlib import nullcontext as does_not_raise
# import demistomock as demisto
from CommonServerPython import DemistoException

from VectraDetect import MAX_RESULTS  # Currently MAX_RESULTS equals 200
from VectraDetect import UI_ACCOUNTS, UI_HOSTS, UI_DETECTIONS
from VectraDetect import VectraException

SERVER_FQDN = "vectra.test"
SERVER_URL = f"https://{SERVER_FQDN}"
API_VERSION_URI = '/api/v2.3'
API_URL = f'{SERVER_URL}{API_VERSION_URI}'
API_SEARCH_ENDPOINT_ACCOUNTS = '/search/accounts'
API_SEARCH_ENDPOINT_DETECTIONS = '/search/detections'
API_SEARCH_ENDPOINT_HOSTS = '/search/hosts'
API_ENDPOINT_ASSIGNMENTS = '/assignments'
API_ENDPOINT_DETECTIONS = '/detections'
API_ENDPOINT_OUTCOMES = '/assignment_outcomes'
API_ENDPOINT_USERS = '/users'
API_TAGGING = '/tagging'


def load_test_data(json_path):
    relative_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data')
    with open(os.path.join(relative_dir, json_path)) as f:
        return json.load(f)


#####
# ## Globals
#
integration_params = None


#####
# ## Validate helpers
#

@pytest.mark.parametrize(
    "input,expected",
    [
        ('true', True),
        ('True', True),
        ('trUE', True),
        ('YES', True),
        ('false', False),
        ('NO', False),
        ('vectra', None),
        ('', None),
        (None, None)
    ]
)
def test_str2bool(input, expected):
    """
    Tests the str2bool helper function.
    """
    from VectraDetect import str2bool

    assert str2bool(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        (100, 100),
        (8, 8),
        ('10', 10),
        (250, MAX_RESULTS)
    ]
)
def test_sanitize_max_results(input, expected):
    """
    Tests sanitize_max_results helper function.
    """
    from VectraDetect import sanitize_max_results

    assert sanitize_max_results(input) == expected


@pytest.mark.parametrize(
    "input_threat,input_certainty,expected",
    [
        (5, 5, 'Low'),
        (39, 55, 'Medium'),
        (51, 35, 'High'),
        (50, 50, 'Critical')
    ]
)
def test_scores_to_severity(input_threat, input_certainty, expected):
    """
    Tests scores_to_severity helper function.
    """
    from VectraDetect import scores_to_severity

    assert scores_to_severity(input_threat, input_certainty) == expected


@pytest.mark.parametrize(
    "input_severity,expected",
    [
        ('Critical', 4),
        ('High', 3),
        ('Medium', 2),
        ('Low', 1),
        ('test', 0),
        ('', 0)
    ]
)
def test_severity_string_to_int(input_severity, expected):
    """
    Tests severity_string_to_int helper function.
    """
    from VectraDetect import severity_string_to_int

    assert severity_string_to_int(input_severity) == expected


@pytest.mark.parametrize(
    "input_date,expected",
    [
        ('2022-10-10T14:28:56Z', '2022-10-10T14:28:56.000Z'),
        ('2022-01-01T01:01:01Z', '2022-01-01T01:01:01.000Z'),
        ('Vectra', None),
        (None, None)
    ]
)
def test_convert_date(input_date, expected):
    """
    Tests convert_Date helper function.
    """
    from VectraDetect import convert_date

    assert convert_date(input_date) == expected


# Compute all combinations
validate_argument_test_data = []
for input_type in {'min_id', 'max_id'}:
    for valid_value in {1, 5}:
        validate_argument_test_data.append(
            pytest.param(input_type, valid_value, does_not_raise(),
                         id=f"{input_type}_{valid_value}_no-exception"))
    for invalid_value in {0, -3, 12.3, 'vectra', '', None}:
        validate_argument_test_data.append(
            pytest.param(input_type, invalid_value,
                         pytest.raises(ValueError, match=f'"{input_type}" must be an integer greater than 0'),
                         id=f"{input_type}_{'none' if invalid_value is None else invalid_value}_gt-0"))
for input_type in {'min_threat', 'min_certainty', 'max_threat', 'max_certainty'}:
    for valid_value in {0, 99}:
        validate_argument_test_data.append(
            pytest.param(input_type, valid_value, does_not_raise(),
                         id=f"{input_type}_{valid_value}_no-exception"))
    for invalid_value in {-1, 100, -3, 12.3, 'vectra', '', None}:
        validate_argument_test_data.append(
            pytest.param(input_type, invalid_value,
                         pytest.raises(ValueError, match=f'"{input_type}" must be an integer between 0 and 99'),
                         id=f"{input_type}_{'none' if invalid_value is None else invalid_value}_0-99"))
for input_type in {'min_privilege_level'}:
    for valid_value in {1, 5, 10}:
        validate_argument_test_data.append(
            pytest.param(input_type, valid_value, does_not_raise(),
                         id=f"{input_type}_{valid_value}_no-exception"))
    for invalid_value in {0, 11, -3, 12.3, 'vectra', '', None}:
        validate_argument_test_data.append(
            pytest.param(input_type, invalid_value,
                         pytest.raises(ValueError, match=f'"{input_type}" must be an integer between 1 and 10'),
                         id=f"{input_type}_{'none' if invalid_value is None else invalid_value}_1-10"))
validate_argument_test_data.append(
    pytest.param('vectra', 'vectra',
                 pytest.raises(SystemError, match='Unknow argument type'),
                 id='invalid-argument_exception'))


@pytest.mark.parametrize(
    "input_type,input_value,expected",
    validate_argument_test_data
)
def test_validate_argument(input_type, input_value, expected):
    """
    Tests validate_argument helper command
    """
    from VectraDetect import validate_argument

    with expected:
        assert validate_argument(input_type, input_value) is not None


@pytest.mark.parametrize(
    "min_type,min_value,max_type,max_value,expected",
    [
        ('min_id', 12, 'max_id', 15, does_not_raise()),
        ('min_id', 20, 'max_id', 20, does_not_raise()),
        ('min_id', 30, 'max_id', 25, pytest.raises(ValueError, match='"max_id" must be greater than or equal to "min_id"')),
        ('min_threat', 12, 'max_threat', 35, does_not_raise()),
        ('min_certainty', 15, 'max_certainty', 35, does_not_raise()),
    ]
)
def test_validate_min_max(min_type, min_value, max_type, max_value, expected):
    """
    Tests validate_min_max helper function.
    """

    from VectraDetect import validate_min_max

    with expected:
        assert validate_min_max(min_type, min_value, max_type, max_value) is True


@pytest.mark.parametrize(
    "input_list,expected,exception",
    [
        pytest.param(None, None,
                     does_not_raise(),
                     id="none_no-exception"),
        pytest.param('', None,
                     does_not_raise(),
                     id="empty_no-exception"),
        pytest.param('1', {1},
                     does_not_raise(),
                     id="single-element_no-exception"),
        pytest.param('1,2,3', {1, 2, 3},
                     does_not_raise(),
                     id="multiple-elements_no-exception"),
        pytest.param('1 , 2, 3', {1, 2, 3},
                     does_not_raise(),
                     id="with-spaces_no-exception"),
        pytest.param('1 , 2, 3', {1, 2, 3},
                     does_not_raise(),
                     id="with-spaces_no-exception"),
        pytest.param('1 , 2, , 3', {1, 2, 3},
                     does_not_raise(),
                     id="with-empty-element_no-exception"),
    ]
)
def test_sanitize_str_ids_list_to_set(input_list, expected, exception):
    """
    Tests sanitize_str_ids_list_to_set helper function.
    """

    from VectraDetect import sanitize_str_ids_list_to_set

    with exception:
        assert sanitize_str_ids_list_to_set(input_list) == expected


@pytest.mark.parametrize(
    "object_type,params,expected",
    [
        pytest.param('account', {'min_id': '12'},
                     'account.id:>=12',
                     id="account_min-id"),
        pytest.param('account', {'max_threat': '12'},
                     'account.threat:<=12',
                     id="account_max-threat"),
        pytest.param('account', {'min_id': '12', 'max_certainty': '28'},
                     'account.id:>=12 account.certainty:<=28',
                     id="account_min-id_max-certainty"),
        pytest.param('host', {'min_id': '12', 'state': 'inactive'},
                     'host.id:>=12 host.state:"inactive"',
                     id="host_min-id_state"),
        pytest.param('host', {'last_timestamp': '20220101T0123', 'state': 'active'},
                     'host.last_detection_timestamp:>=20220101T0123 host.state:"active"',
                     id="host_last_timestamp_state"),
        pytest.param('detection', {'last_timestamp': '20220101T0123', 'state': 'active'},
                     'detection.last_timestamp:>=20220101T0123 detection.state:"active"',
                     id="detection_last_timestamp_state"),
    ]
)
def test_build_search_query(object_type, params, expected):
    """
    Tests build_search_query helper command
    """

    from VectraDetect import build_search_query

    assert build_search_query(object_type, params) == expected


@pytest.mark.parametrize(
    "object_type,id,expected,exception",
    [
        pytest.param('account', 123, f"{SERVER_URL}{UI_ACCOUNTS}/123",
                     does_not_raise(),
                     id="account_ok"),
        pytest.param('host', 234, f"{SERVER_URL}{UI_HOSTS}/234",
                     does_not_raise(),
                     id="host_ok"),
        pytest.param('detection', 345, f"{SERVER_URL}{UI_DETECTIONS}/345",
                     does_not_raise(),
                     id="detection_ok"),
        pytest.param('vectra', 15, True,
                     pytest.raises(Exception, match='Unknown type : vectra'),
                     id="invalid-type_exception"),
        pytest.param('account', None, True,
                     pytest.raises(Exception, match='Missing ID'),
                     id="invalid-id_exception"),
    ]
)
def test_forge_entity_url(object_type, id, expected, exception):
    """
    Tests forge_entity_url helper function
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    with exception:
        assert VectraDetect.forge_entity_url(object_type, id) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_account.json'),
                     load_test_data('single_account_extracted.json').get('common_extract'),
                     id="common_account_ok"),
        pytest.param(load_test_data('single_host.json'),
                     load_test_data('single_host_extracted.json').get('common_extract'),
                     id="common_host_ok"),
        pytest.param(load_test_data('single_detection.json'),
                     load_test_data('single_detection_extracted.json').get('common_extract'),
                     id="common_detection_ok"),
    ]
)
def test_common_extract_data(api_entry, expected):
    """
    Tests common_extract_data helper function
    """
    from VectraDetect import common_extract_data

    assert common_extract_data(api_entry) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_account.json'),
                     load_test_data('single_account_extracted.json').get('account_extract'),
                     id="account_ok")
    ]
)
def test_extract_account_data(api_entry, expected):
    """
    Tests extract_account_data helper function
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import extract_account_data

    assert extract_account_data(api_entry) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_detection.json'),
                     load_test_data('single_detection_extracted.json').get('detection_extract'),
                     id="common_detection_ok"),
    ]
)
def test_extract_detection_data(api_entry, expected):
    """
    Tests extract_detection_data helper function
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import extract_detection_data

    assert extract_detection_data(api_entry) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_host.json'),
                     load_test_data('single_host_extracted.json').get('host_extract'),
                     id="common_host_ok"),
    ]
)
def test_extract_host_data(api_entry, expected):
    """
    Tests extract_host_data helper function
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import extract_host_data

    assert extract_host_data(api_entry) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_assignment.json'),
                     load_test_data('single_assignment_extracted.json'),
                     id="assignment_ok")
    ]
)
def test_extract_assignment_data(api_entry, expected):
    """
    Tests extract_assignment_data helper function
    """
    from VectraDetect import extract_assignment_data

    assert extract_assignment_data(api_entry) == expected


@pytest.mark.parametrize(
    "api_entry,expected",
    [
        pytest.param(load_test_data('single_outcome.json'),
                     load_test_data('single_outcome_extracted.json'),
                     id="outcome_ok")
    ]
)
def test_extract_outcome_data(api_entry, expected):
    """
    Tests extract_outcome_data helper function
    """
    from VectraDetect import extract_outcome_data

    assert extract_outcome_data(api_entry) == expected


@pytest.mark.parametrize(
    "input_date,expected,exception",
    [
        pytest.param('2022-06-30T01:23:45Z', '2022-06-30T0123',
                     does_not_raise(),
                     id="timestamp_ok"),
        pytest.param('2022-06-30T01:23:45.000Z', '2022-06-30T0123',
                     does_not_raise(),
                     id="timestamp-with-milli_ok"),
        pytest.param('vectra', 'exception',
                     pytest.raises(SystemError, match='Invalid ISO date'),
                     id="string_exception"),
    ]
)
def test_iso_date_to_vectra_start_time(input_date, expected, exception):
    """
    Tests iso_date_to_vectra_start_time helper function
    """
    from VectraDetect import iso_date_to_vectra_start_time

    with exception:
        assert iso_date_to_vectra_start_time(input_date) == expected


@pytest.mark.parametrize(
    "input_severity,expected",
    [
        ('critical', 'Critical'),
        ('HIGH', 'High'),
        ('mEdIuM', 'Medium'),
        ('', 'Unknown')
    ]
)
def test_unify_severity(input_severity, expected):
    """
    Tests severity_string_to_int helper function.
    """
    from VectraDetect import unify_severity

    assert unify_severity(input_severity) == expected


@pytest.mark.parametrize(
    "input_category,expected",
    [
        ('benign_true_positive', 'Benign True Positive'),
        ('malicious_true_positive', 'Malicious True Positive'),
        ('false_positive', 'False Positive'),
        ('dummy', None),
        ('', None),
    ]
)
def test_convert_outcome_category_raw2text(input_category, expected):
    """
    Tests convert_outcome_category_raw2text helper function.
    """
    from VectraDetect import convert_outcome_category_raw2text

    assert convert_outcome_category_raw2text(input_category) == expected


@pytest.mark.parametrize(
    "input_category,expected",
    [
        ('Benign True Positive', 'benign_true_positive'),
        ('Malicious True Positive', 'malicious_true_positive'),
        ('False Positive', 'false_positive'),
        ('dummy', None),
        ('', None),
    ]
)
def test_convert_outcome_category_text2raw(input_category, expected):
    """
    Tests convert_outcome_category_text2raw helper function.
    """
    from VectraDetect import convert_outcome_category_text2raw

    assert convert_outcome_category_text2raw(input_category) == expected


#####
# ## Validate functions
#

@pytest.mark.parametrize(
    "integration_params,expected",
    [
        pytest.param({},
                     'ok',
                     id="no-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': 'vectra'},
                     'Fetch first timestamp is invalid.',
                     id="wrong-fetch-time"),
        pytest.param({'isFetch': True, 'first_fetch': '7 days', 'fetch_entity_types': ['vectra']},
                     'This entity type "vectra" is invalid.',
                     id="wrong-entity-type"),
        pytest.param({'isFetch': True, 'first_fetch': '7 days', 'fetch_entity_types': ['Hosts']},
                     'ok',
                     id="hosts-entity"),
        pytest.param({'isFetch': True, 'first_fetch': '7 days', 'fetch_entity_types': ['Hosts'], 'max_fetch': 'vectra'},
                     'Max incidents per fetch must be a positive integer.',
                     id="string-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7 days', 'fetch_entity_types': ['Hosts'], 'max_fetch': '0'},
                     'Max incidents per fetch must be a positive integer.',
                     id="0-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7d', 'fetch_entity_types': ['Hosts', 'Detections'], 'max_fetch': '1'},
                     "Max incidents per fetch (1) must be >= to the number of entity types you're fetching (2)",
                     id="too-low-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7d', 'fetch_entity_types': ['Hosts', 'Detections'], 'max_fetch': '5'},
                     'ok',
                     id="all-good"),
    ]
)
# @freeze_time("2022-07-01 11:00:00 GMT")
def test_test_module(requests_mock, integration_params, expected):
    """
    Tests test_module command function.
    """
    from VectraDetect import Client, test_module

    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=1',
                      json={'count': 1, 'results': [load_test_data('single_detection.json')]})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=1'
                      f'&query_string=detection.state:"active"',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_detection.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    assert test_module(client=client, integration_params=integration_params) == expected


# Test only the exceptions for now
@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({'search_query_only': 'no-count'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param({'search_query': 'no-results'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception")
    ]
)
def test_vectra_search_accounts_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_accounts_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_search_accounts_command

    # Default answer
    # Not implemented yet

    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=account.state:"active" AND no-results',
                      complete_qs=True,
                      json={'count': 1})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_accounts_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


# Test only the exceptions for now
@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({'search_query_only': 'no-count'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param({'search_query': 'no-results'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception")
    ]
)
def test_vectra_search_detections_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_detections_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_search_detections_command

    # Default answer
    # Not implemented yet

    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=detection.state:"active" AND no-results',
                      complete_qs=True,
                      json={'count': 1})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_detections_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


# Test only the exceptions for now
@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({'search_query_only': 'no-count'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param({'search_query': 'no-results'}, None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception")
    ]
)
def test_vectra_search_hosts_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_hosts_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_search_hosts_command

    # Default answer
    # Not implemented yet

    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=host.state:"active" AND no-results',
                      complete_qs=True,
                      json={'count': 1})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_hosts_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({}, [load_test_data('single_assignment_extracted.json')], None,
                     does_not_raise(),
                     id="full-pull")
    ]
)
def test_vectra_search_assignments_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_assignments_command command function.
    """
    from VectraDetect import Client, vectra_search_assignments_command

    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}'
                      f'?resolved=false',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_assignment.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_assignments_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({}, [load_test_data('single_outcome_extracted.json')], None,
                     does_not_raise(),
                     id="full-pull")
    ]
)
def test_vectra_search_outcomes_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_outcomes_command command function.
    """
    from VectraDetect import Client, vectra_search_outcomes_command

    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_OUTCOMES}'
                      f'?page=1&page_size=200',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_outcome.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_outcomes_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "query_args,expected_outputs,expected_readable,exception",
    [
        pytest.param({}, [load_test_data('single_user_extracted.json')], None,
                     does_not_raise(),
                     id="full-pull")
    ]
)
def test_vectra_search_users_command(requests_mock, query_args, expected_outputs, expected_readable, exception):
    """
    Tests vectra_search_users_command command function.
    """
    from VectraDetect import Client, vectra_search_users_command

    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_USERS}',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_user.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_search_users_command(client=client, **query_args)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('no-count', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param('no-results', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception"),
        pytest.param('multiple', None, None,
                     pytest.raises(VectraException, match='Multiple Accounts found'),
                     id="api-multiple-results_exception"),
        pytest.param('1', None, 'Cannot find Account with ID "1".',
                     does_not_raise(),
                     id="not-found_no-exception"),
        pytest.param('36', load_test_data('single_account_extracted.json').get('account_extract'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_account_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_account_by_id_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_get_account_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}',
                      json={'count': 0, 'results': []})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=account.id:no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=account.id:no-results',
                      complete_qs=True,
                      json={'count': 1})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=account.id:multiple',
                      complete_qs=True,
                      json={'count': 2, 'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=account.id:36',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_account.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_account_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('no-count', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param('no-results', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception"),
        pytest.param('multiple', None, None,
                     pytest.raises(VectraException, match='Multiple Detections found'),
                     id="api-multiple-results_exception"),
        pytest.param('1', None, 'Cannot find Detection with ID "1".',
                     does_not_raise(),
                     id="not-found_no-exception"),
        pytest.param('14', load_test_data('single_detection_extracted.json').get('detection_extract'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_detection_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_detection_by_id_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_get_detection_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}',
                      json={'count': 0, 'results': []})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=detection.id:no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=detection.id:no-results',
                      complete_qs=True,
                      json={'count': 1})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=detection.id:multiple',
                      complete_qs=True,
                      json={'count': 2, 'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}'
                      f'?page=1&order_field=last_timestamp&page_size=200'
                      f'&query_string=detection.id:14',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_detection.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_detection_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('no-count', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-count_exception"),
        pytest.param('no-results', None, None,
                     pytest.raises(VectraException, match='API issue - Response is empty or invalid'),
                     id="api-no-results_exception"),
        pytest.param('multiple', None, None,
                     pytest.raises(VectraException, match='Multiple Hosts found'),
                     id="api-multiple-results_exception"),
        pytest.param('1', None, 'Cannot find Host with ID "1".',
                     does_not_raise(),
                     id="not-found_no-exception"),
        pytest.param('472', load_test_data('single_host_extracted.json').get('host_extract'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_host_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_host_by_id_command command function.
    """
    # Force some integration settings for testing purpose
    # It's used inside the forge_entity_url function
    # Need to import all module due to global variable
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    from VectraDetect import Client, vectra_get_host_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}',
                      json={'count': 0, 'results': []})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=host.id:no-count',
                      complete_qs=True,
                      json={'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=host.id:no-results',
                      complete_qs=True,
                      json={'count': 1})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=host.id:multiple',
                      complete_qs=True,
                      json={'count': 2, 'results': []})
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}'
                      f'?page=1&order_field=last_detection_timestamp&page_size=200'
                      f'&query_string=host.id:472',
                      complete_qs=True,
                      json={'count': 1, 'results': [load_test_data('single_host.json')]})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_host_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


# Test only the exceptions for now
@pytest.mark.parametrize(
    "id,expected,exception",
    [
        pytest.param(None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('15', None,
                     pytest.raises(DemistoException, match='Error in API call'),
                     id="no-pcap_exception"),
    ]
)
def test_get_detection_pcap_file_command(requests_mock, id, expected, exception):
    """
    Tests get_detection_pcap_file_command command function.
    """
    from VectraDetect import Client, get_detection_pcap_file_command

    requests_mock.get(f'{API_URL}{API_ENDPOINT_DETECTIONS}/10/pcap',
                      complete_qs=True,
                      content=b"0000")
    requests_mock.get(f'{API_URL}{API_ENDPOINT_DETECTIONS}/15/pcap',
                      complete_qs=True,
                      status_code=404,
                      json={"status": 404, "reason": "File Not Found"})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        assert get_detection_pcap_file_command(client=client, id=id) == expected


@pytest.mark.parametrize(
    "id,fixed,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('12', None, None, None,
                     pytest.raises(VectraException, match='"fixed" not specified'),
                     id="no-fixed_exception"),
        pytest.param('12', 'vectra', None, None,
                     pytest.raises(VectraException, match='"fixed" not specified'),
                     id="no-fixed_exception"),
        pytest.param('12', 'true', None, 'Detection "12" successfully marked as fixed.',
                     does_not_raise(),
                     id="fixed_no-exception"),
        pytest.param('12', 'no', None, 'Detection "12" successfully unmarked as fixed.',
                     does_not_raise(),
                     id="unfixed_no-exception"),
    ]
)
def test_mark_detection_as_fixed_command(requests_mock, id, fixed, expected_outputs, expected_readable, exception):
    """
    Tests mark_detection_as_fixed_command command function.
    """
    from VectraDetect import Client, mark_detection_as_fixed_command

    requests_mock.patch(f'{API_URL}{API_ENDPOINT_DETECTIONS}',
                        complete_qs=True,
                        json={"_meta": {"level": "Success", "message": "Successfully marked detections"}})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = mark_detection_as_fixed_command(client=client, id=id, fixed=fixed)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="none-id_exception"),
        pytest.param('25', load_test_data('single_assignment_extracted.json'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_assignment_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_assignment_by_id_command command function.
    """
    from VectraDetect import Client, vectra_get_assignment_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}',
                      json={})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}'
                      f'/25',
                      complete_qs=True,
                      json={'assignment': load_test_data('single_assignment.json')})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_assignment_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


# Test only the exceptions for now
@pytest.mark.parametrize(
    "assignee_id,account_id,host_id,assignment_id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None, None, None, None,
                     pytest.raises(VectraException, match='"assignee_id" not specified'),
                     id="none-assignee-id_exception"),
        pytest.param('1', None, None, None, None, None,
                     pytest.raises(VectraException, match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="none-entity-ids_exception"),
        pytest.param('1', '2', '3', None, None, None,
                     pytest.raises(VectraException, match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="account-and-host-ids_exception"),
        pytest.param('1', '2', None, '4', None, None,
                     pytest.raises(VectraException, match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="account-and-assignment-ids_exception"),
        pytest.param('1', None, '3', '4', None, None,
                     pytest.raises(VectraException, match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="host-and-assignment-ids_exception"),
        pytest.param('1', '2', '3', '4', None, None,
                     pytest.raises(VectraException, match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="all-ids_exception"),
        pytest.param('text-id', None, None, '4', None, None,
                     pytest.raises(ValueError, match='"assignee_id" value is invalid'),
                     id="text-assignee-id_exception"),
        pytest.param('1', 'text-id', None, None, None, None,
                     pytest.raises(ValueError, match='"account_id" value is invalid'),
                     id="text-account-id_exception"),
        pytest.param('1', None, 'text-id', None, None, None,
                     pytest.raises(ValueError, match='"host_id" value is invalid'),
                     id="text-host-id_exception"),
        pytest.param('1', None, None, 'text-id', None, None,
                     pytest.raises(ValueError, match='"assignment_id" value is invalid'),
                     id="text-assignment-id_exception"),
        pytest.param('1', None, None, '25', load_test_data('single_assignment_extracted.json'), None,
                     does_not_raise(),
                     id="assignment_ok"),
    ]
)
def test_vectra_assignment_assign_command(requests_mock,
                                          assignee_id, account_id, host_id, assignment_id,
                                          expected_outputs, expected_readable, exception):
    """
    Tests vectra_assignment_assign_command command function.
    """
    from VectraDetect import Client, vectra_assignment_assign_command

    # Test answer, useless to check XSOAR inner exceptions (none API call raised)
    # Need to create inner checks based on post query body to have a better coverage
    requests_mock.put(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}'
                      '/25',
                      complete_qs=True,
                      json={'assignment': load_test_data('single_assignment.json')})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_assignment_assign_command(client=client, assignee_id=assignee_id,
                                                  account_id=account_id, host_id=host_id,
                                                  assignment_id=assignment_id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


# Test only the exceptions for now
@pytest.mark.parametrize(
    "assignment_id,outcome_id,note,detections_filter,filter_rule_name,detections_list,"
    "expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None, None, None, None,
                     None, None,
                     pytest.raises(VectraException, match='"assignment_id" not specified'),
                     id="none-assignment-id_exception"),
        pytest.param('1', None, None, None, None, None,
                     None, None,
                     pytest.raises(VectraException, match='"outcome_id" not specified'),
                     id="none-outcome-id_exception"),
        pytest.param('1', '2', None, 'Filter Rule', None, None,
                     None, None,
                     pytest.raises(VectraException, match='"filter_rule_name" not specified'),
                     id="none-filter-rule-name_exception"),
        pytest.param('1', '2', None, 'Filter Rule', 'Dummy Name', None,
                     None, None,
                     pytest.raises(VectraException, match='"detections_list" not specified'),
                     id="none-detections-list_exception"),
        pytest.param('text-id', '2', None, None, None, None,
                     None, None,
                     pytest.raises(ValueError, match='"assignment_id" value is invalid'),
                     id="text-assignment-id_exception"),
        pytest.param('1', 'text-id', None, None, None, None,
                     None, None,
                     pytest.raises(ValueError, match='"outcome_id" value is invalid'),
                     id="text-outcome-id_exception"),
        pytest.param('1', '2', None, 'Filter Rule', 'Dummy Name', ',',
                     None, None,
                     pytest.raises(ValueError, match='"detections_list" value is invalid'),
                     id="wrong-detections-list_exception"),
        pytest.param('25', '4', None, 'Filter Rule', "Test-Triage", "2201, 2202, 2203",
                     load_test_data('single_assignment_extracted.json'), None,
                     does_not_raise(),
                     id="assignment-resolution_ok"),
    ]
)
def test_vectra_assignment_resolve_command(requests_mock,
                                           assignment_id, outcome_id, note,
                                           detections_filter, filter_rule_name, detections_list,
                                           expected_outputs, expected_readable, exception):
    """
    Tests vectra_assignment_resolve_command command function.
    """
    from VectraDetect import Client, vectra_assignment_resolve_command

    # Default answer, useless to check XSOAR inner exceptions (none API call raised)
    # Need to create inner checks based on post query body to have a better coverage
    requests_mock.put(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}'
                      '/25/resolve',
                      complete_qs=True,
                      json={'assignment': load_test_data('single_assignment.json')})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_assignment_resolve_command(client=client, assignment_id=assignment_id, outcome_id=outcome_id, note=note,
                                                   detections_filter=detections_filter, filter_rule_name=filter_rule_name,
                                                   detections_list=detections_list)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('4', load_test_data('single_outcome_extracted.json'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_outcome_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_outcome_by_id_command command function.
    """
    from VectraDetect import Client, vectra_get_outcome_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_ENDPOINT_OUTCOMES}',
                      json={})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_OUTCOMES}'
                      f'/4'
                      f'?page=1&page_size=200',
                      complete_qs=True,
                      json=load_test_data('single_outcome.json'))

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_outcome_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "category,title,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, "Dummy-Title", None, None,
                     pytest.raises(VectraException, match='"category" not specified'),
                     id="none-category_exception"),
        pytest.param('', "Dummy-Title", None, None,
                     pytest.raises(VectraException, match='"category" not specified'),
                     id="empty-category_exception"),
        pytest.param("False Positive", None, None, None,
                     pytest.raises(VectraException, match='"title" not specified'),
                     id="none-title_exception"),
        pytest.param("Wrong Category", "Dummy-Title", None, None,
                     pytest.raises(ValueError, match='"category" value is invalid'),
                     id="wrong-category_exception"),
        pytest.param("False Positive", '', None, None,
                     pytest.raises(VectraException, match='"title" not specified'),
                     id="empty-title_exception"),
        pytest.param('Benign True Positive', 'Vectra Outcome Test True Positive',
                     load_test_data('single_outcome_extracted.json'), None,
                     does_not_raise(),
                     id="valid_no-exception"),
    ]
)
def test_vectra_outcome_create_command(requests_mock, category, title, expected_outputs, expected_readable, exception):
    """
    Tests vectra_outcome_create_command command function.
    """
    from VectraDetect import Client, vectra_outcome_create_command

    # Test post
    requests_mock.post(f'{API_URL}{API_ENDPOINT_OUTCOMES}',
                       json=load_test_data('single_outcome.json'))

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_outcome_create_command(client=client, category=category, title=title)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "id,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('123', load_test_data('single_user_extracted.json'), None,
                     does_not_raise(),
                     id="valid-id_no-exception"),
    ]
)
def test_vectra_get_user_by_id_command(requests_mock, id, expected_outputs, expected_readable, exception):
    """
    Tests vectra_get_user_by_id_command command function.
    """
    from VectraDetect import Client, vectra_get_user_by_id_command

    # Default answer
    requests_mock.get(f'{API_URL}{API_ENDPOINT_USERS}',
                      json={})
    # Specific answers
    requests_mock.get(f'{API_URL}{API_ENDPOINT_USERS}'
                      f'/123',
                      complete_qs=True,
                      json=load_test_data('single_user.json'))

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = vectra_get_user_by_id_command(client=client, id=id)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "type,id,tags,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None, None, None,
                     pytest.raises(VectraException, match='"type" not specified'),
                     id="no-type_exception"),
        pytest.param('accounts', None, None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('accounts', '12', None, None, None,
                     pytest.raises(VectraException, match='"tags" not specified'),
                     id="no-tags_exception"),
        pytest.param('accounts', '12', 'vectra', None, 'Tags "vectra" successfully added.',
                     does_not_raise(),
                     id="del-account-tag_no-exception"),
        pytest.param('accounts', '12', 'vectra-1,Vectra-2', None, 'Tags "vectra-1,Vectra-2" successfully added.',
                     does_not_raise(),
                     id="del-account-tags_no-exception"),
    ]
)
def test_add_tags_command(requests_mock, type, id, tags, expected_outputs, expected_readable, exception):
    """
    Tests add_tags_command command function.
    """
    from VectraDetect import Client, add_tags_command

    requests_mock.get(f'{API_URL}{API_TAGGING}/{type}/{id}',
                      complete_qs=True,
                      json={'tags': ['vectra']})
    requests_mock.patch(f'{API_URL}{API_TAGGING}/{type}/{id}',
                        complete_qs=True,
                        json={'tags': ['vectra']})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = add_tags_command(client=client, type=type, id=id, tags=tags)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable


@pytest.mark.parametrize(
    "type,id,tags,expected_outputs,expected_readable,exception",
    [
        pytest.param(None, None, None, None, None,
                     pytest.raises(VectraException, match='"type" not specified'),
                     id="no-type_exception"),
        pytest.param('accounts', None, None, None, None,
                     pytest.raises(VectraException, match='"id" not specified'),
                     id="no-id_exception"),
        pytest.param('accounts', '12', None, None, None,
                     pytest.raises(VectraException, match='"tags" not specified'),
                     id="no-tags_exception"),
        pytest.param('accounts', '12', 'vectra', None, 'Tags "vectra" successfully deleted.',
                     does_not_raise(),
                     id="del-account-tag_no-exception"),
        pytest.param('accounts', '12', 'vectra-1,Vectra-2', None, 'Tags "vectra-1,Vectra-2" successfully deleted.',
                     does_not_raise(),
                     id="del-account-tags_no-exception"),
    ]
)
def test_del_tags_command(requests_mock, type, id, tags, expected_outputs, expected_readable, exception):
    """
    Tests del_tags_command command function.
    """
    from VectraDetect import Client, del_tags_command

    requests_mock.get(f'{API_URL}{API_TAGGING}/{type}/{id}',
                      complete_qs=True,
                      json={'tags': ['vectra']})
    requests_mock.patch(f'{API_URL}{API_TAGGING}/{type}/{id}',
                        complete_qs=True,
                        json={'tags': ['vectra']})

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    with exception:
        result = del_tags_command(client=client, type=type, id=id, tags=tags)
        assert result.outputs == expected_outputs
        if expected_outputs is None:
            assert result.readable_output == expected_readable

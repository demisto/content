"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import os
import pytest
from contextlib import nullcontext as does_not_raise
import copy

import demistomock as demisto
from CommonServerPython import DemistoException

import VectraDetect
from VectraDetect import MAX_RESULTS, UI_ACCOUNTS, UI_HOSTS, UI_DETECTIONS, UTM_PIVOT, VectraException, \
    fetch_incidents, get_modified_remote_data_command, Client, get_remote_data_command, \
    update_remote_system_command, OUTPUT_PREFIXES, ENDPOINTS, ERRORS, NOTE_OUTPUT_KEY_FIELD, \
    markall_detections_asfixed_command, BACK_IN_TIME_SEARCH_IN_MINUTES, vectra_group_list_command, \
    API_ENDPOINT_GROUPS, VALID_IMPORTANCE_VALUE, VALID_GROUP_TYPE, vectra_group_assign_command, \
    vectra_group_unassign_command

SERVER_FQDN = "vectra.test"
SERVER_URL = f"https://{SERVER_FQDN}"
API_VERSION_URI = '/api/v2.5'
API_URL = f'{SERVER_URL}{API_VERSION_URI}'
API_SEARCH_ENDPOINT_ACCOUNTS = '/search/accounts'
API_SEARCH_ENDPOINT_DETECTIONS = '/search/detections'
API_SEARCH_ENDPOINT_HOSTS = '/search/hosts'
API_ENDPOINT_ASSIGNMENTS = '/assignments'
API_ENDPOINT_DETECTIONS = '/detections'
API_ENDPOINT_OUTCOMES = '/assignment_outcomes'
API_ENDPOINT_USERS = '/users'
API_TAGGING = '/tagging'
API_ENDPOINT_HOST = '/hosts'
API_ENDPOINT_ACCOUNT = '/accounts'


def load_test_data(json_path):
    relative_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data')
    with open(os.path.join(relative_dir, json_path)) as f:
        return json.load(f)


@pytest.fixture
def client():
    from VectraDetect import Client

    return Client(
        base_url=f'{API_URL}', headers={}
    )


#####
# ## Globals
#


integration_params = None

# helper functions


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

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
                 pytest.raises(SystemError, match='Unknown argument type'),
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
        pytest.param('account', 123, f"{SERVER_URL}{UI_ACCOUNTS}/123{UTM_PIVOT}",
                     does_not_raise(),
                     id="account_ok"),
        pytest.param('host', 234, f"{SERVER_URL}{UI_HOSTS}/234{UTM_PIVOT}",
                     does_not_raise(),
                     id="host_ok"),
        pytest.param('detection', 345, f"{SERVER_URL}{UI_DETECTIONS}/345{UTM_PIVOT}",
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
    "input_date,look_back,expected,exception",
    [
        pytest.param('2022-06-30T01:23:45Z', '60', '2022-06-30T0023',
                     does_not_raise(),
                     id="timestamp_ok"),
        pytest.param('2022-06-30T01:23:45.000Z', '60', '2022-06-30T0023',
                     does_not_raise(),
                     id="timestamp-with-milli_ok"),
        pytest.param('vectra', BACK_IN_TIME_SEARCH_IN_MINUTES, 'exception',
                     pytest.raises(SystemError, match='Invalid ISO date'),
                     id="string_exception"),
        pytest.param('2022-06-30T01:23:45.000Z', '-1', '-1',
                     pytest.raises(ValueError, match=ERRORS['POSITIVE_VALUE'].format('look back')),
                     id="negative_value_exception"),
    ]
)
def test_iso_date_to_vectra_start_time(input_date, look_back, expected, exception):
    """
    Tests iso_date_to_vectra_start_time helper function
    """
    from VectraDetect import iso_date_to_vectra_start_time

    with exception:
        assert iso_date_to_vectra_start_time(input_date, look_back) == expected


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
                     '"vectra" is an invalid value for Max incidents per fetch. The value must be between 1 to 200.',
                     id="string-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7 days', 'fetch_entity_types': ['Hosts'], 'max_fetch': '0'},
                     '"0" is an invalid value for Max incidents per fetch. The value must be between 1 to 200.',
                     id="0-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7d', 'fetch_entity_types': ['Hosts', 'Detections'], 'max_fetch': '1'},
                     "Max incidents per fetch (1) must be >= to the number of entity types you're fetching (2)",
                     id="too-low-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7d', 'fetch_entity_types': ['Hosts', 'Detections'], 'max_fetch': '201'},
                     ERRORS['INVALID_MAX_FETCH'].format(201), id="too-high-max-fetch"),
        pytest.param({'isFetch': True, 'first_fetch': '7d', 'fetch_entity_types': ['Hosts', 'Accounts'], 'max_fetch': '5'},
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

    account_data = load_test_data('single_account.json')
    account_response = {'count': 1, 'results': [account_data]}
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_ACCOUNTS}', json=account_response)
    host_data = load_test_data('single_host.json')
    host_response = {'count': 1, 'results': [host_data]}
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}', json=host_response)
    detection_data = load_test_data('single_detection.json')
    detection_response = {'count': 1, 'results': [detection_data]}
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_DETECTIONS}', json=detection_response)

    assignment_data = load_test_data('single_assignment.json')
    assignment_response = {'count': 1, 'results': [assignment_data]}
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?accounts=36', json=assignment_response)
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?hosts=472', json=assignment_response)

    requests_mock.get(f'{API_URL}{API_ENDPOINT_DETECTIONS}?state=active&host_id=472',
                      complete_qs=True, json={'results': [detection_data]})

    group_res = load_test_data('group_list_response.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_GROUPS}', json=group_res)

    client = Client(
        base_url=f'{API_URL}', headers={}
    )

    assert test_module(client=client, integration_params=integration_params) == expected


def test_fetch_incidents(mocker, client, requests_mock):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method that returns mocked last run.
    - A mocked 'list_entities_request' method that returns a sample entity data.

    When:
    - Fetching incidents using the 'fetch_incidents' function with no additional parameters.

    Then:
    - Assert that the number of fetched incidents is equal to the number of entities in the entity data.
    """
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    last_run = load_test_data('fetch_incidents_last_run.json')
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)

    account_data = load_test_data('single_account.json')
    account_response = {'count': 1, 'results': [account_data]}
    mocker.patch.object(client, 'search_accounts', return_value=account_response)
    host_data = load_test_data('single_host.json')
    host_response = {'count': 1, 'results': [host_data]}
    mocker.patch.object(client, 'search_hosts', return_value=host_response)
    detection_data = load_test_data('single_detection.json')
    detection_response = {'count': 1, 'results': [detection_data]}
    mocker.patch.object(client, 'search_detections', return_value=detection_response)

    assignment_data = load_test_data('single_assignment.json')
    assignment_response = {'count': 1, 'results': [assignment_data]}
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?accounts=36', json=assignment_response)
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?hosts=472', json=assignment_response)

    assignment_data = load_test_data('single_assignment.json')
    assignment_response = {'count': 1, 'results': [assignment_data]}
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?accounts=36', json=assignment_response)
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}?hosts=472', json=assignment_response)

    requests_mock.get(f'{API_URL}{API_ENDPOINT_DETECTIONS}?state=active&host_id=472',
                      complete_qs=True, json={'results': [detection_data]})

    group_res = load_test_data('group_list_response.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_GROUPS}', json=group_res)

    params = {
        'isFetch': True,
        'first_fetch': '1 hour',
        'max_fetch': '201',
        'fetch_entity_types': ['Accounts', 'Hosts', 'Detections'],
        'tags': 'hello,world'
    }
    new_last_run, incidents = fetch_incidents(client, params)
    new_last_run_expected = load_test_data('fetch_incidents_new_last_run.json')
    assert new_last_run == new_last_run_expected

    incidents_expected = load_test_data('fetch_incidents_expected.json')
    assert incidents == incidents_expected


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
                     pytest.raises(VectraException,
                                   match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="none-entity-ids_exception"),
        pytest.param('1', '2', '3', None, None, None,
                     pytest.raises(VectraException,
                                   match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="account-and-host-ids_exception"),
        pytest.param('1', '2', None, '4', None, None,
                     pytest.raises(VectraException,
                                   match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="account-and-assignment-ids_exception"),
        pytest.param('1', None, '3', '4', None, None,
                     pytest.raises(VectraException,
                                   match='You must specify one of "assignment_id", "account_id" or "host_id"'),
                     id="host-and-assignment-ids_exception"),
        pytest.param('1', '2', '3', '4', None, None,
                     pytest.raises(VectraException,
                                   match='You must specify one of "assignment_id", "account_id" or "host_id"'),
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


def test_get_modified_remote_command_successful_retrieval(client, mocker, requests_mock):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'search_hosts' function to return a list of hosts.
    - Mocking the 'search_accounts' function to return an empty list of accounts.
    - Mocking the 'demisto.args' function to return a specific argument.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    """
    mocker.patch.object(demisto, 'args', return_value={"lastUpdate": "2023-09-20T10:00:00+00:00"})
    mocker.patch.object(Client, 'search_accounts', return_value={"results": [], "next": None})

    response = load_test_data('search_hosts_response.json')
    requests_mock.get(f'{API_URL}{API_SEARCH_ENDPOINT_HOSTS}', json=response, status_code=200)

    get_modified_remote_return = {
        'Contents': get_modified_remote_data_command(client=client).to_entry().get('Contents'),
        'ContentsFormat': 'json',
        'Type': 1,
    }

    assert get_modified_remote_data_command(client=client).to_entry() == get_modified_remote_return


def test_get_modified_remote_command_max_mirroring_limit_reached(client, mocker):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_last_mirror_run' function to return a specific last mirror run timestamp.
    - Mocking the 'list_entities_request' function to return a large number of entities (more than the mirroring limit).
    - Mocking the 'set_last_mirror_run' function.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    """
    mocker.patch.object(demisto, 'args', return_value={"lastUpdate": "2023-09-20T10:00:00+00:00"})
    mocker.patch.object(Client, 'search_accounts', return_value={"results": [], "next": None})
    mocker.patch.object(client, 'search_hosts',
                        return_value={"results": [{"id": id, "type": "host"} for id in range(1, 2550)],
                                      "next": None})

    get_modified_remote_return = {
        'Contents': get_modified_remote_data_command(client=client).to_entry().get('Contents'),
        'ContentsFormat': 'json',
        'Type': 1,
    }

    assert get_modified_remote_data_command(client=client).to_entry() == get_modified_remote_return


def test_get_remote_data_command_when_detections_found(mocker, client, requests_mock):
    """
    Given:
    - A client object.
    - A mocked get entities endpoint.
    - A mocked list detection endpoint.

    When:
    - Fetching modified incident using the 'get_remote_data_command' function with the provided parameters.

    Then:
    - Assert that the reopening entry exists.
    """
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    host_data = {"id": 1, "last_modified": "2023-09-20T19:00:00+00:00",
                 "certainty": 90,
                 "notes": []}
    requests_mock.get(f'{API_URL}{API_ENDPOINT_HOST}/1', json=host_data, status_code=200)
    mocker.patch.object(client, 'get_account_by_account_id', return_value={})

    detection_data = load_test_data('list_detection_by_host_id_response.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_DETECTIONS}?host_id=1', json=detection_data, status_code=200)

    mocker.patch.object(client, 'list_assignments_request', return_value={})

    args = {'id': '1-host', 'lastUpdate': '2023-06-20T10:00:00+00:00'}
    mocker.patch.object(demisto, 'args', return_value=args)

    remote_data = load_test_data('get_remote_data_entry.json')
    assert get_remote_data_command(client).extract_for_local() == remote_data


def test_get_remote_data_command_when_assignment_found(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - A mocked get entities endpoint.
    - A mocked list detection endpoint.

    When:
    - Fetching modified incident using the 'get_remote_data_command' function with the provided parameters.

    Then:
    - Assert that the reopening entry exists.
    """
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    account_data = load_test_data('get_account_by_account_id.json')
    mocker.patch.object(client, 'get_account_by_account_id', return_value=account_data)

    detection_data = load_test_data('single_detection.json')
    detection_response = {'count': 1, 'results': [detection_data]}
    mocker.patch.object(client, 'search_detections', return_value=detection_response)

    group_res = load_test_data('group_list_response.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_GROUPS}', json=group_res)

    args = {'id': '107-account', 'lastUpdate': '2023-06-20T10:00:00+00:00'}
    mocker.patch.object(demisto, 'args', return_value=args)

    remote_data = load_test_data('get_remote_data_entry_by_account.json')
    assert get_remote_data_command(client).extract_for_local() == remote_data


def test_get_remote_data_command_when_past_assignment_found(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - A mocked get entities endpoint.
    - A mocked list detection endpoint.

    When:
    - Fetching modified incident using the 'get_remote_data_command' function with the provided parameters.

    Then:
    - Assert that the reopening entry exists.
    """
    import VectraDetect
    VectraDetect.global_UI_URL = SERVER_URL

    account_data = load_test_data('get_account_by_id_with_past_assignment.json')
    mocker.patch.object(client, 'get_account_by_account_id', return_value=account_data)

    detection_data = load_test_data('single_detection.json')
    detection_response = {'count': 1, 'results': [detection_data]}
    mocker.patch.object(client, 'search_detections', return_value=detection_response)

    group_res = load_test_data('group_list_response.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_GROUPS}', json=group_res)

    args = {'id': '107-account', 'lastUpdate': '2023-06-20T10:00:00+00:00'}
    mocker.patch.object(demisto, 'args', return_value=args)

    remote_data = load_test_data('get_remote_data_entry_by_account_past_assignment.json')
    assert get_remote_data_command(client).extract_for_local() == remote_data


def test_get_remote_data_command_entity_not_needs_update(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying an entity ID and last update timestamp.

    When:
    - Mocking the 'get_entity_request' and 'list_assignments_request' functions to return empty data.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    """
    mocker.patch.object(client, 'get_account_by_account_id', return_value={})
    mocker.patch.object(client, 'get_host_by_host_id', return_value={})

    args = {
        'id': '1-host',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    mocker.patch.object(demisto, 'args', return_value=args)

    assert get_remote_data_command(client) == "Incident was not found."


def test_get_remote_data_command_entity_needs_update_notes(client, mocker, requests_mock):
    """
    Given:
    - A client object.
    - Mocked arguments specifying an entity ID and last update timestamp.

    When:
    - Mocking the 'get_entity_request' function to return entity data with a note.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    """
    args = {
        'id': '1-host',
        'lastUpdate': '2023-09-20T10:00:00+00:00'
    }
    mocker.patch.object(demisto, 'args', return_value=args)

    note_response_1 = {
        "id": 239,
        "date_created": "2023-09-20T10:33:14Z",
        "created_by": "dummy_api_client",
        "note": "test note."
    }
    note_response_2 = copy.deepcopy(note_response_1)
    note_response_2["date_created"] = "2023-08-20T10:33:14Z"
    note_response_3 = copy.deepcopy(note_response_1)
    note_response_3["note"] = "[Mirrored From XSOAR]"
    note_response_4 = copy.deepcopy(note_response_1)
    note_response_4["date_modified"] = "2023-09-20T08:33:14Z"

    response = {"id": 1, "last_modified": "2023-09-20T19:00:00+00:00",
                "certainty": 90,
                "notes": [note_response_1, note_response_2, note_response_3, note_response_4]}

    mocker.patch.object(client, 'get_account_by_account_id', return_value={})
    requests_mock.get(f'{API_URL}{API_ENDPOINT_HOST}/1', json=response, status_code=200)

    mocker.patch.object(client, 'list_assignments_request', return_value={})

    remote_data = load_test_data('get_remote_data_note_update_entry.json')
    assert get_remote_data_command(client).extract_for_local() == remote_data


def test_update_remote_system_command_when_tags_mirror(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying a remote ID and delta of tags.

    When:
    - Calling the 'update_remote_system_command' function with the provided client and arguments.

    Then:
    - Assert that the ID of the updated remote entity is returned.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'remoteId': '1-account',
        'delta': {'tags': ['tag1', 'tag2']},
        'data': {'id': '1'}
    })

    mocker.patch.object(client, 'add_note_request', return_value={})
    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})

    assert update_remote_system_command(client) == '1-account'


def test_update_remote_system_command_when_note_mirror(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying a remote ID and delta of tags.

    When:
    - Calling the 'update_remote_system_command' function with the provided client and arguments.

    Then:
    - Assert that the ID of the updated remote entity is returned.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'remoteId': '1-account',
        'delta': {},
        'entries': load_test_data('update_remote_system_entry.json'),
        'data': {'id': '1'}
    })

    mocker.patch.object(client, 'add_note_request', return_value={})
    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})

    assert update_remote_system_command(client) == '1-account'


def test_update_remote_system_command_when_incident_reopened(client, mocker, requests_mock):
    """
    Given:
    - A client object.
    - Mocked arguments specifying a remote ID and delta of tags.
    - Mocked requests to Vectra API.

    When:
    - Calling the 'update_remote_system_command' function with the provided client and arguments.

    Then:
    - Assert that the ID of the updated remote entity is returned.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'remoteId': '1-account',
        'delta': {'closingUserId': '', 'runStatus': 'waiting'},
        'entries': [],
        'data': {'id': '1'}
    })

    mocker.patch.object(client, 'add_note_request', return_value={})
    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_assignments_request', return_value={'id': 1})
    requests_mock.delete(f'{API_URL}{API_ENDPOINT_ASSIGNMENTS}/1', json={}, status_code=200)

    assert update_remote_system_command(client) == '1-account'


def test_update_remote_system_command_when_closing_note_mirror(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying a remote ID and delta of tags.

    When:
    - Calling the 'update_remote_system_command' function with the provided client and arguments.

    Then:
    - Assert that the ID of the updated remote entity is returned.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'remoteId': '1-account',
        'delta': {'closeNotes': 'resolved', 'closeReason': 'Resolved', 'closingUserId': 'admin', 'runStatus': ''},
        'data': {'closeNotes': 'resolved', 'closeReason': 'Resolved', 'closingUserId': 'admin', 'id': 1},
        'incidentChanged': True,
        'status': 2
    })

    mocker.patch.object(client, 'add_note_request', return_value={})
    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})

    assert update_remote_system_command(client) == '1-account'


def test_update_remote_system_command_when_no_arguments_provided(client, mocker):
    """
    Given:
    - A client object.
    - Mocked arguments specifying a remote ID and delta of tags.

    When:
    - Calling the 'update_remote_system_command' function with the provided client and arguments.

    Then:
    - Assert that the ID of the updated remote entity is returned.
    """
    mocker.patch.object(demisto, 'args', return_value={'remoteId': '1-account'})

    mocker.patch.object(client, 'add_note_request', return_value={})
    mocker.patch.object(client, 'update_entity_tags_request', return_value={})
    mocker.patch.object(client, 'list_entity_tags_request', return_value={})

    assert update_remote_system_command(client) == '1-account'


def test_markall_detections_asfixed_command_for_host_when_success(client, requests_mock, mocker):
    """
    Tests markall_detections_asfixed_command command function when success with host.
    """
    host_id = '472'

    host_data = load_test_data('single_host.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_HOST}/{host_id}', json=host_data, status_code=200)

    response = {
        '_meta': {
            'level': 'Success',
            'message': 'Successfully marked detections'
        }
    }

    requests_mock.patch(f'{API_URL}{API_ENDPOINT_DETECTIONS}', json=response, status_code=200)

    result = markall_detections_asfixed_command(client=client, type='host', host_id=host_id)

    assert result.readable_output == 'The active detections of the provided host have been successfully marked as fixed.'
    assert result.raw_response == response


def test_markall_detections_asfixed_command_for_account_when_success(client, requests_mock, mocker):
    """
    Tests markall_detections_asfixed_command command function when success with account.
    """
    account_id = '36'

    host_data = load_test_data('single_account.json')
    requests_mock.get(f'{API_URL}{API_ENDPOINT_ACCOUNT}/{account_id}', json=host_data, status_code=200)

    response = {
        '_meta': {
            'level': 'Success',
            'message': 'Successfully marked detections'
        }
    }

    requests_mock.patch(f'{API_URL}{API_ENDPOINT_DETECTIONS}', json=response, status_code=200)

    result = markall_detections_asfixed_command(client=client, type='account', account_id=account_id)

    assert result.readable_output == 'The active detections of the provided account have been successfully marked as fixed.'
    assert result.raw_response == response


def test_markall_detections_asfixed_command_for_account_when_no_detection(client, requests_mock, mocker):
    """
    Tests markall_detections_asfixed_command command function when no detection in account.
    """
    account_id = '36'

    account_data = load_test_data('single_account.json')
    account_data['detection_summaries'] = []

    requests_mock.get(f'{API_URL}{API_ENDPOINT_ACCOUNT}/{account_id}', json=account_data, status_code=200)

    result = markall_detections_asfixed_command(client=client, type='account', account_id=account_id)

    assert result.readable_output == 'There are no active detections present.'
    assert result.raw_response == {}


def test_markall_detections_asfixed_command_for_host_when_host_id_missing(client, mocker):
    """
    Tests markall_detections_asfixed_command command function when host_id is missing.
    """
    with pytest.raises(ValueError) as err:
        markall_detections_asfixed_command(client=client, type='host', host_id='')

    assert str(err.value) == ERRORS['REQUIRED_ARGUMENT'].format('host_id')


def test_markall_detections_asfixed_command_for_host_when_host_id_wrong(client, mocker):
    """
    Tests markall_detections_asfixed_command command function when host_id is wrong.
    """
    host_id = 'id'

    with pytest.raises(ValueError) as err:
        markall_detections_asfixed_command(client=client, type='host', host_id=host_id)

    assert str(err.value) == ERRORS['INVALID_INTEGER_VALUE'].format('host_id')


def test_vectra_account_tag_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'tag_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import tag_list_command
    args = {'id': '2'}

    notes_res = load_test_data('tag_list_response.json')
    context_data = load_test_data('account_tag_list_context.json')
    with open('test_data/tag_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{API_TAGGING}/account/2', json=notes_res)

    result = tag_list_command(client=client, entity_type='account', args=args)

    result_context = result.to_context()

    assert result.outputs_prefix == 'Vectra.Account'
    assert result.outputs_key_field == 'ID'
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_vectra_host_tag_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'tag_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import tag_list_command
    args = {'id': '2'}

    notes_res = load_test_data('tag_list_response.json')
    context_data = load_test_data('host_tag_list_context.json')
    with open('test_data/tag_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{API_TAGGING}/host/2', json=notes_res)

    result = tag_list_command(client=client, entity_type='host', args=args)

    result_context = result.to_context()

    assert result.outputs_prefix == 'Vectra.Host'
    assert result.outputs_key_field == 'ID'
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_vectra_detection_tag_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'tag_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import tag_list_command
    args = {'id': '2'}

    notes_res = load_test_data('tag_list_response.json')
    context_data = load_test_data('detection_tag_list_context.json')
    with open('test_data/tag_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{API_TAGGING}/detection/2', json=notes_res)

    result = tag_list_command(client=client, entity_type='detection', args=args)

    result_context = result.to_context()

    assert result.outputs_prefix == 'Vectra.Detection'
    assert result.outputs_key_field == 'ID'
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


@pytest.mark.parametrize('args,error_msg',
                         [({},
                           'Missing "id"'),
                          ({'id': ' '},
                           'Missing "id"'),
                          ({'id': '-3'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('id'))])
def test_vectra_tag_list_invalid_args(client, args, error_msg):
    """
    Given:
    - Arguments specifying different invalid values for id.
    When:
    - Calling the 'tag_list_command' function with the provided client and arguments.
    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    from VectraDetect import tag_list_command

    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()

    with pytest.raises(ValueError) as exception:
        tag_list_command(client=client, entity_type='account', args=args)

    assert str(exception.value) == error_msg


def test_vectra_account_tag_list_when_tag_response_is_empty(client, requests_mock):
    """
    Given:
    - An empty tag list response.

    When:
    - Calling the 'note_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    from VectraDetect import tag_list_command
    args = {'id': '5'}

    notes_res = load_test_data('tag_list_empty_response.json')
    context_data = load_test_data('tag_list_empty_context.json')

    requests_mock.get(f'{API_URL}{API_TAGGING}/account/5', json=notes_res)

    result = tag_list_command(client=client, entity_type='account', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == 'Vectra.Account'
    assert result.outputs_key_field == 'ID'
    assert result_context.get('Contents') == notes_res
    assert result_context.get(
        'HumanReadable') == "##### No tags were found for the given account ID."
    assert result_context.get('EntryContext') == context_data


def test_vectra_tag_list_when_something_went_wrong(client, requests_mock):
    """
    Given:
    response with 'failure' status.
    When:
    - Calling the 'tag_list_command' function with the provided client and arguments.
    Then:
    - Assert that the function raises a VectraException.
    - Assert that the error message matches the expected error message.
    """
    from VectraDetect import tag_list_command
    args = {'id': '3'}
    notes_res = {
        "status": "failure",
        "message": "Could not find requested object"
    }

    requests_mock.get(f'{API_URL}{API_TAGGING}/account/3', json=notes_res)

    with pytest.raises(VectraException) as exception:
        tag_list_command(client=client, entity_type='account', args=args)

    assert str(exception.value) == 'Something went wrong. Message: Could not find requested object.'


def test_account_note_add_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to an account.

    When:
    - Calling the 'note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_add_command
    args = {'account_id': '2', 'note': 'test note'}

    notes_res = util_load_json('test_data/account_note_add_response.json')
    context_data = util_load_json('test_data/account_note_add_context.json')
    requests_mock.post(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_ACCOUNT_NOTE_ENDPOINT"].format(2)}', json=notes_res)
    with open('test_data/account_note_add_hr.md') as f:
        result_hr = f.read()

    result = note_add_command(client=client, entity_type='account', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['ACCOUNT_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_host_note_add_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to a host.

    When:
    - Calling the 'note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """

    from VectraDetect import note_add_command
    args = {'host_id': '7', 'note': 'test note'}

    notes_res = util_load_json('test_data/host_note_add_response.json')
    context_data = util_load_json('test_data/host_note_add_context.json')
    requests_mock.post(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_HOST_NOTE_ENDPOINT"].format(7)}', json=notes_res)
    with open('test_data/host_note_add_hr.md') as f:
        result_hr = f.read()

    result = note_add_command(client=client, entity_type='host', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['HOST_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_detection_note_add_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to a detection.

    When:
    - Calling the 'note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_add_command
    args = {'detection_id': '9', 'note': 'test note'}

    notes_res = util_load_json('test_data/detection_note_add_response.json')
    context_data = util_load_json('test_data/detection_note_add_context.json')
    requests_mock.post(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format(9)}', json=notes_res)
    with open('test_data/detection_note_add_hr.md') as f:
        result_hr = f.read()

    result = note_add_command(client=client, entity_type='detection', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['DETECTION_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


@pytest.mark.parametrize('args,error_msg',
                         [({'account_id': '1'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'account_id': '1', 'note': ' '},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'note': 'test note'},
                           'Missing "account_id"'),
                          ({'account_id': ' ', 'note': 'test note'},
                           'Missing "account_id"'),
                          ({'account_id': '-3', 'note': 'test note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('account_id'))])
def test_note_add_command_invalid_args(client, args, error_msg):
    """
    Given:
    - Arguments specifying different invalid values for id and note.

    When:
    - Calling the 'note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    from VectraDetect import note_add_command

    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()

    with pytest.raises(ValueError) as exception:
        note_add_command(client=client, entity_type='account', args=args)

    assert str(exception.value) == error_msg


def test_account_note_update_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters to update a note to an account.

    When:
    - Calling the 'note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_update_command
    args = {'account_id': '2', 'note_id': '1959', 'note': 'updated test note'}

    notes_res = util_load_json('test_data/account_note_update_response.json')
    context_data = util_load_json('test_data/account_note_update_context.json')
    requests_mock.patch(
        f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_ACCOUNT_NOTE_ENDPOINT"].format(2, 1959)}', json=notes_res)
    with open('test_data/account_note_update_hr.md') as f:
        result_hr = f.read()

    result = note_update_command(client=client, entity_type='account', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['ACCOUNT_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res  # Replace with the expected output
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data  # Replace with the expected raw response


def test_host_note_update_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters to update a note to a host.

    When:
    - Calling the 'note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_update_command
    args = {'host_id': '7', 'note_id': '1960', 'note': 'updated test note'}

    entity_type = 'host'

    notes_res = util_load_json('test_data/host_note_update_response.json')
    context_data = util_load_json('test_data/host_note_update_context.json')
    requests_mock.patch(f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_HOST_NOTE_ENDPOINT"].format(7, 1960)}', json=notes_res)
    with open('test_data/host_note_update_hr.md') as f:
        result_hr = f.read()

    result = note_update_command(client=client, entity_type=entity_type, args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['HOST_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res  # Replace with the expected output
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data  # Replace with the expected raw response


def test_detection_note_update_command_valid_arguments(client, requests_mock):
    """
    Given:
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters to update a note to a detection.

    When:
    - Calling the 'note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_update_command
    args = {'detection_id': '9', 'note_id': '1961', 'note': 'updated test note'}

    entity_type = 'detection'

    notes_res = util_load_json('test_data/detection_note_update_response.json')
    context_data = util_load_json('test_data/detection_note_update_context.json')
    requests_mock.patch(
        f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(9, 1961)}', json=notes_res)
    with open('test_data/detection_note_update_hr.md') as f:
        result_hr = f.read()

    result = note_update_command(client=client, entity_type=entity_type, args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['DETECTION_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res  # Replace with the expected output
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data  # Replace with the expected raw response


@pytest.mark.parametrize('args,error_msg',
                         [({'account_id': '1', 'note_id': '5'},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'account_id': '1', 'note_id': '5', 'note': ' '},
                           ERRORS['REQUIRED_ARGUMENT'].format('note')),
                          ({'note_id': '5', 'note': 'test note'},
                           'Missing "account_id"'),
                          ({'account_id': ' ', 'note_id': '5', 'note': 'test note'},
                           'Missing "account_id"'),
                          ({'account_id': '-3', 'note_id': '5', 'note': 'test note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('account_id')),
                          ({'account_id': '1', 'note': 'test note'},
                           'Missing "note_id"'),
                          ({'account_id': '1', 'note_id': ' ', 'note': 'test note'},
                           'Missing "note_id"'),
                          ({'account_id': '1', 'note_id': '-3', 'note': 'test note'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id'))])
def test_note_update_command_invalid_args(client, args, error_msg):
    """
    Given:
    - Arguments specifying different invalid arguments.

    When:
    - Calling the 'note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """

    from VectraDetect import note_update_command

    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()

    with pytest.raises(ValueError) as exception:
        note_update_command(client, entity_type='account', args=args)

    assert str(exception.value) == error_msg


def test_vectra_account_note_remove_valid_arguments(client, requests_mock):
    """
    Given:
    - Arguments specifying valid parameters to remove a note from an account.

    When:
    - Calling the 'note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context matches the context data.
    """
    from VectraDetect import note_remove_command
    args = {'account_id': '2', 'note_id': '1959'}

    requests_mock.delete(
        f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_ACCOUNT_NOTE_ENDPOINT"].format(2, 1959)}', status_code=204)

    # Call the function
    result = note_remove_command(client, entity_type='account', args=args)

    # Assert the result
    result_context = result.to_context()
    assert result_context.get('HumanReadable') == '##### The note has been successfully removed from the account.'
    assert result_context.get('Contents') == ''


def test_vectra_host_note_remove_valid_arguments(client, requests_mock):
    """
    Given:
    - Arguments specifying valid parameters to remove a note from a host.

    When:
    - Calling the 'note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context matches the context data.
    """
    from VectraDetect import note_remove_command
    args = {'host_id': '7', 'note_id': '1960'}

    requests_mock.delete(
        f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_HOST_NOTE_ENDPOINT"].format(7, 1960)}', status_code=204)

    # Call the function
    result = note_remove_command(client, entity_type='host', args=args)

    # Assert the result
    result_context = result.to_context()
    assert result_context.get('HumanReadable') == '##### The note has been successfully removed from the host.'
    assert result_context.get('Contents') == ''


def test_vectra_detection_note_remove_valid_arguments(client, requests_mock):
    """
    Given:
    - Arguments specifying valid parameters to remove a note from a detection.

    When:
    - Calling the 'note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'EntryContext' property in the context matches the context data.
    """
    from VectraDetect import note_remove_command
    args = {'detection_id': '9', 'note_id': '1961'}

    requests_mock.delete(f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(9, 1961)}', status_code=204)
    result = note_remove_command(client, entity_type='detection', args=args)

    # Assert the result
    result_context = result.to_context()
    assert result_context.get('HumanReadable') == '##### The note has been successfully removed from the detection.'
    assert result_context.get('Contents') == ''


def test_vectra_note_remove_invalid_status_code(client, requests_mock):
    """
    Tests the 'note_remove_command' function with valid arguments.

    Ensures that the function gives error in HR for status code.

    Args:
        requests_mock: The requests mock object.

    Returns:
        Human Readable and Context Output.
    """
    from VectraDetect import note_remove_command

    args = {'host_id': '7', 'note_id': '1980'}

    requests_mock.delete(f'{API_URL}{ENDPOINTS["UPDATE_AND_REMOVE_HOST_NOTE_ENDPOINT"].format(7, 1980)}',
                         status_code=200, text='test fail')

    # Call the function
    result = note_remove_command(client, entity_type='host', args=args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == 'Something went wrong. API Response: test fail'
    assert result_context.get('Contents') == 'test fail'


@pytest.mark.parametrize('args,error_msg',
                         [({'note_id': '5'},
                           'Missing "account_id"'),
                          ({'account_id': ' ', 'note_id': '5'},
                           'Missing "account_id"'),
                          ({'account_id': '-3', 'note_id': '5'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('account_id')),
                          ({'account_id': '1'},
                           'Missing "note_id"'),
                          ({'account_id': '1', 'note_id': ' '},
                           'Missing "note_id"'),
                          ({'account_id': '1', 'note_id': '-3'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('note_id'))])
def test_note_remove_command_invalid_args(client, args, error_msg):
    """
    Given:
    - Arguments specifying different invalid values.

    When:
    - Calling the 'note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    from VectraDetect import note_remove_command

    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()

    with pytest.raises(ValueError) as exception:
        note_remove_command(client, entity_type='account', args=args)

    assert str(exception.value) == error_msg


def test_vectra_account_note_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_list_command
    args = {'account_id': '2'}

    notes_res = load_test_data('account_note_list_response.json')
    context_data = load_test_data('account_note_list_context.json')
    with open('test_data/account_note_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_ACCOUNT_NOTE_ENDPOINT"].format(2)}', json=notes_res)

    result = note_list_command(client=client, entity_type='account', args=args)

    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['ACCOUNT_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_vectra_host_note_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_list_command
    args = {'host_id': '7'}

    notes_res = load_test_data('host_note_list_response.json')
    context_data = load_test_data('host_note_list_context.json')
    with open('test_data/host_note_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_HOST_NOTE_ENDPOINT"].format(7)}', json=notes_res)

    result = note_list_command(client=client, entity_type='host', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['HOST_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


def test_vectra_detection_note_list_valid_arguments(client, requests_mock):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.

    When:
    - Calling the 'note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    from VectraDetect import note_list_command
    args = {'detection_id': '9'}

    notes_res = load_test_data('detection_note_list_response.json')
    context_data = load_test_data('detection_note_list_context.json')
    with open('test_data/detection_note_list_hr.md') as f:
        result_hr = f.read()

    requests_mock.get(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format(9)}', json=notes_res)

    result = note_list_command(client=client, entity_type='detection', args=args)
    result_context = result.to_context()

    assert result.outputs_prefix == OUTPUT_PREFIXES['DETECTION_NOTES']
    assert result.outputs_key_field == NOTE_OUTPUT_KEY_FIELD
    assert result_context.get('Contents') == notes_res
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data


@pytest.mark.parametrize('args,error_msg',
                         [({},
                           'Missing "account_id"'),
                          ({'account_id': ' '},
                           'Missing "account_id"'),
                          ({'account_id': '-3'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('account_id'))])
def test_vectra_note_list_invalid_args(client, args, error_msg):
    """
    Given:
    - Arguments specifying different invalid values for account_id.
    When:
    - Calling the 'note_list_command' function with the provided client and arguments.
    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    from VectraDetect import note_list_command

    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()

    with pytest.raises(ValueError) as exception:
        note_list_command(client=client, entity_type='account', args=args)

    assert str(exception.value) == error_msg


def test_vectra_account_note_list_when_note_response_is_empty(client, requests_mock):
    """
    Given:
    - An empty notes list response.

    When:
    - Calling the 'note_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    from VectraDetect import note_list_command
    args = {'account_id': '5'}

    requests_mock.get(f'{API_URL}{ENDPOINTS["ADD_AND_LIST_ACCOUNT_NOTE_ENDPOINT"].format(5)}', json=[])

    result = note_list_command(client=client, entity_type='account', args=args)
    result_context = result.to_context()

    assert result_context.get('Contents') == []
    assert result_context.get(
        'HumanReadable') == "Couldn't find any notes for provided account."
    assert result_context.get('EntryContext') == {}


def test_vectra_group_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    group_res = load_test_data('group_list_response.json')
    context_data = load_test_data('group_list_context.json')
    with open('./test_data/group_list_hr.md') as f:
        result_hr = f.read()
    requests_mock.get(f'{API_URL}{API_ENDPOINT_GROUPS}', json=group_res)
    args = {
        'group_type': 'account',
        'importance': 'high'
    }
    # Call the function
    result = vectra_group_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data
    assert result.outputs_key_field == 'group_id'


def test_vectra_group_list_when_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_group_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {
        "count": 0,
        "next": None,
        "previous": None,
        "results": []
    }
    mocker.patch.object(client, 'list_group_request', return_value=empty_response)

    # Call the function
    result = vectra_group_list_command(client, {})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "##### Couldn't find any matching groups for provided filters."
    assert result_context.get('EntryContext') == {}


@pytest.mark.parametrize('args,error_msg',
                         [({'group_type': 'invalid'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('group_type', ', '.join(VALID_GROUP_TYPE))),
                          ({'group_type': 'host', 'account_names': 'account_name'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'account', 'account_names')),
                          ({'group_type': 'host', 'domains': 'domain'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'domain', 'domains')),
                          ({'group_type': 'account', 'host_ids': '1'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_ids')),
                          ({'group_type': 'host', 'host_ids': 'abc'},
                           'Invalid number: "{}"="{}"'.format('host_ids', 'abc')),
                          ({'group_type': 'host', 'host_ids': '-1'},
                           ERRORS['INVALID_INTEGER_VALUE'].format('host_ids')),
                          ({'group_type': 'account', 'host_names': 'host_name'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'host', 'host_names')),
                          ({'group_type': 'host', 'ips': '0.0.0.0'},
                           ERRORS['INVALID_SUPPORT_FOR_ARG'].format('group_type', 'ip', 'ips')),
                          ({'importance': 'invalid'},
                           ERRORS['INVALID_COMMAND_ARG_VALUE'].format('importance', ', '.join(VALID_IMPORTANCE_VALUE))),
                          ])
def test_vectra_group_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid values.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for the corresponding invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_assign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    assign_group_res = load_test_data('assign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('assign_group_context.json')
    # For Domain group
    with open('test_data/assign_domain_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '1', 'members': "*.domain3.com,*.domain2.com"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[0])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=assign_group_res[0])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[0]
    assert result.outputs_key_field == 'group_id'


def test_vectra_assign_ip_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    assign_group_res = load_test_data('assign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('assign_group_context.json')
    # For Domain group
    with open('test_data/assign_ip_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '4', 'members': "8.8.8.8/25"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[3])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=assign_group_res[3])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[3]
    assert result.outputs_key_field == 'group_id'


def test_vectra_assign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    assign_group_res = load_test_data('assign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('assign_group_context.json')
    # For Account group
    with open('test_data/assign_account_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '3', 'members': "account_3,account_4"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[2])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=assign_group_res[2])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[2]
    assert result.outputs_key_field == 'group_id'


def test_vectra_assign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    assign_group_res = load_test_data('assign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('assign_group_context.json')
    # For Host group
    with open('test_data/assign_host_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '2', 'members': "1,2"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[1])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=assign_group_res[1])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[1]
    assert result.outputs_key_field == 'group_id'


def test_vectra_assign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = load_test_data('assign_group_response.json')

    args = {'group_id': '2', 'members': "1,2"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[1])

    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get('HumanReadable') == "##### Member(s) 1, 2 are already in the group."


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'members': 'account1'},
                              ERRORS['REQUIRED_ARGUMENT'].format('group_id')),
                             ({'group_id': '0', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '-1', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1.5', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1'}, ERRORS['REQUIRED_ARGUMENT'].format('members'))
                         ])
def test_vectra_group_assign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_assign_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_assign_account_group_invalid_group_name(requests_mock, mocker, client):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a account group.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a return_warning.
    """
    assign_group_res = load_test_data('assign_group_response.json')
    groups = load_test_data('get_groups_response.json')

    args = {'group_id': '3', 'members': "account_5"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[2])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=assign_group_res[2])

    return_warning = mocker.patch.object(VectraDetect, "return_warning")
    vectra_group_assign_command(client, args)

    assert return_warning.call_args[0][0] == "The following account names were invalid: account_5"


def test_vectra_unassign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    unassign_group_res = load_test_data('unassign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('unassign_group_context.json')
    # For Domain group
    with open('test_data/unassign_domain_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '1', 'members': "*.domain1.net"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[0])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=unassign_group_res[0])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[0]
    assert result.outputs_key_field == 'group_id'


def test_vectra_unassign_ip_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    unassign_group_res = load_test_data('unassign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('unassign_group_context.json')
    # For Domain group
    with open('test_data/unassign_ip_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '4', 'members': "0.0.0.17/8"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[3])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=unassign_group_res[3])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[3]
    assert result.outputs_key_field == 'group_id'


def test_vectra_unassign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    unassign_group_res = load_test_data('unassign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('unassign_group_context.json')

    with open('test_data/unassign_host_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '2', 'members': "3"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[1])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=unassign_group_res[1])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[1]
    assert result.outputs_key_field == 'group_id'


def test_vectra_unassign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    unassign_group_res = load_test_data('unassign_group_response.json')
    groups = load_test_data('get_groups_response.json')
    context_data = load_test_data('unassign_group_context.json')

    with open('test_data/unassign_account_group_hr.md') as f:
        result_hr = f.read()
    args = {'group_id': '3', 'members': "account_1"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[2])
    requests_mock.patch(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')),
                        json=unassign_group_res[2])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == 'Vectra.Group'
    assert result_context.get('HumanReadable') == result_hr
    assert result_context.get('EntryContext') == context_data[2]
    assert result.outputs_key_field == 'group_id'


def test_vectra_unassign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = load_test_data('assign_group_response.json')

    args = {'group_id': '2', 'members': "6,7"}
    requests_mock.get(API_URL + "{}/{}".format(API_ENDPOINT_GROUPS, args.get('group_id')), json=groups[1])

    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get(
        'HumanReadable') == "##### Member(s) 6, 7 do not exist in the group."


@pytest.mark.parametrize('args,error_msg',
                         [
                             ({'members': 'account1'},
                              ERRORS['REQUIRED_ARGUMENT'].format('group_id')),
                             ({'group_id': '0', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '-1', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1.5', 'members': 'account1'},
                              ERRORS['INVALID_INTEGER_VALUE'].format('group_id')),
                             ({'group_id': '1'}, ERRORS['REQUIRED_ARGUMENT'].format('members'))
                         ])
def test_vectra_group_unassign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_unassign_command(client, args)

    assert str(exception.value) == error_msg

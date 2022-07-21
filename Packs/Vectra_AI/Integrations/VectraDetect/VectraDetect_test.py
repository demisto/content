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

from VectraDetect import MAX_RESULTS  # Currently MAX_RESULTS equals 200
from VectraDetect import UI_ACCOUNTS, UI_HOSTS, UI_DETECTIONS
from VectraDetect import VectraException

SERVER_FQDN = "vectra.test"
SERVER_URL = f"https://{SERVER_FQDN}"
API_VERSION_URI = '/api/v2.3'
API_URL = f'{SERVER_URL}{API_VERSION_URI}'
API_TAGGING = '/tagging'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


# # TODO: REMOVE the following dummy unit test function
# def test_baseintegration_dummy():
#     """Tests helloworld-say-hello command function.

#     Checks the output of the command function with the expected output.

#     No mock is needed here because the say_hello_command does not call
#     any external API.
#     """
#     from BaseIntegration import Client, baseintegration_dummy_command

#     client = Client(base_url='some_mock_url', verify=False)
#     args = {
#         'dummy': 'this is a dummy response'
#     }
#     response = baseintegration_dummy_command(client, args)

#     mock_response = util_load_json('test_data/baseintegration-dummy.json')

#     assert response.outputs == mock_response


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


# def test_convert_date():
#     pass

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
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_account.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_account_extracted.json')).get('common_extract'),
                     id="common_account_ok"),
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_host.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_host_extracted.json')).get('common_extract'),
                     id="common_host_ok"),
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_detection.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_detection_extracted.json')).get('common_extract'),
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
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_account.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_account_extracted.json')).get('account_extract'),
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
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_detection.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_detection_extracted.json')).get('detection_extract'),
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
        pytest.param(load_test_data(os.path.join(RELATIVE_DIR, 'single_host.json')),
                     load_test_data(os.path.join(RELATIVE_DIR, 'single_host_extracted.json')).get('host_extract'),
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

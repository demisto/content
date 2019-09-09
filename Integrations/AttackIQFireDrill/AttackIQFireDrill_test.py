import pytest

from AttackIQFireDrill import build_transformed_dict, activate_assessment_command, \
    get_assessment_execution_status_command, get_test_execution_status_command, get_test_results_command, \
    list_assessments_command, get_assessment_by_id_command, list_tests_by_assessment_command, \
    run_all_tests_in_assessment_command
from test_data.constants import DICT_1to5, TRANS_DICT_134, DICT_NESTED_123, TRANS_DICT_NESTED_12, \
    TRANS_DICT_NESTED_VAL_12, DICT_LST_AAB2B, TRANS_DICT_LST_A2B, DICT_LST_NESTED, TRANS_DICT_LST_NESTED, \
    ACTIVATE_ASS_RESP, ACTIVATE_ASS_RES, GET_ASS_EXECUTION_STATUS_RESP, GET_ASS_EXECUTION_RESULT, \
    GET_TEST_STATUS_RESP, GET_TEST_STATUS_RESULT, GET_TEST_RESULT_RESP, GET_TEST_RESULT_RESULT, GET_ASS_RESP, \
    GET_ASS_RESULT, GET_ASS_BY_ID_RESULT, GET_TESTS_RESP, GET_TEST_RESULT, RUN_ALL_TESTS_RESP, RUN_ALL_TESTS_RESULT

import requests
import demistomock as demisto


class ResponseMock:
    def __init__(self, _json={}):
        self.status_code = 200
        self._json = _json

    def json(self):
        return self._json


def test_build_transformed_dict_basic():
    assert build_transformed_dict(DICT_1to5, TRANS_DICT_134) == {'one': 1, 'three': 3, 'four': 4}
    assert 'one' not in DICT_1to5


def test_build_transformed_dict_nested_keys():
    assert build_transformed_dict(DICT_NESTED_123, TRANS_DICT_NESTED_12) == {'one': 1, 'two': 2}


def test_build_transformed_dict_nested_vals():
    assert build_transformed_dict(DICT_1to5, TRANS_DICT_NESTED_VAL_12) == {'one': {'1': 1}, 'two': 2}


def test_build_transformed_dict_list():
    assert build_transformed_dict(DICT_LST_AAB2B, TRANS_DICT_LST_A2B) == {'AaB': [{'two': 2}, {'two': 3}], 'four': 4}
    assert build_transformed_dict(DICT_LST_NESTED, TRANS_DICT_LST_NESTED) == {
        'Master': {'ID': 1, 'Assets': [{'ID': 1, 'Name': 'a'}, {'ID': 2, 'Name': 'b'}]}}


def test_activate_assessment_command(mocker):
    mocker.patch.object(requests, 'request', return_value=ResponseMock(ACTIVATE_ASS_RESP))
    mocker.patch.object(demisto, 'results')
    activate_assessment_command()
    demisto.results.assert_called_with('Successfully activated project c4e352ae-1506-4c74-bd90-853f02dd765a')


@pytest.mark.parametrize('command,args,response,expected_result', [
    (activate_assessment_command, {}, ACTIVATE_ASS_RESP, ACTIVATE_ASS_RES),
    (get_assessment_execution_status_command, {'assessment_id': 1}, GET_ASS_EXECUTION_STATUS_RESP,
     GET_ASS_EXECUTION_RESULT),
    (get_test_execution_status_command, {'test_id': 1}, GET_TEST_STATUS_RESP, GET_TEST_STATUS_RESULT),
    (get_test_results_command, {'test_id': 1}, GET_TEST_RESULT_RESP, GET_TEST_RESULT_RESULT),
    (list_assessments_command, {'page_number': 1}, GET_ASS_RESP, GET_ASS_RESULT),
    (get_assessment_by_id_command, {'assessment_id': 1}, GET_ASS_RESP, GET_ASS_BY_ID_RESULT),
    (list_tests_by_assessment_command, {}, GET_TESTS_RESP, GET_TEST_RESULT),
    (run_all_tests_in_assessment_command, {}, RUN_ALL_TESTS_RESP, RUN_ALL_TESTS_RESULT)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    mocker.patch.object(requests, 'request', return_value=ResponseMock(response))
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value=args)
    command()
    demisto.results.assert_called_with(expected_result)

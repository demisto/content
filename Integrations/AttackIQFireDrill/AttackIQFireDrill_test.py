from AttackIQFireDrill import build_transformed_dict
from test_data.constants import DICT_1to5, TRANS_DICT_134, DICT_NESTED_123, TRANS_DICT_NESTED_12, \
    TRANS_DICT_NESTED_VAL_12, DICT_LST_AAB2B, TRANS_DICT_LST_A2B, DICT_LST_NESTED, TRANS_DICT_LST_NESTED


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

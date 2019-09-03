from Integrations.AttackIQFireDrill.AttackIQFireDrill import build_transformed_dict

# Constants
DICT_1to5 = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5}
DICT_NESTED_123 = {'nested': {'1': 1, '2': 2, '3': 3}}
DICT_LST_A2B = {'ab': [{'2': 2}, {'2': 3}], 'b': 4}

TRANS_DICT_134 = {'1': 'one', '3': 'three', '4': 'four'}
TRANS_DICT_NESTED_12 = {'nested.1': 'one', 'nested.2': 'two'}
TRANS_DICT_NESTED_VAL_12 = {'1': 'one.1', '2': 'two'}
TRANS_DICT_LST_A2B = {'ab': {'2': 'two'}, 'b': 'four'}


def test_build_transformed_dict_basic():
    res = build_transformed_dict(DICT_1to5, TRANS_DICT_134)
    assert len(res) == 3
    assert 'one' in res and 'three' in res and 'four' in res
    assert 'one' not in DICT_1to5
    assert '1' not in res


def test_build_transformed_dict_nested_keys():
    res = build_transformed_dict(DICT_NESTED_123, TRANS_DICT_NESTED_12)
    assert len(res) == 2
    assert 'one' in res and 'two' in res


def test_build_transformed_dict_nested_vals():
    res = build_transformed_dict(DICT_1to5, TRANS_DICT_NESTED_VAL_12)
    assert res['one'] == {'1': 1}
    assert res['two'] == 2


def test_build_transformed_dict_list():
    assert {'Ab': [{'two': 2}, {'two': 3}], 'four': 4} == build_transformed_dict(DICT_LST_A2B, TRANS_DICT_LST_A2B)

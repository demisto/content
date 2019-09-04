from Integrations.AttackIQFireDrill.AttackIQFireDrill import build_transformed_dict

# Constants
DICT_1to5 = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5}
DICT_NESTED_123 = {'nested': {'1': 1, '2': 2, '3': 3}}
DICT_LST_AAB2B = {'aa_b': [{'2': 2}, {'2': 3}], 'b': 4}
DICT_LST_NESTED = {
    'master': {
        'id': 1,
        'assets': [
            {
                'id': 1,
                'name': 'a'
            },
            {
                'id': 2,
                'name': 'b'
            }
        ]
    }
}

TRANS_DICT_134 = {'1': 'one', '3': 'three', '4': 'four'}
TRANS_DICT_NESTED_12 = {'nested.1': 'one', 'nested.2': 'two'}
TRANS_DICT_NESTED_VAL_12 = {'1': 'one.1', '2': 'two'}
TRANS_DICT_LST_A2B = {'aa_b': {'2': 'two'}, 'b': 'four'}
TRANS_DICT_LST_NESTED = {
    'master.id': 'Master.ID',
    'master.assets': {
        'id': 'ID',
        'name': 'Name'
    }
}


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

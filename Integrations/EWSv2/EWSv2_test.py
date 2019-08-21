from EWSv2 import keys_to_camel_case


def test_keys_to_camel_case():
    assert keys_to_camel_case('this_is_a_test') == 'thisIsATest'
    # assert keys_to_camel_case(('this_is_a_test', 'another_one')) == ('thisIsATest', 'anotherOne')
    obj = {}
    obj['this_is_a_value'] = 'the_value'
    obj['this_is_a_list'] = []
    obj['this_is_a_list'].append('list_value')
    res = keys_to_camel_case(obj)
    assert res['thisIsAValue'] == 'the_value'
    assert res['thisIsAList'][0] == 'listValue'

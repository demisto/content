from MapValuesTransformer import mapValues


def test_apply_tranformer():
    args = {
        'value': '3',
        'input_values': ['1', '2', '3', '4'],
        'mapped_values': ['4', '3', '2', '1']
    }
    results = mapValues(args.get('value'), args.get('input_values'), args.get('mapped_values'))
    assert results == '2'

from AddTime import apply_variation
args = {
    'value': '2020/01/01',
    'variation': 'in 1 day'
}
results = apply_variation(args.get('value'), args.get('variation'))
assert results == '2020-01-02T00:00:00'

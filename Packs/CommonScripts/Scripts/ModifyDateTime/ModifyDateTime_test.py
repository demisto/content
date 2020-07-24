import dateparser
from ModifyDateTime import apply_variation


def test_apply_variation():
    args = {
        'value': dateparser.parse('2020/01/01'),
        'variation': 'in 1 day'
    }
    results = apply_variation(args.get('value'), args.get('variation'))
    assert results == (dateparser.parse('2020-01-02T00:00:00'))

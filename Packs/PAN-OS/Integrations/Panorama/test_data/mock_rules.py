case_with_name = (
    'test',
    {'tags': ['test', 'tag'], 'disabled': 'yes', 'nat-type': 'ipv4'},
    "@name='test'and(tag/member='test')and(tag/member='tag')and(nat-type='ipv4')"
)
case_without_name = (
    '',
    {'tags': ['test', 'tag'], 'disabled': 'yes', 'nat-type': 'ipv4'},
    "(tag/member='test')and(tag/member='tag')and(nat-type='ipv4')"
)
case_empty = (
    '',
    {},
    ''
)
get_mock_rules = [case_with_name, case_without_name, case_empty]

case_with_name = (
    'test',
    None,
    {'tags': ['test', 'tag'], 'disabled': 'yes', 'nat-type': 'ipv4'},
    "@name='test'and(tag/member='test')and(tag/member='tag')and(nat-type='ipv4')"
)
case_without_name = (
    '',
    None,
    {'tags': ['test', 'tag'], 'disabled': 'yes', 'nat-type': 'ipv4'},
    "(tag/member='test')and(tag/member='tag')and(nat-type='ipv4')"
)
case_empty = (
    '',
    None,
    {},
    ''
)

case_with_characteristics = (
    'name',
    None,
    {'category': 'some_category',
     'characteristics': ['file-type-ident', 'consume-big-bandwidth', 'used-by-malware'],
     'risk': '5',
     'sub_category': 'some_sub_category',
     'technology': 'browser-based'
     },
    "@name='name'and(category='some_category')and(file-type-ident='yes')and(consume-big-bandwidth='yes')"
    "and(used-by-malware='yes')and(risk='5')and(technology='browser-based')"
)

case_only_name_match: tuple = (
    None,
    'name_match',
    {},
    "contains(@name,'name_match')"
)

get_mock_rules_and_application = [case_with_name, case_without_name, case_empty, case_with_characteristics, case_only_name_match]

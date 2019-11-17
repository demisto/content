from __future__ import print_function
import pytest
from FilterByList import filter_list

'''Test arguments'''

raw_list_only_lower_case = ['demisto', 'paloalto', 'foo', 'boo', 'bar']
raw_list_only_caps = ['DEMISTO', 'PALOALTO', 'FOO', 'BOO', 'BAR']
raw_list_lower_and_caps = ['Demisto', 'paloAlto', 'FoO', 'boo', 'baR']
raw_empty_list = []

raw_string_only_lower_case = 'demisto,paloalto,foo,boo,bar'
raw_string_only_caps = 'DEMISTO,PALOALTO,FOO,BOO,BAR'
raw_string_lower_and_caps = 'Demisto,paloAlto,FoO,boo,baR'

'''Search options'''

no_match, yes_match = 'no', 'yes'
no_ignore_case, yes_ignore_case = 'no', 'yes'

'''Search arguments'''

search_case1 = ['demisto', 'not in list', 'paloalto', 'FOO', 'bar', 'bo']

'''Expected results'''

empty_list_result = 'The list test_list is empty'

search_no_no_case1 = 'demisto is in the list\n' \
                     'paloalto is in the list\n' \
                     'FOO is in the list\n' \
                     'bar is in the list\n' \
                     'bo is in the list\n' \
                     'not in list is not part of the list'

search_yes_no_case1_1 = 'demisto is in the list\n' \
                        'paloalto is in the list\n' \
                        'bar is in the list\n' \
                        'not in list is not part of the list\n' \
                        'bo is in the list\n' \
                        'FOO is not part of the list'

search_yes_no_case1_2 = 'FOO is in the list\n' \
                        'demisto is not part of the list\n' \
                        'not in list is not part of the list\n' \
                        'paloalto is not part of the list\n' \
                        'bar is not part of the list\n' \
                        'bo is not part of the list\n'

search_yes_no_case1_3 = 'demisto is not part of the list\n' \
                        'not in list is not part of the list\n' \
                        'paloalto is not part of the list\n' \
                        'FOO is not part of the list\n' \
                        'bar is not part of the list\n' \
                        'bo is not part of the list\n'

search_no_yes_case1_1 = 'demisto is in the list\n' \
                        'paloalto is in the list\n' \
                        'bar is in the list\n' \
                        'not in list is not part of the list\n' \
                        'FOO is in the list\n' \
                        'bo is in the list\n'

search_no_yes_case1_2 = 'FOO is in the list\n' \
                        'demisto is not part of the list\n' \
                        'not in list is not part of the list\n' \
                        'paloalto is not part of the list\n' \
                        'bar is not part of the list\n' \
                        'bo is not part of the list\n'

search_no_yes_case1_3 = 'demisto is not part of the list\n' \
                        'not in list is not part of the list\n' \
                        'paloalto is is not part of the list\n' \
                        'FOO is is not part of the list\n' \
                        'bar is is not part of the list\n' \
                        'bo is is not part of the list\n'

search_yes_yes_case1_1 = 'demisto is in the list\n' \
                         'paloalto is in the list\n' \
                         'bar is in the list\n' \
                         'not in list is not part of the list\n' \
                         'FOO is in the list\n' \
                         'bo is in the list\n'

search_yes_yes_case1_2 = 'FOO is in the list\n' \
                         'demisto is not part of the list\n' \
                         'not in list is not part of the list\n' \
                         'paloalto is not part of the list\n' \
                         'bar is not part of the list\n' \
                         'bo is not part of the list\n'

search_yes_yes_case1_3 = 'demisto is not part of the list\n' \
                         'not in list is not part of the list\n' \
                         'paloalto is is not part of the list\n' \
                         'FOO is is not part of the list\n' \
                         'bar is is not part of the list\n' \
                         'bo is is not part of the list\n'

'''Test packages'''

empty_list_package = (raw_empty_list, search_case1, no_ignore_case, no_match, search_no_no_case1,
                      'test_list')

test_no_no_packages = [
    (raw_list_only_lower_case, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
    (raw_list_only_caps, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
    (raw_list_lower_and_caps, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
    (raw_string_only_lower_case, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
    (raw_string_only_caps, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
    (raw_string_lower_and_caps, search_case1, no_ignore_case, no_match, search_no_no_case1, 'list'),
]

test_yes_no_packages = [
    (raw_list_only_lower_case, search_case1, yes_ignore_case, no_match, search_no_yes_case1_1, 'list'),
    (raw_list_only_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1_2, 'list'),
    (raw_list_lower_and_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1_3, 'list'),
    (raw_string_only_lower_case, search_case1, yes_ignore_case, no_match, search_yes_no_case1_1, 'list'),
    (raw_string_only_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1_2, 'list'),
    (raw_string_lower_and_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1_3, 'list')
]

test_no_yes_packages = [
    (raw_list_only_lower_case, search_case1, yes_ignore_case, no_match, search_no_yes_case1_1, 'list'),
    (raw_list_only_caps, search_case1, yes_ignore_case, no_match, search_no_yes_case1_2, 'list'),
    (raw_list_lower_and_caps, search_case1, yes_ignore_case, no_match, search_no_yes_case1_3, 'list'),
    (raw_string_only_lower_case, search_case1, yes_ignore_case, no_match, search_yes_no_case1_1, 'list'),
    (raw_string_only_caps, search_case1, yes_ignore_case, no_match, search_no_yes_case1_2, 'list'),
    (raw_string_lower_and_caps, search_case1, yes_ignore_case, no_match, search_no_yes_case1_3, 'list')
]

test_yes_yes_packages = [
    (raw_list_only_lower_case, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_1, 'list'),
    (raw_list_only_caps, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_2, 'list'),
    (raw_list_lower_and_caps, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_3, 'list'),
    (raw_string_only_lower_case, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_1, 'list'),
    (raw_string_only_caps, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_2, 'list'),
    (raw_string_lower_and_caps, search_case1, yes_ignore_case, no_match, search_yes_yes_case1_3, 'list')
]


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result, list_name', empty_list_package)
def test_empty_list(lst, items, ignore_case, match_exact, expected_result, list_name):
    result = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result['Contents'] == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result', test_no_no_packages)
def test_no_ignore_no_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result['HumanReadable'] == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result', test_yes_no_packages)
def test_yes_ignore_no_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result['HumanReadable'] == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result', test_no_yes_packages)
def test_no_ignore_yes_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result['HumanReadable'] == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result', test_yes_yes_packages)
def test_yes_ignore_yes_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result['HumanReadable'] == expected_result

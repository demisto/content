from __future__ import print_function
import pytest
from FilterByList import filter_list

'''Test arguments'''

raw_string_only_lower_case = [{'Contents': 'demisto,paloalto,foo,boo,bar'}]
raw_string_only_caps = [{'Contents': 'DEMISTO,PALOALTO,FOO,BOO,BAR'}]
raw_string_lower_and_caps = [{'Contents': 'Demisto,paloAlto,FoO,boo,baR'}]

'''Search options'''

no_match, yes_match = False, True
no_ignore_case, yes_ignore_case = False, True

'''Search arguments'''

search_case1 = ['demisto', 'not_in_list', 'paloalto', 'FOO', 'bar', 'bo']

'''Expected results'''

empty_list_result = 'The list test_list is empty'

search_yes_no_case1 = 'demisto is in the list\n' \
                      'paloalto is in the list\n' \
                      'FOO is in the list\n' \
                      'bar is in the list\n' \
                      'bo is in the list\n' \
                      'not_in_list is not part of the list\n'

search_no_no_case1_1 = 'demisto is in the list\n' \
                       'paloalto is in the list\n' \
                       'bar is in the list\n' \
                       'bo is in the list\n' \
                       'not_in_list is not part of the list\n' \
                       'FOO is not part of the list\n'

search_no_no_case1_2 = 'FOO is in the list\n' \
                       'demisto is not part of the list\n' \
                       'not_in_list is not part of the list\n' \
                       'paloalto is not part of the list\n' \
                       'bar is not part of the list\n' \
                       'bo is not part of the list\n'

search_no_no_case1_3 = 'demisto is not part of the list\n' \
                       'not_in_list is not part of the list\n' \
                       'paloalto is not part of the list\n' \
                       'FOO is not part of the list\n' \
                       'bar is not part of the list\n' \
                       'bo is not part of the list\n'

search_no_yes_case1_1 = 'demisto is in the list\n' \
                        'paloalto is in the list\n' \
                        'bar is in the list\n' \
                        'not_in_list is not part of the list\n' \
                        'FOO is not part of the list\n' \
                        'bo is not part of the list\n'

search_no_yes_case1_2 = 'FOO is in the list\n' \
                        'demisto is not part of the list\n' \
                        'not_in_list is not part of the list\n' \
                        'paloalto is not part of the list\n' \
                        'bar is not part of the list\n' \
                        'bo is not part of the list\n'

search_no_yes_case1_3 = 'demisto is not part of the list\n' \
                        'not_in_list is not part of the list\n' \
                        'paloalto is not part of the list\n' \
                        'FOO is not part of the list\n' \
                        'bar is not part of the list\n' \
                        'bo is not part of the list\n'

search_yes_yes_case1 = 'demisto is in the list\n' \
                       'paloalto is in the list\n' \
                       'FOO is in the list\n' \
                       'bar is in the list\n' \
                       'not_in_list is not part of the list\n' \
                       'bo is not part of the list\n'

'''Test packages'''

test_yes_no_packages = [
    (raw_string_only_lower_case, search_case1, yes_ignore_case, no_match, search_yes_no_case1, 'list'),
    (raw_string_only_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1, 'list'),
    (raw_string_lower_and_caps, search_case1, yes_ignore_case, no_match, search_yes_no_case1, 'list'),
]

test_no_no_packages = [
    (raw_string_only_lower_case, search_case1, no_ignore_case, no_match, search_no_no_case1_1, 'list'),
    (raw_string_only_caps, search_case1, no_ignore_case, no_match, search_no_no_case1_2, 'list'),
    (raw_string_lower_and_caps, search_case1, no_ignore_case, no_match, search_no_no_case1_3, 'list')
]

test_no_yes_packages = [
    (raw_string_only_lower_case, search_case1, no_ignore_case, yes_match, search_no_yes_case1_1, 'list'),
    (raw_string_only_caps, search_case1, no_ignore_case, yes_match, search_no_yes_case1_2, 'list'),
    (raw_string_lower_and_caps, search_case1, no_ignore_case, yes_match, search_no_yes_case1_3, 'list')
]

test_yes_yes_packages = [
    (raw_string_only_lower_case, search_case1, yes_ignore_case, yes_match, search_yes_yes_case1, 'list'),
    (raw_string_only_caps, search_case1, yes_ignore_case, yes_match, search_yes_yes_case1, 'list'),
    (raw_string_lower_and_caps, search_case1, yes_ignore_case, yes_match, search_yes_yes_case1, 'list')
]


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result, list_name', test_yes_no_packages)
def test_yes_ignore_no_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result, _ = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result, list_name', test_yes_no_packages)
def test_no_ignore_no_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result, _ = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result, list_name', test_no_yes_packages)
def test_no_ignore_yes_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result, _ = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result == expected_result


@pytest.mark.parametrize('lst, items, ignore_case, match_exact, expected_result, list_name', test_yes_yes_packages)
def test_yes_ignore_yes_match(lst, items, ignore_case, match_exact, expected_result, list_name):
    result, _ = filter_list(lst, items, ignore_case, match_exact, list_name)
    assert result == expected_result

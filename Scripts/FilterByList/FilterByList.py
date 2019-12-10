import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def empty_list_context(items, list_name):
    ec = {'List.In': [], 'List.NotIn': items}
    human_readable = 'The list ' + list_name + ' is empty'

    return human_readable, ec


def build_filtered_data(lst, items, ignore_case, match_exact, regex_ignore_case_flag):
    not_white_listed = []  # type: list
    white_listed = []  # type: list
    human_readable = ''

    # fill whitelisted array with all the the values that match the regex items in listname argument
    list_to_lowercase = [list_item.lower().strip() for list_item in lst]
    for item in items:
        if match_exact:
            if ignore_case:
                if item.lower() not in list_to_lowercase:
                    continue
            else:
                if item not in lst:
                    continue

            human_readable += item + ' is in the list\n'
            white_listed.append(item)
        else:
            for list_item in lst:
                if list_item and re.search(item, list_item, regex_ignore_case_flag):
                    human_readable += item + ' is in the list\n'
                    white_listed.append(item)

    # fill not_white_listed array with all the the values that not in whitelisted
    for item in items:
        if item not in white_listed:
            human_readable += item + ' is not part of the list\n'
            not_white_listed.append(item)

    return white_listed, not_white_listed, human_readable


def filter_list(lst, items, ignore_case, match_exact, list_name):
    # If the list is empty
    if not lst[0]['Contents']:
        return empty_list_context(items, list_name)

    lst = lst[0]['Contents'].split(',')
    regex_ignore_case_flag = re.IGNORECASE if ignore_case else 0

    white_listed, not_white_listed, human_readable = build_filtered_data(lst, items, ignore_case, match_exact,
                                                                         regex_ignore_case_flag)

    ec = {'List.In': white_listed, 'List.NotIn': not_white_listed}

    return human_readable, ec


def main():
    list_name = demisto.args()['listname']
    ignore_case = demisto.args().get('ignorecase', '').lower() == 'yes'
    match_exact = demisto.args().get('matchexact', '').lower() == 'yes'
    items = argToList(demisto.args().get('values'))

    lst = demisto.executeCommand('getList', {'listName': list_name})

    if isError(lst[0]):
        return_error('List not found')

    human_readable, ec = filter_list(lst, items, ignore_case, match_exact, list_name)
    return_outputs(human_readable, ec, None)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def filter_list(lst, items, ignore_case, match_exact, list_name):
    not_white_listed = []  # type: list
    white_listed = []  # type: list
    human_readable = ""

    # If the list is empty
    if not lst[0]["Contents"]:
        for item in items:
            not_white_listed.append(item)

        ec = {"List.In": white_listed, "List.NotIn": not_white_listed}

        return {
            "ContentsFormat": formats["text"],
            "Type": entryTypes["note"],
            "Contents": 'The list ' + list_name + ' is empty',
            "EntryContext": ec
        }

    lst = lst[0]["Contents"].split(",")
    search_flag = re.IGNORECASE if ignore_case else 0

    # fill whitelisted array with all the the values that match the regex items in listname argument
    for item in items:
        if match_exact:
            if ignore_case:
                if not item.lower() in [list_item.lower().strip() for list_item in lst]:
                    continue
            else:
                if item not in lst:
                    continue

            human_readable += item + " is in the list\n"
            white_listed.append(item)

        else:
            for list_item in lst:
                if list_item and re.search(item, list_item, search_flag):
                    human_readable += item + " is in the list\n"
                    white_listed.append(item)

    # fill not_white_listed array with all the the values that not in whitelisted
    for item in items:
        if item not in white_listed:
            human_readable += item + " is not part of the list\n"
            not_white_listed.append(item)

    ec = {"List.In": white_listed, "List.NotIn": not_white_listed}
    contents = {"inList": white_listed, "notInList": not_white_listed}

    return {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": contents,
        "HumanReadable": human_readable,
        "HumanReadableFormat": formats["markdown"],
        "EntryContext": ec
    }


def main():
    list_name = demisto.args()["listname"]
    ignore_case = demisto.args().get("ignorecase", "").lower() == "yes"
    match_exact = demisto.args().get("matchexact", "").lower() == "yes"
    items = demisto.args().get("values", "")

    lst = demisto.executeCommand("getList", {"listName": list_name})

    if isError(lst[0]):
        return_error('List not found')

    if not isinstance(items, list):
        items = items.split(",")

    demisto.results(filter_list(lst, items, ignore_case, match_exact, list_name))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

from CommonServerPython import *


def where_field_equals(args):
    """
    Handles the operation of finding a list of objects where the given field is present under the
    specified location.
    :param args: dictionary containing the Demisto arguments object.
    :return: hr_string as a human readable string. entry_context as a dictionary containing the
    results.
    """
    values_to_search = argToList(args.get('value'))
    field = args.get('field')
    equal_to = args.get('equalTo')
    get_field = args.get('getField')
    found_matches = []
    for dict_item in values_to_search:
        if dict_item.get(field, None) == equal_to:
            if get_field:
                found_matches.append(dict_item[get_field])
            else:
                found_matches.append(dict_item)
    if len(found_matches) == 1:
        return found_matches[0]

    return json.dumps(found_matches, separators=(',', ':'), ensure_ascii=False)


def main():
    args = demisto.args()
    hr_string = where_field_equals(args)
    return_outputs(readable_output=hr_string)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

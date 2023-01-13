import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_fields(args):
    """
    Retrieves fields from an object using dot notation by leveraging demisto.get().
    :param args: dictionary containing the Demisto arguments object.
    :return: hr_string as a human readable string. entry_context as a dictionary containing the
    results.
    """
    values_to_search = argToList(args.get('value'))
    get_field = args.get('getField')

    reduced_dicts = []
    for dict_item in values_to_search:
        if isinstance(dict_item, dict):
            if get_field:
                fields_to_get = get_field.split(",")
                value = {field: demisto.get(dict_item, field) for field in fields_to_get}
                if value:
                    reduced_dicts.append(value)
            else:
                reduced_dicts.append(dict_item)

    if len(reduced_dicts) == 1:
        return reduced_dicts[0]

    if argToBoolean(args.get('stringify', 'false')):
        return json.dumps(reduced_dicts, ensure_ascii=False)
    else:
        return reduced_dicts


def main():
    args = demisto.args()
    return_results(get_fields(args))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()

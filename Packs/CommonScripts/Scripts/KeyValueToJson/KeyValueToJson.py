import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
def key_to_json(keys, values):
    return_data = None
    key_length = len(keys)

    # Are there sub-lists or tuples in the values
    values_has_lists = False
    for value in values:
        if isinstance(value, list) or isinstance(value, tuple):
            values_has_lists = True
            break

    # If there are sub-lists or tuples in the values, ensure the length matches the keys length
    if values_has_lists:
        for value in values:
            if not isinstance(value, list) and not isinstance(value, tuple):
                return_error("There are a mix of lists/tuples/values in the values")
            elif len(value) != key_length:
                return_error("The number of sub-values provided do not match the length of keys")

    # If the values are NOT lists or tuples
    if not values_has_lists:

        # Check that the lengths are equal
        if len(keys) != len(values):
            return_error("The number of values provided do not match the length of keys")

        return_data = dict()
        try:
            for index in range(0, len(keys) - 1):
                return_data[keys[index]] = values[index]
        except Exception as err:
            return_error(err)

    # If the values contains sub lists or tuples
    else:
        return_data = []
        for value in values:
            this_dictionary = {}
            for x in range(0, len(value)):
                this_dictionary[keys[x]] = values[x]
            return_data.append(this_dictionary)

    return return_data


def main():
    args = demisto.args()
    values = argToList(args.get('value'))
    keys = argToList(args.get('key'))
    return_results(key_to_json(keys, values))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
